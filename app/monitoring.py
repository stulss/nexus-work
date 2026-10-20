"""Local team-stack bridge. Existing Graylog Event Definitions are unchanged."""
import hmac
import ipaddress
import json
import logging
import os
import socket
import subprocess
import threading
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from . import db, security

bp = Blueprint('monitoring', __name__, url_prefix='/api/v1/security')
PROTECTED = {'127.0.0.1', '::1', '172.16.50.1', '172.16.50.2',
             '172.16.50.10', '192.168.3.10', '192.168.3.14', '192.168.81.1', '192.168.81.128'}
FIELDS = set('ts event_type user role src_ip method path decision reason request_id source_component severity action target outcome integration_test'.split())


class GelfHandler(logging.Handler):
    def emit(self, record):
        try:
            e = json.loads(record.getMessage())
            fields = {k:v for k,v in e.items() if k in FIELDS and isinstance(v,(str,int,float,bool))}
            fields.setdefault('source_component', 'nexus_portal')
            wire = {'version':'1.1','host':'nexus-portal-local',
                    'short_message':'NEXUS '+str(e.get('event_type','event')),
                    'timestamp':datetime.fromisoformat(e['ts']).timestamp()}
            wire.update({'_'+k:v for k,v in fields.items()})
            wire['_username'] = fields.get('user','-')
            if e.get('event_type') in ('login_failure','login_locked'):
                wire['_rule'] = 'login-bruteforce'
                wire['_locked'] = int(e['event_type']=='login_locked')
            elif e.get('event_type')=='not_found':
                wire['_rule']='web-scan'
            payload=json.dumps(wire,ensure_ascii=False).encode('utf-8')
            if len(payload)>8000: raise ValueError('oversized GELF')
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.sendto(payload,('127.0.0.1',12201))
        except Exception:
            # Local file remains the source of truth; failures are visible in server stderr.
            self.handleError(record)


def init_app(app):
    token=os.environ.get('NEXUS_RESPONSE_TOKEN','')
    if len(token)<32: raise RuntimeError('NEXUS_RESPONSE_TOKEN must be configured')
    app.config['NEXUS_RESPONSE_TOKEN']=token
    app.register_blueprint(bp)
    logger=logging.getLogger('nexus.security')
    if not any(isinstance(h,GelfHandler) for h in logger.handlers): logger.addHandler(GelfHandler())


@bp.before_request
def authorize():
    supplied=request.headers.get('Authorization','')
    expected='Bearer '+current_app.config['NEXUS_RESPONSE_TOKEN']
    if not hmac.compare_digest(supplied.encode(),expected.encode()):
        return jsonify(ok=False,error='unauthorized'),401
    if request.content_length and request.content_length>16384:
        return jsonify(ok=False,error='payload_too_large'),413


@bp.get('/health')
def health():
    return jsonify(ok=True,bridge='nexus-local-v1',firewall='pfsense',audit='/admin/audit')


def payload():
    data=request.get_json(silent=True)
    if not isinstance(data,dict): raise ValueError('JSON object required')
    return data


def audit(action,data,outcome='applied'):
    target=str(data.get('ip') or data.get('src_ip') or data.get('username') or '-')[:128]
    security.log_event('security_response','INFO','n8n_'+action,action=action,target=target,
                       outcome=outcome,source_component='n8n_response',
                       request_id=str(data.get('request_id','-'))[:100])


@bp.post('/events')
@bp.post('/incident')
def record_event():
    try: data=payload()
    except ValueError: return jsonify(ok=False,error='invalid_payload'),400
    action='incident' if request.path.endswith('/incident') else 'event'
    audit(action,data,'recorded')
    return jsonify(ok=True,status='recorded',action=action,src_ip=data.get('src_ip','-'))


def firewall(action,ip):
    address=ipaddress.ip_address(ip)
    allowed={x.strip() for x in os.environ.get('NEXUS_BLOCK_ALLOWED_IPS','').split(',') if x.strip()}
    if address.version!=4 or str(address) in PROTECTED or str(address) not in allowed:
        raise ValueError('target_not_allowlisted')
    op='add' if action=='block' else 'delete'
    command=f'/sbin/pfctl -t NEXUS_AUTO_BLOCK -T {op} {address}'
    result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5',
                           '-o','StrictHostKeyChecking=yes','-i',
                           'C:/Users/user/.ssh/pfsense_admin','admin@172.16.50.2',command],
                          capture_output=True,timeout=12)
    if result.returncode: raise RuntimeError('firewall_command_failed')
    verify=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5',
                           '-o','StrictHostKeyChecking=yes','-i',
                           'C:/Users/user/.ssh/pfsense_admin','admin@172.16.50.2',
                           '/sbin/pfctl -t NEXUS_AUTO_BLOCK -T show'],capture_output=True,text=True,timeout=12)
    if verify.returncode or ((str(address) in verify.stdout.split()) != (action=='block')):
        raise RuntimeError('firewall_verification_failed')


@bp.post('/block')
@bp.post('/unblock')
def change_block():
    action=request.path.rsplit('/',1)[-1]
    try:
        data=payload(); ip=str(data.get('ip') or data.get('src_ip') or '')
        firewall(action,ip)
    except ValueError:
        return jsonify(ok=False,error='target_not_allowlisted'),403
    except (RuntimeError,subprocess.TimeoutExpired):
        return jsonify(ok=False,error='firewall_failed'),502
    audit(action,data)
    return jsonify(ok=True,status='blocked' if action=='block' else 'unblocked',ip=ip,
                   src_ip=ip,firewall='pfsense')


@bp.post('/lock')
@bp.post('/unlock')
def change_lock():
    action=request.path.rsplit('/',1)[-1]
    try: data=payload()
    except ValueError: return jsonify(ok=False,error='invalid_payload'),400
    username=str(data.get('username',''))
    allowed={s.strip() for s in os.environ.get('NEXUS_LOCK_ALLOWED_USERS','').split(',') if s.strip()}
    if username not in allowed: return jsonify(ok=False,error='target_not_allowlisted'),403
    row=db.query_one('SELECT id, role FROM users WHERE username = %s FOR UPDATE',(username,))
    if not row or row['role']=='admin': return jsonify(ok=False,error='protected_or_missing_user'),403
    if action=='lock':
        db.execute('UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE id = %s',(row['id'],))
    else:
        db.execute('UPDATE users SET locked_until = NULL, failed_count = 0 WHERE id = %s',(row['id'],))
    db.commit()
    audit(action,data)
    return jsonify(ok=True,status='locked' if action=='lock' else 'unlocked',username=username)
