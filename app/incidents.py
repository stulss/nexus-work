"""Incident views over the existing Ticket and AI-XDR tables."""
import json
import re
from datetime import datetime, timezone

from . import db


TICKET_ID_RE = re.compile(r"NX-DB-(\d{6,18})", re.IGNORECASE)
RESPONSE_FIELDS = {
    "action", "created_at", "at", "actor", "by", "status", "reason", "assessment_id", "rule_id", "result",
    "response_id", "step", "mode", "src_ip", "ticket_id", "policy_reason", "executed_at", "minutes",
    "resolution", "note",
}


def display_ticket_id(ticket_db_id):
    return f"NX-DB-{int(ticket_db_id):06d}"


def _as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, list) else []
        except (TypeError, ValueError):
            return []
    return []


def _json_object(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            result = json.loads(value)
            return result if isinstance(result, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


def _safe_responses(value):
    safe = []
    for item in _as_list(value)[-30:]:
        if not isinstance(item, dict):
            continue
        entry = {}
        for key in RESPONSE_FIELDS:
            val = item.get(key)
            if isinstance(val, (str, int, float, bool)):
                if key in {"reason", "result"} and isinstance(val, str) and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", val):
                    continue
                entry[key] = str(val)[:500] if isinstance(val, str) else val
        if entry:
            safe.append(entry)
    return safe


def _decode_ticket(row):
    if not row:
        return None
    ticket = dict(row)
    for key in ("rule_ids", "user_names"):
        ticket[key] = _as_list(ticket.get(key))
    ticket["latest_event"] = _json_object(ticket.get("latest_event"))
    ticket["responses"] = _safe_responses(ticket.get("responses"))
    ticket["display_id"] = display_ticket_id(ticket["id"])
    ticket["ticket_id"] = ticket["display_id"]
    return ticket


def list_tickets(limit=500):
    limit = max(1, min(int(limit), 500))
    rows = db.query_all(
        "SELECT id, ticket_key, status, src_ip, ticket_type, event_count, rule_ids, user_names, "
        "first_seen, last_seen, latest_event, resolution, closed_at, note, responses "
        "FROM security_incident_tickets ORDER BY last_seen DESC LIMIT %s",
        (limit,),
    )
    return [_decode_ticket(row) for row in rows if row]


def get_ticket(ticket_db_id):
    ticket_id = int(ticket_db_id)
    row = db.query_one(
        "SELECT id, ticket_key, status, src_ip, ticket_type, event_count, rule_ids, user_names, "
        "first_seen, last_seen, latest_event, resolution, closed_at, note, responses "
        "FROM security_incident_tickets WHERE id = %s LIMIT 1",
        (ticket_id,),
    )
    ticket = _decode_ticket(row)
    if ticket is None:
        return None

    ticket["alerts"] = db.query_all(
        "SELECT alert_id, rule_id, event_type, user_name AS user, src_ip, event_count, occurred_at, severity "
        "FROM security_xdr_events WHERE incident_ticket_id = %s ORDER BY occurred_at ASC LIMIT 500",
        (ticket_id,),
    )
    return ticket


def close_ticket(ticket_db_id, resolution, note, actor):
    if resolution not in {"resolved", "false_positive", "other"}:
        raise ValueError("invalid_resolution")

    ticket_id = int(ticket_db_id)
    row = db.query_one(
        "SELECT id, status, responses FROM security_incident_tickets WHERE id = %s LIMIT 1",
        (ticket_id,),
    )
    if not row:
        raise LookupError("incident_not_found")
    if row.get("status") == "closed":
        return {"status": "already_closed", "ticket_db_id": ticket_id}

    responses = _safe_responses(row.get("responses"))
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")
    response = {
        "action": "incident_close",
        "created_at": now,
        "actor": str(actor or "admin")[:64],
        "status": "closed",
        "resolution": resolution,
        "note": str(note or "")[:500],
        "ticket_id": display_ticket_id(ticket_id),
    }
    responses.append(response)
    responses = responses[-30:]
    changed = db.execute_rowcount(
        "UPDATE security_incident_tickets SET status = %s, resolution = %s, closed_at = %s, note = %s, "
        "responses = CAST(%s AS JSON) WHERE id = %s AND status <> 'closed'",
        ("closed", resolution, now, str(note or "")[:500], json.dumps(responses, ensure_ascii=False), ticket_id),
    )
    if changed:
        return {"status": "closed", "ticket_db_id": ticket_id}

    current = db.query_one("SELECT status FROM security_incident_tickets WHERE id = %s LIMIT 1", (ticket_id,))
    if current and current.get("status") == "closed":
        return {"status": "already_closed", "ticket_db_id": ticket_id}
    raise RuntimeError("incident_close_failed")


def record_auto_block_result(ticket_ids, response):
    """Append a minimized AI-XDR result to responses on the existing Ticket rows."""
    if not isinstance(ticket_ids, list) or not isinstance(response, dict):
        return 0
    local_ids = list(dict.fromkeys(
        int(match.group(1))
        for ticket_id in ticket_ids
        if isinstance(ticket_id, str)
        for match in [TICKET_ID_RE.fullmatch(ticket_id.strip())]
        if match and int(match.group(1)) > 0
    ))[:50]
    safe_response = _safe_responses([response])
    if not local_ids or not safe_response or not safe_response[0].get("response_id"):
        return 0

    placeholders = ",".join(["%s"] * len(local_ids))
    rows = db.query_all(
        "SELECT id FROM security_incident_tickets WHERE id IN (" + placeholders + ")",
        tuple(local_ids),
    )
    response_json = json.dumps(safe_response[0], ensure_ascii=False, separators=(",", ":"))
    response_id = safe_response[0]["response_id"]
    updated = 0
    for row in rows:
        updated += db.execute_rowcount(
            "UPDATE security_incident_tickets SET responses=IF("
            "JSON_SEARCH(COALESCE(responses,JSON_ARRAY()),'one',%s,NULL,'$[*].response_id') IS NOT NULL,"
            "COALESCE(responses,JSON_ARRAY()),"
            "JSON_ARRAY_APPEND(IF(JSON_LENGTH(COALESCE(responses,JSON_ARRAY()))>=30,"
            "JSON_REMOVE(COALESCE(responses,JSON_ARRAY()),'$[0]'),COALESCE(responses,JSON_ARRAY())),'$',CAST(%s AS JSON))) "
            "WHERE id=%s",
            (response_id, response_json, int(row["id"])),
        )
    return updated


def assessments_for_ticket(ticket_db_id):
    rows = db.query_all(
        "SELECT assessment_id, incident_ticket_id, status, verdict, threat_score, confidence, "
        "recommended_actions, policy_reason, auto_allowed, response_result, rule_ids, event_types, "
        "event_count, first_seen, last_seen, created_at "
        "FROM security_xdr_assessments WHERE incident_ticket_id = %s "
        "ORDER BY created_at DESC LIMIT 50",
        (int(ticket_db_id),),
    )
    for row in rows:
        for key in ("recommended_actions", "rule_ids", "event_types"):
            row[key] = _as_list(row.get(key))
        row["response_result"] = _json_object(row.get("response_result"))
    return rows


def latest_assessments_for_tickets(tickets):
    """Attach the newest assessment using the numeric Ticket FK."""
    ticket_ids = list(dict.fromkeys(
        int(ticket["id"]) for ticket in tickets
        if isinstance(ticket, dict) and str(ticket.get("id", "")).isdigit() and int(ticket["id"]) > 0
    ))
    if not ticket_ids:
        return

    placeholders = ",".join(["%s"] * len(ticket_ids))
    rows = db.query_all(
        "SELECT incident_ticket_id, assessment_id, status, verdict, threat_score, confidence, "
        "recommended_actions, policy_reason, auto_allowed, response_result, created_at "
        "FROM security_xdr_assessments WHERE incident_ticket_id IN (" + placeholders + ") "
        "ORDER BY created_at DESC LIMIT 500",
        tuple(ticket_ids),
    )
    ticket_by_id = {int(ticket["id"]): ticket for ticket in tickets if ticket.get("id") is not None}
    assigned = set()
    for row in rows:
        try:
            ticket_id = int(row.get("incident_ticket_id"))
        except (TypeError, ValueError):
            continue
        ticket = ticket_by_id.get(ticket_id)
        if ticket is None or ticket_id in assigned:
            continue
        row["recommended_actions"] = _as_list(row.get("recommended_actions"))
        row["response_result"] = _json_object(row.get("response_result"))
        ticket["latest_assessment"] = row
        assigned.add(ticket_id)
