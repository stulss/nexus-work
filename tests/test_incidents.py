import json
import logging

import pymysql
from flask import g

from app import admin, incidents
from support import as_user, post


def _ticket_row(ticket_id=86, *, status="open"):
    return {
        "id": ticket_id, "ticket_key": "ip:192.0.2.10", "status": status, "src_ip": "192.0.2.10",
        "ticket_type": "보안 경보", "event_count": 2, "rule_ids": '["R3","R8"]',
        "user_names": '["analyst"]', "first_seen": "2026-10-30 01:00:00",
        "last_seen": "2026-10-30 01:05:00", "latest_event": "{}", "resolution": None,
        "closed_at": None, "note": None,
        "responses": '[{"action":"auto_block","status":"success","result":"blocked_ips_registered"}]',
    }


def test_incident_list_reads_ticket_table_and_correlates_latest_assessment(aapp, monkeypatch):
    aapp.config["XDR_ENABLED"] = True
    queries = []

    def query_all(sql, params=(), **_kwargs):
        queries.append((sql, params))
        if "FROM security_incident_tickets" in sql:
            return [_ticket_row()]
        if "FROM security_xdr_assessments" in sql:
            return [{
                "incident_ticket_id": 86, "assessment_id": "assessment-86", "status": "NO_ACTION",
                "verdict": "BENIGN", "threat_score": 12, "confidence": 0.9,
                "recommended_actions": '["notify_only"]', "policy_reason": "NO_ACTION",
                "auto_allowed": 0, "response_result": '{"reason":"dry_run"}',
                "created_at": "2026-10-30 01:06:00",
            }]
        raise AssertionError(sql)

    monkeypatch.setattr(incidents.db, "query_all", query_all)
    response = as_user(aapp, "zz_sec").get("/admin/incidents")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "NX-DB-000086" in html and "BENIGN · 12/100" in html
    assert "ip:192.0.2.10" not in html
    assert "표시할 인시던트가 없습니다" not in html
    assert "FROM security_incident_tickets" in queries[0][0]
    assert "JOIN" not in queries[0][0]
    assert queries[1][1] == (86,)
    assert all("security_incident_alerts" not in sql for sql, _ in queries)


def test_incident_list_database_error_keeps_detail_only_in_server_log(aapp, monkeypatch, caplog):
    aapp.config["XDR_ENABLED"] = True

    def fail_query(*_args, **_kwargs):
        raise pymysql.OperationalError(1142, "SELECT denied synthetic")

    audit_events = []

    def capture_audit(*args, **kwargs):
        g.nexus_request_id = "incident-list-test-request"
        audit_events.append((args, kwargs))

    monkeypatch.setattr(incidents.db, "query_all", fail_query)
    monkeypatch.setattr(admin, "log_event", capture_audit)
    with caplog.at_level(logging.ERROR):
        response = as_user(aapp, "zz_sec").get("/admin/incidents")

    html = response.get_data(as_text=True)
    records = [record for record in caplog.records if "incident_database_exception" in record.getMessage()]
    assert response.status_code == 200
    assert "1142" not in html and "SELECT denied" not in html
    assert len(records) == 1
    assert "request_id=incident-list-test-request" in records[0].getMessage()
    assert "mysql_error_code=1142" in records[0].getMessage()
    assert records[0].exc_info and records[0].exc_info[0] is pymysql.OperationalError
    assert audit_events == [(("incident_list", "ERROR", "OperationalError"), {})]


def test_incident_detail_uses_xdr_events_and_assessment_numeric_fk(aapp, monkeypatch):
    aapp.config["XDR_ENABLED"] = True
    client = as_user(aapp, "zz_sec")
    original_query_one = incidents.db.query_one
    queries = []

    def query_one(sql, params=(), **_kwargs):
        queries.append((sql, params))
        if "FROM users" in sql:
            return original_query_one(sql, params, **_kwargs)
        if "FROM security_incident_tickets" in sql:
            return _ticket_row()
        raise AssertionError(sql)

    def query_all(sql, params=(), **_kwargs):
        queries.append((sql, params))
        if "FROM security_xdr_events" in sql:
            return [{
                "alert_id": "graylog-alert-86", "rule_id": "R8", "event_type": "not_found",
                "user": "analyst", "src_ip": "192.0.2.10", "event_count": 35,
                "occurred_at": "2026-10-30 01:05:00", "severity": "info",
            }]
        if "FROM security_xdr_assessments" in sql:
            return [{
                "incident_ticket_id": 86, "assessment_id": "assessment-86", "status": "NO_ACTION",
                "verdict": "BENIGN", "threat_score": 12, "confidence": 0.9,
                "recommended_actions": '["notify_only"]', "policy_reason": "NO_ACTION",
                "auto_allowed": 0, "response_result": '{"reason":"dry_run"}',
                "rule_ids": '["R8"]', "event_types": '["not_found"]', "event_count": 35,
                "first_seen": "2026-10-30 01:00:00", "last_seen": "2026-10-30 01:05:00",
                "created_at": "2026-10-30 01:06:00",
            }]
        raise AssertionError(sql)

    monkeypatch.setattr(incidents.db, "query_one", query_one)
    monkeypatch.setattr(incidents.db, "query_all", query_all)
    response = client.get("/admin/incidents/86")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    for value in ("NX-DB-000086", "not_found", "assessment-86", "BENIGN", "차단 목록에 15분 등록"):
        assert value in html
    assert "security_incident_alerts" not in " ".join(sql for sql, _ in queries)
    assert queries[1][1] == (86,) and queries[2][1] == (86,)
    assert "event_payload" not in " ".join(sql for sql, _ in queries)


def test_incident_detail_unknown_numeric_id_returns_404(aapp, monkeypatch):
    client = as_user(aapp, "zz_sec")
    original_query_one = incidents.db.query_one
    monkeypatch.setattr(
        incidents.db, "query_one",
        lambda sql, params=(), **kwargs: original_query_one(sql, params, **kwargs) if "FROM users" in sql else None,
    )
    assert client.get("/admin/incidents/999999").status_code == 404


def test_incident_close_requires_csrf_and_updates_ticket_row(aapp, monkeypatch):
    client = as_user(aapp, "zz_sec")
    original_query_one = incidents.db.query_one
    row = {"id": 86, "status": "open", "responses": '[{"action":"notify"}]'}
    writes = []

    def query_one(sql, params=(), **_kwargs):
        if "FROM users" in sql:
            return original_query_one(sql, params, **_kwargs)
        assert "FROM security_incident_tickets" in sql
        assert params == (86,)
        return dict(row)

    def execute_rowcount(sql, params=(), **_kwargs):
        writes.append((sql, params))
        row["status"] = "closed"
        return 1

    monkeypatch.setattr(incidents.db, "query_one", query_one)
    monkeypatch.setattr(incidents.db, "execute_rowcount", execute_rowcount)
    assert client.post("/admin/incidents/86/close", data={"resolution": "resolved"}).status_code == 403
    response = post(client, "/admin/incidents/86/close", resolution="false_positive", note="오탐 확인")
    assert response.status_code == 303
    assert len(writes) == 1
    assert "UPDATE security_incident_tickets" in writes[0][0]
    assert "security_incident_alerts" not in writes[0][0]
    assert writes[0][1][0:2] == ("closed", "false_positive")
    recorded = json.loads(writes[0][1][4])
    assert recorded[-1]["action"] == "incident_close"
    assert recorded[-1]["resolution"] == "false_positive"
    assert recorded[-1]["note"] == "오탐 확인"


def test_close_ticket_is_idempotent_and_missing_ticket_is_reported(app, monkeypatch):
    row = {"id": 86, "status": "open", "responses": "[]"}
    updates = []

    def query_one(_sql, _params=(), **_kwargs):
        return dict(row)

    def execute_rowcount(_sql, _params=(), **_kwargs):
        updates.append(True)
        row["status"] = "closed"
        return 1

    monkeypatch.setattr(incidents.db, "query_one", query_one)
    monkeypatch.setattr(incidents.db, "execute_rowcount", execute_rowcount)
    with app.app_context():
        first = incidents.close_ticket(86, "resolved", "", "analyst")
        second = incidents.close_ticket(86, "resolved", "", "analyst")

    assert first["status"] == "closed"
    assert second["status"] == "already_closed"
    assert len(updates) == 1

    monkeypatch.setattr(incidents.db, "query_one", lambda *_args, **_kwargs: None)
    with app.app_context():
        try:
            incidents.close_ticket(999, "resolved", "", "analyst")
        except LookupError as exc:
            assert str(exc) == "incident_not_found"
        else:
            raise AssertionError("missing Ticket must be reported")


def test_record_auto_block_result_maps_external_ticket_id_to_numeric_id(monkeypatch):
    reads = []
    writes = []
    monkeypatch.setattr(
        incidents.db, "query_all",
        lambda sql, params=(): reads.append((sql, params)) or [{"id": 86}],
    )
    monkeypatch.setattr(
        incidents.db, "execute_rowcount",
        lambda sql, params=(): writes.append((sql, params)) or 1,
    )

    updated = incidents.record_auto_block_result(["NX-DB-000086"], {
        "action": "auto_block", "status": "success", "response_id": "auto_block:assessment-86",
        "assessment_id": "assessment-86", "ticket_id": "NX-DB-000086",
    })

    assert updated == 1
    assert "FROM security_incident_tickets" in reads[0][0]
    assert "security_incident_alerts" not in reads[0][0]
    assert reads[0][1] == (86,)
    assert writes[0][1][-1] == 86
