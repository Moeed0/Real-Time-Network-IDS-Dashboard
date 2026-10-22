import sqlite3

from ids.alert_intelligence import (
    build_alert_intelligence_context,
    get_alert_intelligence,
)


RULE_DB = "data/lab/rules/ids_rules.db"


def get_real_rule(engine="snort"):
    conn = sqlite3.connect(RULE_DB)
    conn.row_factory = sqlite3.Row

    try:
        return conn.execute(
            """
            SELECT gid, sid, msg
            FROM rules
            WHERE gid IS NOT NULL
              AND engine = ?
            ORDER BY id
            LIMIT 1
            """,
            (engine,),
        ).fetchone()
    finally:
        conn.close()


def test_real_rule_lookup():
    row = get_real_rule()

    assert row is not None

    result = get_alert_intelligence(
        gid=row["gid"],
        sid=row["sid"],
    )

    assert result is not None
    assert result["rule"]["gid"] == row["gid"]
    assert result["rule"]["sid"] == row["sid"]
    assert result["rule"]["msg"] == row["msg"]


def test_documentation_lookup():
    row = get_real_rule()

    result = get_alert_intelligence(
        gid=row["gid"],
        sid=row["sid"],
    )

    assert result is not None

    documentation = result["documentation"]

    assert isinstance(documentation, dict)
    assert documentation.get("sid") == row["sid"]
    assert documentation.get("msg") == row["msg"]


def test_sources_are_reported():
    row = get_real_rule()

    result = get_alert_intelligence(
        gid=row["gid"],
        sid=row["sid"],
    )

    assert result is not None

    assert (
        result["sources"]["rule_database"]
        == "data/lab/rules/ids_rules.db"
    )

    assert (
        result["sources"]["rule_documentation"]
        == "data/json/rule_docs_preprocessed_by_sid.json"
    )


def test_missing_rule_returns_none():
    result = get_alert_intelligence(
        gid=999999,
        sid=999999999,
    )

    assert result is None


def test_alert_context_contains_original_alert():
    row = get_real_rule()

    alert = {
        "engine": "snort",
        "gid": row["gid"],
        "sid": row["sid"],
        "msg": row["msg"],
        "src_ip": "192.168.50.141",
        "dest_ip": "192.168.50.114",
    }

    context = build_alert_intelligence_context(alert)

    assert context["rule_context_found"] is True
    assert context["alert"] == alert
    assert context["rule"]["gid"] == row["gid"]
    assert context["rule"]["sid"] == row["sid"]


def test_invalid_alert_identifiers_do_not_crash():
    alert = {
        "engine": "snort",
        "gid": "not-a-number",
        "sid": "also-not-a-number",
    }

    context = build_alert_intelligence_context(alert)

    assert context["rule_context_found"] is False
    assert context["alert"] == alert
    assert context["rule"] == {}
    assert context["documentation"] == {}

def test_alert_context_contains_llm_ready_summary():
    row = get_real_rule()

    alert = {
        "engine": "snort",
        "gid": row["gid"],
        "sid": row["sid"],
        "msg": row["msg"],
        "src_ip": "192.168.50.141",
        "dest_ip": "192.168.50.114",
        "protocol": "TCP",
    }

    context = build_alert_intelligence_context(alert)

    assert context["rule_context_found"] is True
    assert "summary" in context

    summary = context["summary"]

    assert isinstance(summary, dict)
    assert summary["engine"] == "snort"
    assert summary["gid"] == row["gid"]
    assert summary["sid"] == row["sid"]
    assert summary["message"] == row["msg"]
    assert summary["protocol"] == "TCP"
    assert "classification" in summary
    assert "priority" in summary
    assert "documentation_available" in summary
    assert "cves" in summary
    assert "mitre_attack" in summary


def test_missing_rule_context_has_safe_summary():
    alert = {
        "engine": "snort",
        "gid": 999999,
        "sid": 999999999,
        "msg": "Unknown alert",
    }

    context = build_alert_intelligence_context(alert)

    assert context["rule_context_found"] is False
    assert "summary" in context

    summary = context["summary"]

    assert summary["engine"] == "snort"
    assert summary["gid"] == 999999
    assert summary["sid"] == 999999999
    assert summary["message"] == "Unknown alert"
    assert summary["documentation_available"] is False



def test_alert_context_contains_cross_engine_normalized_alert():
    row = get_real_rule("suricata")

    alert = {
        "engine": "suricata",
        "timestamp": "2026-10-08T10:00:00.000000+0000",
        "gid": row["gid"],
        "sid": row["sid"],
        "rev": 3,
        "msg": row["msg"],
        "classification": "attempted-admin",
        "priority": 1,
        "protocol": "tcp",
        "service": "http",
        "src": "192.168.50.141:60914",
        "dst": "192.168.50.114:80",
        "src_addr": "192.168.50.141",
        "src_port": 60914,
        "dst_addr": "192.168.50.114",
        "dst_port": 80,
        "direction": "to_server",
        "severity": 2,
        "flow_id": 12345,
        "community_id": "1:example",
        "correlation_group_id": "cid:test",
    }

    context = build_alert_intelligence_context(alert)

    assert context["rule_context_found"] is True
    assert context["alert"] == alert
    assert "normalized_alert" in context

    normalized = context["normalized_alert"]

    assert normalized["engine"] == "suricata"
    assert normalized["timestamp"] == alert["timestamp"]
    assert normalized["gid"] == row["gid"]
    assert normalized["sid"] == row["sid"]
    assert normalized["revision"] == 3
    assert normalized["message"] == row["msg"]
    assert normalized["classification"] == "attempted-admin"
    assert normalized["priority"] == 1
    assert normalized["protocol"] == "TCP"
    assert normalized["service"] == "http"
    assert normalized["source"] == "192.168.50.141:60914"
    assert normalized["destination"] == "192.168.50.114:80"
    assert normalized["direction"] == "to_server"
    assert normalized["severity"] == 2
    assert normalized["flow_id"] == 12345
    assert normalized["community_id"] == "1:example"
    assert normalized["correlation_group_id"] == "cid:test"


def test_normalized_alert_handles_missing_optional_fields():
    row = get_real_rule()

    alert = {
        "engine": "snort",
        "gid": row["gid"],
        "sid": row["sid"],
        "msg": row["msg"],
    }

    context = build_alert_intelligence_context(alert)

    assert context["rule_context_found"] is True

    normalized = context["normalized_alert"]

    assert normalized["engine"] == "snort"
    assert normalized["gid"] == row["gid"]
    assert normalized["sid"] == row["sid"]
    assert normalized["message"] == row["msg"]
    assert normalized["protocol"] == ""
    assert normalized["service"] == ""
    assert normalized["source"] == ""
    assert normalized["destination"] == ""
    assert normalized["direction"] == ""
    assert normalized["severity"] is None
    assert normalized["flow_id"] is None
    assert normalized["community_id"] == ""
    assert normalized["correlation_group_id"] == ""
