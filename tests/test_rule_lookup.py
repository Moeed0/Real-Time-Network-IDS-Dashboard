import sqlite3
from pathlib import Path

import pytest

from ids.alert_intelligence import (
    RULE_DB_PATH,
    RULE_DOCS_PATH,
    _documentation_for_rule,
    _fetch_rule,
    get_alert_intelligence,
)


@pytest.fixture
def rules_db(tmp_path):
    path = tmp_path / "rules.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE rules (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "engine TEXT, gid INTEGER, sid INTEGER, rev INTEGER, msg TEXT)"
    )
    conn.executemany(
        "INSERT INTO rules (engine, gid, sid, rev, msg) VALUES (?,?,?,?,?)",
        [
            ("snort", 1, 100, 1, "snort r1"),
            ("snort", 1, 100, 2, "snort r2"),
            ("suricata", 1, 100, 3, "suricata r3"),
        ],
    )
    conn.commit()
    conn.close()
    return path


def test_engine_is_a_hard_filter(rules_db):
    assert _fetch_rule(1, 100, rules_db, engine="suricata")["msg"] == "suricata r3"
    assert _fetch_rule(1, 100, rules_db, engine="snort")["engine"] == "snort"


def test_revision_preferred_then_latest(rules_db):
    assert _fetch_rule(1, 100, rules_db, engine="snort", rev=1)["msg"] == "snort r1"
    assert _fetch_rule(1, 100, rules_db, engine="snort")["msg"] == "snort r2"


def test_gid_mismatch_still_matches_within_engine(rules_db):
    assert _fetch_rule(0, 100, rules_db, engine="suricata")["msg"] == "suricata r3"


def test_unknown_sid_or_engine_returns_none(rules_db):
    assert _fetch_rule(1, 999, rules_db, engine="snort") is None
    assert _fetch_rule(1, 100, rules_db, engine="zeek") is None


def test_documentation_only_attached_to_snort_rules():
    docs = {"100": {"msg": "documented"}}

    assert _documentation_for_rule({"engine": "snort", "sid": 100}, docs)
    assert _documentation_for_rule({"engine": "suricata", "sid": 100}, docs) == {}


datasets_present = Path(RULE_DB_PATH).exists() and Path(RULE_DOCS_PATH).exists()


@pytest.mark.skipif(not datasets_present, reason="rule datasets not present")
def test_real_shellshock_rules_resolve_to_the_right_engine():
    suricata = get_alert_intelligence(1, 2022028, engine="suricata", rev=2)
    snort = get_alert_intelligence(1, 31978, engine="snort", rev=5)

    assert suricata["rule"]["engine"] == "suricata"
    assert "CVE-2014-6271" in suricata["rule"]["cve_ids_json"]
    assert suricata["documentation"] == {}

    assert snort["rule"]["engine"] == "snort"
    assert snort["documentation"]
