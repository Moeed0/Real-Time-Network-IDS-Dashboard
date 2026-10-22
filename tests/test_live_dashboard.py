from __future__ import annotations

import sqlite3

from ids.live_dashboard import (
    get_live_database_status,
    load_correlation_groups,
    load_live_alerts,
    load_live_summary,
)


def _create_database(path):
    conn = sqlite3.connect(path)

    conn.execute(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            rule TEXT,
            classification TEXT,
            priority INTEGER,
            protocol TEXT,
            src TEXT,
            dst TEXT,
            src_addr TEXT,
            src_port INTEGER,
            dst_addr TEXT,
            dst_port INTEGER,
            direction TEXT,
            pkt_len INTEGER,
            action TEXT,
            msg TEXT,
            gid INTEGER,
            sid INTEGER,
            rev INTEGER,
            service TEXT,
            engine TEXT,
            event_ts_utc INTEGER,
            flow_id TEXT,
            community_id TEXT,
            severity INTEGER,
            rule_key TEXT,
            correlation_group_id TEXT,
            event_hash TEXT
        )
        """
    )

    conn.executemany(
        """
        INSERT INTO alerts (
            id,
            timestamp,
            rule,
            classification,
            priority,
            protocol,
            src,
            dst,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            direction,
            pkt_len,
            action,
            msg,
            gid,
            sid,
            rev,
            service,
            engine,
            event_ts_utc,
            flow_id,
            community_id,
            severity,
            rule_key,
            correlation_group_id,
            event_hash
        )
        VALUES (
            ?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?,?,?
        )
        """,
        [
            (
                1,
                "t1",
                "Rule A",
                "class",
                1,
                "TCP",
                "1",
                "2",
                "192.168.50.141",
                54238,
                "192.168.50.114",
                80,
                "C2S",
                100,
                "allow",
                "Snort alert",
                1,
                100,
                1,
                "http",
                "snort",
                1000,
                None,
                "1:test-flow",
                5,
                "snort:1:100:1",
                "cid:test-group",
                "hash-1",
            ),
            (
                2,
                "t2",
                "Rule B",
                "class",
                1,
                "TCP",
                "1",
                "2",
                "192.168.50.141",
                54238,
                "192.168.50.114",
                80,
                "C2S",
                100,
                "allowed",
                "Suricata alert",
                1,
                200,
                1,
                "http",
                "suricata",
                1100,
                None,
                "1:test-flow",
                5,
                "suricata:1:200:1",
                "cid:test-group",
                "hash-2",
            ),
        ],
    )

    conn.commit()
    conn.close()


def test_database_status_ready(tmp_path):
    db = tmp_path / "ids.db"

    _create_database(db)

    status = get_live_database_status(db)

    assert status["exists"] is True
    assert status["alerts_table"] is True
    assert status["ready"] is True
    assert status["missing_columns"] == []


def test_database_status_missing_schema(tmp_path):
    db = tmp_path / "ids.db"

    conn = sqlite3.connect(db)

    conn.execute(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY
        )
        """
    )

    conn.commit()
    conn.close()

    status = get_live_database_status(db)

    assert status["ready"] is False
    assert "community_id" in status["missing_columns"]


def test_summary(tmp_path):
    db = tmp_path / "ids.db"

    _create_database(db)

    summary = load_live_summary(db)

    assert summary["total_alerts"] == 2
    assert summary["grouped_alerts"] == 2
    assert summary["correlation_groups"] == 1
    assert summary["community_ids"] == 1
    assert summary["by_engine"] == {
        "snort": 1,
        "suricata": 1,
    }


def test_alert_filters(tmp_path):
    db = tmp_path / "ids.db"

    _create_database(db)

    alerts = load_live_alerts(
        db,
        limit=10,
        engine="suricata",
    )

    assert len(alerts) == 1
    assert alerts[0]["engine"] == "suricata"
    assert alerts[0]["community_id"] == "1:test-flow"


def test_correlation_groups(tmp_path):
    db = tmp_path / "ids.db"

    _create_database(db)

    groups = load_correlation_groups(db)

    assert len(groups) == 1
    assert groups[0]["correlation_group_id"] == (
        "cid:test-group"
    )
    assert groups[0]["community_id"] == (
        "1:test-flow"
    )
    assert groups[0]["alert_count"] == 2
    assert groups[0]["engine_count"] == 2
    assert set(
        groups[0]["engines"].split(",")
    ) == {"snort", "suricata"}
