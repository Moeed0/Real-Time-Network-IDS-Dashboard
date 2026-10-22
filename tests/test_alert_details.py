import sqlite3

from ids.alert_details import load_alert_investigation


def make_database(path):
    db = sqlite3.connect(path)

    db.executescript("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            engine TEXT,
            event_ts_utc INTEGER,
            msg TEXT,
            src_addr TEXT,
            src_port INTEGER,
            dst_addr TEXT,
            dst_port INTEGER,
            protocol TEXT,
            severity INTEGER,
            gid INTEGER,
            sid INTEGER,
            rev INTEGER,
            client_pkts INTEGER,
            client_bytes INTEGER,
            server_pkts INTEGER,
            server_bytes INTEGER,
            community_id TEXT,
            correlation_group_id TEXT,
            raw_json TEXT
        );

        CREATE TABLE packets (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            event_ts_utc INTEGER,
            src TEXT,
            src_port INTEGER,
            dst TEXT,
            dst_port INTEGER,
            protocol TEXT,
            size INTEGER,
            info TEXT,
            tcp_flags TEXT
        );
    """)

    alert_values = (
        "2026-10-12 12:00:00",
        1010,
        "192.168.50.141",
        46270,
        "192.168.50.114",
        80,
        "TCP",
        5,
        1,
        31978,
        5,
        3,
        325,
        2,
        140,
        "community-1",
        "group-1",
        '{"test": true}',
    )

    for alert_id, engine, sid, timestamp in (
        (1, "snort", 31978, 1010),
        (2, "suricata", 2022028, 1020),
    ):
        db.execute("""
            INSERT INTO alerts (
                id, timestamp, event_ts_utc, engine, msg,
                src_addr, src_port, dst_addr, dst_port,
                protocol, severity, gid, sid, rev,
                client_pkts, client_bytes, server_pkts, server_bytes,
                community_id, correlation_group_id, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id, alert_values[0], timestamp, engine,
            "Shellshock detection",
            alert_values[2], alert_values[3],
            alert_values[4], alert_values[5],
            alert_values[6], alert_values[7], alert_values[8],
            sid, alert_values[10], alert_values[11], alert_values[12],
            alert_values[13], alert_values[14], alert_values[15],
            alert_values[16], alert_values[17],
        ))

    packets = [
        (1000, "192.168.50.141", 46270, "192.168.50.114", 80, 74, "SYN"),
        (1002, "192.168.50.114", 80, "192.168.50.141", 46270, 74, "SYN,ACK"),
        (1003, "192.168.50.141", 46270, "192.168.50.114", 80, 66, "ACK"),
        (1005, "192.168.50.141", 46270, "192.168.50.114", 80, 185, "ACK,PSH"),
        (1010, "192.168.50.114", 80, "192.168.50.141", 46270, 519, "ACK,PSH"),
        (1015, "192.168.50.141", 46270, "192.168.50.114", 80, 66, "ACK"),
        (1020, "192.168.50.141", 46270, "192.168.50.114", 80, 66, "ACK,FIN"),
        (1025, "192.168.50.114", 80, "192.168.50.141", 46270, 66, "ACK,FIN"),
        (1028, "192.168.50.141", 46270, "192.168.50.114", 80, 66, "ACK"),
        (1030, "192.168.50.141", 12345, "192.168.50.114", 80, 99, "SYN"),
    ]

    for packet_id, item in enumerate(packets, 1):
        timestamp, src, src_port, dst, dst_port, size, flags = item
        db.execute("""
            INSERT INTO packets (
                id, timestamp, event_ts_utc, src, src_port, dst,
                dst_port, protocol, size, info, tcp_flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'HTTP', ?, 'test', ?)
        """, (
            packet_id, "test", timestamp, src, src_port, dst,
            dst_port, size, flags,
        ))

    db.commit()
    db.close()


def test_load_investigation_counts_matching_packets_both_directions(tmp_path):
    path = tmp_path / "test.db"
    make_database(path)

    result = load_alert_investigation(path, 1)
    assert result is not None

    summary = result["packet_summary"]
    assert summary["total_packets"] == 9
    assert summary["source_to_destination_packets"] == 6
    assert summary["destination_to_source_packets"] == 3
    assert summary["source_to_destination_bytes"] == 523
    assert summary["destination_to_source_bytes"] == 659
    assert summary["duration_ms"] == 28
    assert summary["tcp_close_observed"] is True
    assert "related_alerts" not in result


def test_missing_alert_returns_none(tmp_path):
    path = tmp_path / "test.db"
    make_database(path)
    assert load_alert_investigation(path, 999) is None
