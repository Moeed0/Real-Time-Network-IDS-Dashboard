import sqlite3

import pytest

from ids.live_dashboard import (
    get_packet_database_status,
    load_live_packet_summary,
    load_live_packets,
)


def make_packet_database(path):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE packets (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            src TEXT,
            dst TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            info TEXT,
            tcp_flags TEXT,
            event_ts_utc INTEGER
        )
    """)

    conn.executemany(
        """
        INSERT INTO packets (
            id, timestamp, src, dst, protocol, src_port, dst_port,
            size, info, tcp_flags, event_ts_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                1, "t1", "192.168.1.10", "192.168.1.20", "TCP",
                1234, 80, 74, "TCP flags: SYN", "SYN", 1000,
            ),
            (
                2, "t2", "192.168.1.10", "192.168.1.20", "HTTP",
                1234, 80, 180, "HTTP GET request", "ACK,PSH", 2000,
            ),
            (
                3, "t3", "192.168.1.30", "192.168.1.40", "UDP",
                53000, 53, 92, "DNS traffic", None, 3000,
            ),
            (
                4, "t4", "192.168.1.50", "192.168.1.60", "TCP",
                3456, 443, 66, "TCP flags: ACK", "ACK", 4000,
            ),
        ],
    )
    conn.commit()
    conn.close()


def test_packet_status_does_not_require_alerts_table(tmp_path):
    path = tmp_path / "packets_only.db"
    make_packet_database(path)

    status = get_packet_database_status(path)

    assert status["exists"] is True
    assert status["packets_table"] is True
    assert status["ready"] is True
    assert status["missing_columns"] == []


def test_packet_summary_counts_records_and_protocols(tmp_path):
    path = tmp_path / "packets.db"
    make_packet_database(path)

    summary = load_live_packet_summary(path)

    assert summary["total_packets"] == 4
    assert summary["first_event_ts_utc"] == 1000
    assert summary["last_event_ts_utc"] == 4000
    assert summary["by_protocol"] == {"TCP": 2, "HTTP": 1, "UDP": 1}


def test_packet_query_filters_protocol_endpoint_and_time(tmp_path):
    path = tmp_path / "packets.db"
    make_packet_database(path)

    result = load_live_packets(
        path,
        protocol="tcp",
        endpoint="192.168.1.10",
        start_ts_utc_ms=1000,
        end_ts_utc_ms=3000,
    )

    assert [row["id"] for row in result] == [1]


def test_packet_query_returns_newest_records_first_and_respects_limit(tmp_path):
    path = tmp_path / "packets.db"
    make_packet_database(path)

    result = load_live_packets(path, limit=2)

    assert [row["id"] for row in result] == [4, 3]


@pytest.mark.parametrize("limit", [0, -1, 5001, True])
def test_packet_query_rejects_invalid_limit(tmp_path, limit):
    path = tmp_path / "packets.db"
    make_packet_database(path)

    with pytest.raises(ValueError):
        load_live_packets(path, limit=limit)


def test_packet_query_rejects_reversed_time_range(tmp_path):
    path = tmp_path / "packets.db"
    make_packet_database(path)

    with pytest.raises(ValueError, match="later than start time"):
        load_live_packets(
            path,
            start_ts_utc_ms=5000,
            end_ts_utc_ms=1000,
        )


def test_missing_packet_table_is_reported_without_migration(tmp_path):
    path = tmp_path / "empty.db"
    sqlite3.connect(path).close()

    status = get_packet_database_status(path)

    assert status["ready"] is False
    assert status["packets_table"] is False
    assert "packets table does not exist" in status["error"].lower()
