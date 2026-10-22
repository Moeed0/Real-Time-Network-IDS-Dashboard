import sqlite3

import pytest

from ids.live_dashboard import get_live_packet_analytics


def make_packet_db(path):
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
            (1, "t1", "10.0.0.1", "10.0.0.2", "TCP",
             1000, 80, 74, "SYN", "SYN", 1000),
            (2, "t2", "10.0.0.1", "10.0.0.2", "TCP",
             1000, 80, 180, "HTTP request", "ACK,PSH", 65000),
            (3, "t3", "10.0.0.3", "10.0.0.2", "UDP",
             53000, 53, 92, "DNS", None, 125000),
            (4, "t4", "10.0.0.4", "10.0.0.5", "TCP",
             3456, 443, 66, "ACK", "ACK", 185000),
        ],
    )
    conn.commit()
    conn.close()


def test_analytics_aggregates_all_matching_packets(tmp_path):
    path = tmp_path / "packets.db"
    make_packet_db(path)

    result = get_live_packet_analytics(path, bucket_minutes=1)

    assert result["matched_packets"] == 4
    assert result["total_bytes"] == 412
    assert result["unique_sources"] == 3
    assert result["unique_destinations"] == 2
    assert result["by_protocol"][0]["protocol"] == "TCP"
    assert result["by_protocol"][0]["packet_count"] == 3
    assert sum(row["packet_count"] for row in result["timeline"]) == 4


def test_analytics_filters_protocol_endpoint_and_time(tmp_path):
    path = tmp_path / "packets.db"
    make_packet_db(path)

    result = get_live_packet_analytics(
        path,
        protocol="tcp",
        endpoint="10.0.0.1",
        start_ts_utc_ms=0,
        end_ts_utc_ms=120000,
        bucket_minutes=1,
    )

    assert result["matched_packets"] == 2
    assert result["total_bytes"] == 254
    assert result["unique_sources"] == 1
    assert result["unique_destinations"] == 1
    assert result["top_sources"][0]["endpoint"] == "10.0.0.1"
    assert sum(row["packet_count"] for row in result["timeline"]) == 2


@pytest.mark.parametrize("bucket", [0, -1, 1441, True])
def test_analytics_rejects_invalid_bucket(bucket, tmp_path):
    path = tmp_path / "packets.db"
    make_packet_db(path)

    with pytest.raises(ValueError):
        get_live_packet_analytics(path, bucket_minutes=bucket)


def test_analytics_rejects_reversed_time_range(tmp_path):
    path = tmp_path / "packets.db"
    make_packet_db(path)

    with pytest.raises(ValueError, match="later than start time"):
        get_live_packet_analytics(
            path,
            start_ts_utc_ms=1000,
            end_ts_utc_ms=500,
        )


def test_top_endpoint_charts_ignore_unknown_placeholders(tmp_path):
    import sqlite3

    path = tmp_path / "unknown_endpoints.db"
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
            (1, "t1", "10.0.0.1", "10.0.0.2", "TCP",
             1000, 80, 74, "SYN", "SYN", 1000),
            (2, "t2", "unknown", "10.0.0.2", "OTHER",
             None, None, 50, "Unparsed", None, 2000),
            (3, "t3", "10.0.0.1", "unknown", "OTHER",
             None, None, 60, "Unparsed", None, 3000),
            (4, "t4", "", "", "OTHER",
             None, None, 70, "Unparsed", None, 4000),
        ],
    )
    conn.commit()
    conn.close()

    result = get_live_packet_analytics(path, bucket_minutes=1)

    assert result["matched_packets"] == 4
    assert result["total_bytes"] == 254
    assert result["unique_sources"] == 1
    assert result["unique_destinations"] == 1
    assert [row["endpoint"] for row in result["top_sources"]] == ["10.0.0.1"]
    assert [row["endpoint"] for row in result["top_destinations"]] == ["10.0.0.2"]
    assert sum(row["packet_count"] for row in result["timeline"]) == 4
