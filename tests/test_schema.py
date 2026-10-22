"""Tests for IDS SQLite schema initialization."""

import sqlite3

from ids.schema import ensure_schema


def test_ensure_schema_creates_correlation_lookup_index():
    conn = sqlite3.connect(":memory:")
    try:
        ensure_schema(conn)

        indexes = {
            row[1]
            for row in conn.execute("PRAGMA index_list('alerts')")
        }
        assert "idx_alerts_correlation_group_id" in indexes

        columns = [
            row[2]
            for row in conn.execute(
                "PRAGMA index_info('idx_alerts_correlation_group_id')"
            )
        ]
        assert columns == [
            "correlation_group_id",
            "community_id",
            "engine",
            "event_ts_utc",
        ]

        # Schema initialization should be safe to call repeatedly.
        ensure_schema(conn)
        indexes_after_second_call = {
            row[1]
            for row in conn.execute("PRAGMA index_list('alerts')")
        }
        assert "idx_alerts_correlation_group_id" in indexes_after_second_call
    finally:
        conn.close()
