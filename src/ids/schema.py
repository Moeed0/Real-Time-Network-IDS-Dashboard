from __future__ import annotations

import sqlite3


ALERT_BASE_COLUMNS = {
    "timestamp": "TEXT",
    "rule": "TEXT",
    "classification": "TEXT",
    "priority": "INTEGER",
    "protocol": "TEXT",
    "src": "TEXT",
    "dst": "TEXT",
    "snort_rule": "TEXT",
    "iface": "TEXT",
    "service": "TEXT",
    "src_addr": "TEXT",
    "src_port": "INTEGER",
    "dst_addr": "TEXT",
    "dst_port": "INTEGER",
    "direction": "TEXT",
    "pkt_len": "INTEGER",
    "action": "TEXT",
    "msg": "TEXT",
    "gid": "INTEGER",
    "sid": "INTEGER",
    "rev": "INTEGER",
    "ttl": "INTEGER",
    "tos": "INTEGER",
    "tcp_flags": "TEXT",
    "icmp_type": "INTEGER",
    "icmp_code": "INTEGER",
    "client_pkts": "INTEGER",
    "client_bytes": "INTEGER",
    "server_pkts": "INTEGER",
    "server_bytes": "INTEGER",
    "raw_json": "TEXT",
}


ALERT_PHASE1_COLUMNS = {
    "engine": "TEXT",
    "event_ts_utc": "INTEGER",
    "flow_id": "TEXT",
    "community_id": "TEXT",
    "severity": "INTEGER",
    "rule_key": "TEXT",
    "correlation_group_id": "TEXT",
    "event_hash": "TEXT",
}


PACKET_BASE_COLUMNS = {
    "timestamp": "TEXT",
    "src": "TEXT",
    "dst": "TEXT",
    "protocol": "TEXT",
    "src_port": "INTEGER",
    "dst_port": "INTEGER",
    "size": "INTEGER",
    "info": "TEXT",
    "tcp_flags": "TEXT",
}


PACKET_PHASE1_COLUMNS = {
    "event_ts_utc": "INTEGER",
}


def _table_columns(
    conn: sqlite3.Connection,
    table: str,
) -> set[str]:
    allowed_tables = {"alerts", "packets"}

    if table not in allowed_tables:
        raise ValueError(f"Unsupported table: {table}")

    rows = conn.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    return {row[1] for row in rows}


def _create_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            rule TEXT,
            classification TEXT,
            priority INTEGER,
            protocol TEXT,
            src TEXT,
            dst TEXT,
            snort_rule TEXT,
            iface TEXT,
            service TEXT,
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
            ttl INTEGER,
            tos INTEGER,
            tcp_flags TEXT,
            icmp_type INTEGER,
            icmp_code INTEGER,
            client_pkts INTEGER,
            client_bytes INTEGER,
            server_pkts INTEGER,
            server_bytes INTEGER,
            raw_json TEXT,
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


def _add_missing_columns(
    conn: sqlite3.Connection,
    table: str,
    definitions: dict[str, str],
) -> None:
    existing = _table_columns(conn, table)

    for column, definition in definitions.items():
        if column not in existing:
            conn.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN {column} {definition}"
            )


def _create_indexes(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_community_id
        ON alerts(community_id)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_event_ts_utc
        ON alerts(event_ts_utc)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_engine_event_ts
        ON alerts(engine, event_ts_utc)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_key
        ON alerts(rule_key)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_flow_id
        ON alerts(flow_id)
        """
    )

    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_event_hash
        ON alerts(event_hash)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_correlation_group_id
        ON alerts(
            correlation_group_id,
            community_id,
            engine,
            event_ts_utc
        )
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_packets_event_ts_utc
        ON packets(event_ts_utc)
        """
    )


def ensure_schema(conn: sqlite3.Connection) -> None:
    _create_tables(conn)

    _add_missing_columns(
        conn,
        "alerts",
        ALERT_BASE_COLUMNS,
    )

    _add_missing_columns(
        conn,
        "alerts",
        ALERT_PHASE1_COLUMNS,
    )

    _add_missing_columns(
        conn,
        "packets",
        PACKET_BASE_COLUMNS,
    )

    _add_missing_columns(
        conn,
        "packets",
        PACKET_PHASE1_COLUMNS,
    )

    _create_indexes(conn)

    conn.commit()
