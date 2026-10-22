from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


REQUIRED_ALERT_COLUMNS = {
    "id",
    "timestamp",
    "rule",
    "classification",
    "priority",
    "protocol",
    "src",
    "dst",
    "src_addr",
    "src_port",
    "dst_addr",
    "dst_port",
    "action",
    "msg",
    "gid",
    "sid",
    "rev",
    "service",
    "engine",
    "event_ts_utc",
    "flow_id",
    "community_id",
    "severity",
    "rule_key",
    "correlation_group_id",
    "event_hash",
}


def _readonly_connect(
    db_path: Path,
) -> sqlite3.Connection:
    """
    Open the live database in SQLite read-only mode.

    The dashboard must never migrate or modify the IDS database.
    """
    path = Path(
        db_path
    ).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(
            f"Live IDS database does not exist: {path}"
        )

    uri = (
        f"file:{path.as_posix()}"
        "?mode=ro"
    )

    return sqlite3.connect(
        uri,
        uri=True,
        timeout=5.0,
    )


def get_live_database_status(
    db_path: Path,
) -> dict[str, Any]:
    """
    Return a non-destructive status describing whether the live
    database is ready for the dashboard.
    """
    path = Path(
        db_path
    ).expanduser().resolve()

    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "alerts_table": False,
        "ready": False,
        "missing_columns": [],
        "error": None,
    }

    if not path.exists():
        result["error"] = (
            "Database file does not exist."
        )
        return result

    try:
        conn = _readonly_connect(path)

        try:
            table = conn.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'alerts'
                """
            ).fetchone()

            if table is None:
                result["error"] = (
                    "alerts table does not exist."
                )
                return result

            result["alerts_table"] = True

            columns = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(alerts)"
                ).fetchall()
            }

            missing = sorted(
                REQUIRED_ALERT_COLUMNS
                - columns
            )

            result["missing_columns"] = missing
            result["ready"] = not missing

            if missing:
                result["error"] = (
                    "Live database schema is missing "
                    "required Phase 4 columns."
                )

        finally:
            conn.close()

    except sqlite3.Error as exc:
        result["error"] = str(exc)

    return result


def load_live_summary(
    db_path: Path,
) -> dict[str, Any]:
    """
    Load high-level live alert statistics.

    Raises RuntimeError when the live schema is not ready.
    """
    status = get_live_database_status(
        db_path
    )

    if not status["ready"]:
        raise RuntimeError(
            status["error"]
            or "Live database is not ready."
        )

    conn = _readonly_connect(
        db_path
    )

    try:
        total = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            """
        ).fetchone()[0]

        grouped = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE correlation_group_id IS NOT NULL
              AND TRIM(correlation_group_id) != ''
            """
        ).fetchone()[0]

        correlation_groups = conn.execute(
            """
            SELECT COUNT(DISTINCT correlation_group_id)
            FROM alerts
            WHERE correlation_group_id IS NOT NULL
              AND TRIM(correlation_group_id) != ''
            """
        ).fetchone()[0]

        community_ids = conn.execute(
            """
            SELECT COUNT(DISTINCT community_id)
            FROM alerts
            WHERE community_id IS NOT NULL
              AND TRIM(community_id) != ''
            """
        ).fetchone()[0]

        engine_rows = conn.execute(
            """
            SELECT
                engine,
                COUNT(*) AS alerts
            FROM alerts
            GROUP BY engine
            ORDER BY engine
            """
        ).fetchall()

        severity_rows = conn.execute(
            """
            SELECT
                severity,
                COUNT(*) AS alerts
            FROM alerts
            GROUP BY severity
            ORDER BY severity DESC
            """
        ).fetchall()

        return {
            "total_alerts": total,
            "grouped_alerts": grouped,
            "correlation_groups": correlation_groups,
            "community_ids": community_ids,
            "by_engine": {
                str(engine): count
                for engine, count in engine_rows
            },
            "by_severity": {
                (str(severity) if severity is not None else "Unknown"): count
                for severity, count in severity_rows
            },
        }

    finally:
        conn.close()


def load_live_alerts(
    db_path: Path,
    *,
    limit: int = 100,
    engine: str | None = None,
    severity: int | None = None,
) -> list[dict[str, Any]]:
    """
    Load recent live alerts in descending event time.

    Results are returned as dictionaries so the Streamlit layer does
    not need to know the SQLite column layout.
    """
    if limit < 1:
        raise ValueError(
            "limit must be >= 1"
        )

    status = get_live_database_status(
        db_path
    )

    if not status["ready"]:
        raise RuntimeError(
            status["error"]
            or "Live database is not ready."
        )

    conditions = []
    parameters: list[Any] = []

    if engine:
        conditions.append(
            "engine = ?"
        )
        parameters.append(
            engine.strip().lower()
        )

    if severity is not None:
        conditions.append(
            "severity = ?"
        )
        parameters.append(
            int(severity)
        )

    where_clause = ""

    if conditions:
        where_clause = (
            "WHERE "
            + " AND ".join(conditions)
        )

    query = f"""
        SELECT
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
        FROM alerts
        {where_clause}
        ORDER BY
            event_ts_utc DESC,
            id DESC
        LIMIT ?
    """

    parameters.append(
        int(limit)
    )

    conn = _readonly_connect(
        db_path
    )

    try:
        cursor = conn.execute(
            query,
            parameters,
        )

        columns = [
            description[0]
            for description in cursor.description
        ]

        return [
            dict(
                zip(
                    columns,
                    row,
                )
            )
            for row in cursor.fetchall()
        ]

    finally:
        conn.close()


def load_correlation_groups(
    db_path: Path,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Load recent cross-engine correlation groups.

    A group is considered cross-engine only when alerts from at least
    two different IDS engines belong to it.
    """
    if limit < 1:
        raise ValueError(
            "limit must be >= 1"
        )

    status = get_live_database_status(
        db_path
    )

    if not status["ready"]:
        raise RuntimeError(
            status["error"]
            or "Live database is not ready."
        )

    conn = _readonly_connect(
        db_path
    )

    try:
        rows = conn.execute(
            """
            SELECT
                correlation_group_id,
                community_id,
                COUNT(*) AS alert_count,
                COUNT(DISTINCT engine) AS engine_count,
                GROUP_CONCAT(
                    DISTINCT engine
                ) AS engines,
                MIN(event_ts_utc) AS first_event_ts_utc,
                MAX(event_ts_utc) AS last_event_ts_utc
            FROM alerts
            WHERE correlation_group_id IS NOT NULL
              AND TRIM(correlation_group_id) != ''
            GROUP BY
                correlation_group_id,
                community_id
            HAVING COUNT(DISTINCT engine) >= 2
            ORDER BY
                last_event_ts_utc DESC,
                correlation_group_id
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

        columns = [
            "correlation_group_id",
            "community_id",
            "alert_count",
            "engine_count",
            "engines",
            "first_event_ts_utc",
            "last_event_ts_utc",
        ]

        return [
            dict(
                zip(
                    columns,
                    row,
                )
            )
            for row in rows
        ]

    finally:
        conn.close()


def load_correlation_group_alerts(
    db_path: Path,
    correlation_group_id: str,
) -> list[dict[str, Any]]:
    """
    Load every alert belonging to one correlation group, oldest first.
    """
    status = get_live_database_status(
        db_path
    )

    if not status["ready"]:
        raise RuntimeError(
            status["error"]
            or "Live database is not ready."
        )

    conn = _readonly_connect(
        db_path
    )

    try:
        cursor = conn.execute(
            """
            SELECT
                id,
                engine,
                severity,
                msg,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                event_ts_utc
            FROM alerts
            WHERE correlation_group_id = ?
            ORDER BY event_ts_utc, id
            """,
            (correlation_group_id,),
        )

        columns = [
            description[0]
            for description in cursor.description
        ]

        return [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

    finally:
        conn.close()

# ============================================================
# READ-ONLY PACKET DASHBOARD QUERIES
# ============================================================

REQUIRED_PACKET_COLUMNS = {
    "id",
    "timestamp",
    "src",
    "dst",
    "protocol",
    "src_port",
    "dst_port",
    "size",
    "info",
    "tcp_flags",
    "event_ts_utc",
}


def get_packet_database_status(db_path: Path) -> dict[str, Any]:
    """Check packet-table readiness without requiring an alerts table."""
    path = Path(db_path).expanduser().resolve()
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "packets_table": False,
        "ready": False,
        "missing_columns": [],
        "error": None,
    }

    if not path.exists():
        result["error"] = "Database file does not exist."
        return result

    conn = None
    try:
        conn = _readonly_connect(path)

        table = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = 'packets'
            """
        ).fetchone()

        if table is None:
            result["error"] = "packets table does not exist."
            return result

        result["packets_table"] = True
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(packets)").fetchall()
        }
        missing = sorted(REQUIRED_PACKET_COLUMNS - columns)
        result["missing_columns"] = missing
        result["ready"] = not missing

        if missing:
            result["error"] = (
                "Packet table is missing required columns: "
                + ", ".join(missing)
            )

    except (OSError, sqlite3.Error) as exc:
        result["error"] = str(exc)
    finally:
        if conn is not None:
            conn.close()

    return result


def load_live_packet_summary(db_path: Path) -> dict[str, Any]:
    """Return counts and timestamp bounds for retained passive packets."""
    status = get_packet_database_status(db_path)
    if not status["ready"]:
        raise RuntimeError(
            status["error"] or "Packet database is not ready."
        )

    conn = _readonly_connect(db_path)
    try:
        total, first_ts, last_ts = conn.execute(
            """
            SELECT COUNT(*), MIN(event_ts_utc), MAX(event_ts_utc)
            FROM packets
            """
        ).fetchone()

        rows = conn.execute(
            """
            SELECT
                COALESCE(NULLIF(TRIM(protocol), ''), 'UNKNOWN') AS protocol,
                COUNT(*) AS packet_count
            FROM packets
            GROUP BY COALESCE(NULLIF(TRIM(protocol), ''), 'UNKNOWN')
            ORDER BY packet_count DESC, protocol
            """
        ).fetchall()

        return {
            "total_packets": int(total or 0),
            "first_event_ts_utc": first_ts,
            "last_event_ts_utc": last_ts,
            "by_protocol": {
                str(protocol): int(count)
                for protocol, count in rows
            },
        }
    finally:
        conn.close()


def load_live_packets(
    db_path: Path,
    *,
    limit: int = 500,
    protocol: str | None = None,
    endpoint: str | None = None,
    start_ts_utc_ms: int | None = None,
    end_ts_utc_ms: int | None = None,
) -> list[dict[str, Any]]:
    """
    Load recent retained packet records without modifying the live database.

    start_ts_utc_ms is inclusive; end_ts_utc_ms is exclusive.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 5000:
        raise ValueError("limit must be an integer from 1 to 5000")

    try:
        start_bound = (
            int(start_ts_utc_ms) if start_ts_utc_ms is not None else None
        )
        end_bound = (
            int(end_ts_utc_ms) if end_ts_utc_ms is not None else None
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Time bounds must be integer epoch milliseconds.") from exc

    if (
        start_bound is not None
        and end_bound is not None
        and end_bound <= start_bound
    ):
        raise ValueError("End time must be later than start time.")

    status = get_packet_database_status(db_path)
    if not status["ready"]:
        raise RuntimeError(
            status["error"] or "Packet database is not ready."
        )

    conditions = []
    parameters: list[Any] = []

    if protocol and protocol.strip().lower() != "all":
        conditions.append("UPPER(TRIM(COALESCE(protocol, ''))) = UPPER(?)")
        parameters.append(protocol.strip())

    if endpoint and endpoint.strip():
        conditions.append(
            """
            (
                instr(lower(COALESCE(src, '')), lower(?)) > 0
                OR instr(lower(COALESCE(dst, '')), lower(?)) > 0
            )
            """
        )
        parameters.extend([endpoint.strip(), endpoint.strip()])

    if start_bound is not None:
        conditions.append("event_ts_utc >= ?")
        parameters.append(start_bound)

    if end_bound is not None:
        conditions.append("event_ts_utc < ?")
        parameters.append(end_bound)

    where_clause = (
        "WHERE " + " AND ".join(conditions) if conditions else ""
    )

    query = f"""
        SELECT
            id,
            timestamp,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            size,
            info,
            tcp_flags,
            event_ts_utc
        FROM packets
        {where_clause}
        ORDER BY event_ts_utc DESC, id DESC
        LIMIT ?
    """
    parameters.append(limit)

    conn = _readonly_connect(db_path)
    try:
        cursor = conn.execute(query, parameters)
        columns = [item[0] for item in cursor.description]
        return [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]
    finally:
        conn.close()


def get_live_packet_analytics(
    db_path: Path,
    *,
    protocol: str | None = None,
    endpoint: str | None = None,
    start_ts_utc_ms: int | None = None,
    end_ts_utc_ms: int | None = None,
    bucket_minutes: int = 60,
) -> dict[str, Any]:
    """Aggregate all retained packets matching the selected dashboard filters."""
    if (
        not isinstance(bucket_minutes, int)
        or isinstance(bucket_minutes, bool)
        or not 1 <= bucket_minutes <= 1440
    ):
        raise ValueError("bucket_minutes must be an integer from 1 to 1440")

    try:
        start_bound = (
            int(start_ts_utc_ms) if start_ts_utc_ms is not None else None
        )
        end_bound = (
            int(end_ts_utc_ms) if end_ts_utc_ms is not None else None
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Time bounds must be integer epoch milliseconds.") from exc

    if (
        start_bound is not None
        and end_bound is not None
        and end_bound <= start_bound
    ):
        raise ValueError("End time must be later than start time.")

    status = get_packet_database_status(db_path)
    if not status["ready"]:
        raise RuntimeError(
            status["error"] or "Packet database is not ready."
        )

    conditions = []
    parameters: list[Any] = []

    if protocol and protocol.strip().lower() != "all":
        conditions.append(
            "UPPER(TRIM(COALESCE(protocol, ''))) = UPPER(?)"
        )
        parameters.append(protocol.strip())

    if endpoint and endpoint.strip():
        conditions.append(
            """
            (
                instr(lower(COALESCE(src, '')), lower(?)) > 0
                OR instr(lower(COALESCE(dst, '')), lower(?)) > 0
            )
            """
        )
        parameters.extend([endpoint.strip(), endpoint.strip()])

    if start_bound is not None:
        conditions.append("event_ts_utc >= ?")
        parameters.append(start_bound)

    if end_bound is not None:
        conditions.append("event_ts_utc < ?")
        parameters.append(end_bound)

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    bucket_ms = bucket_minutes * 60_000
    conn = _readonly_connect(db_path)

    try:
        totals = conn.execute(
            f"""
            SELECT
                COUNT(*),
                COALESCE(SUM(size), 0),
                COUNT(DISTINCT CASE
                    WHEN LOWER(TRIM(COALESCE(src, ''))) NOT IN ('', 'unknown')
                    THEN TRIM(src)
                END),
                COUNT(DISTINCT CASE
                    WHEN LOWER(TRIM(COALESCE(dst, ''))) NOT IN ('', 'unknown')
                    THEN TRIM(dst)
                END)
            FROM packets
            {where_clause}
            """,
            parameters,
        ).fetchone()

        protocol_rows = conn.execute(
            f"""
            SELECT
                COALESCE(NULLIF(TRIM(protocol), ''), 'UNKNOWN') AS protocol,
                COUNT(*) AS packet_count,
                COALESCE(SUM(size), 0) AS total_bytes
            FROM packets
            {where_clause}
            GROUP BY COALESCE(NULLIF(TRIM(protocol), ''), 'UNKNOWN')
            ORDER BY packet_count DESC, protocol
            """,
            parameters,
        ).fetchall()

        def top_endpoints(column: str) -> list[dict[str, Any]]:
            # Only these internal column names are accepted.
            if column not in {"src", "dst"}:
                raise ValueError("Unsupported endpoint column.")

            endpoint_conditions = list(conditions)
            endpoint_conditions.append(
                f"LOWER(TRIM(COALESCE({column}, ''))) "
                "NOT IN ('', 'unknown')"
            )
            endpoint_where_clause = (
                "WHERE " + " AND ".join(endpoint_conditions)
            )

            rows = conn.execute(
                f"""
                SELECT
                    TRIM({column}) AS endpoint,
                    COUNT(*) AS packet_count,
                    COALESCE(SUM(size), 0) AS total_bytes
                FROM packets
                {endpoint_where_clause}
                GROUP BY TRIM({column})
                ORDER BY packet_count DESC, endpoint
                LIMIT 10
                """,
                parameters,
            ).fetchall()

            return [
                {
                    "endpoint": row[0],
                    "packet_count": int(row[1]),
                    "total_bytes": int(row[2]),
                }
                for row in rows
            ]

        timeline_where = (
            where_clause + " AND event_ts_utc IS NOT NULL"
            if where_clause else "WHERE event_ts_utc IS NOT NULL"
        )

        timeline_rows = conn.execute(
            f"""
            SELECT
                CAST(event_ts_utc / ? AS INTEGER) * ?
                    AS bucket_start_ts_utc_ms,
                COUNT(*) AS packet_count,
                COALESCE(SUM(size), 0) AS total_bytes
            FROM packets
            {timeline_where}
            GROUP BY CAST(event_ts_utc / ? AS INTEGER)
            ORDER BY bucket_start_ts_utc_ms
            """,
            [bucket_ms, bucket_ms, *parameters, bucket_ms],
        ).fetchall()

        return {
            "matched_packets": int(totals[0] or 0),
            "total_bytes": int(totals[1] or 0),
            "unique_sources": int(totals[2] or 0),
            "unique_destinations": int(totals[3] or 0),
            "by_protocol": [
                {
                    "protocol": row[0],
                    "packet_count": int(row[1]),
                    "total_bytes": int(row[2]),
                }
                for row in protocol_rows
            ],
            "top_sources": top_endpoints("src"),
            "top_destinations": top_endpoints("dst"),
            "timeline": [
                {
                    "bucket_start_ts_utc_ms": int(row[0]),
                    "packet_count": int(row[1]),
                    "total_bytes": int(row[2]),
                }
                for row in timeline_rows
            ],
            "bucket_minutes": bucket_minutes,
        }
    finally:
        conn.close()
