from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from ids.db import canonical_event_hash, connect_database
from ids.schema import ensure_schema
from ids.time_utils import parse_event_timestamp


PHASE1_SCHEMA_VERSION = 1


def native_severity(event: dict, engine: str | None) -> int:
    """Read the engine's source rank and normalize it to severity 1-4."""
    if (engine or "").lower() == "suricata":
        alert = event.get("alert")
        value = alert.get("severity") if isinstance(alert, dict) else None
    else:
        # Snort alert JSON reports its rank in "priority".
        value = event.get("priority")
    try:
        parsed = int(value) if value not in (None, "") else 4
    except (TypeError, ValueError):
        parsed = 4
    return max(1, min(4, parsed))

def rule_key_for_snort(alert: dict) -> str | None:
    sid = alert.get("sid")

    if sid in (None, ""):
        return None

    gid = alert.get("gid")
    rev = alert.get("rev")

    if gid in (None, ""):
        gid = 1

    if rev in (None, ""):
        rev = 0

    return f"snort:{int(gid)}:{int(sid)}:{int(rev)}"


def load_native_event(raw_json: str, row_id: int) -> dict:
    if not raw_json:
        raise ValueError(
            f"Alert id={row_id} has no raw_json; "
            "cannot safely backfill event_hash."
        )

    try:
        event = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Alert id={row_id} contains invalid raw_json: {exc}"
        ) from exc

    if not isinstance(event, dict):
        raise ValueError(
            f"Alert id={row_id} raw_json is not a JSON object."
        )

    return event


def backfill_alerts(
    conn: sqlite3.Connection,
) -> tuple[int, int]:
    rows = conn.execute(
        """
        SELECT
            id,
            raw_json,
            engine,
            event_ts_utc,
            flow_id,
            severity,
            rule_key,
            correlation_group_id,
            event_hash
        FROM alerts
        ORDER BY id
        """
    ).fetchall()

    updated = 0
    checked_existing_hashes = 0

    for row in rows:
        (
            row_id,
            raw_json,
            engine,
            event_ts_utc,
            flow_id,
            severity,
            rule_key,
            correlation_group_id,
            event_hash,
        ) = row

        event = load_native_event(raw_json, row_id)

        engine = engine or "snort"

        expected_hash = canonical_event_hash(
            event,
            engine=engine,
        )

        if event_hash and event_hash != expected_hash:
            raise ValueError(
                f"Alert id={row_id} has an event_hash that does "
                "not match canonical native event hashing."
            )

        if event_hash:
            checked_existing_hashes += 1

        values = {
            "engine": engine,
            "event_ts_utc": (
                event_ts_utc
                if event_ts_utc is not None
                else parse_event_timestamp(event)
            ),
            "flow_id": (
                flow_id
                if flow_id is not None
                else event.get("flow_id")
            ),
            "severity": native_severity(event, engine),
            "rule_key": (
                rule_key
                if rule_key is not None
                else rule_key_for_snort(event)
            ),
            "correlation_group_id": correlation_group_id,
            "event_hash": event_hash or expected_hash,
        }

        needs_update = any(
            values[column] != current
            for column, current in {
                "engine": engine,
                "event_ts_utc": event_ts_utc,
                "flow_id": flow_id,
                "severity": severity,
                "rule_key": rule_key,
                "correlation_group_id": correlation_group_id,
                "event_hash": event_hash,
            }.items()
        )

        if not needs_update:
            continue

        conn.execute(
            """
            UPDATE alerts
            SET
                engine = ?,
                event_ts_utc = ?,
                flow_id = ?,
                severity = ?,
                rule_key = ?,
                correlation_group_id = ?,
                event_hash = ?
            WHERE id = ?
            """,
            (
                values["engine"],
                values["event_ts_utc"],
                values["flow_id"],
                values["severity"],
                values["rule_key"],
                values["correlation_group_id"],
                values["event_hash"],
                row_id,
            ),
        )

        updated += 1

    return updated, checked_existing_hashes


def check_duplicate_hashes(
    conn: sqlite3.Connection,
) -> list[tuple[str, int]]:
    return conn.execute(
        """
        SELECT
            event_hash,
            COUNT(*) AS count
        FROM alerts
        WHERE event_hash IS NOT NULL
        GROUP BY event_hash
        HAVING COUNT(*) > 1
        ORDER BY count DESC, event_hash
        """
    ).fetchall()


def create_phase1_indexes(
    conn: sqlite3.Connection,
) -> None:
    duplicates = check_duplicate_hashes(conn)

    if duplicates:
        details = ", ".join(
            f"{event_hash} ({count})"
            for event_hash, count in duplicates[:10]
        )

        raise ValueError(
            "Duplicate event_hash values prevent creation of the "
            f"unique event hash index: {details}"
        )

    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        ux_alerts_event_hash
        ON alerts(event_hash)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_alerts_flow_id
        ON alerts(flow_id)
        """
    )


def migrate_database(
    db_path: Path,
) -> dict:
    conn = connect_database(db_path)

    try:
        ensure_schema(conn)

        before_count = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        updated, checked_existing_hashes = backfill_alerts(conn)

        null_hashes = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE event_hash IS NULL
            """
        ).fetchone()[0]

        if null_hashes:
            raise ValueError(
                f"{null_hashes} alert rows still have NULL event_hash."
            )

        create_phase1_indexes(conn)

        conn.execute(
            f"PRAGMA user_version = {PHASE1_SCHEMA_VERSION}"
        )

        conn.commit()

        after_count = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        distinct_hashes = conn.execute(
            """
            SELECT COUNT(DISTINCT event_hash)
            FROM alerts
            """
        ).fetchone()[0]

        journal_mode = conn.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]

        return {
            "database": str(Path(db_path).resolve()),
            "schema_version": PHASE1_SCHEMA_VERSION,
            "alerts_before": before_count,
            "alerts_after": after_count,
            "rows_updated": updated,
            "existing_hashes_verified": checked_existing_hashes,
            "null_event_hashes": null_hashes,
            "distinct_event_hashes": distinct_hashes,
            "journal_mode": journal_mode,
        }

    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply the Phase 1 SQLite migration."
    )

    parser.add_argument(
        "--db",
        required=True,
        help="SQLite database to migrate.",
    )

    args = parser.parse_args()

    result = migrate_database(
        Path(args.db).expanduser().resolve()
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
