from __future__ import annotations

import hashlib
import sqlite3
from typing import Iterable


CORRELATION_VERSION = "v1"


def correlation_group_id_for_community(
    community_id: str | None,
) -> str | None:
    """
    Create a deterministic correlation-group ID from Community ID.

    Community ID is the direct same-flow evidence used by this
    correlation layer. The resulting group ID is stable across
    restarts and database reads.
    """
    if community_id is None:
        return None

    value = str(community_id).strip()

    if not value:
        return None

    payload = (
        f"{CORRELATION_VERSION}\n"
        f"{value}"
    ).encode("utf-8")

    digest = hashlib.sha256(
        payload
    ).hexdigest()

    return f"cid:{digest[:24]}"


def correlate_alerts(
    conn: sqlite3.Connection,
    alert_ids: Iterable[int] | None = None,
) -> int:
    """
    Assign deterministic correlation_group_id values.

    Only alerts with a valid Community ID are correlated.

    Existing correct group IDs are left unchanged.

    Returns the number of rows whose correlation_group_id changed.
    """
    if alert_ids is None:
        rows = conn.execute(
            """
            SELECT
                id,
                community_id,
                correlation_group_id
            FROM alerts
            WHERE
                community_id IS NOT NULL
                AND TRIM(community_id) != ''
            ORDER BY id
            """
        ).fetchall()
    else:
        ids = [
            int(alert_id)
            for alert_id in alert_ids
        ]

        if not ids:
            return 0

        placeholders = ",".join(
            "?" for _ in ids
        )

        rows = conn.execute(
            f"""
            SELECT
                id,
                community_id,
                correlation_group_id
            FROM alerts
            WHERE
                id IN ({placeholders})
                AND community_id IS NOT NULL
                AND TRIM(community_id) != ''
            ORDER BY id
            """,
            ids,
        ).fetchall()

    updates = []

    for (
        alert_id,
        community_id,
        current_group,
    ) in rows:
        expected_group = (
            correlation_group_id_for_community(
                community_id
            )
        )

        if expected_group is None:
            continue

        if current_group == expected_group:
            continue

        updates.append(
            (
                expected_group,
                alert_id,
            )
        )

    if not updates:
        return 0

    conn.executemany(
        """
        UPDATE alerts
        SET correlation_group_id = ?
        WHERE id = ?
        """,
        updates,
    )

    return len(updates)
