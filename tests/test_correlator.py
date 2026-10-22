import sqlite3

from ids.correlator import (
    correlate_alerts,
    correlation_group_id_for_community,
)


def test_group_id_is_deterministic():
    community_id = (
        "1:x0QqJ3LfINpmkX8sO0E2/PHA7e0="
    )

    first = correlation_group_id_for_community(
        community_id
    )

    second = correlation_group_id_for_community(
        community_id
    )

    assert first == second
    assert first.startswith("cid:")


def test_different_community_ids_create_different_groups():
    first = correlation_group_id_for_community(
        "1:first"
    )

    second = correlation_group_id_for_community(
        "1:second"
    )

    assert first != second


def test_missing_community_id_has_no_group():
    assert (
        correlation_group_id_for_community(None)
        is None
    )

    assert (
        correlation_group_id_for_community("")
        is None
    )


def test_correlate_alerts_assigns_groups():
    conn = sqlite3.connect(":memory:")

    conn.execute(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY,
            community_id TEXT,
            correlation_group_id TEXT,
            engine TEXT
        )
        """
    )

    cid_one = "1:flow-one"
    cid_two = "1:flow-two"

    conn.executemany(
        """
        INSERT INTO alerts (
            community_id,
            correlation_group_id,
            engine
        )
        VALUES (?, ?, ?)
        """,
        [
            (cid_one, None, "snort"),
            (cid_one, None, "suricata"),
            (cid_two, None, "snort"),
        ],
    )

    changed = correlate_alerts(conn)

    assert changed == 3

    rows = conn.execute(
        """
        SELECT
            community_id,
            correlation_group_id
        FROM alerts
        ORDER BY id
        """
    ).fetchall()

    assert rows[0][1] == rows[1][1]
    assert rows[0][1] != rows[2][1]

    # Running it again must be idempotent.
    changed_again = correlate_alerts(conn)

    assert changed_again == 0

    conn.close()
