#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from ids.extended_alert_intelligence import (
    build_extended_alert_intelligence_context,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

CACHE_VERSION = 2

DEFAULT_CACHE_DIR = (
    PROJECT_ROOT
    / "data/lab/intelligence/live_alerts"
)


def _cache_dir() -> Path:

    raw = os.environ.get(
        "IDS_INTELLIGENCE_CACHE_DIR"
    )

    if raw:
        path = Path(raw).expanduser()

        if not path.is_absolute():
            path = PROJECT_ROOT / path

        return path.resolve()

    return DEFAULT_CACHE_DIR


def alert_cache_key(
    alert: dict[str, Any],
) -> str:

    event_hash = alert.get(
        "event_hash"
    )

    if event_hash:
        return str(
            event_hash
        )

    event_id = alert.get(
        "id"
    )

    if event_id is not None:
        identity = (
            f"{alert.get('engine', '')}|"
            f"{event_id}|"
            f"{alert.get('gid', '')}|"
            f"{alert.get('sid', '')}"
        )
    else:
        identity = json.dumps(
            alert,
            sort_keys=True,
            default=str,
        )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


def cache_path(
    alert: dict[str, Any],
) -> Path:

    engine = str(
        alert.get(
            "engine",
            "unknown",
        )
    ).lower()

    return (
        _cache_dir()
        / engine
        / f"{alert_cache_key(alert)}.json"
    )


def load_cached_live_intelligence(
    alert: dict[str, Any],
) -> dict[str, Any] | None:

    path = cache_path(
        alert
    )

    if not path.exists():
        return None

    try:

        with path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            payload = json.load(handle)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None

    if not isinstance(
        payload,
        dict,
    ):
        return None

    # Reject results created by older enrichment implementations.
    if payload.get("cache_version") != CACHE_VERSION:
        return None

    expected_engine = str(alert.get("engine") or "unknown").lower()
    cached_engine = str(payload.get("engine") or "unknown").lower()

    if cached_engine != expected_engine:
        return None

    for field in ("gid", "sid"):
        expected = alert.get(field)
        cached = payload.get(field)

        if str(expected if expected is not None else "") != str(
            cached if cached is not None else ""
        ):
            return None

    intelligence = payload.get(
        "intelligence"
    )

    if not isinstance(
        intelligence,
        dict,
    ):
        return None

    # Reject incomplete results and rule identity mismatches.
    base_intelligence = intelligence.get("base_intelligence")

    if not isinstance(base_intelligence, dict):
        return None

    if base_intelligence.get("rule_context_found"):
        rule = base_intelligence.get("rule")

        if not isinstance(rule, dict):
            return None

        for field in ("gid", "sid"):
            expected = alert.get(field)
            actual = rule.get(field)

            if (
                expected is not None
                and actual is not None
                and str(expected) != str(actual)
            ):
                return None

        rule_engine = rule.get("engine")
        if (
            rule_engine
            and str(rule_engine).lower() != expected_engine
        ):
            return None

    result = dict(
        intelligence
    )

    # Always use the current live alert.
    result["alert"] = alert

    result["cache"] = {
        "cached": True,
        "path": str(path),
        "cache_key": alert_cache_key(
            alert
        ),
        "generated_at": payload.get(
            "generated_at"
        ),
    }

    return result


def save_live_intelligence(
    alert: dict[str, Any],
    intelligence: dict[str, Any],
) -> Path:

    path = cache_path(
        alert
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    clean_intelligence = dict(
        intelligence
    )

    # Do not duplicate the complete raw alert
    # in every cache file.
    clean_intelligence.pop(
        "alert",
        None,
    )

    payload = {
        "cache_version": CACHE_VERSION,
        "generated_at": (
            intelligence.get(
                "retrieved_at"
            )
        ),
        "alert_id": alert.get(
            "id"
        ),
        "event_hash": alert.get(
            "event_hash"
        ),
        "engine": alert.get(
            "engine"
        ),
        "gid": alert.get(
            "gid"
        ),
        "sid": alert.get(
            "sid"
        ),
        "intelligence": clean_intelligence,
    }

    temporary = path.with_suffix(
        ".json.tmp"
    )

    with temporary.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            payload,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    temporary.replace(
        path
    )

    return path


def get_live_intelligence(
    alert: dict[str, Any],
    *,
    allow_network: bool = True,
    force_refresh: bool = False,
) -> tuple[dict[str, Any], bool]:

    if not force_refresh:

        cached = (
            load_cached_live_intelligence(
                alert
            )
        )

        if cached is not None:
            return cached, True

    intelligence = (
        build_extended_alert_intelligence_context(
            alert,
            force_refresh=force_refresh,
            allow_network=allow_network,
        )
    )

    path = save_live_intelligence(
        alert,
        intelligence,
    )

    intelligence["cache"] = {
        "cached": False,
        "path": str(path),
        "cache_key": alert_cache_key(
            alert
        ),
        "generated_at": intelligence.get(
            "retrieved_at"
        ),
    }

    return intelligence, False


def _database_path() -> Path:

    raw = os.environ.get(
        "IDS_DB_FILE",
        "ids_live.db",
    )

    path = Path(
        raw
    ).expanduser()

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def _readonly_connect(
    db_path: Path,
) -> sqlite3.Connection:

    uri = (
        f"file:{db_path.as_posix()}"
        "?mode=ro"
    )

    return sqlite3.connect(
        uri,
        uri=True,
        timeout=5.0,
    )


def find_alerts_after_id(
    db_path: Path,
    last_id: int,
    limit: int,
) -> list[dict[str, Any]]:

    conn = _readonly_connect(
        db_path
    )

    try:

        cursor = conn.execute(
            """
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
            WHERE id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (
                int(last_id),
                int(limit),
            ),
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


def get_max_alert_id(
    db_path: Path,
) -> int:

    conn = _readonly_connect(
        db_path
    )

    try:

        row = conn.execute(
            """
            SELECT COALESCE(
                MAX(id),
                0
            )
            FROM alerts
            """
        ).fetchone()

        return int(
            row[0]
            if row and row[0] is not None
            else 0
        )

    finally:
        conn.close()


__all__ = [
    "alert_cache_key",
    "cache_path",
    "find_alerts_after_id",
    "get_live_intelligence",
    "get_max_alert_id",
    "load_cached_live_intelligence",
    "save_live_intelligence",
]
