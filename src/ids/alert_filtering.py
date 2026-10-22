"""Time-window filtering for retained IDS alert records."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import math
from typing import Any


TIME_WINDOW_OPTIONS = (
    "Last 24 hours",
    "Last 7 days",
    "Last 30 days",
    "All retained",
)

_WINDOW_DURATIONS = {
    "Last 24 hours": timedelta(hours=24),
    "Last 7 days": timedelta(days=7),
    "Last 30 days": timedelta(days=30),
}


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a numeric epoch or ISO timestamp as an aware UTC datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, bool) or value is None:
        return None

    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number):
            return None
        if abs(number) >= 100_000_000_000:
            number /= 1000.0
        elif abs(number) < 1_000_000_000:
            return None
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    try:
        number = float(value)
    except ValueError:
        number = None

    if number is not None:
        return _parse_timestamp(number)

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def event_timestamp_utc(record: dict[str, Any]) -> datetime | None:
    """Return the first parseable timestamp from a native or adapted alert."""
    alert = record.get("alert")
    if not isinstance(alert, dict):
        alert = {}

    native_event = record.get("native_event")
    if not isinstance(native_event, dict):
        native_event = {}

    candidates = (
        record.get("event_ts_utc"),
        record.get("timestamp"),
        record.get("Timestamp"),
        alert.get("event_ts_utc"),
        alert.get("timestamp"),
        native_event.get("event_ts_utc"),
        native_event.get("timestamp"),
    )

    for candidate in candidates:
        parsed = _parse_timestamp(candidate)
        if parsed is not None:
            return parsed

    return None


def filter_alert_records_by_time(
    records: list[dict[str, Any]],
    window: str,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Filter alerts by event time without altering the input records.

    Records without parseable event timestamps are omitted from bounded
    windows. "All retained" returns every input record, including those
    whose timestamps are unavailable.
    """
    if window == "All retained":
        return list(records)

    duration = _WINDOW_DURATIONS.get(window)
    if duration is None:
        raise ValueError(f"Unsupported alert time window: {window}")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)

    cutoff = current - duration
    filtered = []

    for record in records:
        timestamp = event_timestamp_utc(record)
        if timestamp is not None and cutoff <= timestamp <= current:
            filtered.append(record)

    return filtered
