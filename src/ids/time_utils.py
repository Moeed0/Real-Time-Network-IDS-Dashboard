from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any


SNORT_TIMESTAMP_RE = re.compile(
    r"^(?P<month>\d{2})/"
    r"(?P<day>\d{2})-"
    r"(?P<time>\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?)$"
)


def local_timezone() -> tzinfo:
    return datetime.now().astimezone().tzinfo or timezone.utc


def to_epoch_ms(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("Datetime must be timezone-aware")

    return int(round(value.timestamp() * 1000))


def _parse_snort_clock(
    raw_timestamp: str,
    year: int,
    tz: tzinfo,
) -> datetime:
    match = SNORT_TIMESTAMP_RE.match(raw_timestamp.strip())

    if not match:
        raise ValueError(
            f"Unsupported Snort timestamp: {raw_timestamp!r}"
        )

    month = int(match.group("month"))
    day = int(match.group("day"))
    clock = match.group("time")

    if "." in clock:
        parsed = datetime.strptime(
            f"{year}/{month:02d}/{day:02d}-{clock}",
            "%Y/%m/%d-%H:%M:%S.%f",
        )
    else:
        parsed = datetime.strptime(
            f"{year}/{month:02d}/{day:02d}-{clock}",
            "%Y/%m/%d-%H:%M:%S",
        )

    return parsed.replace(tzinfo=tz)


def parse_snort_timestamp(
    raw_timestamp: str,
    *,
    now: datetime | None = None,
    tz: tzinfo | None = None,
    anchor_epoch_seconds: float | int | None = None,
) -> datetime:
    """
    Parse Snort's year-less local timestamp.

    Year selection:
    1. If flowstart_time is available, use its local year as the anchor.
    2. Otherwise use the current local year.
    3. If the resulting timestamp is more than 24 hours in the future,
       use the previous year.

    The returned datetime is timezone-aware.
    """
    tz = tz or local_timezone()
    now = now or datetime.now(tz)

    if now.tzinfo is None:
        now = now.replace(tzinfo=tz)

    year = now.year

    if anchor_epoch_seconds is not None:
        try:
            anchor = datetime.fromtimestamp(
                float(anchor_epoch_seconds),
                tz=timezone.utc,
            ).astimezone(tz)
            year = anchor.year
        except (TypeError, ValueError, OSError, OverflowError):
            year = now.year

    candidate = _parse_snort_clock(
        raw_timestamp,
        year,
        tz,
    )

    if anchor_epoch_seconds is None and candidate > (
        now + timedelta(hours=24)
    ):
        candidate = candidate.replace(year=year - 1)

    return candidate


def parse_suricata_timestamp(
    raw_timestamp: str,
) -> datetime:
    """
    Parse Suricata EVE timestamps such as:
    2026-10-01T11:54:05.225898+0500
    """
    value = raw_timestamp.strip()

    parsed = datetime.strptime(
        value,
        "%Y-%m-%dT%H:%M:%S.%f%z",
    )

    return parsed


def parse_event_timestamp(
    alert: dict[str, Any],
) -> int | None:
    """
    Return normalized UTC epoch-ms for a Snort alert.

    Prefer a real epoch 'seconds' field when present.
    Otherwise parse the year-less Snort timestamp.

    flowstart_time is used only as a year anchor because it represents
    flow start time, not necessarily alert time.
    """
    seconds = alert.get("seconds")

    if seconds not in (None, ""):
        try:
            return int(round(float(seconds) * 1000))
        except (TypeError, ValueError, OverflowError):
            pass

    timestamp = alert.get("timestamp")

    if not timestamp:
        return None

    anchor = alert.get("flowstart_time")

    try:
        parsed = parse_snort_timestamp(
            str(timestamp),
            anchor_epoch_seconds=(
                float(anchor)
                if anchor not in (None, "")
                else None
            ),
        )

        return to_epoch_ms(parsed)

    except (TypeError, ValueError, OSError, OverflowError):
        return None


def packet_time_fields(
    packet_epoch_seconds: float | int,
) -> tuple[str, int]:
    """
    Convert Scapy packet capture time into:
    - legacy local timestamp string
    - normalized UTC epoch-ms
    """
    epoch = float(packet_epoch_seconds)
    local_dt = datetime.fromtimestamp(
        epoch,
        tz=local_timezone(),
    )

    return (
        local_dt.strftime("%Y-%m-%d %H:%M:%S"),
        int(round(epoch * 1000)),
    )
