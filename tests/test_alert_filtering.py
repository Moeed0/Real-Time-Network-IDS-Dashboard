from datetime import datetime, timedelta, timezone

import pytest

from ids.alert_filtering import (
    TIME_WINDOW_OPTIONS,
    event_timestamp_utc,
    filter_alert_records_by_time,
)


UTC = timezone.utc
NOW = datetime(2026, 10, 20, 7, 0, tzinfo=UTC)


def test_parses_epoch_milliseconds():
    record = {"event_ts_utc": int(NOW.timestamp() * 1000)}
    assert event_timestamp_utc(record) == NOW


def test_parses_epoch_seconds():
    record = {"timestamp": NOW.timestamp()}
    assert event_timestamp_utc(record) == NOW


def test_parses_iso_timestamp_and_normalizes_timezone():
    record = {"timestamp": "2026-10-20T12:00:00+05:00"}
    assert event_timestamp_utc(record) == NOW


def test_uses_nested_alert_timestamp_when_needed():
    record = {"alert": {"timestamp": "2026-10-20T07:00:00Z"}}
    assert event_timestamp_utc(record) == NOW


def test_last_24_hours_excludes_old_missing_and_future_timestamps():
    records = [
        {"id": 1, "event_ts_utc": int((NOW - timedelta(hours=2)).timestamp() * 1000)},
        {"id": 2, "event_ts_utc": int((NOW - timedelta(hours=25)).timestamp() * 1000)},
        {"id": 3},
        {"id": 4, "event_ts_utc": int((NOW + timedelta(minutes=1)).timestamp() * 1000)},
    ]

    result = filter_alert_records_by_time(records, "Last 24 hours", now=NOW)
    assert [record["id"] for record in result] == [1]


def test_cutoff_boundary_is_included():
    cutoff = NOW - timedelta(hours=24)
    records = [{"id": 1, "timestamp": cutoff.isoformat()}]

    result = filter_alert_records_by_time(records, "Last 24 hours", now=NOW)
    assert [record["id"] for record in result] == [1]


def test_all_retained_preserves_records_without_timestamps():
    records = [{"id": 1}, {"id": 2, "timestamp": "invalid"}]
    assert filter_alert_records_by_time(records, "All retained", now=NOW) == records


def test_unknown_window_is_rejected():
    with pytest.raises(ValueError, match="Unsupported alert time window"):
        filter_alert_records_by_time([], "Last 2 hours", now=NOW)


def test_supported_time_window_options():
    assert TIME_WINDOW_OPTIONS == (
        "Last 24 hours",
        "Last 7 days",
        "Last 30 days",
        "All retained",
    )
