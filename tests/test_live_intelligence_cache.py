from __future__ import annotations

import json

from ids.live_intelligence_cache import (
    alert_cache_key,
    cache_path,
    load_cached_live_intelligence,
    save_live_intelligence,
)


def sample_alert():
    return {
        "id": 123,
        "engine": "snort",
        "gid": 1,
        "sid": 51037,
        "rev": 1,
        "msg": "Test alert",
        "event_hash": "abc123",
    }


def test_alert_cache_key_prefers_event_hash():
    alert = sample_alert()

    assert (
        alert_cache_key(alert)
        == "abc123"
    )


def test_cache_round_trip(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "IDS_INTELLIGENCE_CACHE_DIR",
        str(tmp_path),
    )

    alert = sample_alert()

    intelligence = {
        "base_intelligence": {
            "rule_context_found": True,
            "rule": {
                "gid": 1,
                "sid": 51037,
                "msg": "Test alert",
            },
            "documentation": {
                "doc_found": 1,
                "rule_explanation": "Test rule explanation",
            },
            "sources": {
                "rule_database": "data/lab/rules/ids_rules.db",
            },
        },
        "identifiers": {
            "cves": [
                "CVE-TEST"
            ],
            "mitre_attack": [],
        },
        "risk_context": {
            "known_exploited": False,
        },
        "retrieved_at": (
            "2026-10-08T00:00:00+00:00"
        ),
    }

    path = save_live_intelligence(
        alert,
        {
            **intelligence,
            "alert": alert,
        },
    )

    assert path.exists()

    loaded = (
        load_cached_live_intelligence(
            alert
        )
    )

    assert loaded is not None
    assert loaded["alert"] == alert
    assert loaded["identifiers"] == (
        intelligence["identifiers"]
    )


def test_cache_path_separates_engine(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "IDS_INTELLIGENCE_CACHE_DIR",
        str(tmp_path),
    )

    path = cache_path(
        sample_alert()
    )

    assert (
        path.parent.name
        == "snort"
    )
