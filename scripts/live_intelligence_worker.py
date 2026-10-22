#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from ids.alert_classification import classify_alert, should_enrich_category

from ids.live_intelligence_cache import (
    find_alerts_after_id,
    get_max_alert_id,
    get_live_intelligence,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

STATE_FILE = (
    PROJECT_ROOT
    / ".runtime/live_intelligence_worker_state.json"
)


def _load_env() -> None:

    env_file = PROJECT_ROOT / ".env"

    if not env_file.exists():
        return

    for raw_line in env_file.read_text(
        encoding="utf-8"
    ).splitlines():

        line = raw_line.strip()

        if (
            not line
            or line.startswith("#")
            or "=" not in line
        ):
            continue

        key, value = line.split(
            "=",
            1,
        )

        key = key.strip()
        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {
                "'",
                '"',
            }
        ):
            value = value[1:-1]

        os.environ.setdefault(
            key,
            value,
        )


def _positive_int(
    name: str,
    default: int,
) -> int:

    raw = os.environ.get(
        name,
        str(default),
    )

    try:
        value = int(raw)
    except ValueError:
        return default

    return max(
        1,
        value,
    )


def _load_state() -> int:

    if not STATE_FILE.exists():
        return 0

    try:

        with STATE_FILE.open(
            "r",
            encoding="utf-8",
        ) as handle:
            data = json.load(handle)

        return int(
            data.get(
                "last_id",
                0,
            )
        )

    except (
        OSError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ):
        return 0


def _save_state(
    last_id: int,
) -> None:

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = STATE_FILE.with_suffix(
        ".json.tmp"
    )

    with temporary.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            {
                "last_id": int(
                    last_id
                )
            },
            handle,
            indent=2,
        )
        handle.write("\n")

    temporary.replace(
        STATE_FILE
    )


def main() -> None:

    _load_env()

    db_path = Path(
        os.environ.get(
            "IDS_DB_FILE",
            "ids_live.db",
        )
    ).expanduser()

    if not db_path.is_absolute():
        db_path = (
            PROJECT_ROOT
            / db_path
        )

    db_path = db_path.resolve()

    poll_seconds = _positive_int(
        "IDS_INTELLIGENCE_POLL_SECONDS",
        5,
    )

    batch_size = _positive_int(
        "IDS_INTELLIGENCE_BATCH_SIZE",
        25,
    )

    print("=" * 70)
    print("LIVE IDS INTELLIGENCE WORKER")
    print("=" * 70)
    print(
        f"Database:    {db_path}"
    )
    print(
        f"Poll:        {poll_seconds}s"
    )
    print(
        f"Batch size:  {batch_size}"
    )
    print()

    last_id = _load_state()

    current_max = get_max_alert_id(
        db_path
    )

    if current_max < last_id:
        print(
            "Database ID moved backwards; "
            "resetting worker state."
        )
        last_id = 0
        _save_state(
            last_id
        )

    print(
        f"Starting after alert ID: {last_id}"
    )

    while True:

        try:

            rows = find_alerts_after_id(
                db_path,
                last_id,
                batch_size,
            )

            if rows:

                for alert in rows:

                    alert_id = int(
                        alert["id"]
                    )

                    # Enrich only high-confidence security alerts.
                    # Keep every record in the database; skip enrichment
                    # for routine events and standalone supporting detections.
                    category = classify_alert(alert)

                    if not should_enrich_category(category):
                        last_id = alert_id
                        _save_state(last_id)

                        if category == "SECURITY_SUPPORT":
                            print(
                                "[SKIPPED SUPPORT] "
                                f"id={alert_id} "
                                f"engine={alert.get('engine')} "
                                f"sid={alert.get('sid')}"
                            )

                        continue

                    try:

                        intelligence, from_cache = (
                            get_live_intelligence(
                                alert,
                                allow_network=True,
                                force_refresh=False,
                            )
                        )

                        identifiers = (
                            intelligence.get(
                                "identifiers",
                                {},
                            )
                        )

                        cves = identifiers.get(
                            "cves",
                            [],
                        )

                        mitre = identifiers.get(
                            "mitre_attack",
                            [],
                        )

                        print(
                            "[ENRICHED] "
                            f"id={alert_id} "
                            f"engine={alert.get('engine')} "
                            f"sid={alert.get('sid')} "
                            f"cached={from_cache} "
                            f"CVEs={len(cves)} "
                            f"MITRE={len(mitre)}"
                        )

                    except Exception as exc:

                        print(
                            "[ERROR] "
                            f"id={alert_id}: "
                            f"{exc}"
                        )

                        # Do not advance past a failed alert.
                        # Retry it on the next worker cycle.
                        break

                    last_id = alert_id
                    _save_state(
                        last_id
                    )

                continue

            time.sleep(
                poll_seconds
            )

        except KeyboardInterrupt:

            print()
            print(
                "Live intelligence worker stopped."
            )
            break

        except Exception as exc:

            print(
                "[WORKER ERROR]",
                exc,
            )

            time.sleep(
                poll_seconds
            )


if __name__ == "__main__":
    main()
