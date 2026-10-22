"""Load synthetic IDS alerts for the public dashboard demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ids.live_normalizer import normalize_live_event


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_FILES = (
    ("snort", PROJECT_ROOT / "sample_data" / "snort" / "alert_json.txt"),
    ("suricata", PROJECT_ROOT / "sample_data" / "suricata" / "eve.json"),
)


def load_demo_alerts() -> list[dict[str, Any]]:
    """Load and normalize bundled synthetic alerts without a database."""
    records: list[dict[str, Any]] = []

    for engine, path in SAMPLE_FILES:
        if not path.is_file():
            continue

        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue

                try:
                    native = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON in {path} at line {line_number}"
                    ) from exc

                if not isinstance(native, dict):
                    continue

                normalized = normalize_live_event(engine, native)
                if normalized is None:
                    continue

                normalized["record_id"] = f"demo-{engine}-{line_number}"
                normalized["demo_mode"] = True
                normalized["native_event"] = native
                records.append(normalized)

    return sorted(
        records,
        key=lambda item: (
            str(item.get("timestamp") or ""),
            str(item.get("engine") or ""),
        ),
    )
