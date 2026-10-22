from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


def _read_project_env() -> dict[str, str]:
    """
    Read a small .env file without adding a third-party dependency.

    Existing process environment variables always take precedence.
    """
    if not ENV_FILE.is_file():
        return {}

    values: dict[str, str] = {}

    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[7:].strip()

        if "=" not in line:
            continue

        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()

        if not name:
            continue

        if len(value) >= 2 and value[0] == value[-1]:
            if value[0] in {"'", '"'}:
                value = value[1:-1]

        values[name] = value

    return values


def _value_from_env(name: str, default: str) -> str:
    """
    Process environment wins over the project .env file.
    """
    project_env = _read_project_env()
    return os.environ.get(name, project_env.get(name, default))


def _path_from_env(name: str, default: str) -> Path:
    value = _value_from_env(name, default)
    path = Path(value).expanduser()

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def _int_from_env(name: str, default: int, minimum: int = 0) -> int:
    raw = _value_from_env(name, str(default))

    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer, got {raw!r}"
        ) from exc

    if value < minimum:
        raise ValueError(
            f"{name} must be >= {minimum}, got {value}"
        )

    return value


@dataclass(frozen=True)
class Settings:
    db_file: Path
    state_file: Path
    snort_alert_file: Path
    suricata_eve_file: Path
    interface: str
    alert_retention: int
    packet_retention: int
    batch_size: int
    batch_flush_ms: int
    retention_interval_seconds: int


def get_settings() -> Settings:
    interface = _value_from_env(
        "IDS_INTERFACE",
        "ens38",
    ).strip()

    if not interface:
        raise ValueError("IDS_INTERFACE cannot be empty")

    return Settings(
        db_file=_path_from_env(
            "IDS_DB_FILE",
            "ids_live.db",
        ),
        state_file=_path_from_env(
            "IDS_STATE_FILE",
            "ids_collector_state.json",
        ),
        snort_alert_file=_path_from_env(
            "IDS_SNORT_ALERT_FILE",
            "/var/log/snort/alert_json.txt",
        ),
        suricata_eve_file=_path_from_env(
            "IDS_SURICATA_EVE_FILE",
            "/var/log/suricata/eve.json",
        ),
        interface=interface,
        alert_retention=_int_from_env(
            "IDS_ALERT_RETENTION",
            10000,
            minimum=1,
        ),
        packet_retention=_int_from_env(
            "IDS_PACKET_RETENTION",
            5000,
            minimum=1,
        ),
        batch_size=_int_from_env(
            "IDS_BATCH_SIZE",
            100,
            minimum=1,
        ),
        batch_flush_ms=_int_from_env(
            "IDS_BATCH_FLUSH_MS",
            250,
            minimum=1,
        ),
        retention_interval_seconds=_int_from_env(
            "IDS_RETENTION_INTERVAL_SECONDS",
            60,
            minimum=1,
        ),
    )
