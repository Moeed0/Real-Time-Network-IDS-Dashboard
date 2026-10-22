"""Research Data page for inspecting and exporting IDS research datasets."""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


def _normalise_datetime(value: Any) -> datetime | None:
    """Parse common Unix timestamp and ISO timestamp representations."""
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        number = float(value)
        unit_divisor = 1000 if abs(number) >= 100_000_000_000 else 1
        try:
            return datetime.fromtimestamp(
                number / unit_divisor,
                tz=timezone.utc,
            )
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None

        if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", raw):
            try:
                number = float(raw)
                unit_divisor = 1000 if abs(number) >= 100_000_000_000 else 1
                return datetime.fromtimestamp(
                    number / unit_divisor,
                    tz=timezone.utc,
                )
            except (OverflowError, OSError, ValueError):
                return None

        pkt_match = re.match(
            r"^(.*?) PKT \(UTC([+-]\d{2}:\d{2})\)$",
            raw,
        )
        if pkt_match:
            raw = f"{pkt_match.group(1)}{pkt_match.group(2)}"
        else:
            raw = raw.replace("Z", "+00:00")

        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _record_event_time(record: dict[str, Any]) -> datetime | None:
    """Read the first usable event timestamp from a record."""
    for field in (
        "event_ts_utc",
        "timestamp",
        "event_time",
        "timestamp_pkt",
    ):
        parsed = _normalise_datetime(record.get(field))
        if parsed is not None:
            return parsed
    return None


def _relative_path(path: Path, project_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(project_root.resolve()))
    except (ValueError, OSError):
        return path.name


def _export_datetime(value: datetime | None = None) -> datetime:
    parsed = value or datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def serialize_alerts_json(alerts: list[dict[str, Any]]) -> str:
    """Serialize the original alert records as readable JSON."""
    return json.dumps(
        alerts,
        indent=2,
        ensure_ascii=False,
        default=str,
    ) + "\n"


def serialize_alerts_csv(alerts: list[dict[str, Any]]) -> str:
    """Export alert records to CSV, JSON-encoding nested values in cells."""
    records = [record for record in alerts if isinstance(record, dict)]
    fieldnames: list[str] = []

    for record in records:
        for field in record:
            if field not in fieldnames:
                fieldnames.append(field)

    if not fieldnames:
        fieldnames = ["id", "engine", "severity", "msg"]

    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        extrasaction="ignore",
    )
    writer.writeheader()

    for record in records:
        row = {}
        for field in fieldnames:
            value = record.get(field)
            if isinstance(value, (dict, list, tuple, set)):
                value = json.dumps(
                    value,
                    ensure_ascii=False,
                    default=str,
                )
            elif value is None:
                value = ""
            row[field] = value
        writer.writerow(row)

    return output.getvalue()


def build_research_manifest(
    alerts: list[dict[str, Any]],
    *,
    ids_sources_file: Path,
    project_root: Path,
    live_db_file: Path | None = None,
    exported_at_utc: datetime | None = None,
) -> dict[str, Any]:
    """Describe the actual records and files included in a research export."""
    records = [record for record in alerts if isinstance(record, dict)]
    generated_at = _export_datetime(exported_at_utc)

    engine_counts = Counter(
        str(record.get("engine") or record.get("engine_key") or "unknown")
        .strip()
        .lower()
        or "unknown"
        for record in records
    )

    event_times = [
        timestamp
        for record in records
        if (timestamp := _record_event_time(record)) is not None
    ]

    source_config_available = ids_sources_file.is_file()
    try:
        config_size = ids_sources_file.stat().st_size if source_config_available else None
    except OSError:
        config_size = None

    db_name = live_db_file.name if live_db_file is not None else None
    first_event = min(event_times).isoformat(timespec="seconds") if event_times else None
    last_event = max(event_times).isoformat(timespec="seconds") if event_times else None

    return {
        "schema_version": 1,
        "export_type": "real_time_network_ids_research_dataset",
        "generated_at_utc": generated_at.isoformat(timespec="seconds"),
        "source": {
            "live_database_file": db_name,
            "ids_source_configuration": _relative_path(
                ids_sources_file,
                project_root,
            ),
            "ids_source_configuration_available": source_config_available,
            "ids_source_configuration_size_bytes": config_size,
        },
        "dataset": {
            "record_count": len(records),
            "records_by_engine": dict(sorted(engine_counts.items())),
            "first_event_utc": first_event,
            "last_event_utc": last_event,
            "top_level_fields": sorted({
                field
                for record in records
                for field in record
            }),
        },
        "notes": [
            "This is a point-in-time export of the records supplied to the dashboard page.",
            "The exported records may include locally cached intelligence where available.",
            "Missing retained packet data does not establish that no traffic occurred.",
            "An IDS alert or correlation does not by itself prove that an attack succeeded.",
            "Nested objects and arrays are preserved in JSON; nested CSV values are JSON-encoded strings.",
        ],
    }


def build_research_package(
    alerts: list[dict[str, Any]],
    *,
    ids_sources_file: Path,
    project_root: Path,
    live_db_file: Path | None = None,
    exported_at_utc: datetime | None = None,
) -> bytes:
    """Create a ZIP research package in memory, without writing project files."""
    generated_at = _export_datetime(exported_at_utc)
    manifest = build_research_manifest(
        alerts,
        ids_sources_file=ids_sources_file,
        project_root=project_root,
        live_db_file=live_db_file,
        exported_at_utc=generated_at,
    )

    readme = """Real-Time Network IDS Dashboard — Research Dataset

Package contents
- dataset/live_alert_snapshot.json: alert records with nested values preserved.
- dataset/live_alert_snapshot.csv: spreadsheet-friendly alert export.
- metadata/research_manifest.json: export timestamp, record counts, event coverage,
  source information, available fields, and interpretation notes.
- configuration/ids_sources.json: IDS source configuration, when available.

Interpretation and limitations
This package reflects the alert records supplied to the dashboard at export time.
It does not guarantee that every event or packet observed by the IDS is included.
An IDS alert or a correlation group does not prove that an attack succeeded.
Nested JSON fields in the CSV are stored as JSON text in individual cells.
Event coverage is calculated only from timestamps that could be parsed.

Handle the package according to your laboratory's data-sharing and retention rules.
"""

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(
        zip_buffer,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "dataset/live_alert_snapshot.json",
            serialize_alerts_json(alerts),
        )
        archive.writestr(
            "dataset/live_alert_snapshot.csv",
            serialize_alerts_csv(alerts),
        )
        archive.writestr(
            "metadata/research_manifest.json",
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        )
        archive.writestr("README.txt", readme)

        if ids_sources_file.is_file():
            archive.write(
                ids_sources_file,
                arcname="configuration/ids_sources.json",
            )

    return zip_buffer.getvalue()


def render_research_data(
    *,
    alerts: list[dict[str, Any]],
    ids_sources_file: Path,
    project_root: Path,
    live_db_file: Path | None = None,
) -> None:
    """Render dataset overview, documentation, and research exports."""
    records = [record for record in alerts if isinstance(record, dict)]
    export_time = datetime.now(timezone.utc)

    st.title("Research Data")
    st.caption(
        "Inspect a point-in-time alert snapshot, review its provenance, "
        "and export data for controlled IDS research."
    )

    engine_counts = Counter(
        str(record.get("engine") or record.get("engine_key") or "unknown")
        .strip()
        .lower()
        or "unknown"
        for record in records
    )

    snort_count = sum(
        count for engine, count in engine_counts.items()
        if engine.startswith("snort")
    )
    suricata_count = sum(
        count for engine, count in engine_counts.items()
        if engine.startswith("suricata")
    )
    other_count = max(len(records) - snort_count - suricata_count, 0)

    st.subheader("Dataset Overview")
    metric_cols = st.columns(4)
    metric_cols[0].metric("Records in snapshot", f"{len(records):,}")
    metric_cols[1].metric("Snort records", f"{snort_count:,}")
    metric_cols[2].metric("Suricata records", f"{suricata_count:,}")
    metric_cols[3].metric("Other or unknown", f"{other_count:,}")

    manifest = build_research_manifest(
        records,
        ids_sources_file=ids_sources_file,
        project_root=project_root,
        live_db_file=live_db_file,
        exported_at_utc=export_time,
    )
    dataset_metadata = manifest["dataset"]
    first_event = dataset_metadata["first_event_utc"]
    last_event = dataset_metadata["last_event_utc"]

    st.caption(
        f"Event coverage in this snapshot (UTC): "
        f"{first_event or 'Unavailable'} to {last_event or 'Unavailable'}"
    )
    st.caption(
        "These counts describe the loaded snapshot passed to this page; "
        "they are not a claim that every IDS event or retained packet is present."
    )

    st.subheader("Research Exports")

    def make_snapshot_json() -> str:
        return serialize_alerts_json(records)

    def make_snapshot_csv() -> bytes:
        return serialize_alerts_csv(records).encode("utf-8")

    def make_manifest_export() -> str:
        export_manifest = build_research_manifest(
            records,
            ids_sources_file=ids_sources_file,
            project_root=project_root,
            live_db_file=live_db_file,
            exported_at_utc=datetime.now(timezone.utc),
        )
        return json.dumps(
            export_manifest,
            indent=2,
            ensure_ascii=False,
        ) + "\n"

    def make_research_package() -> bytes:
        return build_research_package(
            records,
            ids_sources_file=ids_sources_file,
            project_root=project_root,
            live_db_file=live_db_file,
            exported_at_utc=datetime.now(timezone.utc),
        )

    export_col1, export_col2 = st.columns(2)
    with export_col1:
        st.download_button(
            "Download alert snapshot (JSON)",
            data=make_snapshot_json,
            file_name="live_alert_snapshot.json",
            mime="application/json",
            key="download_live_alert_snapshot_json",
        )
        st.download_button(
            "Download research manifest (JSON)",
            data=make_manifest_export,
            file_name="research_manifest.json",
            mime="application/json",
            key="download_research_manifest",
        )

    with export_col2:
        st.download_button(
            "Download alert snapshot (CSV)",
            data=make_snapshot_csv,
            file_name="live_alert_snapshot.csv",
            mime="text/csv",
            key="download_live_alert_snapshot_csv",
        )
        st.download_button(
            "Download research package (ZIP)",
            data=make_research_package,
            file_name="ids_research_dataset.zip",
            mime="application/zip",
            key="download_research_package",
        )

    st.caption(
        "Exports are generated only when requested. The research package "
        "is assembled in memory and is not written to the project."
    )

    st.subheader("Available Configuration")
    if ids_sources_file.is_file():
        try:
            config_bytes = ids_sources_file.read_bytes()
        except OSError as exc:
            st.error("The IDS source configuration could not be read.")
            st.caption(f"{type(exc).__name__}: {exc}")
        else:
            st.write(f"**IDS source configuration**")
            st.caption(
                f"`{_relative_path(ids_sources_file, project_root)}` · "
                f"{len(config_bytes):,} bytes"
            )
            st.download_button(
                "Download IDS source configuration",
                data=config_bytes,
                file_name=ids_sources_file.name,
                mime="application/json",
                key="download_ids_sources_configuration",
            )
    else:
        st.warning(
            "The IDS source configuration is not available at the configured path."
        )

    st.subheader("Dataset Preview")
    if records:
        preview_count = st.slider(
            "Records to preview",
            min_value=1,
            max_value=min(20, len(records)),
            value=min(5, len(records)),
            key="live_alert_snapshot_preview_count",
        )
        preview_records = records[:preview_count]
        preview_frame = pd.DataFrame(preview_records)
        preferred_columns = (
            "id", "engine", "engine_key", "event_ts_utc", "timestamp",
            "timestamp_pkt", "severity", "msg", "rule", "src_addr", "src_ip",
            "src_port", "dst_addr", "dest_ip", "dst_port", "dest_port",
            "protocol", "community_id", "correlation_group_id",
        )
        preview_columns = [
            column for column in preferred_columns
            if column in preview_frame.columns
        ]
        if preview_columns:
            st.dataframe(
                preview_frame[preview_columns],
                width="stretch",
                hide_index=True,
            )
        else:
            st.dataframe(
                preview_frame,
                width="stretch",
                hide_index=True,
            )

        with st.expander("Inspect raw JSON records"):
            st.json(preview_records)
    else:
        st.info("No alert records are present in the loaded snapshot.")

    with st.expander("Dataset Documentation"):
        st.markdown(
            """
            **Snapshot scope:** This page exports the alert records supplied by
            the dashboard's live-alert data adapter at the time of export.

            **JSON:** Preserves nested alert fields and cached enrichment in a
            structured format.

            **CSV:** Suitable for spreadsheet and statistical workflows.
            Nested dictionaries, lists, and other compound values are encoded
            as JSON text in a cell.

            **Research package:** Combines the JSON snapshot, CSV snapshot,
            manifest, README, and IDS source configuration when available.

            **Timestamp coverage:** The manifest records the earliest and latest
            parseable event times in UTC. Records without usable timestamps are
            not included in this coverage range.

            **Evidence limitations:** Alert records and retained packet
            observations may represent only part of the activity captured in
            the lab. Correlation does not establish causation or prove attack
            success.
            """
        )
        st.json(manifest)
