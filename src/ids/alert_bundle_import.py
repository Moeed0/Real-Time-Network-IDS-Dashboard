"""Validate and prepare local IDS alert bundles for manual correlation."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import io
import json
import re
import zipfile

from ids.alert_bundle import (
    BUNDLE_SCHEMA_VERSION,
    BUNDLE_TYPE,
    EVIDENCE_NOTE,
    INDIVIDUAL_ALERT_DOCUMENT_TYPE,
    INDIVIDUAL_ALERT_DOCUMENT_VERSION,
    PROJECT_NAME,
)


MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ALERTS_PER_BUNDLE = 1000
MAX_SELECTED_RECORDS = 250


class AlertBundleImportError(ValueError):
    """Raised when an uploaded alert bundle is invalid or unsafe to parse."""


def _safe_filename(filename: str) -> str:
    """Use only a short basename for display and provenance."""
    name = Path(str(filename).replace("\x00", "")).name
    return (name or "uploaded-bundle").replace("\\", "_")[:180]


def _bundle_from_individual_alert_payloads(
    payloads: list[bytes],
) -> dict[str, Any]:
    """Convert individual alert JSON documents into the importer's common shape."""
    if not payloads:
        raise AlertBundleImportError("No individual alert JSON documents were provided.")
    if len(payloads) > MAX_ALERTS_PER_BUNDLE:
        raise AlertBundleImportError(
            f"The archive exceeds the limit of {MAX_ALERTS_PER_BUNDLE} alert files."
        )

    documents: list[dict[str, Any]] = []
    for index, payload in enumerate(payloads):
        try:
            document = json.loads(payload.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AlertBundleImportError(
                f"Individual alert JSON file {index + 1} is not valid UTF-8 JSON."
            ) from exc

        if not isinstance(document, dict):
            raise AlertBundleImportError(
                f"Individual alert JSON file {index + 1} must contain an object."
            )
        if document.get("document_type") != INDIVIDUAL_ALERT_DOCUMENT_TYPE:
            raise AlertBundleImportError(
                f"JSON file {index + 1} is not a supported individual alert document."
            )
        if (
            type(document.get("document_version")) is not int
            or document["document_version"]
            not in {1, INDIVIDUAL_ALERT_DOCUMENT_VERSION}
        ):
            raise AlertBundleImportError(
                f"Unsupported individual alert document version in file {index + 1}."
            )

        alert = document.get("alert")
        if not isinstance(alert, dict):
            raise AlertBundleImportError(
                f"Individual alert JSON file {index + 1} has no valid alert object."
            )

        for field in ("enrichment", "packet_investigation"):
            value = document.get(field)
            if value is not None and not isinstance(value, dict):
                raise AlertBundleImportError(
                    f"Individual alert JSON file {index + 1} has invalid {field} data."
                )

        native_event = document.get("native_event")
        if native_event is not None and not isinstance(native_event, (dict, str)):
            raise AlertBundleImportError(
                f"Individual alert JSON file {index + 1} has invalid native_event data."
            )

        documents.append(document)

    first = documents[0]
    source = first.get("source")
    if not isinstance(source, dict):
        source = {
            "application": PROJECT_NAME,
            "mode": "individual_alert_export_import",
        }

    alerts = []
    for document in documents:
        alert = document["alert"]
        alert_id = document.get("alert_id")
        if alert_id is None:
            alert_id = alert.get("record_id", alert.get("id", alert.get("alert_id")))

        alerts.append({
            "alert_id": alert_id,
            "alert": alert,
            "native_event": document.get("native_event"),
            "intelligence": None,
            "packet_investigation": document.get("packet_investigation"),
            "enrichment": document.get("enrichment"),
        })

    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_type": BUNDLE_TYPE,
        "created_at_utc": first.get("created_at_utc"),
        "source": source,
        "summary": {
            "alert_count": len(alerts),
            "alerts_with_intelligence": 0,
            "alerts_with_packet_investigation": sum(
                item["packet_investigation"] is not None for item in alerts
            ),
            "alerts_with_enrichment": sum(
                item["enrichment"] is not None for item in alerts
            ),
        },
        "evidence_note": first.get("evidence_note") or EVIDENCE_NOTE,
        "alerts": alerts,
    }


def _decode_bundle_json(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AlertBundleImportError(
            f"The bundle does not contain valid UTF-8 JSON: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise AlertBundleImportError("The JSON root must be an object.")

    if value.get("bundle_type") != BUNDLE_TYPE:
        raise AlertBundleImportError(
            "This is not a supported IDS alert bundle."
        )

    if value.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise AlertBundleImportError(
            f"Unsupported bundle schema version: "
            f"{value.get('schema_version')!r}"
        )

    records = value.get("alerts")
    if not isinstance(records, list):
        raise AlertBundleImportError(
            "The bundle must contain an 'alerts' list."
        )

    if len(records) > MAX_ALERTS_PER_BUNDLE:
        raise AlertBundleImportError(
            f"The bundle exceeds the limit of "
            f"{MAX_ALERTS_PER_BUNDLE} records."
        )

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise AlertBundleImportError(
                f"Bundle record {index} must be an object."
            )

        alert = record.get("alert")
        if not isinstance(alert, dict):
            raise AlertBundleImportError(
                f"Bundle record {index} has no valid original alert object."
            )

        for field in ("intelligence", "packet_investigation", "enrichment"):
            attachment = record.get(field)
            if attachment is not None and not isinstance(attachment, dict):
                raise AlertBundleImportError(
                    f"Bundle record {index} has an invalid {field} object."
                )

    return value


def parse_alert_bundle_upload(
    filename: str,
    content: bytes,
    *,
    max_size_bytes: int = MAX_UPLOAD_BYTES,
) -> dict[str, Any]:
    """Validate a JSON bundle or ZIP bundle without extracting files.

    ZIP imports read only the root member named ``alert_bundle.json``.
    Uploads and expanded JSON are size-limited. No path is written to disk.
    """
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")

    if isinstance(max_size_bytes, bool) or not isinstance(max_size_bytes, int):
        raise TypeError("max_size_bytes must be an integer")
    if max_size_bytes <= 0:
        raise ValueError("max_size_bytes must be greater than zero")

    safe_name = _safe_filename(filename)
    suffix = Path(safe_name).suffix.lower()

    if suffix not in {".json", ".zip"}:
        raise AlertBundleImportError(
            "Unsupported file type. Upload a .json or .zip alert bundle."
        )

    if len(content) > max_size_bytes:
        raise AlertBundleImportError(
            f"Upload exceeds the {max_size_bytes:,}-byte size limit."
        )

    payload = content
    individual_payloads: list[bytes] | None = None

    if suffix == ".zip":
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = [
                    info for info in archive.infolist()
                    if not info.is_dir()
                ]
                matches = [
                    info for info in members
                    if info.filename == "alert_bundle.json"
                ]

                if len(matches) > 1:
                    raise AlertBundleImportError(
                        "ZIP must not contain multiple root alert_bundle.json files."
                    )

                if len(matches) == 1:
                    member = matches[0]
                    if member.file_size > max_size_bytes:
                        raise AlertBundleImportError(
                            "Expanded alert_bundle.json exceeds the size limit."
                        )
                    with archive.open(member, "r") as handle:
                        payload = handle.read(max_size_bytes + 1)
                    if len(payload) > max_size_bytes:
                        raise AlertBundleImportError(
                            "Expanded alert_bundle.json exceeds the size limit."
                        )
                else:
                    json_members = [
                        info for info in members
                        if (
                            "/" not in info.filename
                            and "\\" not in info.filename
                            and Path(info.filename).suffix.lower() == ".json"
                        )
                    ]
                    if not json_members:
                        raise AlertBundleImportError(
                            "ZIP must contain a root alert_bundle.json or individual alert JSON files."
                        )
                    if len(json_members) > MAX_ALERTS_PER_BUNDLE:
                        raise AlertBundleImportError(
                            f"The archive exceeds the limit of {MAX_ALERTS_PER_BUNDLE} alert files."
                        )

                    individual_payloads = []
                    expanded_total = 0
                    for member in json_members:
                        expanded_total += member.file_size
                        if expanded_total > max_size_bytes:
                            raise AlertBundleImportError(
                                "Expanded individual alert JSON files exceed the size limit."
                            )
                        with archive.open(member, "r") as handle:
                            item_payload = handle.read(max_size_bytes + 1)
                        if len(item_payload) > max_size_bytes:
                            raise AlertBundleImportError(
                                "An individual alert JSON file exceeds the size limit."
                            )
                        individual_payloads.append(item_payload)
        except AlertBundleImportError:
            raise
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            raise AlertBundleImportError(
                f"The ZIP file could not be read: {exc}"
            ) from exc

    if individual_payloads is not None:
        bundle = _bundle_from_individual_alert_payloads(individual_payloads)
    else:
        try:
            root = json.loads(payload.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            bundle = _decode_bundle_json(payload)
        else:
            if (
                isinstance(root, dict)
                and root.get("document_type") == INDIVIDUAL_ALERT_DOCUMENT_TYPE
            ):
                bundle = _bundle_from_individual_alert_payloads([payload])
            else:
                bundle = _decode_bundle_json(payload)

    digest = sha256(content).hexdigest()[:12]
    imported_records: list[dict[str, Any]] = []

    for index, entry in enumerate(bundle["alerts"]):
        alert = dict(entry["alert"])
        alert_id = entry.get("alert_id")
        if alert_id is None:
            alert_id = alert.get("record_id", alert.get("id", alert.get("alert_id")))

        key_id = str(alert_id) if alert_id is not None else "no-id"
        record_key = f"{safe_name}::{digest}::{index + 1}::{key_id}"

        imported_records.append(
            {
                "record_key": record_key,
                "source_file": safe_name,
                "source_bundle_created_at_utc": bundle.get("created_at_utc"),
                "source_bundle": bundle.get("source"),
                "source_bundle_schema_version": bundle.get("schema_version"),
                "source_bundle_evidence_note": bundle.get("evidence_note"),
                "alert_id": alert_id,
                "alert": alert,
                "native_event": entry.get("native_event"),
                "intelligence": entry.get("intelligence"),
                "packet_investigation": entry.get("packet_investigation"),
                "enrichment": entry.get("enrichment"),
            }
        )

    source = bundle.get("source")
    summary = bundle.get("summary")

    return {
        "filename": safe_name,
        "bundle_type": bundle["bundle_type"],
        "schema_version": bundle["schema_version"],
        "created_at_utc": bundle.get("created_at_utc"),
        "source": dict(source) if isinstance(source, dict) else {},
        "summary": dict(summary) if isinstance(summary, dict) else {},
        "evidence_note": bundle.get("evidence_note"),
        "record_count": len(imported_records),
        "records": imported_records,
    }


def build_manual_correlation_analysis(
    imported_bundles: Iterable[Mapping[str, Any]],
    selected_record_keys: Iterable[str],
    group_label: str,
    *,
    classify_alert: Callable[[dict[str, Any]], Any],
    is_security_related: Callable[[dict[str, Any]], Any],
    format_alert_timestamp_pkt: Callable[[dict[str, Any]], Any],
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Create an analysis snapshot from explicitly selected imported records.

    The original alert fields, included intelligence and packet evidence remain
    available in each analysis row. Imported records are not written to SQLite.
    """
    label = str(group_label or "").strip()
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", label).strip("-_").lower()[:80].strip("-_")
    if not label or not slug:
        raise ValueError("Enter a manual correlation label containing letters or numbers.")

    bundles = list(imported_bundles)
    record_lookup: dict[str, dict[str, Any]] = {}

    for bundle in bundles:
        records = bundle.get("records")
        if not isinstance(records, list):
            raise ValueError("An imported bundle has no valid records list.")
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("An imported bundle contains an invalid record.")
            key = record.get("record_key")
            if not isinstance(key, str) or not key:
                raise ValueError("An imported record has no valid selection key.")
            if key in record_lookup:
                raise ValueError("Imported record keys must be unique.")
            if not isinstance(record.get("alert"), dict):
                raise ValueError("An imported record has no valid original alert.")
            record_lookup[key] = record

    requested_keys = list(dict.fromkeys(str(key) for key in selected_record_keys))
    if not requested_keys:
        raise ValueError("Select at least one imported alert.")
    if len(requested_keys) > MAX_SELECTED_RECORDS:
        raise ValueError(
            f"Select no more than {MAX_SELECTED_RECORDS} alerts per manual group."
        )

    missing = [key for key in requested_keys if key not in record_lookup]
    if missing:
        raise ValueError(
            f"{len(missing)} selected record(s) are not present in the imported bundles."
        )

    chosen = [record_lookup[key] for key in requested_keys]
    rows: list[dict[str, Any]] = []

    for item in chosen:
        original = dict(item["alert"])
        row = dict(original)

        # Imported bundles may store Unix timestamps in `timestamp` rather
        # than the normalized `event_ts_utc` field used by the dashboard.
        # Preserve the original field and add the normalized alias only when
        # the native event timestamp is absent.
        if row.get("event_ts_utc") is None:
            timestamp_value = row.get("timestamp")
            if isinstance(timestamp_value, (int, float)) and not isinstance(
                timestamp_value, bool
            ):
                row["event_ts_utc"] = timestamp_value

        if row.get("id") is None:
            row["id"] = item.get("alert_id")
        if row.get("record_id") is None and item.get("alert_id") is not None:
            row["record_id"] = item.get("alert_id")

        row["engine"] = (
            row.get("engine") or row.get("engine_key") or "unknown"
        )
        if not row.get("msg") and row.get("rule"):
            row["msg"] = row["rule"]

        row["presentation_category"] = classify_alert(row)
        try:
            row["timestamp_pkt"] = format_alert_timestamp_pkt(row)
        except Exception:
            row["timestamp_pkt"] = (
                row.get("timestamp") or row.get("event_ts_utc") or "Unavailable"
            )

        row["correlation_group_id"] = f"manual:{slug}"
        row["bundle_record_key"] = item["record_key"]
        row["bundle_source_file"] = item.get("source_file")
        row["bundle_source_created_at_utc"] = (
            item.get("source_bundle_created_at_utc")
        )
        row["bundle_intelligence"] = item.get("intelligence")
        row["bundle_packet_investigation"] = item.get("packet_investigation")
        row["bundle_enrichment"] = item.get("enrichment")
        row["bundle_record"] = {
            "alert_id": item.get("alert_id"),
            "alert": original,
            "intelligence": item.get("intelligence"),
            "packet_investigation": item.get("packet_investigation"),
            "enrichment": item.get("enrichment"),
            "source_bundle": {
                "filename": item.get("source_file"),
                "created_at_utc": item.get("source_bundle_created_at_utc"),
                "source": item.get("source_bundle"),
                "schema_version": item.get("source_bundle_schema_version"),
                "evidence_note": item.get("source_bundle_evidence_note"),
            },
        }
        rows.append(row)

    def time_key(row: dict[str, Any]) -> tuple[float, str]:
        value = row.get("event_ts_utc")
        numeric = float(value) if isinstance(value, (int, float)) else -1.0
        return numeric, str(row.get("id") or "")

    rows.sort(key=time_key)

    engines = sorted({
        str(row.get("engine") or "unknown").lower()
        for row in rows
    })
    numeric_times = [
        row["event_ts_utc"]
        for row in rows
        if isinstance(row.get("event_ts_utc"), (int, float))
    ]

    first_time = (
        format_alert_timestamp_pkt({"event_ts_utc": min(numeric_times)})
        if numeric_times else "Unavailable"
    )
    last_time = (
        format_alert_timestamp_pkt({"event_ts_utc": max(numeric_times)})
        if numeric_times else "Unavailable"
    )

    community_ids = sorted({
        str(row.get("community_id"))
        for row in rows
        if row.get("community_id")
    })

    generated_at = created_at or datetime.now(timezone.utc)
    if not isinstance(generated_at, datetime):
        raise TypeError("created_at must be a datetime or None")
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    generated_at = generated_at.astimezone(timezone.utc)

    bundle_names = sorted({
        str(item.get("filename") or "unknown")
        for bundle in bundles
        for item in [bundle]
        if any(
            record.get("record_key") in requested_keys
            for record in bundle.get("records", [])
            if isinstance(record, dict)
        )
    })

    return {
        "schema_version": 1,
        "generated_at_utc": generated_at.isoformat(timespec="seconds"),
        "correlation_group_id": f"manual:{slug}",
        "community_id": community_ids[0] if len(community_ids) == 1 else None,
        "source_mode": "imported_alert_bundles",
        "source_bundle_files": bundle_names,
        "summary": {
            "record_count": len(rows),
            "security_related_record_count": sum(
                1 for row in rows if is_security_related(row)
            ),
            "engine_count": len(engines),
            "engines": engines,
            "first_event_pkt": first_time,
            "last_event_pkt": last_time,
            "manual_group_label": label,
            "source_bundle_count": len(bundle_names),
        },
        "alerts": rows,
    }
