"""Build local, JSON-serializable investigation bundles from IDS alerts."""

from __future__ import annotations

import base64
import io
import json
import math
import re
import zipfile
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


BUNDLE_SCHEMA_VERSION = 1
BUNDLE_TYPE = "real_time_network_ids_alert_bundle"
PROJECT_NAME = "Real-Time-Network-IDS-Dashboard"

INDIVIDUAL_ALERT_DOCUMENT_TYPE = "real_time_network_ids_alert"
INDIVIDUAL_ALERT_DOCUMENT_VERSION = 2

EVIDENCE_NOTE = (
    "Packet evidence represents retained observations matched to the alert. "
    "It is not guaranteed to include all traffic or prove that an attack "
    "succeeded."
)


def _utc_isoformat(value: datetime) -> str:
    """Format a datetime as UTC ISO 8601; treat naive values as UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _json_safe(value: Any) -> Any:
    """Convert common Python values into JSON-compatible values."""
    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, datetime):
        return _utc_isoformat(value)

    if isinstance(value, date):
        return value.isoformat()

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, bytes):
        return {
            "encoding": "base64",
            "data": base64.b64encode(value).decode("ascii"),
        }

    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]

    if isinstance(value, (set, frozenset)):
        return [
            _json_safe(item)
            for item in sorted(value, key=repr)
        ]

    # Keep unexpected third-party values exportable without failing the
    # entire bundle. Known structured types are handled above.
    return str(value)


def _alert_identifier(alert: Mapping[str, Any]) -> Any:
    """Find the stable alert identifier used to attach supporting data."""
    for field in ("record_id", "id", "alert_id"):
        value = alert.get(field)
        if value is not None and value != "":
            return value
    return None


def _find_attachment(
    attachments: Mapping[Any, Any] | None,
    identifier: Any,
) -> Any:
    """Look up supporting data by integer or string alert ID."""
    if attachments is None or identifier is None:
        return None

    candidates = [identifier]
    text_identifier = str(identifier)

    if text_identifier not in candidates:
        candidates.append(text_identifier)

    if isinstance(identifier, str) and identifier.isdecimal():
        integer_identifier = int(identifier)
        if integer_identifier not in candidates:
            candidates.append(integer_identifier)

    for candidate in candidates:
        try:
            if candidate in attachments:
                return attachments[candidate]
        except TypeError:
            # Ignore identifiers that cannot be used as mapping keys.
            continue

    return None




def _compact_references(value: Any, limit: int = 5) -> Any:
    """Keep reference previews while explicitly reporting omitted entries."""
    if not isinstance(value, list):
        return value

    preview = []
    for item in value[:limit]:
        if isinstance(item, Mapping):
            allowed = (
                "url", "name", "source", "refsource",
                "tags", "severity", "date", "description",
            )
            preview.append({
                key: item[key] for key in allowed if key in item
            })
        else:
            preview.append(item)

    return {
        "count": len(value),
        "preview": preview,
        "omitted": max(0, len(value) - limit),
    }


def _summarize_nvd_configurations(value: Any) -> dict[str, Any]:
    """Summarize large NVD configuration trees and retain a CPE preview."""
    matches = []
    seen = set()
    stack = [value]
    fields = (
        "criteria", "cpe23Uri", "vulnerable", "matchCriteriaId",
        "versionStartIncluding", "versionStartExcluding",
        "versionEndIncluding", "versionEndExcluding",
    )

    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            if item.get("criteria") or item.get("cpe23Uri"):
                match = {key: item[key] for key in fields if key in item}
                marker = json.dumps(match, sort_keys=True, default=str)
                if marker not in seen:
                    seen.add(marker)
                    matches.append(match)
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)

    return {
        "configuration_count": len(value) if isinstance(value, list) else None,
        "cpe_match_count": len(matches),
        "cpe_matches_preview": matches[:10],
        "cpe_matches_omitted": max(0, len(matches) - 10),
        "note": (
            "Full NVD configurations were summarized for compactness. "
            "The preview is not a replacement for the complete source record."
        ),
    }


def _native_equivalent(
    field: str,
    value: Any,
    native_event: Mapping[str, Any],
) -> bool:
    """Check a field against matching aliases anywhere in the native event."""
    aliases = {
        "message": ("msg", "message", "signature"),
        "msg": ("msg", "message", "signature"),
        "signature": ("signature", "msg", "message"),
        "classification": ("classification", "category", "classtype", "class"),
        "category": ("category", "classification", "classtype", "class"),
        "class": ("class", "category", "classification", "classtype"),
        "timestamp": ("timestamp", "@timestamp", "ts"),
        "gid": ("gid", "generator_id", "generatorid"),
        "sid": ("sid", "signature_id", "signatureid"),
        "rev": ("rev", "revision"),
        "severity": ("severity", "priority"),
        "priority": ("priority", "severity"),
        "protocol": ("protocol", "proto"),
        "proto": ("proto", "protocol"),
        "service": ("service", "app_proto"),
        "app_proto": ("app_proto", "service"),
        "src_addr": ("src_addr", "src_ip", "source_ip"),
        "src_ip": ("src_ip", "src_addr", "source_ip"),
        "source_ip": ("source_ip", "src_ip", "src_addr"),
        "dst_addr": ("dst_addr", "dest_ip", "dst_ip", "destination_ip"),
        "dest_ip": ("dest_ip", "dst_ip", "dst_addr", "destination_ip"),
        "dst_ip": ("dst_ip", "dest_ip", "dst_addr", "destination_ip"),
        "dst_port": ("dst_port", "dest_port", "destination_port"),
        "dest_port": ("dest_port", "dst_port", "destination_port"),
        "src_port": ("src_port", "source_port"),
        "source_port": ("source_port", "src_port"),
        "direction": ("direction", "dir"),
        "dir": ("dir", "direction"),
        "action": ("action",),
        "pkt_len": ("pkt_len", "packet_length"),
        "client_pkts": ("client_pkts", "pkts_toserver"),
        "client_bytes": ("client_bytes", "bytes_toserver"),
        "server_pkts": ("server_pkts", "pkts_toclient"),
        "server_bytes": ("server_bytes", "bytes_toclient"),
        "flow_id": ("flow_id",),
        "community_id": ("community_id",),
        "iface": ("iface", "in_iface", "interface"),
        "interface": ("interface", "in_iface", "iface"),
    }
    candidate_keys = {key.lower() for key in aliases.get(field.lower(), (field,))}
    stack: list[Any] = [native_event]

    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key, child in current.items():
                if str(key).lower() in candidate_keys and child == value:
                    return True
                if isinstance(child, (Mapping, list, tuple)):
                    stack.append(child)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)

    return False

def _prune_nested_alert(
    value: Any,
    parent: Mapping[str, Any],
    native_event: Mapping[str, Any],
) -> Any:
    """Remove duplicated cached context and exact field copies, not unique data."""
    if isinstance(value, Mapping):
        result = {}
        for key, child in value.items():
            if key == "security_context":
                continue
            if key in parent and parent[key] == child:
                continue
            if _native_equivalent(str(key), child, native_event):
                continue
            pruned = _prune_nested_alert(child, parent, native_event)
            if pruned not in ({}, []):
                result[key] = pruned
        return result

    if isinstance(value, list):
        return [
            _prune_nested_alert(item, parent, native_event)
            for item in value
        ]

    return value


def _compact_alert_for_export(
    alert: Mapping[str, Any],
    native_event: Any,
    enrichment: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Create a compact copy; never mutate the caller's original alert."""
    result = _json_safe(dict(alert))
    if not isinstance(result, dict):
        return dict(alert)

    # Only deduplicate against a structured event when canonical analysis exists.
    if not isinstance(native_event, Mapping) or not native_event or enrichment is None:
        return result

    for field in ("raw_json", "native_event", "event", "security_context"):
        result.pop(field, None)

    for key, value in list(result.items()):
        if _native_equivalent(str(key), value, native_event):
            result.pop(key, None)

    detection = enrichment.get("detection")
    rule = detection.get("rule") if isinstance(detection, Mapping) else None
    if isinstance(rule, Mapping) and rule.get("rule_text"):
        result.pop("rule", None)

    # Keep any unique information from a nested normalized alert.
    if isinstance(result.get("alert"), Mapping):
        nested = _prune_nested_alert(result["alert"], result, native_event)
        if nested:
            result["alert"] = nested
        else:
            result.pop("alert", None)

    return result


def _compact_enrichment_for_export(
    enrichment: Mapping[str, Any] | None,
    native_event: Any,
    investigation: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Remove exact duplicates and summarize large reference/configuration lists."""
    if enrichment is None:
        return None

    result = _json_safe(dict(enrichment))
    if not isinstance(result, dict):
        return None

    if isinstance(native_event, Mapping):
        network = result.get("network")
        if isinstance(network, dict):
            removed = []

            for field, native_key in (
                ("protocol", "proto"),
                ("application_protocol", "app_proto"),
                ("direction", "direction"),
                ("interface", "in_iface"),
                ("community_id", "community_id"),
                ("flow_id", "flow_id"),
            ):
                if (
                    field in network
                    and native_key in native_event
                    and network[field] == native_event[native_key]
                ):
                    network.pop(field)
                    removed.append(field)

            for field, native_ip, native_port in (
                ("source", "src_ip", "src_port"),
                ("destination", "dest_ip", "dest_port"),
            ):
                endpoint = network.get(field)
                if not isinstance(endpoint, dict):
                    continue
                for endpoint_field, event_field in (
                    ("ip", native_ip), ("port", native_port)
                ):
                    if (
                        endpoint_field in endpoint
                        and event_field in native_event
                        and endpoint[endpoint_field] == native_event[event_field]
                    ):
                        endpoint.pop(endpoint_field)
                if not endpoint:
                    network.pop(field)
                    removed.append(field)

            native_flow = native_event.get("flow")
            flow = network.get("flow")
            if (
                isinstance(flow, Mapping)
                and isinstance(native_flow, Mapping)
                and all(
                    key in native_flow and native_flow[key] == value
                    for key, value in flow.items()
                )
            ):
                network.pop("flow")
                removed.append("flow")

            protocol_evidence = network.get("protocol_evidence")
            if isinstance(protocol_evidence, dict):
                for protocol_key in (
                    "http", "dns", "tls", "ssh", "ftp", "smb",
                    "smtp", "rdp", "dcerpc", "mqtt", "quic",
                ):
                    native_protocol = native_event.get(protocol_key)
                    if not isinstance(native_protocol, Mapping):
                        continue

                    # Handle a direct protocol record as well as a nested
                    # {"http": {...}, "alert_metadata": {...}} structure.
                    if protocol_evidence and all(
                        key in native_protocol and native_protocol[key] == value
                        for key, value in protocol_evidence.items()
                    ):
                        network.pop("protocol_evidence", None)
                        removed.append("protocol_evidence")
                        protocol_evidence = None
                        break

                    nested_protocol = protocol_evidence.get(protocol_key)
                    if (
                        isinstance(nested_protocol, Mapping)
                        and all(
                            key in native_protocol and native_protocol[key] == value
                            for key, value in nested_protocol.items()
                        )
                    ):
                        protocol_evidence.pop(protocol_key, None)
                        removed.append(f"protocol_evidence.{protocol_key}")

                if isinstance(protocol_evidence, dict):
                    native_alert = native_event.get("alert")
                    native_metadata = (
                        native_alert.get("metadata")
                        if isinstance(native_alert, Mapping)
                        else None
                    )
                    alert_metadata = protocol_evidence.get("alert_metadata")
                    if (
                        isinstance(native_metadata, Mapping)
                        and isinstance(alert_metadata, Mapping)
                        and dict(alert_metadata) == dict(native_metadata)
                    ):
                        protocol_evidence.pop("alert_metadata", None)
                        removed.append("protocol_evidence.alert_metadata")

                    if not protocol_evidence:
                        network.pop("protocol_evidence", None)
                        if "protocol_evidence" not in removed:
                            removed.append("protocol_evidence")

            if removed:
                network["native_event_ref"] = "native_event"
                network["deduplicated_fields"] = removed

    detection = result.get("detection")
    rule = detection.get("rule") if isinstance(detection, dict) else None
    if isinstance(rule, dict) and rule.get("rule_text"):
        for field in (
            "options_json", "raw_options", "metadata_json",
            "references_json", "cve_ids_json", "mitre_ids_json", "urls_json",
        ):
            rule.pop(field, None)

    threat = result.get("threat_intelligence")
    if isinstance(threat, dict):
        vulnerabilities = threat.get("vulnerabilities")
        if isinstance(vulnerabilities, dict):
            for record in vulnerabilities.values():
                if not isinstance(record, dict):
                    continue
                nvd = record.get("nvd")
                if isinstance(nvd, dict):
                    if isinstance(nvd.get("references"), list):
                        nvd["references"] = _compact_references(nvd["references"])
                    configurations = nvd.pop("configurations", None)
                    if isinstance(configurations, list):
                        nvd["configuration_summary"] = (
                            _summarize_nvd_configurations(configurations)
                        )

                epss = record.get("epss")
                if isinstance(epss, dict) and "raw" in epss:
                    epss.pop("raw")
                    epss["raw_data_omitted"] = True

        if isinstance(threat.get("references"), list):
            threat["references"] = _compact_references(threat["references"])

    # Individual-alert enrichment retains correlation context, not peer records.
    investigation_section = result.get("investigation")
    if isinstance(investigation_section, dict):
        investigation_section.pop("related_alerts", None)
        investigation_section.pop("related_alert_count", None)

    # Detailed analysis stays in one location. Keep an explicit pointer.
    assessment = result.get("assessment")
    analysis = detection.get("analysis") if isinstance(detection, dict) else None
    if isinstance(assessment, dict) and assessment.get("explanation") == analysis:
        assessment.pop("explanation")
        assessment["explanation_ref"] = "detection.analysis"

    # If the optional investigation repeats exact packet/flow arrays, refer to
    # the separate packet_investigation section instead of duplicating them.
    canonical = result.get("investigation")
    if isinstance(canonical, dict) and isinstance(investigation, Mapping):
        removed = []
        for field in ("packet_summary", "packets", "related_alerts"):
            if (
                field in canonical
                and field in investigation
                and canonical[field] == _json_safe(investigation[field])
            ):
                canonical.pop(field)
                removed.append(field)
        if removed:
            canonical["details_reference"] = "packet_investigation"
            canonical["details_fields_included"] = removed

    return result



def _compact_investigation_for_export(
    investigation: Mapping[str, Any] | None,
    alert: Mapping[str, Any],
    native_event: Any,
) -> dict[str, Any] | None:
    """Remove repeated alert details while preserving unique investigation data."""
    if investigation is None:
        return None

    result = _json_safe(dict(investigation))
    if not isinstance(result, dict):
        return None

    selected_id = _alert_identifier(alert)

    if isinstance(native_event, Mapping) and native_event:
        nested_alert = result.get("alert")
        if isinstance(nested_alert, Mapping):
            nested = dict(nested_alert)

            for field in ("raw_json", "native_event", "event", "security_context"):
                nested.pop(field, None)

            selected_message = alert.get("msg") or alert.get("message")
            if (
                isinstance(nested.get("rule"), str)
                and selected_message
                and nested["rule"] == selected_message
            ):
                nested.pop("rule", None)

            compacted_nested = _prune_nested_alert(nested, alert, native_event)
            compacted_nested = {
                key: value
                for key, value in compacted_nested.items()
                if value is not None and value != "" and value != {} and value != []
            }

            if compacted_nested:
                result["alert"] = compacted_nested
                result["alert_details_compacted"] = True
                result["alert_reference"] = {
                    "alert_id": selected_id,
                    "section": "alert",
                }
            else:
                result.pop("alert", None)
                result["alert_reference"] = {
                    "alert_id": selected_id,
                    "section": "alert",
                }

    # Individual alert exports omit related-alert records and counts.
    result.pop("related_alerts", None)
    result.pop("related_alert_count", None)
    result.pop("selected_alert_excluded_from_related_alerts", None)
    return result


def build_individual_alert_document(
    alert: Mapping[str, Any],
    *,
    enrichment: Mapping[str, Any] | None = None,
    native_event: Any | None = None,
    investigation: Mapping[str, Any] | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Build an individual compact JSON document without mutating inputs."""
    if not isinstance(alert, Mapping):
        raise TypeError("alert must be a mapping")
    if enrichment is not None and not isinstance(enrichment, Mapping):
        raise TypeError("enrichment must be a mapping or None")
    if native_event is not None and not isinstance(native_event, (Mapping, str)):
        raise TypeError("native_event must be a mapping, string, or None")
    if investigation is not None and not isinstance(investigation, Mapping):
        raise TypeError("investigation must be a mapping or None")

    export_time = created_at or datetime.now(timezone.utc)
    if not isinstance(export_time, datetime):
        raise TypeError("created_at must be a datetime or None")

    compact_alert = _compact_alert_for_export(alert, native_event, enrichment)
    compact_enrichment = _compact_enrichment_for_export(
        enrichment, native_event, investigation
    )
    compact_investigation = _compact_investigation_for_export(
        investigation, alert, native_event
    )

    return {
        "document_type": INDIVIDUAL_ALERT_DOCUMENT_TYPE,
        "document_version": INDIVIDUAL_ALERT_DOCUMENT_VERSION,
        "created_at_utc": _utc_isoformat(export_time),
        "source": {
            "application": PROJECT_NAME,
            "mode": "individual_alert_export",
        },
        "alert_id": _json_safe(_alert_identifier(alert)),
        "alert": _json_safe(compact_alert),
        "native_event": (
            _json_safe(dict(native_event))
            if isinstance(native_event, Mapping)
            else _json_safe(native_event)
        ),
        "enrichment": _json_safe(compact_enrichment),
        "packet_investigation": _json_safe(compact_investigation),
        "evidence_note": EVIDENCE_NOTE,
    }


def serialize_individual_alert_document(
    document: Mapping[str, Any],
    *,
    indent: int = 2,
) -> str:
    """Serialize a single individual-alert document as readable JSON."""
    if not isinstance(document, Mapping):
        raise TypeError("document must be a mapping")
    if isinstance(indent, bool) or not isinstance(indent, int) or indent < 0:
        raise ValueError("indent must be a non-negative integer")

    return json.dumps(
        _json_safe(dict(document)),
        indent=indent,
        ensure_ascii=False,
        allow_nan=False,
    ) + "\n"


def individual_alert_filename(
    alert: Mapping[str, Any],
    *,
    sequence: int | None = None,
) -> str:
    """Generate a safe, recognizable filename without user-controlled paths."""
    if not isinstance(alert, Mapping):
        raise TypeError("alert must be a mapping")
    if sequence is not None and (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
    ):
        raise ValueError("sequence must be a positive integer or None")

    def safe_component(value: Any, fallback: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", str(value or ""))
        return cleaned.strip("-_")[:64] or fallback

    identifier = _alert_identifier(alert)
    engine = alert.get("engine_key") or alert.get("engine") or "unknown"
    sid = alert.get("sid")
    if sid is None and isinstance(alert.get("rule"), Mapping):
        sid = alert["rule"].get("sid")

    prefix = f"{sequence:02d}-" if sequence is not None else ""
    parts = [
        "alert",
        safe_component(identifier, "unknown-id"),
        safe_component(engine, "unknown-engine"),
    ]
    if sid is not None and str(sid).strip():
        parts.extend(["sid", safe_component(sid, "unknown-sid")])

    return prefix + "-".join(parts) + ".json"


def build_individual_alert_zip(files: Mapping[str, str]) -> bytes:
    """Create a ZIP containing exactly the supplied JSON files, no README."""
    if not isinstance(files, Mapping):
        raise TypeError("files must be a mapping of filenames to JSON text")
    if not files:
        raise ValueError("at least one JSON file is required")

    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for filename, content in files.items():
            if (
                not isinstance(filename, str)
                or Path(filename).name != filename
                or "/" in filename
                or "\\\\" in filename
                or not filename.lower().endswith(".json")
            ):
                raise ValueError("each archive filename must be a plain .json filename")
            if not isinstance(content, str):
                raise TypeError("each file content must be a string")
            archive.writestr(filename, content)

    return buffer.getvalue()


def build_alert_bundle(
    alerts: Iterable[Mapping[str, Any]],
    *,
    intelligence_by_alert_id: Mapping[Any, Any] | None = None,
    investigations_by_alert_id: Mapping[Any, Any] | None = None,
    enrichment_by_alert_id: Mapping[Any, Any] | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Build an export bundle from alerts and optional associated results.

    The caller supplies alert dictionaries and may supply offline intelligence
    contexts and packet-investigation results keyed by alert ID. This function
    does not retrieve data, access a database, or make network requests.

    Each exported record preserves the complete original alert under ``alert``.
    Missing optional attachments are represented as ``None``.
    """
    if isinstance(alerts, (str, bytes, Mapping)):
        raise TypeError("alerts must be an iterable of alert mappings")

    try:
        input_alerts = list(alerts)
    except TypeError as exc:
        raise TypeError(
            "alerts must be an iterable of alert mappings"
        ) from exc

    for index, alert in enumerate(input_alerts):
        if not isinstance(alert, Mapping):
            raise TypeError(
                f"alerts[{index}] must be a mapping, "
                f"not {type(alert).__name__}"
            )

    export_time = created_at or datetime.now(timezone.utc)
    if not isinstance(export_time, datetime):
        raise TypeError("created_at must be a datetime or None")

    records: list[dict[str, Any]] = []
    intelligence_count = 0
    investigation_count = 0
    enrichment_count = 0

    for alert in input_alerts:
        identifier = _alert_identifier(alert)
        intelligence = _find_attachment(
            intelligence_by_alert_id,
            identifier,
        )
        investigation = _find_attachment(
            investigations_by_alert_id,
            identifier,
        )
        enrichment = _find_attachment(
            enrichment_by_alert_id,
            identifier,
        )

        if intelligence is not None:
            intelligence_count += 1
        if investigation is not None:
            investigation_count += 1
        if enrichment is not None:
            enrichment_count += 1

        records.append(
            {
                "alert_id": _json_safe(identifier),
                "alert": _json_safe(dict(alert)),
                "intelligence": _json_safe(intelligence),
                "packet_investigation": _json_safe(investigation),
                "enrichment": _json_safe(enrichment),
            }
        )

    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_type": BUNDLE_TYPE,
        "created_at_utc": _utc_isoformat(export_time),
        "source": {
            "application": PROJECT_NAME,
            "mode": "local_data_export",
        },
        "summary": {
            "alert_count": len(records),
            "alerts_with_intelligence": intelligence_count,
            "alerts_with_packet_investigation": investigation_count,
            "alerts_with_enrichment": enrichment_count,
        },
        "evidence_note": EVIDENCE_NOTE,
        "alerts": records,
    }


def serialize_alert_bundle(
    bundle: Mapping[str, Any],
    *,
    indent: int = 2,
) -> str:
    """Serialize a bundle as readable UTF-8-compatible JSON text."""
    if not isinstance(bundle, Mapping):
        raise TypeError("bundle must be a mapping")

    if isinstance(indent, bool) or not isinstance(indent, int) or indent < 0:
        raise ValueError("indent must be a non-negative integer")

    return json.dumps(
        _json_safe(dict(bundle)),
        indent=indent,
        ensure_ascii=False,
        allow_nan=False,
    ) + "\n"
