"""Manually triggered cross-engine correlation investigations."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import json
import re

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASE_DIRECTORY = PROJECT_ROOT / "data" / "lab" / "analysis" / "correlation_cases"


def _slugify_case_name(name: str) -> str:
    """Return a safe, bounded filename slug for a case name."""
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", name.strip())
    return slug.strip("-_").lower()[:80].strip("-_")


def _bundle_evidence_for_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Return imported evidence, supporting both current and saved case rows."""
    bundle_record = alert.get("bundle_record")
    if not isinstance(bundle_record, dict):
        bundle_record = {}

    intelligence = alert.get("bundle_intelligence")
    if not isinstance(intelligence, dict):
        intelligence = bundle_record.get("intelligence")
    if not isinstance(intelligence, dict):
        intelligence = {}

    packet_investigation = alert.get("bundle_packet_investigation")
    if not isinstance(packet_investigation, dict):
        packet_investigation = bundle_record.get("packet_investigation")
    if not isinstance(packet_investigation, dict):
        packet_investigation = {}

    source_bundle = bundle_record.get("source_bundle")
    if not isinstance(source_bundle, dict):
        source_bundle = {}
    source_bundle = dict(source_bundle)

    source_bundle.setdefault("filename", alert.get("bundle_source_file"))
    source_bundle.setdefault(
        "created_at_utc", alert.get("bundle_source_created_at_utc")
    )

    original_alert = bundle_record.get("alert")
    if not isinstance(original_alert, dict):
        original_alert = {}

    return {
        "intelligence": intelligence,
        "packet_investigation": packet_investigation,
        "source_bundle": source_bundle,
        "original_alert": original_alert,
    }


def _render_manual_bundle_correlation(
    *,
    classify_alert: Callable[..., Any],
    is_security_related: Callable[..., Any],
    format_alert_timestamp_pkt: Callable[..., Any],
) -> None:
    """Import exported bundles and create an analyst-selected group."""
    from ids.alert_bundle_import import (
        MAX_SELECTED_RECORDS,
        AlertBundleImportError,
        build_manual_correlation_analysis,
        parse_alert_bundle_upload,
    )

    st.divider()
    st.subheader("Manual Correlation from Exported Bundles")
    st.caption(
        "Import JSON or ZIP bundles created by Alert Explorer, then select "
        "records to group for investigation. Imported intelligence and retained "
        "packet evidence are preserved. This workflow does not write to the live database."
    )

    uploaded_files = st.file_uploader(
        "Upload one or more Alert Explorer bundles",
        type=["json", "zip"],
        accept_multiple_files=True,
        key="manual_correlation_bundle_uploads",
        help=(
            "ZIP bundles must contain alert_bundle.json at the archive root. "
            "Each upload is size-limited and validated before use."
        ),
    )

    if st.button(
        "Import uploaded bundle(s)",
        key="import_manual_correlation_bundles",
    ):
        if not uploaded_files:
            st.session_state["manual_correlation_bundle_errors"] = [
                "Choose at least one JSON or ZIP bundle first."
            ]
        else:
            imported = []
            errors = []
            total_records = 0

            for uploaded in uploaded_files:
                try:
                    result = parse_alert_bundle_upload(
                        uploaded.name,
                        uploaded.getvalue(),
                    )
                    total_records += result["record_count"]
                    if total_records > 1000:
                        raise AlertBundleImportError(
                            "The combined import exceeds 1,000 alert records."
                        )
                    imported.append(result)
                except (AlertBundleImportError, TypeError, ValueError) as exc:
                    errors.append(f"{uploaded.name}: {exc}")

            st.session_state["manual_correlation_bundle_errors"] = errors

            if errors:
                st.session_state.pop("manual_correlation_bundles", None)
                st.session_state.pop("correlation_investigation_analysis", None)
                st.session_state.pop("correlation_investigation_loaded_case", None)
            else:
                st.session_state["manual_correlation_bundles"] = imported
                st.session_state.pop("correlation_investigation_analysis", None)
                st.session_state.pop("correlation_investigation_loaded_case", None)
                st.success(
                    f"Imported {len(imported)} bundle(s) containing "
                    f"{total_records} alert record(s)."
                )

    for message in st.session_state.get("manual_correlation_bundle_errors", []):
        st.error(message)

    imported_bundles = st.session_state.get("manual_correlation_bundles", [])
    if not imported_bundles:
        st.info(
            "Upload and import an Alert Explorer JSON/ZIP bundle to start a manual group."
        )
        return

    available_records = [
        record
        for bundle in imported_bundles
        for record in bundle.get("records", [])
    ]

    st.write("**Imported bundle sources**")
    st.dataframe(
        pd.DataFrame([
            {
                "File": bundle.get("filename"),
                "Created at": bundle.get("created_at_utc") or "Unknown",
                "Records": bundle.get("record_count", 0),
                "Source": (
                    (bundle.get("source") or {}).get("application")
                    if isinstance(bundle.get("source"), dict)
                    else "Unknown"
                ),
            }
            for bundle in imported_bundles
        ]),
        width="stretch",
        hide_index=True,
    )

    record_by_key = {
        record["record_key"]: record
        for record in available_records
    }

    def record_label(key: str) -> str:
        record = record_by_key[key]
        alert = record.get("alert") or {}
        engine = alert.get("engine") or alert.get("engine_key") or "unknown"
        alert_id = record.get("alert_id")
        message = alert.get("msg") or alert.get("rule") or "No alert message"
        return (
            f"{engine} | ID {alert_id if alert_id is not None else 'unknown'} | "
            f"{str(message)[:120]} | {record.get('source_file')}"
        )

    # Use display labels as the actual widget options. This avoids Streamlit
    # AppTest passing formatted labels where internal record keys are expected.
    label_to_key: dict[str, str] = {}
    for key in record_by_key:
        label = record_label(key)
        if label in label_to_key:
            label = f"{label} | record {key}"
        label_to_key[label] = key

    selected_labels = st.multiselect(
        f"Select records for the manual correlation group (maximum {MAX_SELECTED_RECORDS})",
        options=list(label_to_key),
        max_selections=MAX_SELECTED_RECORDS,
        key="manual_correlation_selected_record_keys",
    )
    selected_keys = [label_to_key[label] for label in selected_labels]

    group_label = st.text_input(
        "Manual correlation group name",
        key="manual_correlation_group_label",
        placeholder="Example: suspected web attack sequence",
    )

    if st.button(
        "Create manual correlation analysis",
        type="primary",
        key="create_manual_correlation_analysis",
    ):
        try:
            analysis = build_manual_correlation_analysis(
                imported_bundles,
                selected_keys,
                group_label,
                classify_alert=classify_alert,
                is_security_related=is_security_related,
                format_alert_timestamp_pkt=format_alert_timestamp_pkt,
            )
            st.session_state["correlation_investigation_analysis"] = analysis
            st.session_state.pop("correlation_investigation_loaded_case", None)
            st.success(
                f"Created manual group with {analysis['summary']['record_count']} record(s)."
            )
        except (ValueError, TypeError, KeyError) as exc:
            st.error("Could not create the manual correlation analysis.")
            st.caption(f"{type(exc).__name__}: {exc}")


def render_correlation_investigation(
    *,
    live_db_path: Path,
    load_correlation_groups: Callable[..., Any],
    load_correlation_group_alerts: Callable[..., Any],
    is_security_related: Callable[..., Any],
    classify_alert: Callable[..., Any],
    format_alert_timestamp_pkt: Callable[..., Any],
) -> None:
    st.title("🔗 Correlation Investigation")
    st.caption(
        "Choose a cross-engine group and explicitly start an analysis. "
        "Saved cases are local JSON snapshots; the live database remains read-only."
    )

    _render_manual_bundle_correlation(
        classify_alert=classify_alert,
        is_security_related=is_security_related,
        format_alert_timestamp_pkt=format_alert_timestamp_pkt,
    )

    try:
        groups = load_correlation_groups(live_db_path, limit=500)
        database_error = None
    except Exception as exc:
        groups = []
        database_error = exc

    if database_error is not None:
        st.error("Could not load correlation groups from the live database.")
        st.caption(f"{type(database_error).__name__}: {database_error}")

    group_options: dict[str, dict[str, Any]] = {}
    for group in groups:
        group_id = str(group.get("correlation_group_id") or "")
        if not group_id:
            continue
        label = (
            f"{group_id} | "
            f"{group.get('engines') or 'Unknown engines'} | "
            f"{group.get('alert_count', 0)} records | "
            f"Community ID: {group.get('community_id') or 'unavailable'}"
        )
        # Include an index to keep labels unique if a database has duplicates.
        unique_label = f"{label} [{len(group_options) + 1}]"
        group_options[unique_label] = dict(group)

    if group_options:
        selected_label = st.selectbox(
            "Cross-engine correlation group",
            list(group_options),
            key="correlation_investigation_group",
        )

        if st.button(
            "Analyze selected group",
            type="primary",
            key="analyze_selected_correlation_group",
        ):
            st.session_state.pop("correlation_investigation_analysis", None)
            st.session_state.pop("correlation_investigation_loaded_case", None)

            group = group_options[selected_label]
            group_id = str(group["correlation_group_id"])

            try:
                raw_records = load_correlation_group_alerts(
                    live_db_path,
                    group_id,
                )

                security_records = []
                for item in raw_records:
                    record = dict(item)
                    if not is_security_related(record):
                        continue
                    record["correlation_group_id"] = group_id
                    record["presentation_category"] = classify_alert(record)
                    record["timestamp_pkt"] = format_alert_timestamp_pkt(record)
                    security_records.append(record)

                security_records.sort(
                    key=lambda record: (
                        record.get("event_ts_utc")
                        if isinstance(record.get("event_ts_utc"), (int, float))
                        else -1,
                        record.get("id") or 0,
                    )
                )

                engines = sorted({
                    str(record.get("engine") or "unknown").lower()
                    for record in security_records
                })

                numeric_times = []
                for record in security_records:
                    value = record.get("event_ts_utc")
                    if isinstance(value, (int, float)):
                        numeric_times.append(value)

                first_time = (
                    format_alert_timestamp_pkt(
                        {"event_ts_utc": min(numeric_times)}
                    )
                    if numeric_times else "Unavailable"
                )
                last_time = (
                    format_alert_timestamp_pkt(
                        {"event_ts_utc": max(numeric_times)}
                    )
                    if numeric_times else "Unavailable"
                )

                analysis = {
                    "schema_version": 1,
                    "generated_at_utc": datetime.now(
                        timezone.utc
                    ).isoformat(timespec="seconds"),
                    "correlation_group_id": group_id,
                    "community_id": group.get("community_id"),
                    "summary": {
                        "security_related_record_count": len(security_records),
                        "engine_count": len(engines),
                        "engines": engines,
                        "first_event_pkt": first_time,
                        "last_event_pkt": last_time,
                    },
                    "alerts": security_records,
                }

                st.session_state["correlation_investigation_analysis"] = analysis

            except Exception as exc:
                st.error("Could not analyze the selected correlation group.")
                st.caption(f"{type(exc).__name__}: {exc}")

    elif database_error is None:
        st.info(
            "No cross-engine correlation groups are currently available. "
            "Generate comparable traffic and confirm that both IDS engines "
            "produce correlated alerts."
        )

    # Saved cases are read only when this page is opened. The folder is
    # created only after the user explicitly saves a case.
    st.divider()
    st.subheader("Saved Cases")

    saved_options: dict[str, Path] = {}
    if CASE_DIRECTORY.is_dir():
        for case_path in sorted(CASE_DIRECTORY.glob("*.json")):
            try:
                document = json.loads(case_path.read_text(encoding="utf-8"))
                case_name = str(document.get("case_name") or case_path.stem)
                created = str(document.get("created_at_utc") or "date unknown")
                label = f"{case_name} — {created} [{case_path.stem}]"
            except (OSError, ValueError, TypeError):
                label = f"Unreadable case [{case_path.stem}]"
            saved_options[label] = case_path

    if saved_options:
        saved_label = st.selectbox(
            "Select a saved case",
            ["— Select a saved case —", *saved_options],
            key="correlation_saved_case_selection",
        )
        if st.button(
            "Load selected case",
            disabled=saved_label == "— Select a saved case —",
            key="load_saved_correlation_case",
        ):
            selected_path = saved_options[saved_label]
            try:
                document = json.loads(
                    selected_path.read_text(encoding="utf-8")
                )
                analysis = document.get("analysis")
                if not isinstance(analysis, dict) or not isinstance(
                    analysis.get("alerts"), list
                ):
                    raise ValueError("Saved file has no valid analysis payload.")

                st.session_state["correlation_investigation_analysis"] = analysis
                st.session_state["correlation_investigation_loaded_case"] = {
                    "case_name": document.get("case_name") or selected_path.stem,
                    "notes": document.get("notes") or "",
                }
                st.success(f"Loaded case: {document.get('case_name') or selected_path.stem}")
            except (OSError, ValueError, TypeError) as exc:
                st.error("Could not load the saved case.")
                st.caption(f"{type(exc).__name__}: {exc}")
    else:
        st.info(
            "No named cases have been saved yet. Cases are stored as JSON files "
            "under data/lab/analysis/correlation_cases when you save them."
        )

    analysis = st.session_state.get("correlation_investigation_analysis")
    if not isinstance(analysis, dict):
        return

    loaded_case = st.session_state.get("correlation_investigation_loaded_case")
    st.divider()
    st.subheader("Analysis Results")

    if isinstance(loaded_case, dict):
        st.caption(f"Loaded saved case: {loaded_case.get('case_name', 'Unnamed')}")

    st.write(f"**Correlation group:** `{analysis.get('correlation_group_id', 'Unknown')}`")
    summary = analysis.get("summary") or {}
    alerts = analysis.get("alerts") or []

    if not alerts:
        st.info(
            "This group contains no records classified as security-related "
            "by the project's current classifier."
        )
        return

    metric_cols = st.columns(3)
    metric_cols[0].metric(
        "Security-related records",
        summary.get("security_related_record_count", len(alerts)),
    )
    metric_cols[1].metric("Engines", summary.get("engine_count", 0))
    metric_cols[2].metric(
        "Community ID",
        str(analysis.get("community_id") or "Unavailable"),
    )

    st.caption(
        f"First observed event: {summary.get('first_event_pkt', 'Unavailable')} "
        f"· Last observed event: {summary.get('last_event_pkt', 'Unavailable')}"
    )
    st.caption(
        "These are IDS alert records associated with a correlation group. "
        "Correlation does not prove that an attack succeeded."
    )

    frame = pd.DataFrame(alerts)
    visible_columns = [
        column for column in (
            "id", "timestamp_pkt", "engine", "severity",
            "presentation_category", "msg",
            "src_addr", "src_port", "dst_addr", "dst_port",
            "correlation_group_id",
        )
        if column in frame.columns
    ]
    st.dataframe(frame[visible_columns], width="stretch", hide_index=True)

    evidence_records = [
        (alert, _bundle_evidence_for_alert(alert))
        for alert in alerts
        if isinstance(alert, dict)
        and (
            alert.get("bundle_record_key")
            or alert.get("bundle_source_file")
            or isinstance(alert.get("bundle_record"), dict)
        )
    ]

    if evidence_records:
        st.markdown("#### Imported Alert Evidence")
        st.caption(
            "Evidence below was included in the imported bundle or saved case. "
            "Packet retention may be incomplete and does not prove an attack succeeded."
        )

        for alert, evidence in evidence_records:
            alert_id = alert.get("id") or alert.get("record_id") or "Unknown"
            engine = alert.get("engine") or alert.get("engine_key") or "unknown"
            message = str(alert.get("msg") or alert.get("rule") or "No alert message")
            label = f"Alert {alert_id} · {engine} · {message[:100]}"

            with st.expander(label, expanded=False):
                intelligence = evidence["intelligence"]
                if intelligence:
                    st.markdown("**Offline intelligence**")
                    st.json(intelligence)
                else:
                    st.info("No intelligence details were included for this alert.")

                investigation = evidence["packet_investigation"]
                if investigation:
                    st.markdown("**Packet investigation**")
                    packet_summary = investigation.get("packet_summary")
                    if isinstance(packet_summary, dict) and packet_summary:
                        st.json(packet_summary)

                    packets = investigation.get("packets")
                    if isinstance(packets, list) and packets:
                        packet_rows = [
                            packet for packet in packets[:100]
                            if isinstance(packet, dict)
                        ]
                        if packet_rows:
                            st.markdown(
                                f"**Retained packet records ({len(packets)})**"
                            )
                            st.dataframe(
                                pd.DataFrame(packet_rows),
                                width="stretch",
                                hide_index=True,
                            )
                        else:
                            st.json(packets[:100])

                        if len(packets) > 100:
                            st.caption(
                                f"Showing the first 100 of {len(packets)} retained "
                                "packet records here. The download exports contain "
                                "the full imported evidence."
                            )
                    else:
                        st.caption(
                            "The bundle includes packet investigation data but "
                            "no individual packet records."
                        )
                else:
                    st.info(
                        "No packet investigation details were included for this alert."
                    )

                source_bundle = evidence["source_bundle"]
                source_metadata = {
                    key: source_bundle[key]
                    for key in (
                        "filename", "created_at_utc", "source",
                        "schema_version", "evidence_note",
                    )
                    if source_bundle.get(key) is not None
                }
                if source_metadata:
                    st.markdown("**Source bundle provenance**")
                    st.json(source_metadata)

                original_alert = evidence["original_alert"]
                if original_alert:
                    st.markdown("**Original imported alert fields**")
                    st.json(original_alert)

    safe_group = _slugify_case_name(
        str(analysis.get("correlation_group_id") or "correlation")
    ) or "correlation"

    download_cols = st.columns(2)
    with download_cols[0]:
        st.download_button(
            "Download analysis JSON",
            data=json.dumps(
                analysis, indent=2, ensure_ascii=False, default=str
            ),
            file_name=f"correlation-{safe_group}.json",
            mime="application/json",
            key="download_correlation_json",
        )
    with download_cols[1]:
        st.download_button(
            "Download alerts CSV",
            data=frame.to_csv(index=False).encode("utf-8"),
            file_name=f"correlation-{safe_group}-alerts.csv",
            mime="text/csv",
            key="download_correlation_csv",
        )

    st.markdown("#### Save a Named Case")
    case_name = st.text_input(
        "Case name",
        key="correlation_case_name",
        placeholder="Example: SSH scan against target",
    )
    case_notes = st.text_area(
        "Investigator notes (optional)",
        key="correlation_case_notes",
    )

    if st.button("Save case", key="save_named_correlation_case"):
        normalized_name = case_name.strip()
        slug = _slugify_case_name(normalized_name)

        if not normalized_name or not slug:
            st.error(
                "Enter a case name containing at least one letter or number."
            )
        else:
            try:
                CASE_DIRECTORY.mkdir(parents=True, exist_ok=True)
                target = CASE_DIRECTORY / f"{slug}.json"

                case_document = {
                    "schema_version": 1,
                    "case_name": normalized_name,
                    "created_at_utc": datetime.now(
                        timezone.utc
                    ).isoformat(timespec="seconds"),
                    "notes": case_notes.strip(),
                    "analysis": analysis,
                }

                # Exclusive creation prevents accidental overwriting.
                with target.open("x", encoding="utf-8") as handle:
                    json.dump(
                        case_document,
                        handle,
                        indent=2,
                        ensure_ascii=False,
                        default=str,
                    )
                    handle.write("\n")

                st.success(f"Saved case to {target.relative_to(PROJECT_ROOT)}")
            except FileExistsError:
                st.error(
                    "A case with that filename already exists. Choose a "
                    "different name; existing cases are never overwritten."
                )
            except OSError as exc:
                st.error("The case could not be saved.")
                st.caption(f"{type(exc).__name__}: {exc}")
