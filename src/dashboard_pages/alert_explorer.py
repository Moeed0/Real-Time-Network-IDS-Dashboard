"""Alert Explorer page."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
import html
import json

import pandas as pd
import streamlit as st

from ids.alert_classification import classify_alert
from ids.alert_filtering import TIME_WINDOW_OPTIONS, filter_alert_records_by_time
from ids.live_alert_view import adapt_live_alert
from ids.alert_details import (
    build_non_repeating_normalized_record,
    load_alert_native_event,
)
from ids.alert_enrichment import build_alert_enrichment


def _render_offline_intelligence_search() -> None:
    """Search local vulnerability and ATT&CK data without network access."""
    from ids.offline_intelligence import (
        get_cve_record,
        get_epss_record,
        get_kev_record,
        get_source_metadata,
        search_attack_techniques,
        search_cves,
    )

    st.divider()
    st.subheader("Offline Intelligence Search")
    st.caption(
        "Search locally imported NVD, EPSS, CISA KEV and MITRE ATT&CK data. "
        "Searches use the local SQLite database only; no external lookup is made."
    )

    cve_tab, attack_tab = st.tabs(
        ["CVE / Vulnerability Search", "MITRE ATT&CK Search"]
    )

    with cve_tab:
        with st.form("offline_cve_search_form"):
            cve_query = st.text_input(
                "CVE ID or description keywords",
                placeholder="e.g. CVE-2021-44228 or remote code execution",
                key="offline_cve_query",
            )
            cve_submitted = st.form_submit_button("Search local CVE database")

        if cve_submitted:
            st.session_state["offline_cve_results"] = []
            st.session_state["offline_cve_error"] = ""
            st.session_state["offline_cve_searched"] = True

            if not cve_query.strip():
                st.session_state["offline_cve_error"] = (
                    "Enter a CVE ID or description keyword."
                )
            else:
                try:
                    st.session_state["offline_cve_results"] = search_cves(
                        cve_query.strip(),
                        limit=25,
                    )
                except Exception as exc:
                    st.session_state["offline_cve_error"] = (
                        f"{type(exc).__name__}: {exc}"
                    )

        cve_error = st.session_state.get("offline_cve_error", "")
        cve_results = st.session_state.get("offline_cve_results", [])

        if cve_error:
            st.error(f"CVE search failed: {cve_error}")
        elif st.session_state.get("offline_cve_searched") and not cve_results:
            st.info("No matching CVEs were found in the local database.")

        if cve_results:
            st.caption(f"Found {len(cve_results)} matching CVE record(s).")
            cve_by_id = {
                str(item.get("cve_id", "")): item
                for item in cve_results
                if item.get("cve_id")
            }

            selected_cve = st.selectbox(
                "Select a CVE result",
                options=list(cve_by_id),
                format_func=lambda value: (
                    f"{value} — "
                    f"{str(cve_by_id[value].get('description', ''))[:100]}"
                ),
                key="offline_selected_cve",
            )
            search_hit = cve_by_id[selected_cve]
            st.write(search_hit.get("description", "No description available."))

            nvd = get_cve_record(selected_cve) or {}
            epss = get_epss_record(selected_cve) or {}
            kev = get_kev_record(selected_cve)

            cvss = nvd.get("cvss")
            if isinstance(cvss, dict):
                cvss_score = cvss.get("score", cvss.get("base_score"))
                cvss_severity = (cvss.get("severity") or cvss.get("base_severity") or nvd.get("severity"))
            else:
                cvss_score = cvss
                cvss_severity = nvd.get("severity")

            epss_score = (epss.get("score") if epss.get("score") is not None else epss.get("epss"))
            try:
                epss_number = float(epss_score) if epss_score is not None else None
            except (TypeError, ValueError):
                epss_number = None

            if epss_number is None:
                epss_display = "N/A"
            elif 0 <= epss_number <= 1:
                epss_display = f"{epss_number:.5f} ({epss_number:.3%})"
            else:
                epss_display = str(epss_score)

            metrics = st.columns(4)
            metrics[0].metric(
                "CVSS score",
                str(cvss_score) if cvss_score is not None else "N/A",
            )
            metrics[1].metric(
                "CVSS severity",
                str(cvss_severity) if cvss_severity else "N/A",
            )
            metrics[2].metric("EPSS probability", epss_display)
            metrics[3].metric("Listed in CISA KEV", "Yes" if kev else "No")

            with st.expander("Local NVD record"):
                if nvd:
                    st.json(nvd)
                else:
                    st.info("No NVD record is available for this CVE.")

            with st.expander("Local EPSS record"):
                if epss:
                    st.json(epss)
                else:
                    st.info("No EPSS score is available for this CVE.")

            with st.expander("Local CISA KEV record"):
                if kev:
                    st.json(kev)
                else:
                    st.info("This CVE was not found in the imported CISA KEV catalog.")

    with attack_tab:
        with st.form("offline_attack_search_form"):
            attack_query = st.text_input(
                "ATT&CK technique ID, name or keywords",
                placeholder="e.g. T1059 or command and scripting interpreter",
                key="offline_attack_query",
            )
            attack_submitted = st.form_submit_button(
                "Search local ATT&CK database"
            )

        if attack_submitted:
            st.session_state["offline_attack_results"] = []
            st.session_state["offline_attack_error"] = ""
            st.session_state["offline_attack_searched"] = True

            if not attack_query.strip():
                st.session_state["offline_attack_error"] = (
                    "Enter a technique ID or search term."
                )
            else:
                try:
                    st.session_state["offline_attack_results"] = (
                        search_attack_techniques(
                            attack_query.strip(),
                            limit=25,
                        )
                    )
                except Exception as exc:
                    st.session_state["offline_attack_error"] = (
                        f"{type(exc).__name__}: {exc}"
                    )

        attack_error = st.session_state.get("offline_attack_error", "")
        attack_results = st.session_state.get("offline_attack_results", [])

        if attack_error:
            st.error(f"ATT&CK search failed: {attack_error}")
        elif (
            st.session_state.get("offline_attack_searched")
            and not attack_results
        ):
            st.info("No matching ATT&CK techniques were found locally.")

        if attack_results:
            st.caption(
                f"Found {len(attack_results)} matching ATT&CK technique(s)."
            )
            technique_by_id = {
                str(item.get("technique_id", "")): item
                for item in attack_results
                if item.get("technique_id")
            }

            selected_technique = st.selectbox(
                "Select an ATT&CK technique",
                options=list(technique_by_id),
                format_func=lambda value: (
                    f"{value} — "
                    f"{technique_by_id[value].get('name', 'Unnamed technique')}"
                ),
                key="offline_selected_technique",
            )
            technique = technique_by_id[selected_technique]
            st.markdown(
                f"**Technique ID:** {selected_technique}\n\n"
                f"**Name:** {technique.get('name', 'Unknown')}"
            )
            st.write(
                technique.get("description", "No description available.")
            )

    with st.expander("Imported source metadata and dates"):
        try:
            st.json(get_source_metadata())
        except Exception as exc:
            st.error(f"Could not read local source metadata: {exc}")


def _render_alert_bundle_export(
    *,
    filtered_alert_df: pd.DataFrame,
    alerts: list[dict[str, Any]],
    selected_id: Any,
    get_live_intelligence: Callable[..., Any],
    live_db_path: Path,
    load_alert_investigation: Callable[..., Any],
) -> None:
    """Offer in-memory JSON and ZIP exports for selected alert records."""
    from datetime import datetime, timezone

    from ids.alert_bundle import (
        build_individual_alert_document,
        build_individual_alert_zip,
        individual_alert_filename,
        serialize_individual_alert_document,
    )

    st.divider()
    st.subheader("Export Selected Alert Bundle")
    st.caption(
        "Export each selected alert as its own JSON document. A single alert "
        "downloads as one JSON file; multiple alerts download as a ZIP "
        "containing one JSON file per alert. Packet investigation is optional. "
        "Exports are assembled in memory; project files and the live database "
        "are not modified."
    )

    if "Record ID" not in filtered_alert_df.columns:
        st.warning("The filtered alert table has no Record ID column.")
        return

    available_ids = list(dict.fromkeys(
        value
        for value in filtered_alert_df["Record ID"].tolist()
        if value is not None and str(value).lower() != "nan"
    ))
    if not available_ids:
        st.info("There are no alert records available for export.")
        return

    default_id = next(
        (value for value in available_ids if str(value) == str(selected_id)),
        available_ids[0],
    )

    selected_ids = st.multiselect(
        "Alerts to include (maximum 10)",
        options=available_ids,
        default=[default_id],
        max_selections=10,
        key="alert_bundle_selected_ids",
    )
    include_packets = st.checkbox(
        "Include retained packet and flow investigation results",
        value=False,
        key="alert_bundle_include_packets",
        help=(
            "Packet results are observations retained by the passive collector, "
            "not a guaranteed complete capture."
        ),
    )

    st.caption(
        "Each selected alert receives its own offline intelligence lookup. "
        "Enable packet evidence only when you need the additional flow details."
    )

    if st.button("Prepare individual alert JSON files", key="build_selected_alert_bundle"):
        if not selected_ids:
            st.warning("Select at least one alert to export.")
        else:
            wanted = [str(value) for value in selected_ids]
            alert_lookup: dict[str, dict[str, Any]] = {}

            for record in alerts:
                identifier = record.get("record_id")
                if identifier is None:
                    identifier = record.get("id")
                if identifier is not None:
                    alert_lookup.setdefault(str(identifier), record)

            chosen_alerts = [
                alert_lookup[identifier]
                for identifier in wanted
                if identifier in alert_lookup
            ]
            missing = [
                identifier for identifier in wanted
                if identifier not in alert_lookup
            ]
            failures: list[str] = []

            if missing:
                failures.append(
                    "Alert records not found in the current in-memory list: "
                    + ", ".join(missing)
                )

            intelligence_by_id: dict[Any, Any] = {}
            investigations_by_id: dict[Any, Any] = {}
            native_events_by_id: dict[Any, Any] = {}
            enrichment_by_id: dict[Any, Any] = {}

            for record in chosen_alerts:
                identifier = record.get("record_id")
                if identifier is None:
                    identifier = record.get("id")
                if identifier is None:
                    failures.append(
                        "An alert without a stable ID was skipped for attachments."
                    )
                    continue

                intelligence_alert = dict(record)
                intelligence_alert["engine"] = (
                    record.get("engine_key") or record.get("engine")
                )

                try:
                    context, _ = get_live_intelligence(intelligence_alert)
                    intelligence_by_id[identifier] = context
                except Exception as exc:
                    failures.append(
                        f"Alert {identifier}: intelligence lookup failed "
                        f"({type(exc).__name__}: {exc})"
                    )

                # Retrieve the source event read-only and verify that it
                # belongs to this exact database alert and engine.
                try:
                    database_id = int(identifier)
                    native_record = load_alert_native_event(
                        live_db_path, database_id
                    )

                    if native_record is None:
                        failures.append(
                            f"Alert {identifier}: no stored native event record was found."
                        )
                    else:
                        expected_engine = str(
                            record.get("engine_key") or record.get("engine") or ""
                        ).strip().lower()
                        stored_engine = str(
                            native_record.get("engine") or ""
                        ).strip().lower()

                        if (
                            str(native_record.get("id")) != str(database_id)
                            or not expected_engine
                            or stored_engine != expected_engine
                        ):
                            failures.append(
                                f"Alert {identifier}: stored native event did not "
                                "match the selected alert and was not attached."
                            )
                        else:
                            raw_payload = native_record.get("raw_json")
                            if not isinstance(raw_payload, str) or not raw_payload.strip():
                                failures.append(
                                    f"Alert {identifier}: no original native payload "
                                    "is stored."
                                )
                            else:
                                try:
                                    parsed_payload = json.loads(raw_payload)
                                except (json.JSONDecodeError, TypeError, ValueError):
                                    # Preserve malformed source text, but do not
                                    # pretend it is structured event data.
                                    native_events_by_id[identifier] = raw_payload
                                    failures.append(
                                        f"Alert {identifier}: native payload was "
                                        "preserved as text because it is not valid JSON."
                                    )
                                else:
                                    native_events_by_id[identifier] = (
                                        parsed_payload
                                        if isinstance(parsed_payload, dict)
                                        else raw_payload
                                    )

                except (TypeError, ValueError, OverflowError):
                    failures.append(
                        f"Alert {identifier}: invalid database ID; native event "
                        "was not attached."
                    )
                except Exception as exc:
                    failures.append(
                        f"Alert {identifier}: native-event lookup failed "
                        f"({type(exc).__name__}: {exc})"
                    )

                if include_packets:
                    try:
                        database_id = int(identifier)
                        investigation = load_alert_investigation(
                            live_db_path,
                            database_id,
                        )
                        if investigation is not None:
                            investigations_by_id[identifier] = investigation
                        else:
                            failures.append(
                                f"Alert {identifier}: no live investigation record found."
                            )
                    except (TypeError, ValueError, OverflowError):
                        failures.append(
                            f"Alert {identifier}: ID is not a valid live database ID; "
                            "packet investigation was skipped."
                        )
                    except Exception as exc:
                        failures.append(
                            f"Alert {identifier}: packet investigation failed "
                            f"({type(exc).__name__}: {exc})"
                        )

                try:
                    enrichment_input = dict(intelligence_alert)
                    native_event = native_events_by_id.get(identifier)
                    if native_event is not None:
                        # Use only a verified event for the canonical analysis.
                        # Do not mutate the original alert record being exported.
                        enrichment_input.pop("raw_json", None)
                        enrichment_input["native_event"] = native_event

                    enrichment_by_id[identifier] = build_alert_enrichment(
                        enrichment_input,
                        intelligence_by_id.get(identifier),
                        investigations_by_id.get(identifier),
                    )
                except Exception as exc:
                    failures.append(
                        f"Alert {identifier}: canonical enrichment failed "
                        f"({type(exc).__name__}: {exc})"
                    )

            if not chosen_alerts:
                st.error(
                    "No selected alert records were available to export. "
                    "Refresh the page and select the alerts again."
                )
            else:
                export_time = datetime.now(timezone.utc)
                individual_documents: list[tuple[str, str]] = []

                for index, record in enumerate(chosen_alerts, start=1):
                    identifier = record.get("record_id")
                    if identifier is None:
                        identifier = record.get("id", record.get("alert_id"))

                    document = build_individual_alert_document(
                        record,
                        enrichment=enrichment_by_id.get(identifier),
                        native_event=native_events_by_id.get(identifier),
                        investigation=investigations_by_id.get(identifier),
                        created_at=export_time,
                    )
                    filename = individual_alert_filename(
                        record,
                        sequence=index if len(chosen_alerts) > 1 else None,
                    )
                    document_text = serialize_individual_alert_document(document)
                    individual_documents.append((filename, document_text))

                export_stamp = export_time.strftime("%Y%m%dT%H%M%SZ")
                filename_base = f"ids-alerts-{export_stamp}"

                # The archive contains only the individual JSON files.
                zip_bytes = build_individual_alert_zip(
                    dict(individual_documents)
                )

                st.session_state["alert_individual_export_payload"] = {
                    "selected_ids": [str(value) for value in selected_ids],
                    "include_packets": include_packets,
                    "json_text": (
                        individual_documents[0][1]
                        if len(individual_documents) == 1
                        else None
                    ),
                    "files": [filename for filename, _ in individual_documents],
                    "zip_bytes": zip_bytes,
                    "filename_base": filename_base,
                    "failures": failures,
                }

                if len(individual_documents) == 1:
                    st.success(
                        "Prepared an individual JSON file for alert "
                        f"{individual_documents[0][0]}."
                    )
                else:
                    st.success(
                        f"Prepared {len(individual_documents)} individual "
                        "JSON files in one ZIP archive."
                    )

    payload = st.session_state.get("alert_individual_export_payload")
    selection_matches = (
        isinstance(payload, dict)
        and payload.get("selected_ids") == [str(value) for value in selected_ids]
        and payload.get("include_packets") == include_packets
    )

    if selection_matches:
        if payload.get("json_text") is not None:
            st.download_button(
                "Download alert JSON",
                data=payload["json_text"],
                file_name=payload["files"][0],
                mime="application/json",
                key="download_individual_alert_json",
            )
        else:
            st.caption(
                "The ZIP contains one separate JSON file per selected alert. "
                "It does not contain a combined alert array or a README file."
            )
            st.download_button(
                f"Download {len(payload['files'])} individual JSON files (ZIP)",
                data=payload["zip_bytes"],
                file_name=f"{payload['filename_base']}.zip",
                mime="application/zip",
                key="download_individual_alerts_zip",
            )

        for failure in payload.get("failures", [])[:5]:
            st.warning(failure)
        remaining = len(payload.get("failures", [])) - 5
        if remaining > 0:
            st.caption(f"{remaining} additional attachment issue(s) were omitted here.")


def render_alert_explorer(
    *,
    alerts: list[dict[str, Any]],
    alert_df: pd.DataFrame,
    alert_engine: Callable[..., Any],
    alert_message: Callable[..., Any],
    alert_sid: Callable[..., Any],
    alert_gid: Callable[..., Any],
    alert_revision: Callable[..., Any],
    alert_protocol: Callable[..., Any],
    alert_service: Callable[..., Any],
    known_exploited: Callable[..., Any],
    get_live_intelligence: Callable[..., Any],
    live_db_path: Path,
    load_alert_investigation: Callable[..., Any],
    format_alert_timestamp_pkt: Callable[..., Any],
    alert_unified_severity: Callable[..., Any],
    safe_dict: Callable[..., Any],
) -> None:
    requested_alert_id = st.session_state.get(
        "alert_explorer_requested_alert_id"
    )
    if requested_alert_id is not None:
        requested_record = next(
            (
                record for record in alerts
                if str(record.get("record_id", record.get("id")))
                == str(requested_alert_id)
            ),
            None,
        )
        if (
            requested_record is not None
            and not filter_alert_records_by_time(
                [requested_record],
                "Last 24 hours",
            )
        ):
            # Explicit navigation to an older alert must not be hidden
            # by the default time filter.
            st.session_state["alert_explorer_time_window"] = "All retained"

        if (
            requested_record is not None
            and classify_alert(requested_record) == "NETWORK_EVENT"
        ):
            # Explicit navigation should also reveal the requested routine
            # or unclassified event, even when the default view hides it.
            st.session_state["alert_explorer_include_routine"] = True

        st.session_state.pop("alert_explorer_requested_alert_id", None)
        st.session_state["alert_explorer_engine_filter"] = []
        st.session_state["alert_explorer_search_text"] = ""

    st.title(
        "Alert Explorer"
    )

    st.markdown(
        """
        Search and inspect individual Snort and Suricata alert
        records. The complete native event remains available.
        """
    )

    _render_offline_intelligence_search()

    filter_cols = st.columns(3)

    engine_filter = filter_cols[0].multiselect(
        "Engine",
        sorted(
            alert_df["Engine"]
            .dropna()
            .unique()
        ),
        key="alert_explorer_engine_filter",
    )

    time_window = filter_cols[1].selectbox(
        "Event time range",
        TIME_WINDOW_OPTIONS,
        index=0,
        key="alert_explorer_time_window",
    )

    include_routine = filter_cols[2].checkbox(
        "Include routine / unclassified network events",
        value=False,
        key="alert_explorer_include_routine",
        help=(
            "When disabled, records classified as network events are omitted "
            "from this view. Their stored records are not changed or deleted."
        ),
    )

    search_text = st.text_input(
        "Search alert / SID / message",
        key="alert_explorer_search_text",
    )
    st.caption(
        "The alert list uses lightweight fields. Use Offline Intelligence Search "
        "above for local CVE and MITRE ATT&CK lookups; per-alert enrichment "
        "is loaded when you inspect a record."
    )

    time_filtered_alerts = filter_alert_records_by_time(alerts, time_window)
    if not include_routine:
        time_filtered_alerts = [
            record for record in time_filtered_alerts
            if classify_alert(record) != "NETWORK_EVENT"
        ]

    eligible_ids = {
        str(record.get("record_id", record.get("id")))
        for record in time_filtered_alerts
        if record.get("record_id", record.get("id")) is not None
    }

    filtered = alert_df[
        alert_df["Record ID"].astype(str).isin(eligible_ids)
    ].copy()

    if engine_filter:
        filtered = filtered[
            filtered["Engine"].isin(engine_filter)
        ]

    if search_text.strip():
        query = search_text.strip().lower()
        mask = (
            filtered.astype(str)
            .apply(
                lambda column: column.str.lower().str.contains(
                    query,
                    regex=False,
                    na=False,
                )
            )
            .any(axis=1)
        )
        filtered = filtered[mask]

    if filtered.empty:
        st.write(
            f"Showing 0 matching alerts out of {len(alert_df):,} retained records."
        )
        st.info("No alerts match the selected time range and filters.")
        st.stop()

    rows_per_page = st.selectbox(
        "Rows per page",
        [10, 25, 50, 100, 250],
        index=2,
        key="alert_explorer_page_size",
    )

    page_key = "alert_explorer_page"
    filter_signature = (
        tuple(engine_filter),
        time_window,
        bool(include_routine),
        search_text,
        int(rows_per_page),
    )

    if st.session_state.get("_alert_explorer_filter_signature") != filter_signature:
        st.session_state["_alert_explorer_filter_signature"] = filter_signature
        st.session_state[page_key] = 1

    total_pages = max(
        1,
        (len(filtered) + int(rows_per_page) - 1) // int(rows_per_page),
    )

    if requested_alert_id is not None:
        requested_row_index = next(
            (
                index
                for index, value in enumerate(filtered["Record ID"].tolist())
                if str(value) == str(requested_alert_id)
            ),
            None,
        )
        if requested_row_index is not None:
            st.session_state[page_key] = (
                requested_row_index // int(rows_per_page)
            ) + 1

    current_page = st.session_state.get(page_key, 1)
    if (
        isinstance(current_page, bool)
        or not isinstance(current_page, int)
        or current_page < 1
        or current_page > total_pages
    ):
        st.session_state[page_key] = 1

    page_column, count_column = st.columns([1, 4])
    with page_column:
        page_number = st.number_input(
            "Page",
            min_value=1,
            max_value=total_pages,
            step=1,
            key=page_key,
        )

    start_index = (int(page_number) - 1) * int(rows_per_page)
    end_index = min(start_index + int(rows_per_page), len(filtered))
    visible_filtered = filtered.iloc[start_index:end_index].copy()

    with count_column:
        st.caption(
            f"Showing rows {start_index + 1:,}–{end_index:,} of "
            f"{len(filtered):,} matching alerts, out of "
            f"{len(alert_df):,} retained records. Time range: {time_window}."
        )

    st.dataframe(
        visible_filtered,
        width="stretch",
        hide_index=True,
    )

    st.subheader(
        "Inspect Alert"
    )

    # Keep selector options limited to the visible page, not all retained rows.
    available_record_ids = visible_filtered["Record ID"].tolist()

    if requested_alert_id is not None:
        requested_match = next(
            (
                value for value in available_record_ids
                if str(value) == str(requested_alert_id)
            ),
            None,
        )
        if requested_match is None:
            st.warning(
                f"Live alert ID {requested_alert_id} is not present in the "
                "currently loaded Alert Explorer dataset."
            )
        else:
            st.session_state["alert_explorer_selected_record"] = requested_match

    current_record_id = st.session_state.get("alert_explorer_selected_record")
    if not any(
        str(value) == str(current_record_id)
        for value in available_record_ids
    ):
        st.session_state["alert_explorer_selected_record"] = (
            available_record_ids[0]
        )

    selected_id = st.selectbox(
        "Select alert record",
        available_record_ids,
        key="alert_explorer_selected_record",
    )

    selected = next(
        (
            record
            for record in alerts
            if str(record.get("record_id", record.get("id"))) == str(selected_id)
        ),
        None,
    )

    if selected is None:
        st.error(
            "Selected alert record was not found."
        )
        st.stop()

    intelligence_alert = dict(selected)
    intelligence_alert["engine"] = (
        selected.get("engine_key") or selected.get("engine")
    )
    selected_identity = (
        str(selected_id),
        str(intelligence_alert.get("engine") or ""),
        str(selected.get("gid") or ""),
        str(selected.get("sid") or ""),
    )

    cached_selection = st.session_state.get(
        "_alert_explorer_selected_intelligence"
    )
    if (
        isinstance(cached_selection, dict)
        and cached_selection.get("identity") == selected_identity
    ):
        intelligence = safe_dict(cached_selection.get("intelligence"))
        intelligence_from_cache = bool(
            cached_selection.get("from_cache", False)
        )
        intelligence_error = str(cached_selection.get("error") or "")
    else:
        intelligence_error = ""
        try:
            intelligence, intelligence_from_cache = get_live_intelligence(
                intelligence_alert
            )
            intelligence = safe_dict(intelligence)
        except Exception as exc:
            intelligence = {}
            intelligence_from_cache = False
            intelligence_error = f"{type(exc).__name__}: {exc}"

        st.session_state["_alert_explorer_selected_intelligence"] = {
            "identity": selected_identity,
            "intelligence": intelligence,
            "from_cache": intelligence_from_cache,
            "error": intelligence_error,
        }

    selected = adapt_live_alert(
        selected,
        intelligence,
        intelligence_loaded=not bool(intelligence_error),
    )

    _render_alert_bundle_export(
        filtered_alert_df=visible_filtered,
        alerts=alerts,
        selected_id=selected_id,
        get_live_intelligence=get_live_intelligence,
        live_db_path=live_db_path,
        load_alert_investigation=load_alert_investigation,
    )

    st.markdown(
        f"""
        <div class="success-card">
        <strong>{html.escape(str(selected_id))}</strong><br>
        {html.escape(str(alert_engine(selected)))} —
        {html.escape(str(alert_message(selected)))}
        </div>
        """,
        unsafe_allow_html=True,
    )

    top_columns = st.columns(7)

    quick_values = [
        ("Engine", alert_engine(selected)),
        ("SID", alert_sid(selected)),
        ("GID", alert_gid(selected)),
        ("Rev", alert_revision(selected)),
        ("Protocol", alert_protocol(selected)),
        ("Service", alert_service(selected)),
        (
            "CISA KEV",
            "Yes"
            if known_exploited(selected)
            else "No",
        ),
    ]

    for column, (
        label,
        value,
    ) in zip(
        top_columns,
        quick_values,
    ):
        with column:
            st.metric(
                label,
                value if value not in (
                    None,
                    "",
                ) else "—",
            )

    selected_investigation: dict[str, Any] | None = None

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "Observed Evidence",
            "Alert Intelligence",
            "Native Data",
            "Live Investigation",
            "Alert Enrichment",
        ]
    )

    with tab1:
        context = safe_dict(selected.get("security_context"))
        evidence = safe_dict(context.get("observed_lab_evidence"))
        st.json(evidence)

    with tab2:
        st.subheader("Selected Alert Intelligence")
        st.caption(
            "Rule analysis, project documentation, vulnerability context, "
            "MITRE ATT&CK references, and source provenance for this alert."
        )

        if intelligence_error:
            st.error("Could not retrieve intelligence for this alert.")
            st.caption(intelligence_error)

        base = safe_dict(intelligence.get("base_intelligence"))
        rule = safe_dict(base.get("rule"))
        documentation = safe_dict(base.get("documentation"))
        explanation = safe_dict(intelligence.get("explanation"))
        identifiers = safe_dict(intelligence.get("identifiers"))

        if intelligence.get("lookup_mode") == "offline_local":
            st.caption(
                "Source status: local offline intelligence database "
                "(no external lookup)"
            )
        elif intelligence_from_cache:
            st.caption("Source status: cached local intelligence")
        elif intelligence:
            st.caption("Source status: generated for the selected alert")
        else:
            st.caption("Source status: intelligence unavailable")

        if intelligence:
            if intelligence.get("retrieved_at"):
                st.caption(
                    f"Retrieved at: {intelligence['retrieved_at']}"
                )

            st.markdown("#### Rule")

            rule_message = (
                rule.get("msg")
                or selected.get("msg")
                or selected.get("rule")
                or "No rule message recorded"
            )
            st.write(f"**Message:** {rule_message}")

            rule_cols = st.columns(4)
            rule_cols[0].metric("GID", str(rule.get("gid", alert_gid(selected)) or "—"))
            rule_cols[1].metric("SID", str(rule.get("sid", alert_sid(selected)) or "—"))
            rule_cols[2].metric("Revision", str(rule.get("rev", alert_revision(selected)) or "—"))
            rule_cols[3].metric(
                "Severity",
                str(selected.get("severity") if selected.get("severity") is not None else "Unknown"),
            )

            if base.get("rule_context_found"):
                st.success("Matching IDS rule found.")
            else:
                st.info("No matching rule context was found.")

            detail_cols = st.columns(2)
            with detail_cols[0]:
                st.markdown("**Classification**")
                st.write(
                    rule.get("classtype")
                    or selected.get("classification")
                    or "Not available"
                )
                st.markdown("**Protocol / Service**")
                st.write(
                    f"{rule.get('protocol') or selected.get('protocol') or 'Unknown'}"
                    f" / {rule.get('service') or selected.get('service') or 'Unknown'}"
                )

            with detail_cols[1]:
                st.markdown("**Rule source**")
                st.write(rule.get("source_file") or "Not available")
                st.markdown("**Source line**")
                st.write(rule.get("source_line") or "Not available")

            st.markdown("#### Security Alert Analysis")
            source_labels = {
                "vendor_documentation": "Vendor rule documentation",
                "rule_fields": "IDS rule fields (fallback explanation)",
            }
            explanation_source = explanation.get("explanation_source")
            st.caption(
                "Explanation source: "
                + source_labels.get(
                    explanation_source,
                    "Source not explicitly identified",
                )
            )

            explanation_fields = [
                ("What happened", "what_happened"),
                ("Why the rule triggered", "why_triggered"),
                ("What it means", "what_it_means"),
                ("Known usage", "known_usage"),
            ]
            explanation_shown = False
            for heading, key in explanation_fields:
                value = explanation.get(key)
                if value is None or value == "" or value == [] or value == {}:
                    continue
                explanation_shown = True
                st.markdown(f"**{heading}**")
                if isinstance(value, (dict, list)):
                    st.json(value)
                else:
                    st.write(value)

            actions = (
                explanation.get("recommended_actions")
                or explanation.get("action_items")
                or explanation.get("actions")
            )
            if actions:
                st.markdown("**Recommended actions**")
                if isinstance(actions, list):
                    for action in actions:
                        st.write(f"- {action}")
                elif isinstance(actions, dict):
                    st.json(actions)
                else:
                    st.write(actions)

            if not explanation_shown:
                st.info(
                    "No detailed explanation is available for this rule."
                )

            st.markdown("#### Project Rule Documentation")
            documentation_fields = [
                ("Rule explanation", "rule_explanation"),
                ("What to look for", "what_to_look_for"),
                ("Known usage", "known_usage"),
                ("False positives", "false_positives"),
                ("Vulnerability / impact", "rule_vulnerability"),
                ("Summary", "summary"),
            ]
            documentation_shown = False
            for heading, key in documentation_fields:
                value = documentation.get(key)
                if value is None or value == "" or value == [] or value == {}:
                    continue
                documentation_shown = True
                st.markdown(f"**{heading}**")
                if isinstance(value, (dict, list)):
                    st.json(value)
                else:
                    st.write(value)

            if documentation_shown:
                st.success("Project rule documentation is available.")
            else:
                st.info("No detailed project documentation was found.")

            cves = identifiers.get("cves") or []
            mitre_ids = identifiers.get("mitre_attack") or []

            if isinstance(cves, str):
                cves = [cves] if cves else []
            elif isinstance(cves, dict):
                cves = list(cves.keys())
            elif not isinstance(cves, (list, tuple, set)):
                cves = []

            if isinstance(mitre_ids, str):
                mitre_ids = [mitre_ids] if mitre_ids else []
            elif isinstance(mitre_ids, dict):
                mitre_ids = list(mitre_ids.keys())
            elif not isinstance(mitre_ids, (list, tuple, set)):
                mitre_ids = []

            st.markdown("#### Security References")
            ref_cols = st.columns(2)

            with ref_cols[0]:
                st.markdown("**CVE references**")
                if cves:
                    for cve in cves:
                        st.write(f"- {cve}")
                else:
                    st.write("None recorded")

            with ref_cols[1]:
                st.markdown("**MITRE ATT&CK references**")
                if mitre_ids:
                    for technique in mitre_ids:
                        st.write(f"- {technique}")
                else:
                    st.write("None recorded")

            vulnerabilities = intelligence.get("vulnerabilities")
            if vulnerabilities not in (None, {}, []):
                from ids.vulnerability_summary import (
                    summarize_vulnerability_intelligence,
                )

                with st.expander("Vulnerability Intelligence", expanded=False):
                    summary_rows = summarize_vulnerability_intelligence(
                        vulnerabilities,
                        risk_context=intelligence.get("risk_context"),
                    )
                    if summary_rows:
                        st.caption(
                            f"{len(summary_rows)} CVE record(s). "
                            "Long descriptions, reference lists, and affected-"
                            "product configurations are omitted from this summary."
                        )
                        st.dataframe(
                            summary_rows,
                            hide_index=True,
                            use_container_width=True,
                        )
                    else:
                        st.caption(
                            "No recognizable CVE summary fields were found. "
                            "Open Complete Intelligence Result for the full data."
                        )
            else:
                st.caption(
                    "No vulnerability enrichment is recorded. This does not "
                    "prove that a vulnerability is absent."
                )

            for heading, key in [
                ("Risk Context", "risk_context"),
                ("MITRE Enrichment", "mitre_enrichment"),
                ("Intelligence Sources", "sources"),
                ("External References", "references"),
                ("Source Data As Of", "data_as_of"),
            ]:
                value = intelligence.get(key)
                if value is None or value == {} or value == [] or value == "":
                    continue
                with st.expander(heading, expanded=False):
                    if isinstance(value, (dict, list)):
                        st.json(value)
                    else:
                        st.write(value)

            if base.get("sources"):
                with st.expander("Rule Data Sources", expanded=False):
                    st.json(base["sources"])

            with st.expander("Complete Intelligence Result", expanded=False):
                st.json(intelligence)

        else:
            st.info(
                "This alert currently has no usable intelligence result. "
                "The raw event and observed evidence remain available in "
                "the other tabs."
            )

    with tab3:
        import json

        st.subheader("Original Native Event")
        st.caption(
            "Original source payload for the selected IDS engine. "
            "This evidence is kept intact and is not merged with the other engine."
        )

        native_event_record = None
        selected_database_id = None

        try:
            selected_database_id = int(
                selected.get("record_id") or selected.get("id")
            )
            native_event_record = load_alert_native_event(
                live_db_path,
                selected_database_id,
            )
        except (TypeError, ValueError, OverflowError):
            st.error("The selected alert does not have a valid database ID.")
        except Exception:
            st.error("The original IDS event could not be loaded.")

        native_payload = None
        raw_payload = None

        if native_event_record is None:
            st.warning(
                "No stored original payload was found. "
                "Only normalized fields can be shown for this record."
            )
        else:
            expected_engine = str(
                selected.get("engine_key") or selected.get("engine") or ""
            ).strip().lower()
            stored_engine = str(
                native_event_record.get("engine") or ""
            ).strip().lower()
            stored_id = native_event_record.get("id")

            if (
                str(stored_id) != str(selected_database_id)
                or stored_engine != expected_engine
            ):
                st.error(
                    "The stored event does not match the selected alert. "
                    "The source payload will not be displayed."
                )
                native_event_record = None
            else:
                raw_payload = native_event_record.get("raw_json")
                if not isinstance(raw_payload, str) or not raw_payload.strip():
                    st.warning("No original payload is stored for this alert.")
                else:
                    try:
                        native_payload = json.loads(raw_payload)
                    except (json.JSONDecodeError, TypeError, ValueError):
                        native_payload = None
                        st.warning(
                            "The stored payload is not valid JSON. "
                            "Its saved text is shown unchanged."
                        )

        with st.expander("View original event payload", expanded=False):
            if native_event_record is None:
                st.info("Original payload is unavailable for this selection.")
            elif isinstance(raw_payload, str) and raw_payload.strip():
                if native_payload is not None:
                    st.code(
                        json.dumps(
                            native_payload,
                            indent=2,
                            ensure_ascii=False,
                        ),
                        language="json",
                    )
                else:
                    st.code(raw_payload, language="json")
            else:
                st.info("No original event payload is available.")

        st.divider()
        st.subheader("Normalized Fields Not Already in the Native Event")
        st.caption(
            "Fields already represented in the original payload are omitted "
            "here. Database correlation metadata is retained when available. "
            "Rule definitions and vulnerability intelligence remain in "
            "Alert Intelligence."
        )

        normalized_record = build_non_repeating_normalized_record(
            selected,
            native_payload,
        )

        if normalized_record:
            st.code(
                json.dumps(
                    normalized_record,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                ),
                language="json",
            )
        else:
            st.info(
                "No additional normalized fields remain; the original event "
                "already contains the available event fields."
            )

    with tab4:
        st.markdown("### Retained Packet and Flow Evidence")
        st.caption(
            "Read-only investigation using the selected alert's live "
            "database ID. Packet totals cover retained observations only."
        )

        try:
            live_alert_id = int(selected.get("record_id"))
        except (TypeError, ValueError, OverflowError):
            st.error(
                "This record has no valid live database ID. "
                "Investigation was not attempted."
            )
        else:
            try:
                investigation = load_alert_investigation(
                    live_db_path,
                    live_alert_id,
                )
            except Exception as exc:
                st.error("The live investigation could not be loaded.")
                st.caption(f"{type(exc).__name__}: {exc}")
            else:
                if investigation is None:
                    st.warning(
                        "The selected record was not found in the live "
                        "alerts database."
                    )
                else:
                    live_record = safe_dict(
                        investigation.get("alert")
                    )

                    try:
                        database_alert_id = int(live_record.get("id"))
                    except (TypeError, ValueError, OverflowError):
                        database_alert_id = None

                    if database_alert_id != live_alert_id:
                        st.error(
                            "Alert identity verification failed. "
                            "Evidence will not be displayed for this record."
                        )
                    else:
                        selected_investigation = investigation
                        packet_summary = safe_dict(
                            investigation.get("packet_summary")
                        )
                        duration_ms = packet_summary.get("duration_ms")
                        duration_label = (
                            f"{duration_ms / 1000:.3f} s"
                            if isinstance(duration_ms, (int, float))
                            else "Unavailable"
                        )

                        summary_cols = st.columns(4)
                        summary_cols[0].metric(
                            "Matched packets",
                            str(packet_summary.get("total_packets") or 0),
                        )

                        if packet_summary.get("all_packet_sizes_known"):
                            total_bytes = packet_summary.get("total_bytes") or 0
                            bytes_label = f"{int(total_bytes):,}"
                        else:
                            bytes_label = "Partial / unknown"

                        summary_cols[1].metric(
                            "Matched bytes",
                            bytes_label,
                        )
                        summary_cols[2].metric(
                            "Observed flow span",
                            duration_label,
                        )
                        summary_cols[3].metric(
                            "Severity (1–4)",
                            str(alert_unified_severity(live_record)),
                        )

                        st.caption(
                            "These packet counts are based on retained passive "
                            "collector records matched to the flow and time "
                            "window. They are not guaranteed complete traffic "
                            "or attack totals."
                        )

                        packets = investigation.get("packets", [])
                        st.markdown(
                            f"#### Matched Captured Packets ({len(packets)})"
                        )

                        if packets:
                            packet_rows = []
                            for item in packets:
                                row = dict(item)
                                row["Time (PKT)"] = (
                                    format_alert_timestamp_pkt(row)
                                )
                                packet_rows.append(row)

                            packet_df = pd.DataFrame(packet_rows)
                            packet_columns = [
                                name
                                for name in (
                                    "id", "Time (PKT)", "src", "src_port",
                                    "dst", "dst_port", "protocol", "size",
                                    "tcp_flags", "info",
                                )
                                if name in packet_df.columns
                            ]
                            st.dataframe(
                                packet_df[packet_columns],
                                width="stretch",
                                hide_index=True,
                            )
                        else:
                            st.info(
                                "No retained packets matched this alert. "
                                "The traffic may have fallen outside the "
                                "matching window or packet-retention limits."
                            )

                        with st.expander("Packet Summary Details"):
                            st.json(packet_summary)

    with tab5:
        st.subheader("Canonical Alert Enrichment")
        st.caption(
            "Structured enrichment using the ids.alert-enrichment schema. "
            "This is the same schema included in JSON bundle exports. "
            "Missing records are reported as unavailable, not as proof "
            "that a vulnerability or threat is absent."
        )

        enrichment_intelligence = (
            intelligence if not intelligence_error else {}
        )
        canonical_enrichment = build_alert_enrichment(
            selected,
            enrichment_intelligence,
            selected_investigation,
        )

        coverage = canonical_enrichment["coverage"]
        status_columns = st.columns(4)
        status_metrics = (
            ("Network", "network"),
            ("Rule intelligence", "rule_intelligence"),
            ("Vulnerability intelligence", "vulnerability_intelligence"),
            ("ATT&CK intelligence", "attack_intelligence"),
        )

        for column, (label, key) in zip(status_columns, status_metrics):
            with column:
                column.metric(label, str(coverage.get(key, "unavailable")))

        st.caption(
            "The complete JSON below contains detection details, network "
            "evidence, threat intelligence, investigation, assessment, "
            "coverage, and provenance. Expand it when you need the full "
            "structured record; the same record is included in JSON exports."
        )
        with st.expander("Complete Canonical Enrichment JSON", expanded=False):
            st.json(canonical_enrichment)
