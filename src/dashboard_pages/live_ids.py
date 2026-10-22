"""Live IDS monitoring, investigation, and correlation page."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any
import json

import pandas as pd
import plotly.express as px
import streamlit as st

from ids.alert_filtering import TIME_WINDOW_OPTIONS, filter_alert_records_by_time


@st.fragment(run_every="15s")
def render_live_ids(
    *,
    live_db_path: Path,
    format_alert_timestamp_pkt: Callable[..., Any],
    _close_alert_investigation_dialog: Callable[..., Any],
    _on_snort_alert_table_select: Callable[..., Any],
    _on_supporting_alert_table_select: Callable[..., Any],
    _on_suricata_alert_table_select: Callable[..., Any],
    alert_unified_severity: Callable[..., Any],
    classify_alert: Callable[..., Any],
    get_live_database_status: Callable[..., Any],
    load_alert_investigation: Callable[..., Any],
    load_live_alerts: Callable[..., Any],
    load_live_summary: Callable[..., Any],
    safe_dict: Callable[..., Any],
) -> None:


    st.title(
        "Live IDS Dashboard"
    )

    st.caption(
        "Read-only view of live Snort and Suricata alert data."
    )

    live_db = live_db_path

    refresh_col, status_col = st.columns(
        [1, 4]
    )

    with refresh_col:

        st.button(
            "Refresh Live Data",
            width="stretch",
            key="refresh_live_data",
        )

    status = get_live_database_status(
        live_db
    )

    with status_col:

        if not status["exists"]:

            st.error(
                "Live IDS database does not exist."
            )

        elif not status["alerts_table"]:

            st.error(
                "The live database does not contain the alerts table."
            )

        elif not status["ready"]:

            st.warning(
                "The live database exists, but its schema is not "
                "ready for the Live IDS dashboard."
            )

        else:

            st.success(
                "Live IDS database is ready."
            )

    st.code(
        str(live_db),
        language="text",
    )

    # --------------------------------------------------------
    # Database is not ready
    # --------------------------------------------------------

    if not status["ready"]:

        if status["missing_columns"]:

            st.write(
                "Missing required columns:"
            )

            st.code(
                ", ".join(
                    status["missing_columns"]
                ),
                language="text",
            )

        if status["error"]:

            st.caption(
                status["error"]
            )

        st.info(
            "This dashboard is read-only. "
            "No database schema changes or migrations are performed here."
        )

    # --------------------------------------------------------
    # Database is ready
    # --------------------------------------------------------

    else:

        summary = load_live_summary(
            live_db
        )

        snort_count = summary["by_engine"].get(
            "snort",
            0,
        )

        suricata_count = summary["by_engine"].get(
            "suricata",
            0,
        )

        # ----------------------------------------------------
        # Load and classify retained IDS alerts
        # ----------------------------------------------------

        retained_count = int(summary.get("total_alerts") or 0)

        retained_alerts = load_live_alerts(
            live_db,
            limit=max(10000, retained_count + 100),
        )

        time_filter_columns = st.columns(2)
        selected_time_window = time_filter_columns[0].selectbox(
            "Event time range",
            TIME_WINDOW_OPTIONS,
            index=0,
            key="live_ids_time_window",
        )
        include_routine = time_filter_columns[1].checkbox(
            "Include routine / unclassified network events",
            value=False,
            key="live_ids_include_routine",
            help=(
                "Adds records classified as network events to the primary "
                "table. They remain labelled as network events."
            ),
        )

        all_live_alerts = filter_alert_records_by_time(
            retained_alerts,
            selected_time_window,
        )
        st.caption(
            f"Event window: {selected_time_window}. "
            f"{len(all_live_alerts):,} of {len(retained_alerts):,} retained "
            "records fall within this window."
        )

        for live_alert in all_live_alerts:
            live_alert["presentation_category"] = classify_alert(
                live_alert
            )
            live_alert["timestamp_pkt"] = format_alert_timestamp_pkt(
                live_alert
            )

        security_alert_records = [
            record for record in all_live_alerts
            if record["presentation_category"] == "SECURITY_ALERT"
        ]

        security_by_engine = Counter(
            str(record.get("engine") or "unknown").lower()
            for record in security_alert_records
        )

        # ----------------------------------------------------
        # Security-focused overview
        # ----------------------------------------------------

        st.subheader("Security Alert Overview")

        metric_cols = st.columns(3)

        metric_cols[0].metric(
            "Security Alerts",
            len(security_alert_records),
        )
        metric_cols[1].metric(
            "Snort Security",
            security_by_engine["snort"],
        )
        metric_cols[2].metric(
            "Suricata Security",
            security_by_engine["suricata"],
        )

        st.caption(
            "The security metrics and chart use the selected event-time range. "
            "Routine network events are excluded from these security metrics. "
            "Supporting detections remain available separately."
        )

        # ----------------------------------------------------
        # Charts for security alerts only
        # ----------------------------------------------------

        st.subheader("Security Alert Distribution")

        engine_df = pd.DataFrame(
            [
                {"engine": engine, "alerts": count}
                for engine, count in sorted(security_by_engine.items())
            ]
        )

        st.markdown("**Security Alerts by Engine**")

        if engine_df.empty:
            st.info("No security alerts are currently recorded.")
        else:
            fig = px.bar(
                engine_df,
                x="engine",
                y="alerts",
                text="alerts",
            )
            fig.update_layout(
                xaxis_title="Engine",
                yaxis_title="Security alerts",
                showlegend=False,
            )
            st.plotly_chart(
                fig,
                width="stretch",
            )

        # ----------------------------------------------------
        # Security alerts and filters
        # ----------------------------------------------------

        st.subheader("Security Alerts")

        st.caption(
            "Security alerts are shown by default. Use the network-event toggle "
            "above to include routine or unclassified records in the main table. "
            "Supporting detections remain in their own section."
        )

        filter_cols = st.columns(3)

        engines = [
            "All",
            *sorted(summary["by_engine"].keys()),
        ]

        selected_engine = filter_cols[0].selectbox(
            "Engine",
            engines,
            key="security_alert_engine_filter",
        )

        severity_options = [
            "All",
            *sorted(
                summary["by_severity"].keys(),
                reverse=True,
            ),
        ]

        selected_severity = filter_cols[1].selectbox(
            "Severity (1-4)",
            severity_options,
            key="security_alert_severity_filter",
        )

        rows_per_page = filter_cols[2].selectbox(
            "Rows per page",
            [10, 25, 50, 100, 250, 500],
            index=3,
            key="security_alert_page_size",
        )

        filtered_records = all_live_alerts

        if selected_engine != "All":
            filtered_records = [
                record for record in filtered_records
                if str(record.get("engine") or "").lower()
                == str(selected_engine).lower()
            ]

        if selected_severity != "All":
            filtered_records = [
                record for record in filtered_records
                if (
                    str(record.get("severity"))
                    if record.get("severity") is not None
                    else "Unknown"
                ) == str(selected_severity)
            ]

        security_filtered = [
            record for record in filtered_records
            if record["presentation_category"] == "SECURITY_ALERT"
        ]

        supporting_filtered = [
            record for record in filtered_records
            if record["presentation_category"] == "SECURITY_SUPPORT"
        ]

        network_filtered = [
            record for record in filtered_records
            if record["presentation_category"] == "NETWORK_EVENT"
        ]

        displayable_filtered = list(security_filtered)
        if include_routine:
            displayable_filtered.extend(network_filtered)

        # Keep the latest-first ordering of the source query across categories.
        displayable_ids = {id(record) for record in displayable_filtered}
        displayable_filtered = [
            record for record in filtered_records
            if id(record) in displayable_ids
        ]

        page_key = "live_ids_alert_page"
        filter_signature = (
            selected_engine,
            str(selected_severity),
            selected_time_window,
            bool(include_routine),
            int(rows_per_page),
        )

        if st.session_state.get("_live_ids_filter_signature") != filter_signature:
            st.session_state["_live_ids_filter_signature"] = filter_signature
            st.session_state[page_key] = 1
            for widget_key in (
                "snort_security_alert_table",
                "suricata_security_alert_table",
                "supporting_detection_table",
            ):
                st.session_state.pop(widget_key, None)

        total_matching = len(displayable_filtered)
        total_pages = max(
            1,
            (total_matching + int(rows_per_page) - 1) // int(rows_per_page),
        )

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
        end_index = min(start_index + int(rows_per_page), total_matching)
        alerts = displayable_filtered[start_index:end_index]

        with count_column:
            if total_matching:
                st.caption(
                    f"Showing records {start_index + 1:,}–{end_index:,} "
                    f"of {total_matching:,} matching records."
                )
            else:
                st.caption("Showing 0 of 0 matching records.")

        if not alerts:
            st.info(
                "No security alerts match the selected filters. "
                "Try another engine or severity."
            )
        else:
            display_columns = [
                "id",
                "timestamp_pkt",
                "engine",
                "Severity",
                "presentation_category",
                "msg",
                "IDS rule classification",
                "src_addr",
                "src_port",
                "dst_addr",
                "dst_port",
                "protocol",
                "action",
                "community_id",
                "correlation_group_id",
            ]

            for heading, engine_name in (
                ("Snort Alerts", "snort"),
                ("Suricata Alerts", "suricata"),
            ):
                st.markdown(f"#### {heading}")

                engine_records = [
                    record for record in alerts
                    if str(record.get("engine") or "").lower()
                    == engine_name
                ]

                if not engine_records:
                    st.info(f"No {heading.lower()} match these filters.")
                    continue

                engine_df = pd.DataFrame(engine_records).rename(
                    columns={
                        "classification": "IDS rule classification",
                        "severity": "Severity",
                            }
                )
                existing_columns = [
                    column for column in display_columns
                    if column in engine_df.columns
                ]

                selection_widget_key = f"{engine_name}_security_alert_table"
                mapping_key = f"_{engine_name}_security_alert_ids"

                st.session_state[mapping_key] = [
                    int(value) for value in engine_df["id"].tolist()
                ]

                selection_callback = (
                    _on_snort_alert_table_select
                    if engine_name == "snort"
                    else _on_suricata_alert_table_select
                )

                st.dataframe(
                    engine_df[existing_columns],
                    width="stretch",
                    hide_index=True,
                    key=selection_widget_key,
                    on_select=selection_callback,
                    selection_mode="single-row",
                )
                st.caption("Select a row to investigate this alert.")

            other_records = [
                record for record in alerts
                if str(record.get("engine") or "").lower()
                not in {"snort", "suricata"}
            ]

            if other_records:
                st.markdown("#### Other IDS Engines")
                other_df = pd.DataFrame(other_records).rename(
                    columns={
                        "classification": "IDS rule classification",
                        "severity": "Severity",
                            }
                )
                existing_columns = [
                    column for column in display_columns
                    if column in other_df.columns
                ]
                st.dataframe(
                    other_df[existing_columns],
                    width="stretch",
                    hide_index=True,
                )

        # ----------------------------------------------------
        # Supporting detections are available separately
        # ----------------------------------------------------

        with st.expander(
            f"Supporting Detections ({len(supporting_filtered)})",
            expanded=False,
        ):
            st.caption(
                "These detections can provide context for an incident, "
                "but do not independently prove malicious activity."
            )

            supporting_to_show = supporting_filtered[:int(rows_per_page)]
            st.caption(
                f"Showing {len(supporting_to_show):,} of "
                f"{len(supporting_filtered):,} supporting detections. "
                "This section displays the first matching records."
            )

            if not supporting_to_show:
                st.info("No supporting detections match these filters.")
            else:
                supporting_df = pd.DataFrame(supporting_to_show).rename(
                    columns={
                        "severity": "Severity",
                            }
                )

                support_columns = [
                    "id",
                    "timestamp_pkt",
                    "engine",
                    "Severity",
                        "msg",
                    "src_addr",
                    "src_port",
                    "dst_addr",
                    "dst_port",
                    "protocol",
                    "correlation_group_id",
                ]

                existing_support_columns = [
                    column for column in support_columns
                    if column in supporting_df.columns
                ]

                support_widget_key = "supporting_detection_table"
                support_mapping_key = "_supporting_detection_ids"

                st.session_state[support_mapping_key] = [
                    int(value) for value in supporting_df["id"].tolist()
                ]

                st.dataframe(
                    supporting_df[existing_support_columns],
                    width="stretch",
                    hide_index=True,
                    key=support_widget_key,
                    on_select=_on_supporting_alert_table_select,
                    selection_mode="single-row",
                )
                st.caption("Select a row to investigate this detection.")

        # Alert details are opened in a modal, keeping the page uncluttered.
        @st.dialog(
            "Alert Investigation",
            width="large",
            on_dismiss=_close_alert_investigation_dialog,
        )
        def _show_alert_investigation_dialog(live_db: Path) -> None:
            selected_id = st.session_state.get("selected_live_alert_id")
            if selected_id is None:
                st.info("Select an alert row to inspect its details.")
                return

            investigation = load_alert_investigation(
                live_db,
                int(selected_id),
            )

            if investigation is None:
                st.warning(
                    f"Alert ID {selected_id} could not be found in the live database."
                )
            else:
                selected = investigation["alert"]
                packet_summary = investigation["packet_summary"]

                st.markdown(
                    f"#### Alert #{selected.get('id')} — "
                    f"{str(selected.get('engine') or 'Unknown').upper()}"
                )
                st.write(
                    selected.get("msg")
                    or selected.get("rule")
                    or "No alert message available."
                )

                if st.button(
                    "Open in Alert Explorer",
                    key="open_alert_explorer_from_live_dialog",
                    help=(
                        "Open this alert's rule details and offline "
                        "intelligence in Alert Explorer."
                    ),
                ):
                    st.session_state["alert_explorer_navigation_request"] = True
                    st.session_state["alert_explorer_requested_alert_id"] = (
                        selected.get("id")
                    )
                    st.session_state["show_alert_investigation_dialog"] = False
                    st.rerun(scope="app")

                identity_cols = st.columns(4)
                identity_cols[0].metric(
                    "SID",
                    str(selected.get("sid") or "Not reported"),
                )
                identity_cols[1].metric(
                    "Severity (1-4)",
                    str(alert_unified_severity(selected)),
                )
                identity_cols[2].metric(
                    "Source",
                    f"{selected.get('src_addr') or selected.get('src') or 'Unknown'}:"
                    f"{selected.get('src_port') or '?'}",
                )
                identity_cols[3].metric(
                    "Destination",
                    f"{selected.get('dst_addr') or selected.get('dst') or 'Unknown'}:"
                    f"{selected.get('dst_port') or '?'}",
                )

                st.caption(
                    "Alert event time: "
                    + format_alert_timestamp_pkt(selected)
                )

                st.markdown("##### Observed Packet Statistics")
                source = str(
                    selected.get("src_addr") or selected.get("src") or "Source"
                )
                destination = str(
                    selected.get("dst_addr") or selected.get("dst") or "Destination"
                )

                duration_ms = packet_summary.get("duration_ms")
                duration_value = (
                    f"{duration_ms / 1000:.3f} s"
                    if duration_ms is not None
                    else "Unavailable"
                )

                observed_cols = st.columns(4)
                observed_cols[0].metric(
                    "Matched captured packets",
                    f"{packet_summary.get('total_packets', 0):,}",
                )
                observed_cols[1].metric(
                    f"{source} → {destination}",
                    f"{packet_summary.get('source_to_destination_packets', 0):,} packets",
                )
                observed_cols[2].metric(
                    f"{destination} → {source}",
                    f"{packet_summary.get('destination_to_source_packets', 0):,} packets",
                )
                observed_cols[3].metric(
                    "Observed flow span",
                    duration_value,
                )

                bytes_cols = st.columns(3)
                bytes_cols[0].metric(
                    "Total matched bytes",
                    f"{packet_summary.get('total_bytes', 0):,}"
                    if packet_summary.get("all_packet_sizes_known")
                    else "Some sizes unavailable",
                )
                bytes_cols[1].metric(
                    "Forward bytes",
                    f"{packet_summary.get('source_to_destination_bytes', 0):,}",
                )
                bytes_cols[2].metric(
                    "Reverse bytes",
                    f"{packet_summary.get('destination_to_source_bytes', 0):,}",
                )

                first_packet = packet_summary.get("first_packet_ts_ms")
                last_packet = packet_summary.get("last_packet_ts_ms")
                timing_cols = st.columns(2)
                timing_cols[0].metric(
                    "First matched packet",
                    format_alert_timestamp_pkt(
                        {"event_ts_utc": first_packet}
                    ) if first_packet is not None else "Unavailable",
                )
                timing_cols[1].metric(
                    "Last matched packet",
                    format_alert_timestamp_pkt(
                        {"event_ts_utc": last_packet}
                    ) if last_packet is not None else "Unavailable",
                )

                gap_ms = packet_summary.get(
                    "first_alert_event_minus_first_packet_ms"
                )
                st.caption(
                    "Earliest related alert timestamp minus first matched "
                    f"packet timestamp: {gap_ms} ms"
                    if gap_ms is not None
                    else "Packet-to-alert timestamp difference unavailable."
                )
                st.caption(
                    "This timestamp difference is not per-packet IDS analysis "
                    "time or proof of detection latency."
                )

                closure = packet_summary.get("tcp_close_observed")
                closure_text = (
                    "Observed (FIN/RST)"
                    if closure is True
                    else (
                        "Not observed in matched packets"
                        if closure is False
                        else "Not applicable or unavailable"
                    )
                )
                st.write(f"**TCP close indication:** {closure_text}")

                if packet_summary.get("reason"):
                    st.warning(packet_summary["reason"])

                st.caption(
                    "Packet statistics count records retained by the passive "
                    "collector in the matched bidirectional IP/port flow and "
                    "time window. They are not guaranteed complete attack totals. "
                    "The packet table retains at most the configured number of "
                    "recent records; missing earlier traffic cannot be recovered."
                )

                st.markdown("##### IDS-Reported Flow Counter Snapshot")
                flow_cols = st.columns(4)
                for column, label, key in zip(
                    flow_cols,
                    (
                        "Client packets",
                        "Client bytes",
                        "Server packets",
                        "Server bytes",
                    ),
                    (
                        "client_pkts",
                        "client_bytes",
                        "server_pkts",
                        "server_bytes",
                    ),
                ):
                    value = selected.get(key)
                    column.metric(
                        label,
                        f"{value:,}" if isinstance(value, (int, float)) else (
                            str(value) if value is not None else "Not reported"
                        ),
                    )

                st.caption(
                    "These counters are reported by the selected IDS alert. "
                    "They are snapshots, may differ between engines, and are "
                    "separate from the packet collector's observed counts."
                )

                packet_records = investigation.get("packets", [])
                st.markdown(
                    f"##### Matched Captured Packets ({len(packet_records)})"
                )

                if packet_records:
                    packet_rows = []
                    for packet in packet_records:
                        row = dict(packet)
                        row["timestamp_pkt"] = format_alert_timestamp_pkt(row)

                        forward = (
                            str(row.get("src")) == source
                            and str(row.get("dst")) == destination
                        )
                        if selected.get("src_port") is not None:
                            forward = forward and (
                                str(row.get("src_port"))
                                == str(selected.get("src_port"))
                                and str(row.get("dst_port"))
                                == str(selected.get("dst_port"))
                            )
                        row["direction"] = (
                            f"{source} → {destination}"
                            if forward
                            else f"{destination} → {source}"
                        )
                        packet_rows.append(row)

                    packet_df = pd.DataFrame(packet_rows)
                    packet_columns = [
                        name for name in (
                            "id", "timestamp_pkt", "direction", "src",
                            "src_port", "dst", "dst_port", "protocol",
                            "size", "tcp_flags", "info",
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
                        "No retained captured packets matched this alert's "
                        "flow and time window. This does not mean the traffic "
                        "never occurred: relevant packets may have fallen "
                        "outside the alert time window or been removed by "
                        "packet retention. Generate the traffic again while "
                        "the passive packet collector is running to investigate "
                        "a fresh occurrence."
                    )

                with st.expander("Normalized Alert Record"):
                    display_record = dict(selected)
                    display_record.pop("raw_json", None)
                    st.json(display_record)

                raw_json = selected.get("raw_json")
                if raw_json:
                    with st.expander("Original IDS Event Payload"):
                        try:
                            st.json(json.loads(raw_json))
                        except (TypeError, ValueError):
                            st.code(str(raw_json), language="json")

        if st.session_state.get("show_alert_investigation_dialog", False):
            _show_alert_investigation_dialog(live_db)

        # ----------------------------------------------------
        # Security-related cross-engine correlation
