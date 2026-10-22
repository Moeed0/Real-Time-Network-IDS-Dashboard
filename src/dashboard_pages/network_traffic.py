"""Chart-first dashboard for passively captured network packets."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo

import pandas as pd
import plotly.express as px
import streamlit as st


PKT_ZONE = ZoneInfo("Asia/Karachi")


def _pkt_date(epoch_ms: int | float) -> date:
    return datetime.fromtimestamp(
        float(epoch_ms) / 1000,
        tz=timezone.utc,
    ).astimezone(PKT_ZONE).date()


def _day_start_utc_ms(day: date) -> int:
    local_midnight = datetime.combine(
        day, time.min, tzinfo=PKT_ZONE
    )
    return int(
        local_midnight.astimezone(timezone.utc).timestamp() * 1000
    )


def _format_pkt_timestamp(value: Any) -> str:
    if value is None:
        return "Unavailable"
    try:
        numeric = float(value)
        if pd.isna(numeric):
            return "Unavailable"
        return datetime.fromtimestamp(
            numeric / 1000,
            tz=timezone.utc,
        ).astimezone(PKT_ZONE).strftime("%Y-%m-%d %H:%M:%S PKT")
    except (TypeError, ValueError, OverflowError, OSError):
        return "Unavailable"


def render_network_traffic(
    *,
    live_db_path: Path,
    get_packet_database_status: Callable[..., Any],
    load_live_packet_summary: Callable[..., Any],
    load_live_packets: Callable[..., Any],
    get_live_packet_analytics: Callable[..., Any],
) -> None:
    st.title("🌐 Network Traffic")
    st.caption(
        "Passive network monitoring. Charts summarize all retained packets "
        "matching the filters; the record table below is intentionally bounded."
    )

    try:
        status = get_packet_database_status(live_db_path)
    except Exception as exc:
        st.error("Could not check the packet database.")
        st.caption(f"{type(exc).__name__}: {exc}")
        return

    if not status.get("ready"):
        st.warning(
            status.get("error") or "The retained packet table is not ready."
        )
        st.caption("This page does not create tables or migrate the database.")
        return

    try:
        summary = load_live_packet_summary(live_db_path)
    except Exception as exc:
        st.error("Could not load packet statistics.")
        st.caption(f"{type(exc).__name__}: {exc}")
        return

    total_retained = int(summary.get("total_packets") or 0)
    protocols = summary.get("by_protocol") or {}

    if total_retained == 0:
        st.info(
            "No packets are currently retained. Confirm that the passive "
            "packet collector is running and receiving traffic."
        )
        return

    first_ts = summary.get("first_event_ts_utc")
    last_ts = summary.get("last_event_ts_utc")
    min_day = _pkt_date(first_ts) if first_ts is not None else None
    max_day = _pkt_date(last_ts) if last_ts is not None else None

    st.subheader("Filters")
    first_row = st.columns([1, 2])
    protocol_options = ["All", *protocols.keys()]

    chosen_protocol = first_row[0].selectbox(
        "Protocol",
        protocol_options,
        key="network_traffic_protocol",
    )
    endpoint = first_row[1].text_input(
        "Endpoint IP contains",
        placeholder="Example: 192.168.50.141",
        key="network_traffic_endpoint",
    ).strip()

    start_bound = None
    end_bound = None

    if min_day is not None and max_day is not None:
        chosen_dates = st.date_input(
            "Packet date range (Pakistan time)",
            value=(min_day, max_day),
            min_value=min_day,
            max_value=max_day,
            key="network_traffic_dates",
        )

        if isinstance(chosen_dates, (tuple, list)):
            if len(chosen_dates) == 2:
                start_day, end_day = chosen_dates
            elif len(chosen_dates) == 1:
                start_day = end_day = chosen_dates[0]
            else:
                start_day = end_day = None
        else:
            start_day = end_day = chosen_dates

        if start_day is None or end_day is None:
            st.info("Choose both a start and end date.")
            return

        if start_day > end_day:
            st.warning("The start date must not be later than the end date.")
            return

        start_bound = _day_start_utc_ms(start_day)
        end_bound = _day_start_utc_ms(end_day + timedelta(days=1))

    span_days = (
        (end_day - start_day).days + 1
        if min_day is not None and max_day is not None
        else 1
    )
    bucket_minutes = (
        1440 if span_days > 60
        else 360 if span_days > 14
        else 60 if span_days > 2
        else 15 if span_days > 1
        else 5
    )

    limit = st.selectbox(
        "Maximum packet rows in the details table",
        [100, 250, 500, 1000, 2500, 5000],
        index=2,
        key="network_traffic_limit",
    )

    filters = {
        "protocol": chosen_protocol,
        "endpoint": endpoint or None,
        "start_ts_utc_ms": start_bound,
        "end_ts_utc_ms": end_bound,
    }

    try:
        analytics = get_live_packet_analytics(
            live_db_path,
            **filters,
            bucket_minutes=bucket_minutes,
        )
    except Exception as exc:
        st.error("Could not calculate traffic analytics.")
        st.caption(f"{type(exc).__name__}: {exc}")
        return

    st.divider()
    st.subheader("Traffic Overview")

    metrics = st.columns(4)
    metrics[0].metric(
        "Packets in Filter",
        f"{analytics['matched_packets']:,}",
    )
    metrics[1].metric(
        "Observed Bytes",
        f"{analytics['total_bytes']:,}",
    )
    metrics[2].metric(
        "Unique Sources",
        f"{analytics['unique_sources']:,}",
    )
    metrics[3].metric(
        "Unique Destinations",
        f"{analytics['unique_destinations']:,}",
    )

    st.caption(
        "Metrics and charts include every retained packet matching the filters. "
        "Older packets may already have been removed by the collector's retention policy."
    )

    if analytics["matched_packets"] == 0:
        st.info("No retained packets match these filters.")
    else:
        timeline = pd.DataFrame(analytics["timeline"])
        protocols_df = pd.DataFrame(analytics["by_protocol"])
        sources_df = pd.DataFrame(analytics["top_sources"])
        destinations_df = pd.DataFrame(analytics["top_destinations"])

        st.subheader("Packet Volume Over Time")

        if timeline.empty:
            st.info(
                "Matching packets exist, but none have a usable event timestamp "
                "for the time-series chart."
            )
        else:
            timeline["Time (PKT)"] = (
                pd.to_datetime(
                    timeline["bucket_start_ts_utc_ms"],
                    unit="ms",
                    utc=True,
                ).dt.tz_convert("Asia/Karachi")
            )
            fig = px.area(
                timeline,
                x="Time (PKT)",
                y="packet_count",
                labels={
                    "packet_count": "Packets",
                    "Time (PKT)": "Time",
                },
                title=f"Packet count per {bucket_minutes} minute(s)",
            )
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, width="stretch")

        chart_left, chart_right = st.columns(2)

        with chart_left:
            st.subheader("Protocol Distribution")
            if protocols_df.empty:
                st.info("No protocol data is available for these filters.")
            else:
                fig = px.pie(
                    protocols_df,
                    names="protocol",
                    values="packet_count",
                    hole=0.55,
                )
                fig.update_layout(
                    legend_title_text="Protocol",
                    margin=dict(t=10, b=10, l=10, r=10),
                )
                st.plotly_chart(fig, width="stretch")

        with chart_right:
            st.subheader("Top Source Addresses")
            if sources_df.empty:
                st.info("No source-address data is available.")
            else:
                fig = px.bar(
                    sources_df.sort_values("packet_count"),
                    x="packet_count",
                    y="endpoint",
                    orientation="h",
                    labels={
                        "packet_count": "Packets",
                        "endpoint": "Source IP",
                    },
                )
                fig.update_layout(showlegend=False)
                st.plotly_chart(fig, width="stretch")

        st.subheader("Top Destination Addresses")
        if destinations_df.empty:
            st.info("No destination-address data is available.")
        else:
            fig = px.bar(
                destinations_df.sort_values("packet_count"),
                x="packet_count",
                y="endpoint",
                orientation="h",
                labels={
                    "packet_count": "Packets",
                    "endpoint": "Destination IP",
                },
            )
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, width="stretch")

    st.divider()
    st.subheader("Packet Details")

    st.caption(
        "The following table shows the newest matching packet records up to "
        "your selected row limit. This limit does not apply to the charts above."
    )

    try:
        records = load_live_packets(
            live_db_path,
            limit=int(limit),
            **filters,
        )
    except Exception as exc:
        st.error("Could not load packet records.")
        st.caption(f"{type(exc).__name__}: {exc}")
        return

    st.write(
        f"Showing **{len(records):,}** packet records "
        f"(table limit: {int(limit):,})."
    )

    if records:
        frame = pd.DataFrame(records)
        frame["Time (PKT)"] = frame["event_ts_utc"].map(
            _format_pkt_timestamp
        )

        display_columns = [
            name for name in (
                "id", "Time (PKT)", "src", "src_port", "dst",
                "dst_port", "protocol", "size", "tcp_flags", "info",
            )
            if name in frame.columns
        ]

        with st.expander("Inspect matching packet records", expanded=False):
            st.dataframe(
                frame[display_columns],
                width="stretch",
                hide_index=True,
            )
            st.download_button(
                "Download displayed packets (CSV)",
                data=frame.to_csv(index=False).encode("utf-8"),
                file_name="network_traffic_packets.csv",
                mime="text/csv",
                key="download_network_traffic_csv",
            )

        if len(records) >= int(limit):
            st.caption(
                "The table limit was reached. Increase the limit or narrow "
                "the filters to inspect a smaller subset."
            )
    else:
        st.info("No packet records match these filters.")
