#!/usr/bin/env python3

import json
import os
from pathlib import Path
from typing import Any
import html
from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st
from dashboard_pages.overview import render_overview
from dashboard_pages.research_data import render_research_data
from dashboard_pages.mitre_attack import render_mitre_attack
from dashboard_pages.vulnerability_intelligence import render_vulnerability_intelligence
from dashboard_pages.alert_explorer import render_alert_explorer
from dashboard_pages.live_ids import render_live_ids
from dashboard_pages.network_traffic import render_network_traffic
from dashboard_pages.correlation_investigation import render_correlation_investigation

from ids.alert_classification import classify_alert, is_security_related
from ids.alert_details import load_alert_investigation
from ids.offline_intelligence import get_offline_live_intelligence
from ids.live_alert_view import load_live_alert_view_records
from ids.demo_alerts import load_demo_alerts
from ids.live_dashboard import (
    get_live_database_status,
    load_correlation_group_alerts,
    load_correlation_groups,
    load_live_alerts,
    load_live_summary,
    get_packet_database_status,
    load_live_packet_summary,
    load_live_packets,
    get_live_packet_analytics,
)


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

IDS_SOURCES_FILE = (
    PROJECT_ROOT
    / "config/ids_sources.json"
)

raw_live_db = os.environ.get("IDS_DB_FILE", "ids_live.db")
LIVE_DB_FILE = Path(raw_live_db).expanduser()
if not LIVE_DB_FILE.is_absolute():
    LIVE_DB_FILE = PROJECT_ROOT / LIVE_DB_FILE
LIVE_DB_FILE = LIVE_DB_FILE.resolve()

DASHBOARD_VERSION = "5.0"


def format_alert_timestamp_pkt(alert: dict[str, Any]) -> str:
    """Format timestamps for display in Pakistan time (UTC+05:00)."""
    value = alert.get("event_ts_utc")

    if value is not None:
        try:
            numeric = float(value)
            unit = "ms" if abs(numeric) >= 100_000_000_000 else "s"
            parsed = pd.to_datetime(
                numeric, unit=unit, utc=True, errors="coerce"
            )
            if not pd.isna(parsed):
                local_time = parsed.tz_convert("Asia/Karachi")
                return local_time.strftime(
                    "%Y-%m-%d %H:%M:%S PKT (UTC+05:00)"
                )
        except (TypeError, ValueError, OverflowError):
            pass

    raw = alert.get("timestamp")
    if raw is not None:
        parsed = pd.to_datetime(raw, utc=True, errors="coerce")
        if not pd.isna(parsed):
            local_time = parsed.tz_convert("Asia/Karachi")
            return local_time.strftime(
                "%Y-%m-%d %H:%M:%S PKT (UTC+05:00)"
            )

    return "PKT timestamp unavailable"


def _select_alert_from_table(
    widget_key: str,
    mapping_key: str,
    selected_key: str = "selected_live_alert_id",
) -> None:
    """Store the selected alert ID and request its investigation dialog."""
    widget_state = st.session_state.get(widget_key)

    if hasattr(widget_state, "get"):
        selection = widget_state.get("selection", {})
    else:
        selection = getattr(widget_state, "selection", {})

    if hasattr(selection, "get"):
        rows = selection.get("rows", [])
    else:
        rows = getattr(selection, "rows", [])

    if not rows:
        return

    ids = st.session_state.get(mapping_key, [])
    try:
        index = int(rows[0])
        if not 0 <= index < len(ids):
            return
        selected_id = int(ids[index])
    except (TypeError, ValueError, IndexError):
        return

    st.session_state[selected_key] = selected_id
    st.session_state["show_alert_investigation_dialog"] = True


def _on_snort_alert_table_select() -> None:
    _select_alert_from_table(
        "snort_security_alert_table",
        "_snort_security_alert_ids",
    )


def _on_suricata_alert_table_select() -> None:
    _select_alert_from_table(
        "suricata_security_alert_table",
        "_suricata_security_alert_ids",
    )


def _on_supporting_alert_table_select() -> None:
    _select_alert_from_table(
        "supporting_detection_table",
        "_supporting_detection_ids",
    )


def _close_alert_investigation_dialog() -> None:
    st.session_state["show_alert_investigation_dialog"] = False


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Snort + Suricata IDS Research Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)




# ============================================================
# GLOBAL STYLE
# ============================================================

st.markdown(
    """
    <style>
        .main {
            background-color: #0e1117;
        }

        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }

        .metric-card {
            background: linear-gradient(
                145deg,
                #161b22,
                #0d1117
            );
            border: 1px solid #30363d;
            border-radius: 14px;
            padding: 18px;
            min-height: 130px;
        }

        .metric-label {
            color: #8b949e;
            font-size: 13px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .metric-value {
            color: #f0f6fc;
            font-size: 34px;
            font-weight: 850;
            line-height: 1.1;
        }

        .info-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 14px;
            padding: 16px 18px;
            margin: 8px 0 16px 0;
        }

        .notice-card {
            background: rgba(88, 166, 255, 0.08);
            border: 1px solid rgba(88, 166, 255, 0.25);
            border-radius: 12px;
            padding: 14px 16px;
            margin: 10px 0 18px 0;
        }

        .warning-card {
            background: rgba(210, 153, 34, 0.10);
            border: 1px solid rgba(210, 153, 34, 0.30);
            border-radius: 12px;
            padding: 14px 16px;
            margin: 10px 0 18px 0;
        }

        .success-card {
            background: rgba(46, 160, 67, 0.10);
            border: 1px solid rgba(46, 160, 67, 0.30);
            border-radius: 12px;
            padding: 14px 16px;
            margin: 10px 0 18px 0;
        }

        h1, h2, h3 {
            color: #f0f6fc;
        }

        .muted {
            color: #8b949e;
        }

        code {
            white-space: pre-wrap !important;
            word-break: break-word !important;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data(show_spinner="Loading IDS research dataset...")
def load_json(path: str) -> Any:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Required file not found: {file_path}"
        )

    with file_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        return json.load(handle)


def safe_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value

    return []


def get_nested(
    value: Any,
    *keys: str,
    default: Any = None,
) -> Any:

    current = value

    for key in keys:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

        if current is None:
            return default

    return current


alerts: list[dict[str, Any]] = []

try:
    ids_sources = load_json(
        str(IDS_SOURCES_FILE)
    )
except Exception as exc:
    st.error("The dashboard could not load IDS source configuration.")
    st.exception(exc)
    st.stop()


if not isinstance(ids_sources, dict):
    ids_sources = {}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def alert_engine(record: dict[str, Any]) -> str:
    return str(
        record.get(
            "engine",
            "Unknown",
        )
    )


def alert_message(record: dict[str, Any]) -> str:
    alert = safe_dict(
        record.get("alert")
    )

    message = alert.get(
        "message"
    )

    if message:
        return str(message)

    rule = safe_dict(
        record.get("rule")
    )

    message = rule.get(
        "msg"
    )

    if message:
        return str(message)

    native = safe_dict(
        record.get("native_event")
    )

    return str(
        native.get(
            "msg",
            ""
        )
    )


def alert_sid(record: dict[str, Any]) -> Any:
    alert = safe_dict(
        record.get("alert")
    )

    rule = safe_dict(
        record.get("rule")
    )

    return (
        alert.get("sid")
        or rule.get("sid")
    )


def alert_gid(record: dict[str, Any]) -> Any:
    alert = safe_dict(
        record.get("alert")
    )

    rule = safe_dict(
        record.get("rule")
    )

    return (
        alert.get("gid")
        or rule.get("gid")
    )


def alert_revision(record: dict[str, Any]) -> Any:
    alert = safe_dict(
        record.get("alert")
    )

    rule = safe_dict(
        record.get("rule")
    )

    return (
        alert.get("rev")
        or rule.get("rev")
    )


def alert_timestamp(record: dict[str, Any]) -> str:
    alert = safe_dict(
        record.get("alert")
    )

    value = alert.get(
        "timestamp"
    )

    if value:
        return str(value)

    native = safe_dict(
        record.get("native_event")
    )

    return str(
        native.get(
            "timestamp",
            ""
        )
    )


def alert_cves(record: dict[str, Any]) -> list[str]:
    context = safe_dict(
        record.get("security_context")
    )

    identifiers = safe_dict(
        context.get(
            "identifier_evidence"
        )
    )

    cves = safe_dict(
        identifiers.get(
            "cves"
        )
    )

    return sorted(
        str(value)
        for value in cves.keys()
    )


def alert_mitre(record: dict[str, Any]) -> list[str]:
    context = safe_dict(
        record.get("security_context")
    )

    identifiers = safe_dict(
        context.get(
            "identifier_evidence"
        )
    )

    techniques = safe_dict(
        identifiers.get(
            "mitre_techniques"
        )
    )

    return sorted(
        str(value)
        for value in techniques.keys()
    )


def alert_service(record: dict[str, Any]) -> str:
    network = safe_dict(
        record.get("network")
    )

    value = network.get(
        "service"
    )

    return (
        str(value)
        if value
        else ""
    )


def alert_protocol(record: dict[str, Any]) -> str:
    network = safe_dict(
        record.get("network")
    )

    value = network.get(
        "protocol"
    )

    return (
        str(value)
        if value
        else ""
    )


def alert_src(record: dict[str, Any]) -> str:
    network = safe_dict(
        record.get("network")
    )

    ip = network.get(
        "source_ip"
    )

    port = network.get(
        "source_port"
    )

    if port is not None:
        return f"{ip}:{port}"

    return str(
        ip or ""
    )


def alert_dst(record: dict[str, Any]) -> str:
    network = safe_dict(
        record.get("network")
    )

    ip = network.get(
        "destination_ip"
    )

    port = network.get(
        "destination_port"
    )

    if port is not None:
        return f"{ip}:{port}"

    return str(
        ip or ""
    )


def alert_classification(
    record: dict[str, Any]
) -> str:

    alert = safe_dict(
        record.get("alert")
    )

    value = alert.get(
        "classification"
    )

    if value:
        return str(value)

    rule = safe_dict(
        record.get("rule")
    )

    return str(
        rule.get(
            "classtype",
            ""
        )
    )


def alert_unified_severity(record: dict[str, Any]) -> int:
    """Return one unified severity value (1 highest, 4 lowest)."""
    value = record.get("severity")
    alert = safe_dict(record.get("alert"))
    if value in (None, ""):
        engine = str(record.get("engine") or "").lower()
        value = (
            alert.get("severity")
            if engine == "suricata"
            else record.get("priority")
        )
    try:
        parsed = int(value) if value not in (None, "") else 4
    except (TypeError, ValueError):
        parsed = 4
    return max(1, min(4, parsed))


def alert_native_severity(record: dict[str, Any]) -> Any:
    """Return only severity actually present in the native event."""
    alert = safe_dict(record.get("alert"))
    for value in (alert.get("severity"), record.get("severity")):
        if value is not None:
            return value
    return None


def alert_native_priority(record: dict[str, Any]) -> Any:
    """Return only priority actually present in the native event."""
    alert = safe_dict(record.get("alert"))
    for value in (alert.get("priority"), record.get("priority")):
        if value is not None:
            return value
    return None

def known_exploited(
    record: dict[str, Any]
) -> bool:

    context = safe_dict(
        record.get("security_context")
    )

    coverage = safe_dict(
        context.get(
            "coverage"
        )
    )

    return bool(
        coverage.get(
            "known_exploited_cve",
            False
        )
    )


def has_project_docs(
    record: dict[str, Any]
) -> bool:

    context = safe_dict(
        record.get("security_context")
    )

    coverage = safe_dict(
        context.get(
            "coverage"
        )
    )

    return bool(
        coverage.get(
            "project_documentation_found",
            False
        )
    )


def build_alert_dataframe(
    records: list[dict[str, Any]]
) -> pd.DataFrame:

    rows = []

    for record in records:

        rows.append(
            {
                "Record ID":
                    record.get(
                        "record_id"
                    ),

                "Engine":
                    alert_engine(record),
                "Timestamp":
                    alert_timestamp(record),

                "GID":
                    alert_gid(record),

                "SID":
                    alert_sid(record),

                "Rev":
                    alert_revision(record),

                "Message":
                    alert_message(record),

                "Classification":
                    alert_classification(
                        record
                    ),

                "Severity": alert_unified_severity(record),


                "Protocol":
                    alert_protocol(
                        record
                    ),

                "Service":
                    alert_service(
                        record
                    ),

                "Source":
                    alert_src(
                        record
                    ),

                "Destination":
                    alert_dst(
                        record
                    ),

                "CVEs": (
                    ", ".join(alert_cves(record))
                    if record.get("intelligence_loaded", True)
                    else "Not loaded"
                ),

                "MITRE": (
                    ", ".join(alert_mitre(record))
                    if record.get("intelligence_loaded", True)
                    else "Not loaded"
                ),

                "CISA KEV": (
                    ("Yes" if known_exploited(record) else "No")
                    if record.get("intelligence_loaded", True)
                    else "Not loaded"
                ),

                "Project Docs": (
                    ("Yes" if has_project_docs(record) else "No")
                    if record.get("intelligence_loaded", True)
                    else "Not loaded"
                ),
            }
        )

    return pd.DataFrame(
        rows,
        columns=[
            "Record ID",
            "Engine",
            "Timestamp",
            "GID",
            "SID",
            "Rev",
            "Message",
            "Classification",
            "Severity",
            "Protocol",
            "Service",
            "Source",
            "Destination",
            "CVEs",
            "MITRE",
            "CISA KEV",
            "Project Docs",
        ],
    )





# ============================================================
@st.cache_data(ttl=30, show_spinner=False)
def load_dashboard_alert_snapshot(
    db_path: str,
    *,
    include_cached_intelligence: bool = True,
) -> list[dict[str, Any]]:
    """Cache an alert snapshot, optionally skipping per-alert cache reads."""
    return load_live_alert_view_records(
        db_path,
        include_cached_intelligence=include_cached_intelligence,
    )


@st.cache_data(ttl=30, show_spinner=False)
def load_dashboard_alert_dataframe(
    db_path: str,
) -> pd.DataFrame:
    """Cache the Alert Explorer table separately from the full snapshot."""
    return build_alert_dataframe(
        load_dashboard_alert_snapshot(db_path)
    )


# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        "## IDS Research"
    )

    st.markdown(
        f"""
        <div class="muted">
            Snort + Suricata<br>
            Enriched research dashboard<br>
            Version {DASHBOARD_VERSION}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    if st.session_state.get("alert_explorer_navigation_request", False):
        st.session_state["alert_explorer_navigation_request"] = False
        st.session_state["dashboard_navigation"] = "Alert Explorer"

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Live IDS",
            "Network Traffic",
            "Correlation Investigation",
            "Alert Explorer",
            "Vulnerability Intelligence",
            "MITRE ATT&CK",
            "Research Data",
        ],
        key="dashboard_navigation",
    )

    st.divider()

    st.markdown(
        "### Research Dataset"
    )

    alert_count_placeholder = st.empty()

    st.write(
        "Passive IDS capture"
    )


# ============================================================
# Load enriched records only for pages that use that dataset.
# A public installation may not have a live IDS database yet.
alerts = []
alert_df = pd.DataFrame()

if page in {"Live IDS", "Network Traffic", "Correlation Investigation"}:
    alert_count_placeholder.write("Live database monitoring")
elif not LIVE_DB_FILE.exists():
    if page in {"Alert Explorer", "Overview", "Vulnerability Intelligence", "MITRE ATT&CK", "Research Data"}:
        alerts = load_demo_alerts()
        if page == "Alert Explorer":
            alert_df = build_alert_dataframe(alerts)
        st.info(
            "Demo Mode — Synthetic Sample Data. "
            "These bundled examples are not live network activity."
        )
        alert_count_placeholder.write(f"**{len(alerts)}** synthetic alert records")
    else:
        st.info(
            "No live IDS database is available. "
            "This page requires the live collector database."
        )
        alert_count_placeholder.write("Live database not initialized")
else:
    try:
        if page == "Alert Explorer":
            alerts = load_dashboard_alert_snapshot(
                str(LIVE_DB_FILE),
                include_cached_intelligence=False,
            )
        else:
            alerts = load_dashboard_alert_snapshot(str(LIVE_DB_FILE))

        if not isinstance(alerts, list):
            st.error("The live alert service did not return a list.")
            st.stop()

        if page == "Alert Explorer":
            alert_df = build_alert_dataframe(alerts)

    except Exception as exc:
        st.error("The dashboard could not load live IDS records.")
        st.exception(exc)
        st.stop()

    alert_count_placeholder.write(f"**{len(alerts)}** alert records")


# PAGE: OVERVIEW
# ============================================================

if page == "Overview":
    render_overview(
        alerts=alerts,
        ids_sources=ids_sources,
        alert_engine=alert_engine,
        alert_cves=alert_cves,
        alert_mitre=alert_mitre,
        known_exploited=known_exploited,
    )


# ============================================================
# PAGE: LIVE IDS
# ============================================================

elif page == "Live IDS":
    render_live_ids(
        live_db_path=LIVE_DB_FILE,
        format_alert_timestamp_pkt=format_alert_timestamp_pkt,
        _close_alert_investigation_dialog=_close_alert_investigation_dialog,
        _on_snort_alert_table_select=_on_snort_alert_table_select,
        _on_supporting_alert_table_select=_on_supporting_alert_table_select,
        _on_suricata_alert_table_select=_on_suricata_alert_table_select,
        alert_unified_severity=alert_unified_severity,
        classify_alert=classify_alert,
        get_live_database_status=get_live_database_status,
        load_alert_investigation=load_alert_investigation,
        load_live_alerts=load_live_alerts,
        load_live_summary=load_live_summary,
        safe_dict=safe_dict,
    )

elif page == "Network Traffic":
    render_network_traffic(
        live_db_path=LIVE_DB_FILE,
        get_packet_database_status=get_packet_database_status,
        load_live_packet_summary=load_live_packet_summary,
        load_live_packets=load_live_packets,
        get_live_packet_analytics=get_live_packet_analytics,
    )

elif page == "Correlation Investigation":
    render_correlation_investigation(
        live_db_path=LIVE_DB_FILE,
        load_correlation_groups=load_correlation_groups,
        load_correlation_group_alerts=load_correlation_group_alerts,
        is_security_related=is_security_related,
        classify_alert=classify_alert,
        format_alert_timestamp_pkt=format_alert_timestamp_pkt,
    )

elif page == "Alert Explorer":
    render_alert_explorer(
        alerts=alerts,
        alert_df=alert_df,
        alert_engine=alert_engine,
        alert_message=alert_message,
        alert_sid=alert_sid,
        alert_gid=alert_gid,
        alert_revision=alert_revision,
        alert_protocol=alert_protocol,
        alert_service=alert_service,
        known_exploited=known_exploited,
        get_live_intelligence=get_offline_live_intelligence,
        live_db_path=LIVE_DB_FILE,
        load_alert_investigation=load_alert_investigation,
        format_alert_timestamp_pkt=format_alert_timestamp_pkt,
        alert_unified_severity=alert_unified_severity,
        safe_dict=safe_dict,
    )

elif page == "Vulnerability Intelligence":
    render_vulnerability_intelligence(
        alerts=alerts,
        alert_cves=alert_cves,
        alert_engine=alert_engine,
        known_exploited=known_exploited,
        safe_dict=safe_dict,
        safe_list=safe_list,
        alert_sid=alert_sid,
        alert_message=alert_message,
    )

elif page == "MITRE ATT&CK":
    render_mitre_attack(
        alerts=alerts,
        alert_mitre=alert_mitre,
        alert_message=alert_message,
        alert_engine=alert_engine,
        alert_sid=alert_sid,
        safe_dict=safe_dict,
        safe_list=safe_list,
    )

elif page == "Research Data":
    render_research_data(
        alerts=alerts,
        ids_sources_file=IDS_SOURCES_FILE,
        project_root=PROJECT_ROOT,
        live_db_file=LIVE_DB_FILE,
    )

# ============================================================
# FOOTER
# ============================================================

st.divider()

footer_alert_description = (
    "Live database monitoring"
    if page == "Live IDS"
    else f"{len(alerts)} enriched alert records"
)

st.caption(
    "Snort + Suricata Controlled IDS Research Dashboard "
    f"v{DASHBOARD_VERSION} | "
    f"{footer_alert_description} | "
    "Passive capture / controlled laboratory dataset"
)
