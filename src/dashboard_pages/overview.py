"""Overview page for the Real-Time Network IDS Dashboard."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pandas as pd
import streamlit as st


def render_overview(
    *,
    alerts: list[dict[str, Any]],
    ids_sources: dict[str, Any],
    alert_engine: Callable[[dict[str, Any]], str],
    alert_cves: Callable[[dict[str, Any]], list[str]],
    alert_mitre: Callable[[dict[str, Any]], list[str]],
    known_exploited: Callable[[dict[str, Any]], bool],
) -> None:
    st.title(
        "🛡️ Snort + Suricata IDS Research Dashboard"
    )

    st.markdown(
        """
        Security monitoring and enriched alerts from passive Snort and Suricata inspection.
        """
    )

    st.markdown(
        """
        <div class="notice-card">
        <strong>Dataset model:</strong>
        Native Snort and Suricata alert records are preserved.
        Rule intelligence and external security intelligence are
        added as enrichment rather than replacing the original data.
        </div>
        """,
        unsafe_allow_html=True,
    )

    total_alerts = len(alerts)

    snort_count = sum(
        alert_engine(r) == "Snort"
        for r in alerts
    )

    suricata_count = sum(
        alert_engine(r) == "Suricata"
        for r in alerts
    )

    unique_cves = set()

    unique_mitre = set()

    kev_count = 0

    for record in alerts:
        unique_cves.update(
            alert_cves(record)
        )

        unique_mitre.update(
            alert_mitre(record)
        )

        if known_exploited(record):
            kev_count += 1

    metric_columns = st.columns(6)

    metrics = [
        ("Total Alerts", total_alerts),
        ("Snort Alerts", snort_count),
        ("Suricata Alerts", suricata_count),
        ("Unique CVEs", len(unique_cves)),
        ("MITRE Techniques", len(unique_mitre)),
        ("CISA KEV Alerts", kev_count),
    ]

    for column, (
        label,
        value,
    ) in zip(
        metric_columns,
        metrics,
    ):
        with column:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">
                        {label}
                    </div>
                    <div class="metric-value">
                        {value}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.subheader(
        "Rule Engine Configuration"
    )

    engine_rows = []

    for engine_name, engine_config in (
        ids_sources.items()
    ):

        engine_rows.append(
            {
                "Engine":
                    engine_name.title(),

                "Rule Format":
                    engine_config.get(
                        "rule_format"
                    ),

                "Engine-Reported Rule Count":
                    engine_config.get(
                        "engine_rule_count"
                    ),

                "Rule Source":
                    (
                        engine_config.get(
                            "rules_path"
                        )
                        or engine_config.get(
                            "rules_file"
                        )
                    ),
            }
        )

    st.dataframe(
        pd.DataFrame(engine_rows),
        width="stretch",
        hide_index=True,
    )

    st.markdown(
        """
        <div class="warning-card">
        <strong>Interpretation note:</strong>
        Alert count is not an accuracy score. Differences can come
        from rulesets, signatures, thresholds, protocol parsing,
        detection logic and alerting behavior.
        </div>
        """,
        unsafe_allow_html=True,
    )
