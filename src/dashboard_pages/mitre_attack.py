"""MITRE ATT&CK intelligence page."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pandas as pd
import streamlit as st


def render_mitre_attack(
    *,
    alerts: list[dict[str, Any]],
    alert_mitre: Callable[..., Any],
    alert_message: Callable[..., Any],
    alert_engine: Callable[..., Any],
    alert_sid: Callable[..., Any],
    safe_dict: Callable[..., Any],
    safe_list: Callable[..., Any],
) -> None:
    st.title(
        "🎯 MITRE ATT&CK Intelligence"
    )

    techniques = sorted(
        {
            technique
            for record in alerts
            for technique in alert_mitre(record)
        }
    )

    st.write(
        f"**{len(techniques)}** unique MITRE techniques "
        "are represented in the enriched dataset."
    )

    for technique_id in techniques:

        matching_records = [
            record
            for record in alerts
            if technique_id in alert_mitre(
                record
            )
        ]

        names = sorted(
            {
                alert_message(record)
                for record in matching_records
            }
        )

        engines = sorted(
            {
                alert_engine(record)
                for record in matching_records
            }
        )

        with st.expander(
            f"{technique_id} — "
            f"{len(matching_records)} alert(s)"
        ):

            columns = st.columns(3)

            columns[0].metric(
                "Alert Records",
                len(matching_records)
            )

            columns[1].metric(
                "Engines",
                len(engines)
            )

            columns[2].metric(
                "Messages",
                len(names)
            )

            st.write(
                "**Engines:** "
                + ", ".join(
                    engines
                )
            )

            context_records = []

            for record in matching_records:

                context = safe_dict(
                    record.get(
                        "security_context"
                    )
                )

                attack = safe_dict(
                    context.get(
                        "mitre_attack_intelligence"
                    )
                )

                for item in safe_list(
                    attack.get(
                        "techniques"
                    )
                ):

                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    if item.get(
                        "technique_id"
                    ) == technique_id:
                        context_records.append(
                            item
                        )

            if context_records:
                st.markdown(
                    "### ATT&CK Record"
                )

                st.json(
                    context_records[0]
                )

            st.markdown(
                "### Related Alerts"
            )

            technique_rows = []

            for record in matching_records:

                technique_rows.append(
                    {
                        "Record ID":
                            record.get(
                                "record_id"
                            ),
                        "Engine":
                            alert_engine(
                                record
                            ),
                        "SID":
                            alert_sid(
                                record
                            ),
                        "Message":
                            alert_message(
                                record
                            ),
                    }
                )

            st.dataframe(
                pd.DataFrame(
                    technique_rows
                ),
                width="stretch",
                hide_index=True,
            )
