"""Dedicated MITRE ATT&CK analysis workspace.

The original Dashboard is intended for network findings and exploratory charts.
This module keeps the ATT&CK view separate and deliberately frames technique
matches as evidence-backed hypotheses until an analyst confirms them.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pandas as pd
import streamlit as st

from app.analysis.visibility import build_capture_metrics
from app.threat_intel.attack_mapping import ATTACKMapper, AttackMapping


def _coerce_mapping(value: Any) -> AttackMapping | None:
    """Normalize session-state or persisted mapping values."""
    if isinstance(value, AttackMapping):
        return value
    if isinstance(value, Mapping):
        return AttackMapping.from_dict(dict(value))
    return None


def build_attack_mapping(state: Mapping[str, Any]) -> AttackMapping | None:
    """Build an ATT&CK mapping from the completed analysis state.

    This function is intentionally UI-agnostic so the Streamlit path and tests
    consume the same production-shaped detector inputs.
    """
    features = state.get("features")
    if not isinstance(features, dict):
        return None

    beacon_df = state.get("beacon_df")
    if isinstance(beacon_df, pd.DataFrame):
        beacon_results = beacon_df.to_dict("records")
    elif isinstance(beacon_df, list):
        beacon_results = beacon_df
    else:
        beacon_results = []

    return ATTACKMapper().map_analysis(
        features=features,
        dns_analysis=state.get("dns_analysis") or {},
        tls_analysis=state.get("tls_analysis") or {},
        yara_results=state.get("yara_results") or {},
        beacon_results=beacon_results,
        osint=state.get("osint") or {},
    )


def build_visibility_rows(state: Mapping[str, Any]) -> list[dict[str, str]]:
    """Return explicit detector visibility status for the coverage subview."""
    features = state.get("features")
    zeek_tables = state.get("zeek_tables")
    yara = state.get("yara_results")
    osint = state.get("osint")
    correlations = state.get("correlations")

    rows: list[dict[str, str]] = []
    if isinstance(features, dict):
        rows.append(
            {
                "Detector": "Packet / flow telemetry",
                "Status": "available",
                "Evidence": f"{len(features.get('flows') or []):,} flows",
            }
        )
    else:
        rows.append(
            {"Detector": "Packet / flow telemetry", "Status": "unavailable", "Evidence": "Run an analysis first"}
        )

    if isinstance(zeek_tables, dict) and zeek_tables:
        names = ", ".join(sorted(zeek_tables.keys()))
        rows.append({"Detector": "Zeek protocol telemetry", "Status": "available", "Evidence": names})
    else:
        rows.append(
            {
                "Detector": "Zeek protocol telemetry",
                "Status": "unavailable",
                "Evidence": "No Zeek tables in this session",
            }
        )

    dns = state.get("dns_analysis")
    rows.append(
        {
            "Detector": "DNS analytics",
            "Status": "available" if isinstance(dns, dict) and dns and not dns.get("error") else "partial",
            "Evidence": f"{(dns or {}).get('total_records', 0):,} DNS records"
            if isinstance(dns, dict)
            else "No DNS result",
        }
    )
    tls = state.get("tls_analysis")
    rows.append(
        {
            "Detector": "TLS / certificate analytics",
            "Status": "available" if isinstance(tls, dict) and tls and not tls.get("error") else "partial",
            "Evidence": f"{(tls or {}).get('total_certificates', 0):,} certificates"
            if isinstance(tls, dict)
            else "No TLS result",
        }
    )
    rows.append(
        {
            "Detector": "YARA file analytics",
            "Status": "available" if isinstance(yara, dict) else "unavailable",
            "Evidence": f"{(yara or {}).get('matched', 0):,} matched files"
            if isinstance(yara, dict)
            else "Not run or not restored",
        }
    )
    rows.append(
        {
            "Detector": "OSINT enrichment",
            "Status": "available" if isinstance(osint, dict) and osint else "unavailable",
            "Evidence": f"{len(osint or {}):,} provider result groups"
            if isinstance(osint, dict)
            else "Not run or not configured",
        }
    )
    rows.append(
        {
            "Detector": "Cross-indicator correlation",
            "Status": "available" if isinstance(correlations, list) else "unavailable",
            "Evidence": f"{len(correlations or []):,} correlated entities"
            if isinstance(correlations, list)
            else "Not available",
        }
    )
    return rows


def _confidence_band(confidence: float) -> str:
    if confidence >= 0.8:
        return "strong support"
    if confidence >= 0.6:
        return "supported"
    return "hypothesis"


def render_mitre_page(state: Mapping[str, Any]) -> None:
    """Render the dedicated MITRE ATT&CK / Behaviors & Coverage page."""
    st.markdown("### MITRE ATT&CK Analysis")
    st.caption(
        "This workspace maps observed network evidence to ATT&CK hypotheses. "
        "It does not prove endpoint execution, user identity, or authorization from PCAP alone."
    )

    raw_mapping = state.get("attack_mapping")
    mapping = _coerce_mapping(raw_mapping)
    if mapping is not None and mapping is not raw_mapping and hasattr(state, "__setitem__"):
        # Persist the normalized object in session state. Otherwise a mapping
        # restored from SQLite as a dict is reconstructed on every rerun and
        # analyst dispositions/notes disappear immediately.
        state["attack_mapping"] = mapping
    if mapping is None:
        mapping = build_attack_mapping(state)
        if mapping is not None and hasattr(state, "__setitem__"):
            # Keep the lazily-built result available to the LLM/export paths on
            # the next rerun without requiring a second mapper invocation.
            state["attack_mapping"] = mapping

    if mapping is None:
        st.info("Run a PCAP analysis first. ATT&CK findings will appear here after the analysis stages complete.")
        return

    techniques = mapping.techniques
    capture_metrics = state.get("capture_metrics")
    if not isinstance(capture_metrics, dict):
        capture_metrics = build_capture_metrics(state)
        if hasattr(state, "__setitem__"):
            state["capture_metrics"] = capture_metrics
    visibility = build_visibility_rows(state)
    gaps = sum(1 for row in visibility if row["Status"] in {"unavailable", "partial"})

    st.info(
        "Scope: network capture only. Empty or unavailable detector results are visibility states, "
        "not proof that the behavior did not occur."
    )
    st.warning(
        "ATT&CK matches are analyst hypotheses generated from network evidence. "
        "Validate the raw flows and supporting telemetry before treating a technique as confirmed."
    )

    metric_cols = st.columns(5)
    metric_cols[0].metric("ATT&CK hypotheses", len(techniques))
    metric_cols[1].metric("Observed tactics", len(mapping.tactics_summary))
    metric_cols[2].metric("Visibility gaps", gaps)
    metric_cols[3].metric("Parsed flows", f"{capture_metrics.get('flow_count', 0):,}")
    metric_cols[4].metric("Mapping severity", mapping.overall_severity.upper())
    st.caption("Mapping severity is a heuristic prioritization signal, not an incident severity verdict.")

    findings_tab, coverage_tab, export_tab = st.tabs(["Findings", "Coverage & Gaps", "Exports"])

    with findings_tab:
        if not techniques:
            st.success("No ATT&CK hypotheses were produced from the available evidence.")
        else:
            rows = [
                {
                    "Assessment": "Hypothesis",
                    "ID": technique.technique_id,
                    "Technique": technique.technique_name,
                    "Tactic": technique.tactic,
                    "Analytic": technique.analytic_id or "Not linked",
                    "Confidence": f"{technique.confidence:.0%}",
                    "Disposition": technique.disposition.title(),
                    "Evidence strength": _confidence_band(technique.confidence),
                    "Evidence": "; ".join(technique.evidence[:2]),
                }
                for technique in techniques
            ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

            st.markdown("#### Evidence detail")
            for technique in techniques:
                with st.expander(f"{technique.technique_id} · {technique.technique_name}"):
                    disposition = st.selectbox(
                        "Analyst disposition",
                        ["unreviewed", "confirmed", "dismissed"],
                        index=["unreviewed", "confirmed", "dismissed"].index(technique.disposition),
                        key=f"mitre_disposition_{technique.technique_id}",
                    )
                    technique.disposition = disposition
                    technique.analyst_note = st.text_input(
                        "Analyst note (optional)",
                        value=technique.analyst_note,
                        key=f"mitre_note_{technique.technique_id}",
                    )
                    st.write(
                        f"**Assessment:** consistent with this technique ({_confidence_band(technique.confidence)})."
                    )
                    st.write(f"**Tactic:** {technique.tactic}")
                    st.write(f"**ATT&CK analytic:** {technique.analytic_id or 'No direct analytic linked'}")
                    if technique.data_components:
                        st.write(f"**Data components:** {', '.join(technique.data_components)}")
                    if technique.evidence:
                        for evidence in technique.evidence:
                            st.markdown(f"- {evidence}")
                    else:
                        st.caption("No structured evidence reference was retained for this hypothesis.")
                    if technique.limitations:
                        st.caption("Limitations: " + " ".join(technique.limitations))
                    if technique.references:
                        st.caption("References: " + ", ".join(technique.references))

    with coverage_tab:
        st.markdown("#### Capture profile")
        profile_rows = [
            {"Metric": "Packets counted", "Value": f"{capture_metrics.get('packet_count', 0):,}"},
            {"Metric": "Packets parsed into flows", "Value": f"{capture_metrics.get('parsed_packet_count', 0):,}"},
            {
                "Metric": "Parse ratio",
                "Value": f"{capture_metrics['parse_ratio']:.1%}"
                if capture_metrics.get("parse_ratio") is not None
                else "Unavailable",
            },
            {"Metric": "Total flow bytes", "Value": f"{capture_metrics.get('total_bytes', 0):,}"},
            {
                "Metric": "Unique IPs / domains",
                "Value": f"{capture_metrics.get('unique_ips', 0):,} / {capture_metrics.get('unique_domains', 0):,}",
            },
            {
                "Metric": "Capture window",
                "Value": f"{capture_metrics.get('duration_seconds'):.1f}s"
                if capture_metrics.get("duration_seconds") is not None
                else "Unavailable",
            },
        ]
        st.dataframe(pd.DataFrame(profile_rows), use_container_width=True, hide_index=True)
        review_counts = {
            status: sum(1 for tech in techniques if tech.disposition == status)
            for status in ("confirmed", "dismissed", "unreviewed")
        }
        st.caption(
            f"Analyst review: {review_counts['confirmed']} confirmed · {review_counts['dismissed']} dismissed · "
            f"{review_counts['unreviewed']} unreviewed"
        )
        st.markdown("#### Detector coverage")
        st.dataframe(pd.DataFrame(visibility), use_container_width=True, hide_index=True)
        st.markdown("#### What this capture cannot establish")
        st.markdown(
            "- Process lineage, logged-in user, asset owner, MFA outcome, and authorization state.\n"
            "- Host-side persistence, credential theft, registry changes, or process injection.\n"
            "- Traffic outside the capture sensor, including asymmetric or dropped packets."
        )

    with export_tab:
        st.markdown("#### ATT&CK Navigator")
        st.caption("The export reflects the current local mapping and preserves the evidence text for analyst review.")
        try:
            from app.utils.navigator_export import export_navigator_json

            st.download_button(
                "Download Navigator layer",
                data=export_navigator_json(mapping),
                file_name="pcap_hunter_attack_layer.json",
                mime="application/json",
                key="mitre_navigator_export",
            )
        except Exception as exc:  # pragma: no cover - defensive UI guard
            st.error(f"Navigator export unavailable: {exc}")
