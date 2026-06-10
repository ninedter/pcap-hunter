from __future__ import annotations

import pandas as pd
import streamlit as st

from app.ui.colors import SEVERITY_COLORS, SEVERITY_ORDER, severity_color
from app.utils.common import is_public_ipv4
from app.utils.export import (
    export_dataframe_to_csv,
    export_dataframe_to_json,
    export_to_csv,
    export_to_json,
    generate_export_filename,
)


def inject_css():
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }
        .stTabs [role="tablist"] { gap: .5rem; }
        .stTabs [role="tab"] { padding: .45rem .9rem; border-radius: 8px; }
        .stButton>button { border-radius: 10px; }
        .phase-row .stButton>button { height: 38px; }
        .phase-row .stProgress { margin-top: 6px; }
        .section-title { margin-top: .75rem; margin-bottom: .5rem; }
        .dashboard-card {
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1.25rem;
            background-color: rgba(255, 255, 255, 0.02);
            margin-bottom: 1rem;
        }
        .metric-card {
            background: linear-gradient(135deg, rgba(74, 144, 226, 0.1), rgba(0,0,0,0));
            border-left: 3px solid #4A90E2;
        }
        .chart-hint {
            color: rgba(255, 255, 255, 0.4);
            font-size: 0.78rem;
            font-style: italic;
            margin-top: -0.5rem;
            margin-bottom: 0.5rem;
        }
        .filter-badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            margin: 0.15rem;
            border-radius: 12px;
            background: rgba(74, 144, 226, 0.15);
            border: 1px solid rgba(74, 144, 226, 0.3);
            font-size: 0.8rem;
            color: #AAA;
        }
        .hunt-item { margin-bottom: 0.3rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_export_buttons(data, prefix: str, key_suffix: str = "", is_dataframe: bool = False):
    """
    Render CSV and JSON export buttons for data.

    Args:
        data: Data to export (list of dicts or DataFrame)
        prefix: Filename prefix (e.g., "flows", "osint")
        key_suffix: Optional suffix for unique button keys
        is_dataframe: Whether data is a pandas DataFrame
    """
    if data is None or (is_dataframe and data.empty) or (not is_dataframe and not data):
        return

    col1, col2, _ = st.columns([1, 1, 4])

    with col1:
        if is_dataframe:
            csv_data = export_dataframe_to_csv(data)
        else:
            csv_data = export_to_csv(data)

        st.download_button(
            label="CSV",
            data=csv_data,
            file_name=generate_export_filename(prefix, "csv"),
            mime="text/csv",
            key=f"export_csv_{prefix}_{key_suffix}",
        )

    with col2:
        if is_dataframe:
            json_data = export_dataframe_to_json(data)
        else:
            json_data = export_to_json(data)

        st.download_button(
            label="JSON",
            data=json_data,
            file_name=generate_export_filename(prefix, "json"),
            mime="application/json",
            key=f"export_json_{prefix}_{key_suffix}",
        )


def make_tabs():
    """Top tabs: Upload • Progress • Dashboard • LLM Analysis • OSINT • Results • Cases • API Keys • Config."""
    tab_names = [
        "📤 Upload",
        "📈 Progress",
        "📊 Dashboard",
        "🤖 LLM Analysis",
        "🕵️ OSINT",
        "📋 Raw Data",
        "📁 Cases",
        "🔑 API Keys",
        "⚙️ Config",
    ]
    tabs = st.tabs(tab_names)
    return tabs[0], tabs[1], tabs[2], tabs[3], tabs[4], tabs[5], tabs[6], tabs[7], tabs[8]


def make_progress_panel(container):
    with container:
        st.markdown("### Progress")
        return st.container()


def make_results_panel(container):
    with container:
        st.markdown("### Results")
        return st.container()


# ---------------- Results renderers ----------------


def render_threat_summary(
    container,
    correlations: list | None,
    beacon_df=None,
    yara_results: dict | None = None,
    tls_analysis: dict | None = None,
    dns_analysis: dict | None = None,
):
    """Render an at-a-glance threat summary panel at the top of the dashboard."""
    with container:
        # --- Count threats by category ---
        critical = high = medium = low = 0
        if correlations:
            for c in correlations:
                v = (c.verdict if hasattr(c, "verdict") else c.get("verdict", "low")).lower()
                if v == "critical":
                    critical += 1
                elif v == "high":
                    high += 1
                elif v == "medium":
                    medium += 1
                else:
                    low += 1

        beacon_count = 0
        if beacon_df is not None and not beacon_df.empty and "score" in beacon_df.columns:
            beacon_count = int((beacon_df["score"] >= 0.6).sum())

        yara_count = 0
        if yara_results and isinstance(yara_results, dict):
            yara_count = yara_results.get("matched", 0)

        tls_issues = 0
        if tls_analysis and isinstance(tls_analysis, dict):
            tls_issues = (tls_analysis.get("self_signed", 0) or 0) + (tls_analysis.get("expired", 0) or 0)

        dns_alerts = 0
        if dns_analysis and isinstance(dns_analysis, dict):
            alerts = dns_analysis.get("alerts", {})
            dns_alerts = (alerts.get("dga_count", 0) or 0) + (alerts.get("tunneling_count", 0) or 0)

        total_alerts = critical + high + beacon_count + yara_count + tls_issues + dns_alerts

        # Determine overall risk level.
        # Beacons alone do not escalate to HIGH — many benign patterns
        # (ICMP health-checks, TLS keep-alives, NTP) trigger beacon scoring.
        # Require corroborating evidence (OSINT high, YARA hits, or multiple
        # beacon candidates with high scores) before escalating.
        # Corroboration count — how many distinct signal categories fired
        corroboration = sum(
            [
                beacon_count > 0,
                yara_count > 0,
                tls_issues > 0,
                dns_alerts > 0,
                high > 0 or critical > 0,
            ]
        )

        if critical > 0:
            risk, color = "CRITICAL", severity_color("critical")
        elif high > 0 or yara_count > 0:
            risk, color = "HIGH", severity_color("high")
        elif medium > 0 or (beacon_count >= 3 and corroboration >= 2) or (tls_issues > 0 and dns_alerts > 0):
            risk, color = "MEDIUM", severity_color("medium")
        elif correlations or beacon_count > 0 or tls_issues > 0 or dns_alerts > 0:
            risk, color = "LOW", severity_color("low")
        else:
            risk, color = "N/A", severity_color("unknown")

        # --- Render ---
        st.markdown(
            f'<div class="dashboard-card" style="border-left: 4px solid {color}; padding: 1rem;">'
            f"<strong>Threat Summary</strong></div>",
            unsafe_allow_html=True,
        )

        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric("Risk Level", risk)
        with c2:
            st.metric("Alerts", total_alerts)
        with c3:
            st.metric("Beacons", beacon_count)
        with c4:
            st.metric("YARA Hits", yara_count)
        with c5:
            st.metric("Cert Issues", tls_issues)

        # One-line detail
        parts = []
        if critical:
            parts.append(f"{critical} critical")
        if high:
            parts.append(f"{high} high-risk IPs")
        if beacon_count:
            parts.append(f"{beacon_count} beacon candidates")
        if yara_count:
            parts.append(f"{yara_count} YARA matches")
        if tls_issues:
            parts.append(f"{tls_issues} cert issues")
        if dns_alerts:
            parts.append(f"{dns_alerts} DNS alerts")
        if parts:
            st.caption(" | ".join(parts))
        elif correlations:
            st.caption("No high-severity indicators detected.")

        # --- Explainability expander ---
        with st.expander("Why this risk level?", expanded=False):
            st.caption(
                "Risk is the highest tier triggered below. Correlated, multi-signal findings "
                "outrank isolated heuristics."
            )
            reasons: list[str] = []
            if critical:
                reasons.append(f"🔴 {critical} critical correlation finding(s)")
            if high:
                reasons.append(f"🟠 {high} high-severity correlation finding(s)")
            if medium:
                reasons.append(f"🟡 {medium} medium-severity correlation finding(s)")
            if yara_count:
                reasons.append(f"🦠 {yara_count} YARA match(es) in carved files")
            if beacon_count:
                reasons.append(f"📡 {beacon_count} beaconing candidate(s) (score ≥ 0.6; needs corroboration)")
            if tls_issues:
                reasons.append(f"🔒 {tls_issues} TLS certificate trust issue(s) (expired + self-signed)")
            if dns_alerts:
                reasons.append(f"🌐 {dns_alerts} DNS anomaly signal(s) (DGA + tunneling)")
            if corroboration >= 2 and beacon_count >= 3:
                reasons.append(
                    f"⚠️ MEDIUM escalation: {beacon_count} beacon candidate(s) corroborated "
                    f"by {corroboration} distinct signal categories"
                )
            if tls_issues > 0 and dns_alerts > 0:
                reasons.append("⚠️ MEDIUM escalation: TLS trust issues corroborated by DNS anomalies")
            if not reasons:
                reasons.append("✅ No threat signals fired — nothing exceeded thresholds.")
            for r in reasons:
                st.markdown(f"- {r}")


def render_severity_legend() -> None:
    """One-line color legend so analysts calibrate once, not per-tab."""
    chips = " ".join(
        f'<span style="background:{SEVERITY_COLORS[lvl]["bg"]};color:{SEVERITY_COLORS[lvl]["fg"]};'
        f'padding:1px 8px;border-radius:8px;font-size:0.75rem;margin-right:4px;">{lvl.upper()}</span>'
        for lvl in SEVERITY_ORDER
    )
    st.markdown(f'<div style="margin:4px 0 8px 0;">{chips}</div>', unsafe_allow_html=True)


def render_overview(result_col, features):
    with result_col:
        st.markdown("#### Overview")
        feats = features or {"flows": [], "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []}}
        row = {
            "Public IPs": len([ip for ip in feats["artifacts"].get("ips", []) if is_public_ipv4(ip)]),
            "Domains": len(feats["artifacts"].get("domains", [])),
            "Flows": len(feats.get("flows", [])),
            "Carved Bodies": len(
                feats["artifacts"].get("hashes", []) if isinstance(feats.get("artifacts", {}), dict) else []
            ),
        }
        df = pd.DataFrame([row]).rename(index={0: ""})
        st.dataframe(df, width="stretch", hide_index=True)


def render_zeek(result_col, zeek_tables):
    with result_col:
        if zeek_tables:
            st.markdown("#### Zeek logs")
            names = sorted(zeek_tables.keys())
            tabs = st.tabs(names)
            for i, name in enumerate(names):
                with tabs[i]:
                    df = zeek_tables.get(name)
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        render_export_buttons(df, f"zeek_{name}", key_suffix=name, is_dataframe=True)
                        st.dataframe(df, width="stretch", hide_index=True)
                    else:
                        st.caption("No rows.")
        else:
            st.caption("No Zeek logs loaded.")


def render_carved(result_col, carved):
    with result_col:
        with st.expander("Carved HTTP payloads", expanded=bool(carved)):
            if carved:
                df = pd.DataFrame(carved)
                cols = ["time", "tcp_stream", "content_type", "content_length", "sha256", "path"]
                cols = [c for c in cols if c in df.columns]
                render_export_buttons(df[cols], "carved_payloads", key_suffix="carved", is_dataframe=True)
                st.dataframe(df[cols], width="stretch", hide_index=True)
            else:
                st.caption("No HTTP payloads carved.")


@st.dialog("WHOIS Info")
def show_whois_dialog(target: str):
    from app.utils.common import get_whois_info, is_public_ipv4

    with st.spinner(f"Fetching WHOIS for {target}..."):
        info = get_whois_info(target)

    if not isinstance(info, dict):
        st.error(str(info))
        return

    # Helper to safely get string or first item of list
    def _s(val):
        if isinstance(val, list):
            return str(val[0]) if val else "n/a"
        return str(val) if val else "n/a"

    # Helper to format dates (supporting space or T separator)
    def _d(val):
        if isinstance(val, list):
            val = val[0] if val else None
        if not val:
            return "n/a"
        s = str(val)
        if "T" in s:
            return s.split("T")[0]
        return s.split(" ")[0]

    # Header
    label = "IP" if is_public_ipv4(target) else "Domain"
    st.subheader(f"{label}: {info.get('domain_name', target)}")

    # Key Metrics
    st.text_input("Registrar", value=_s(info.get("registrar")), disabled=True)
    st.text_input("Created", value=_d(info.get("creation_date")), disabled=True)
    st.text_input("Expires", value=_d(info.get("expiration_date")), disabled=True)

    st.divider()

    # Registrant Info
    st.markdown("**Registrant Details**")
    rc1, rc2 = st.columns(2)
    with rc1:
        st.text_input("Name", value=_s(info.get("name")), disabled=True)
        st.text_input("Organization", value=_s(info.get("org")), disabled=True)
    with rc2:
        st.text_input("Email", value=_s(info.get("emails")), disabled=True)
        st.text_input("Country", value=_s(info.get("country")), disabled=True)

    # Location
    if info.get("city") or info.get("state"):
        st.caption(f"Location: {_s(info.get('city'))}, {_s(info.get('state'))}")

    # Name Servers
    if info.get("name_servers"):
        st.markdown("**Name Servers**")
        ns = info["name_servers"]
        if isinstance(ns, list):
            for n in ns:
                st.markdown(f"- `{n}`")
        else:
            st.markdown(f"- `{ns}`")

    st.divider()
    with st.expander("Raw Data"):
        st.json(info)


def _verdict_badge(verdict: str) -> str:
    """Return a colored HTML badge for an IOC verdict."""
    bg = severity_color(verdict)
    fg = severity_color(verdict, "fg")
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
        f"background:{bg};color:{fg};font-weight:600;font-size:0.8rem;"
        f'text-transform:uppercase;">{verdict}</span>'
    )


def _provider_pill(name: str, status: str) -> str:
    """Return a small pill showing provider status."""
    if status == "ok":
        bg, icon = "rgba(81,207,102,0.18)", "✅"
    elif status == "error":
        bg, icon = "rgba(255,107,107,0.18)", "❌"
    elif status == "cached":
        bg, icon = "rgba(77,171,247,0.18)", "💾"
    else:  # not configured
        bg, icon = "rgba(173,181,189,0.18)", "⚪"
    return (
        f'<span style="display:inline-block;padding:2px 8px;margin:2px;'
        f'border-radius:10px;background:{bg};font-size:0.75rem;">'
        f"{icon} {name}</span>"
    )


def _extract_vt_ip_stats(obj: dict) -> dict:
    """Extract VT detection stats from raw IP OSINT data."""
    vt = obj.get("vt") or {}
    attr = vt.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    return {
        "reputation": attr.get("reputation", "n/a"),
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "detections": f"{malicious}/{total}" if total > 0 else "n/a",
        "asn": attr.get("asn", ""),
        "as_owner": attr.get("as_owner", ""),
        "network": attr.get("network", ""),
        "last_analysis_date": attr.get("last_analysis_date", ""),
        "community_score": attr.get("reputation", 0),
    }


def _extract_abuseipdb_stats(obj: dict) -> dict:
    """Extract AbuseIPDB stats from raw OSINT data."""
    abuse = obj.get("abuseipdb") or {}
    data = abuse.get("data", abuse)  # AbuseIPDB wraps in 'data'
    return {
        "score": data.get("abuseConfidenceScore", data.get("score", "n/a")),
        "total_reports": data.get("totalReports", data.get("totalReports", 0)),
        "isp": data.get("isp", ""),
        "usage_type": data.get("usageType", ""),
        "domain": data.get("domain", ""),
        "is_tor": data.get("isTor", False),
        "is_whitelisted": data.get("isWhitelisted", False),
        "last_reported": data.get("lastReportedAt", ""),
    }


def _extract_shodan_stats(obj: dict) -> dict:
    """Extract Shodan stats from raw OSINT data."""
    shodan = obj.get("shodan") or {}
    ports = shodan.get("ports", [])
    vulns = shodan.get("vulns", [])
    hostnames = shodan.get("hostnames", [])
    os_info = shodan.get("os", "")
    org = shodan.get("org", "")
    return {
        "ports": ports[:20] if isinstance(ports, list) else [],
        "vulns": vulns[:10] if isinstance(vulns, list) else [],
        "hostnames": hostnames[:5] if isinstance(hostnames, list) else [],
        "os": os_info or "",
        "org": org or "",
        "isp": shodan.get("isp", ""),
        "last_update": shodan.get("last_update", ""),
        "country": shodan.get("country_name", ""),
        "city": shodan.get("city", ""),
    }


def _extract_greynoise_stats(obj: dict) -> dict:
    """Extract GreyNoise stats from raw OSINT data."""
    gn = obj.get("greynoise") or {}
    return {
        "classification": gn.get("classification", "n/a"),
        "name": gn.get("name", ""),
        "noise": gn.get("noise", False),
        "riot": gn.get("riot", False),
        "link": gn.get("link", ""),
    }


def _determine_ip_verdict(vt_stats: dict, abuse_stats: dict, gn_stats: dict, shodan_stats: dict) -> str:
    """Determine overall verdict for an IP based on all provider data."""
    vt_malicious = vt_stats.get("malicious", 0)
    abuse_score = abuse_stats.get("score", 0)
    if isinstance(abuse_score, str):
        abuse_score = 0
    gn_class = gn_stats.get("classification", "unknown")
    vulns = shodan_stats.get("vulns", [])

    if vt_malicious >= 5 or abuse_score >= 80 or gn_class == "malicious":
        return "critical"
    elif vt_malicious >= 2 or abuse_score >= 50 or len(vulns) >= 3:
        return "high"
    elif vt_malicious >= 1 or abuse_score >= 20 or gn_class == "unknown":
        return "medium"
    elif gn_class == "benign" and abuse_score == 0 and vt_malicious == 0:
        return "clean"
    return "low"


def _determine_domain_verdict(obj: dict) -> str:
    """Determine overall verdict for a domain."""
    vt = obj.get("vt") or {}
    attr = vt.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    otx = obj.get("otx") or {}
    pulse_count = len(otx.get("pulse_info", {}).get("pulses", [])) if isinstance(otx.get("pulse_info"), dict) else 0

    if malicious >= 5 or pulse_count >= 10:
        return "critical"
    elif malicious >= 2 or pulse_count >= 5:
        return "high"
    elif malicious >= 1 or suspicious >= 2 or pulse_count >= 1:
        return "medium"
    elif malicious == 0 and suspicious == 0:
        return "clean"
    return "low"


def _categorize_domain(domain: str, vt_attr: dict) -> str:
    """Categorize a domain (CDN, Cloud, DGA, Hosting, etc.)."""
    import math

    cats = vt_attr.get("categories", {})
    if isinstance(cats, dict):
        for v in cats.values():
            v_lower = str(v).lower()
            if "cdn" in v_lower:
                return "CDN"
            if "cloud" in v_lower:
                return "Cloud"
            if "malware" in v_lower or "phishing" in v_lower:
                return "Malicious"
            if "parking" in v_lower or "parked" in v_lower:
                return "Parked"

    # Simple DGA heuristic — high consonant ratio + high entropy
    if domain and "." in domain:
        label = domain.split(".")[0]
        if len(label) > 8:
            consonants = sum(1 for c in label.lower() if c.isalpha() and c not in "aeiou")
            ratio = consonants / max(len(label), 1)
            # Shannon entropy
            freq = {}
            for c in label:
                freq[c] = freq.get(c, 0) + 1
            entropy = -sum((cnt / len(label)) * math.log2(cnt / len(label)) for cnt in freq.values())
            if entropy > 3.5 and ratio > 0.7:
                return "DGA-suspect"

    # Common CDN/Cloud patterns
    cdn_patterns = ["cloudfront", "akamai", "fastly", "cloudflare", "cdn", "edgecast"]
    cloud_patterns = ["amazonaws", "azure", "googleapis", "gcloud", "digitalocean"]
    for pat in cdn_patterns:
        if pat in domain.lower():
            return "CDN"
    for pat in cloud_patterns:
        if pat in domain.lower():
            return "Cloud"

    return "General"


def _render_ip_detail_card(ip: str, obj: dict, vt: dict, abuse: dict, gn: dict, shodan: dict):
    """Render an expandable detail card for a single IP."""
    verdict = _determine_ip_verdict(vt, abuse, gn, shodan)

    with st.expander(f"🔍 {ip}  —  {_verdict_badge(verdict)}", expanded=False):
        # Provider status pills
        providers_html = ""
        ip_providers_map = [
            ("VT", "vt"),
            ("AbuseIPDB", "abuseipdb"),
            ("GreyNoise", "greynoise"),
            ("Shodan", "shodan"),
        ]
        for name, data_key in ip_providers_map:
            raw = obj.get(data_key)
            if raw is None:
                providers_html += _provider_pill(name, "none")
            elif raw.get("_error"):
                providers_html += _provider_pill(name, "error")
            elif raw.get("_cached"):
                providers_html += _provider_pill(name, "cached")
            else:
                providers_html += _provider_pill(name, "ok")
        st.markdown(f"**Providers:** {providers_html}", unsafe_allow_html=True)

        # Three-column layout for key data
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**VirusTotal**")
            st.text(f"Detections: {vt.get('detections', 'n/a')}")
            st.text(f"Reputation: {vt.get('reputation', 'n/a')}")
            st.text(f"ASN: {vt.get('asn', 'n/a')} ({vt.get('as_owner', '')})")
            st.text(f"Network: {vt.get('network', 'n/a')}")

        with c2:
            st.markdown("**AbuseIPDB**")
            abuse_score_val = abuse.get("score", "n/a")
            st.text(f"Confidence: {abuse_score_val}%")
            st.text(f"Reports: {abuse.get('total_reports', 0)}")
            st.text(f"ISP: {abuse.get('isp', 'n/a')}")
            st.text(f"Usage: {abuse.get('usage_type', 'n/a')}")
            if abuse.get("is_tor"):
                st.warning("🧅 TOR Exit Node")

        with c3:
            st.markdown("**GreyNoise**")
            gn_class = gn.get("classification", "n/a")
            gn_color = {"malicious": "🔴", "benign": "🟢", "unknown": "🟡"}.get(gn_class, "⚪")
            st.text(f"Classification: {gn_color} {gn_class}")
            st.text(f"Name: {gn.get('name', 'n/a')}")
            if gn.get("riot"):
                st.info("ℹ️ Known benign service (RIOT)")

        # Shodan section
        if shodan.get("ports") or shodan.get("vulns") or shodan.get("os"):
            st.markdown("---")
            sc1, sc2 = st.columns(2)
            with sc1:
                st.markdown("**Shodan**")
                if shodan.get("ports"):
                    st.text(f"Open Ports: {', '.join(str(p) for p in shodan['ports'])}")
                if shodan.get("os"):
                    st.text(f"OS: {shodan['os']}")
                if shodan.get("org"):
                    st.text(f"Org: {shodan['org']}")
                if shodan.get("hostnames"):
                    st.text(f"Hostnames: {', '.join(shodan['hostnames'])}")
            with sc2:
                if shodan.get("vulns"):
                    st.markdown("**Known Vulnerabilities**")
                    for cve in shodan["vulns"][:10]:
                        st.error(f"⚠️ {cve}")

        # GeoIP + PTR
        st.markdown("---")
        gc1, gc2 = st.columns(2)
        with gc1:
            st.text(f"Country: {obj.get('country', 'n/a')}")
            st.text(f"City: {obj.get('city', 'n/a')}")
        with gc2:
            st.text(f"PTR: {obj.get('ptr', 'n/a')}")
            if abuse.get("last_reported"):
                st.text(f"Last Reported: {abuse['last_reported']}")

    return verdict


def _render_provider_status_bar(osint_data: dict):
    """Render provider configuration and response status indicators."""
    ips_data = osint_data.get("ips") or {}
    if not ips_data:
        return

    # Sample first IP to determine provider status
    sample = next(iter(ips_data.values()), {})
    providers = {
        "VirusTotal": "vt",
        "AbuseIPDB": "abuseipdb",
        "GreyNoise": "greynoise",
        "Shodan": "shodan",
    }

    pills = []
    for name, key in providers.items():
        raw = sample.get(key)
        if raw is None:
            pills.append(_provider_pill(name, "none"))
        elif raw.get("_error"):
            pills.append(_provider_pill(name, "error"))
        elif raw.get("_cached"):
            pills.append(_provider_pill(name, "cached"))
        else:
            pills.append(_provider_pill(name, "ok"))

    # Domain providers
    doms_data = osint_data.get("domains") or {}
    if doms_data:
        sample_dom = next(iter(doms_data.values()), {})
        for name, key in [("VT (Domain)", "vt"), ("OTX", "otx")]:
            raw = sample_dom.get(key)
            if raw is None:
                pills.append(_provider_pill(name, "none"))
            elif raw.get("_error"):
                pills.append(_provider_pill(name, "error"))
            elif raw.get("_cached"):
                pills.append(_provider_pill(name, "cached"))
            else:
                pills.append(_provider_pill(name, "ok"))

    st.markdown("**Provider Status:** " + " ".join(pills), unsafe_allow_html=True)


def _render_osint_coverage_heatmap(osint_data: dict):
    """Render a coverage heatmap showing which IOCs have full/partial/no OSINT data."""
    ips_data = osint_data.get("ips") or {}
    doms_data = osint_data.get("domains") or {}
    if not ips_data and not doms_data:
        return

    full = partial = none_count = 0
    ip_providers = ["vt", "abuseipdb", "greynoise", "shodan"]
    for obj in ips_data.values():
        has = sum(1 for p in ip_providers if obj.get(p) and not obj.get(p, {}).get("_error"))
        if has == len(ip_providers):
            full += 1
        elif has > 0:
            partial += 1
        else:
            none_count += 1

    dom_providers = ["vt", "otx"]
    for obj in doms_data.values():
        has = sum(1 for p in dom_providers if obj.get(p) and not obj.get(p, {}).get("_error"))
        if has == len(dom_providers):
            full += 1
        elif has > 0:
            partial += 1
        else:
            none_count += 1

    total = full + partial + none_count
    if total == 0:
        return

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total IOCs", total)
    with c2:
        st.metric("Full Coverage", full, help="All configured providers returned data")
    with c3:
        st.metric("Partial", partial, help="Some providers returned data")
    with c4:
        st.metric("No Data", none_count, help="No provider data available")

    # Simple bar
    if total > 0:
        pct_full = full / total * 100
        pct_partial = partial / total * 100
        pct_none = none_count / total * 100
        st.markdown(
            f'<div style="display:flex;height:8px;border-radius:4px;overflow:hidden;margin-bottom:1rem;">'
            f'<div style="width:{pct_full}%;background:#51cf66;"></div>'
            f'<div style="width:{pct_partial}%;background:#ffd43b;"></div>'
            f'<div style="width:{pct_none}%;background:#adb5bd;"></div>'
            f"</div>",
            unsafe_allow_html=True,
        )


def _render_asn_grouping(osint_data: dict):
    """Render IPs grouped by ASN/Organization."""
    ips_data = osint_data.get("ips") or {}
    if not ips_data:
        return

    asn_groups: dict[str, list] = {}
    for ip, obj in ips_data.items():
        vt_attr = (obj.get("vt") or {}).get("data", {}).get("attributes", {})
        shodan = obj.get("shodan") or {}
        asn = vt_attr.get("as_owner") or shodan.get("org") or "Unknown"
        asn_num = vt_attr.get("asn", "")
        key = f"AS{asn_num} — {asn}" if asn_num else asn
        if key not in asn_groups:
            asn_groups[key] = []
        asn_groups[key].append(ip)

    if not asn_groups:
        return

    # Sort by number of IPs (descending) to surface infrastructure patterns
    sorted_groups = sorted(asn_groups.items(), key=lambda x: len(x[1]), reverse=True)

    rows = []
    for asn_label, ips in sorted_groups:
        rows.append(
            {
                "ASN / Organization": asn_label,
                "IP Count": len(ips),
                "IPs": ", ".join(ips[:10]) + ("..." if len(ips) > 10 else ""),
            }
        )

    if rows:
        st.markdown("#### ASN / Organization Grouping")
        st.caption("IPs grouped by autonomous system — spot shared infrastructure.")
        df = pd.DataFrame(rows)
        st.dataframe(df, width="stretch", hide_index=True)


def _render_related_iocs(osint_data: dict):
    """Render related IOC discovery — IPs in same /24 subnet, domains on same IP."""
    ips_data = osint_data.get("ips") or {}
    if len(ips_data) < 2:
        return

    # Group by /24 subnet
    subnet_groups: dict[str, list] = {}
    for ip in ips_data:
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = ".".join(parts[:3]) + ".0/24"
            if subnet not in subnet_groups:
                subnet_groups[subnet] = []
            subnet_groups[subnet].append(ip)

    # Only show subnets with multiple IPs
    shared_subnets = {k: v for k, v in subnet_groups.items() if len(v) >= 2}
    if not shared_subnets:
        return

    st.markdown("#### Related IOC Discovery")
    st.caption("IPs sharing the same /24 subnet — may indicate shared infrastructure.")

    rows = []
    for subnet, ips in sorted(shared_subnets.items(), key=lambda x: len(x[1]), reverse=True):
        rows.append(
            {
                "Subnet": subnet,
                "Count": len(ips),
                "IPs": ", ".join(ips),
            }
        )

    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def _render_ioc_export_panel(osint_data: dict):
    """Render IOC export panel with multiple format options."""
    import json as _json

    ips_data = osint_data.get("ips") or {}
    doms_data = osint_data.get("domains") or {}
    if not ips_data and not doms_data:
        return

    st.markdown("#### IOC Export")
    fmt = st.radio("Format", ["CSV", "JSON", "STIX 2.1", "Clipboard-ready"], horizontal=True, key="ioc_export_fmt")

    all_iocs = []
    for ip, obj in ips_data.items():
        vt = _extract_vt_ip_stats(obj)
        abuse = _extract_abuseipdb_stats(obj)
        gn = _extract_greynoise_stats(obj)
        verdict = _determine_ip_verdict(vt, abuse, gn, _extract_shodan_stats(obj))
        all_iocs.append(
            {
                "type": "ip",
                "value": ip,
                "verdict": verdict,
                "vt_detections": vt.get("detections", ""),
                "abuse_score": abuse.get("score", ""),
                "greynoise": gn.get("classification", ""),
                "country": obj.get("country", ""),
                "ptr": obj.get("ptr", ""),
            }
        )

    for dom, obj in doms_data.items():
        verdict = _determine_domain_verdict(obj)
        vt_attr = (obj.get("vt") or {}).get("data", {}).get("attributes", {})
        stats = vt_attr.get("last_analysis_stats", {})
        all_iocs.append(
            {
                "type": "domain",
                "value": dom,
                "verdict": verdict,
                "vt_detections": f"{stats.get('malicious', 0)}/{sum(stats.values()) if stats else 0}",
            }
        )

    if fmt == "CSV":
        csv_bytes = export_to_csv(all_iocs)
        st.download_button(
            "📥 Download CSV", csv_bytes, generate_export_filename("iocs", "csv"), "text/csv", key="ioc_dl_csv"
        )
    elif fmt == "JSON":
        json_bytes = export_to_json(all_iocs)
        st.download_button(
            "📥 Download JSON",
            json_bytes,
            generate_export_filename("iocs", "json"),
            "application/json",
            key="ioc_dl_json",
        )
    elif fmt == "STIX 2.1":
        stix_bundle = _build_stix_bundle(all_iocs)
        stix_bytes = _json.dumps(stix_bundle, indent=2).encode("utf-8")
        st.download_button(
            "📥 Download STIX 2.1",
            stix_bytes,
            generate_export_filename("iocs", "stix.json"),
            "application/json",
            key="ioc_dl_stix",
        )
    elif fmt == "Clipboard-ready":
        lines = [ioc["value"] for ioc in all_iocs]
        st.code("\n".join(lines), language="text")


def _build_stix_bundle(iocs: list[dict]) -> dict:
    """Build a minimal STIX 2.1 bundle from IOCs."""
    import datetime
    import uuid

    objects = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for ioc in iocs:
        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")

        if ioc_type == "ip":
            obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"IP: {value}",
                "pattern": f"[ipv4-addr:value = '{value}']",
                "pattern_type": "stix",
                "valid_from": now,
                "labels": [f"verdict:{ioc.get('verdict', 'unknown')}"],
            }
        elif ioc_type == "domain":
            obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Domain: {value}",
                "pattern": f"[domain-name:value = '{value}']",
                "pattern_type": "stix",
                "valid_from": now,
                "labels": [f"verdict:{ioc.get('verdict', 'unknown')}"],
            }
        else:
            continue
        objects.append(obj)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _render_geo_map(osint_data: dict):
    """Render a world map of IP geolocations using Plotly scatter_geo."""
    ips_data = osint_data.get("ips") or {}
    if not ips_data:
        return

    # Build location data from GeoIP and Shodan
    geo_rows = []
    for ip, obj in ips_data.items():
        country = obj.get("country", "")
        city = obj.get("city", "")
        if country:
            vt = _extract_vt_ip_stats(obj)
            abuse = _extract_abuseipdb_stats(obj)
            gn = _extract_greynoise_stats(obj)
            verdict = _determine_ip_verdict(vt, abuse, gn, _extract_shodan_stats(obj))
            geo_rows.append(
                {
                    "IP": ip,
                    "Country": country,
                    "City": city or "",
                    "Verdict": verdict,
                    "VT Detections": vt.get("detections", "n/a"),
                }
            )

    if not geo_rows:
        return

    st.markdown("#### IP Geolocation Map")
    df_geo = pd.DataFrame(geo_rows)
    # Group by country for a choropleth count
    country_counts = df_geo["Country"].value_counts().reset_index()
    country_counts.columns = ["Country", "Count"]

    try:
        import plotly.express as px

        fig = px.choropleth(
            country_counts,
            locations="Country",
            locationmode="country names",
            color="Count",
            color_continuous_scale="Reds",
            title="",
            height=350,
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            geo=dict(showframe=False, showcoastlines=True, projection_type="natural earth"),
            coloraxis_colorbar=dict(title="IPs"),
        )
        st.plotly_chart(fig, use_container_width=True)
    except ImportError:
        st.warning("Plotly required for geo map. Install with: pip install plotly")

    # Detail table
    st.dataframe(df_geo, width="stretch", hide_index=True)


def _render_analyst_notes(osint_data: dict):
    """Render per-IOC analyst notes with session-state persistence."""
    key = "osint_analyst_notes"
    if key not in st.session_state:
        st.session_state[key] = {}

    notes = st.session_state[key]

    st.markdown("#### Analyst Notes")
    st.caption("Add notes for any IOC. Notes are saved for this session.")

    ips = list((osint_data.get("ips") or {}).keys())
    doms = list((osint_data.get("domains") or {}).keys())
    all_iocs = [f"IP: {ip}" for ip in ips] + [f"Domain: {d}" for d in doms]

    if not all_iocs:
        st.info("No IOCs available for notes.")
        return

    selected = st.selectbox("Select IOC", all_iocs, key="note_ioc_select")
    current_note = notes.get(selected, "")
    new_note = st.text_area("Note", value=current_note, key="note_text_area", height=100)
    if st.button("💾 Save Note", key="save_note_btn"):
        notes[selected] = new_note
        st.session_state[key] = notes
        st.success(f"Note saved for {selected}")

    # Show all existing notes
    if notes:
        st.markdown("---")
        st.markdown("**Saved Notes:**")
        for ioc_label, note_text in notes.items():
            if note_text.strip():
                st.markdown(f"**{ioc_label}:** {note_text}")


def render_osint(result_col, osint_data, *, correlations=None, features=None, beacon_df=None):
    """Render comprehensive OSINT investigation panel with all enrichment data."""
    # Initialize selection state trackers
    if "last_ip_sel" not in st.session_state:
        st.session_state["last_ip_sel"] = []
    if "last_dom_sel" not in st.session_state:
        st.session_state["last_dom_sel"] = []

    with result_col:
        # Provider status bar
        _render_provider_status_bar(osint_data)

        # Coverage heatmap
        _render_osint_coverage_heatmap(osint_data)

        st.markdown("---")

        # Main tabs
        tab_ips, tab_doms, tab_details, tab_geo, tab_infra, tab_export, tab_devices, tab_notes = st.tabs(
            [
                "🎯 IP Triage",
                "🌐 Domains",
                "🔍 Detail Cards",
                "🗺️ Geo Map",
                "🏗️ Infrastructure",
                "📦 Export",
                "💻 Devices",
                "📝 Notes",
            ]
        )

        # ==================== IP TRIAGE TAB ====================
        with tab_ips:
            st.caption("Prioritized IP table — select a row for WHOIS lookup.")
            ip_rows = []
            for ip, obj in (osint_data.get("ips") or {}).items():
                vt = _extract_vt_ip_stats(obj)
                abuse = _extract_abuseipdb_stats(obj)
                gn = _extract_greynoise_stats(obj)
                shodan = _extract_shodan_stats(obj)
                verdict = _determine_ip_verdict(vt, abuse, gn, shodan)

                # Check if IP appears in flow data (cross-reference)
                in_flows = False
                if features and isinstance(features, dict):
                    flow_ips = features.get("artifacts", {}).get("ips", [])
                    in_flows = ip in flow_ips

                ip_rows.append(
                    {
                        "Verdict": verdict.upper(),
                        "IP": ip,
                        "ASN/Org": f"{vt.get('as_owner', '') or shodan.get('org', '')}",
                        "Country": obj.get("country", "n/a"),
                        "AbuseIPDB": f"{abuse.get('score', 'n/a')}% ({abuse.get('total_reports', 0)} rpts)",
                        "VT": vt.get("detections", "n/a"),
                        "GreyNoise": gn.get("classification", "n/a"),
                        "Shodan Ports": ", ".join(str(p) for p in shodan.get("ports", [])[:8]) or "n/a",
                        "PTR": obj.get("ptr", "n/a"),
                        "In Flows": "✅" if in_flows else "",
                        "_sort_score": (
                            {"critical": 4, "high": 3, "medium": 2, "low": 1, "clean": 0, "unknown": 0}.get(verdict, 0)
                        ),
                    }
                )

            if ip_rows:
                # Sort by verdict severity
                ip_rows.sort(key=lambda r: r["_sort_score"], reverse=True)
                # Remove internal sort key
                for r in ip_rows:
                    del r["_sort_score"]

                df_ips = pd.DataFrame(ip_rows)

                # Color-code verdict column using Streamlit column_config
                render_export_buttons(df_ips, "osint_ips", key_suffix="ips_v2", is_dataframe=True)

                # Apply row coloring via HTML (low/unknown rows stay untinted)
                def _color_rows(row):
                    v = (row.get("Verdict") or "").lower()
                    if v in ("low", "unknown") or not v:
                        return [""] * len(row)
                    return [f"background-color: {severity_color(v, 'rgba')};"] * len(row)

                styled = df_ips.style.apply(_color_rows, axis=1)

                event = st.dataframe(
                    styled,
                    width="stretch",
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key=f"osint_ips_v2_{len(ip_rows)}",
                )

                current_sel = event.selection.rows
                if current_sel != st.session_state["last_ip_sel"]:
                    st.session_state["last_ip_sel"] = current_sel
                    if current_sel:
                        idx = current_sel[0]
                        target_ip = df_ips.iloc[idx]["IP"]
                        show_whois_dialog(target_ip)

                # Verdict summary
                from collections import Counter

                verdict_counts = Counter(r["Verdict"] for r in ip_rows if "Verdict" in r)
                # Use the original ip_rows which still has Verdict
                parts = []
                for v in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]:
                    cnt = verdict_counts.get(v, 0)
                    if cnt:
                        parts.append(f"{_verdict_badge(v)} ×{cnt}")
                if parts:
                    st.markdown(" ".join(parts), unsafe_allow_html=True)

                # Quick-copy IOC list
                with st.expander("📋 Copy IOCs to clipboard", expanded=False):
                    all_ips_text = "\n".join(r["IP"] for r in ip_rows)
                    st.code(all_ips_text, language="text")
                    threat_ips = [r["IP"] for r in ip_rows if r.get("Verdict") in ("CRITICAL", "HIGH")]
                    if threat_ips:
                        st.markdown("**High-risk IPs only:**")
                        st.code("\n".join(threat_ips), language="text")
            else:
                st.info("No public IP findings.")

        # ==================== DOMAINS TAB ====================
        with tab_doms:
            st.caption("Domain enrichment — select a row for WHOIS lookup.")
            dom_rows = []
            for dom, obj in (osint_data.get("domains") or {}).items():
                vt = obj.get("vt") or {}
                vt_attr = vt.get("data", {}).get("attributes", {})
                stats = vt_attr.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0

                otx = obj.get("otx") or {}
                pulse_info = otx.get("pulse_info", {})
                pulse_count = len(pulse_info.get("pulses", [])) if isinstance(pulse_info, dict) else 0

                cats = vt_attr.get("categories", {})
                cat_str = ", ".join(str(v) for v in cats.values()) if isinstance(cats, dict) and cats else "n/a"

                verdict = _determine_domain_verdict(obj)
                category = _categorize_domain(dom, vt_attr)

                # WHOIS-like data from VT
                creation_date = vt_attr.get("creation_date", "")
                registrar = vt_attr.get("registrar", "")

                # Domain age calculation
                age_str = "n/a"
                if creation_date:
                    try:
                        import datetime

                        if isinstance(creation_date, (int, float)):
                            created = datetime.datetime.fromtimestamp(creation_date, tz=datetime.timezone.utc)
                        else:
                            created = datetime.datetime.fromisoformat(str(creation_date))
                        age_days = (datetime.datetime.now(datetime.timezone.utc) - created).days
                        if age_days < 30:
                            age_str = f"⚠️ {age_days}d"
                        elif age_days < 365:
                            age_str = f"{age_days // 30}mo"
                        else:
                            age_str = f"{age_days // 365}y"
                    except Exception:
                        age_str = "n/a"

                dom_rows.append(
                    {
                        "Verdict": verdict.upper(),
                        "Domain": dom,
                        "Category": category,
                        "VT Detections": f"{malicious}/{total}" if total > 0 else "n/a",
                        "OTX Pulses": pulse_count,
                        "VT Categories": cat_str,
                        "Registrar": registrar or "n/a",
                        "Age": age_str,
                        "_sort": {"critical": 4, "high": 3, "medium": 2, "low": 1, "clean": 0}.get(verdict, 0),
                    }
                )

            if dom_rows:
                dom_rows.sort(key=lambda r: r["_sort"], reverse=True)
                for r in dom_rows:
                    del r["_sort"]

                df_doms = pd.DataFrame(dom_rows)
                render_export_buttons(df_doms, "osint_domains", key_suffix="doms_v2", is_dataframe=True)

                def _color_dom_rows(row):
                    v = (row.get("Verdict") or "").lower()
                    if v in ("low", "unknown") or not v:
                        return [""] * len(row)
                    return [f"background-color: {severity_color(v, 'rgba')};"] * len(row)

                styled = df_doms.style.apply(_color_dom_rows, axis=1)

                event = st.dataframe(
                    styled,
                    width="stretch",
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key=f"osint_doms_v2_{len(dom_rows)}",
                )

                current_sel = event.selection.rows
                if current_sel != st.session_state["last_dom_sel"]:
                    st.session_state["last_dom_sel"] = current_sel
                    if current_sel:
                        idx = current_sel[0]
                        target_dom = df_doms.iloc[idx]["Domain"]
                        show_whois_dialog(target_dom)

                # Verdict summary
                from collections import Counter

                dom_verdict_counts = Counter(r["Verdict"] for r in dom_rows if "Verdict" in r)
                parts = []
                for v in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]:
                    cnt = dom_verdict_counts.get(v, 0)
                    if cnt:
                        parts.append(f"{_verdict_badge(v)} ×{cnt}")
                if parts:
                    st.markdown(" ".join(parts), unsafe_allow_html=True)

                # Passive DNS section
                st.markdown("---")
                st.markdown("##### Passive DNS History")
                st.caption("Historical resolution data from VirusTotal / OTX.")
                pdns_rows = []
                for dom, obj in (osint_data.get("domains") or {}).items():
                    # VT passive DNS (resolutions)
                    vt = obj.get("vt") or {}
                    vt_attr = vt.get("data", {}).get("attributes", {})
                    last_dns = vt_attr.get("last_dns_records", [])
                    if isinstance(last_dns, list):
                        for rec in last_dns[:5]:
                            pdns_rows.append(
                                {
                                    "Domain": dom,
                                    "Type": rec.get("type", ""),
                                    "Value": rec.get("value", ""),
                                    "TTL": rec.get("ttl", ""),
                                    "Source": "VirusTotal",
                                }
                            )

                    # OTX passive DNS
                    otx = obj.get("otx") or {}
                    pdns = otx.get("passive_dns", [])
                    if isinstance(pdns, list):
                        for rec in pdns[:5]:
                            pdns_rows.append(
                                {
                                    "Domain": dom,
                                    "Type": "A",
                                    "Value": rec.get("address", rec.get("hostname", "")),
                                    "TTL": "",
                                    "Source": "OTX",
                                }
                            )

                if pdns_rows:
                    st.dataframe(pd.DataFrame(pdns_rows), width="stretch", hide_index=True)
                else:
                    st.caption("No passive DNS records available.")
            else:
                st.info("No domain findings.")

        # ==================== DETAIL CARDS TAB ====================
        with tab_details:
            st.markdown("#### IP Detail Cards")
            st.caption("Expand any card for full provider data, vulnerabilities, and context.")
            ips_data = osint_data.get("ips") or {}
            if ips_data:
                # Sort by threat level
                sorted_ips = []
                for ip, obj in ips_data.items():
                    vt = _extract_vt_ip_stats(obj)
                    abuse = _extract_abuseipdb_stats(obj)
                    gn = _extract_greynoise_stats(obj)
                    shodan = _extract_shodan_stats(obj)
                    verdict = _determine_ip_verdict(vt, abuse, gn, shodan)
                    sort_val = {"critical": 4, "high": 3, "medium": 2, "low": 1, "clean": 0}.get(verdict, 0)
                    sorted_ips.append((sort_val, ip, obj, vt, abuse, gn, shodan))
                sorted_ips.sort(key=lambda x: x[0], reverse=True)

                for _, ip, obj, vt, abuse, gn, shodan in sorted_ips:
                    _render_ip_detail_card(ip, obj, vt, abuse, gn, shodan)
            else:
                st.info("No IP data available for detail view.")

        # ==================== GEO MAP TAB ====================
        with tab_geo:
            _render_geo_map(osint_data)

        # ==================== INFRASTRUCTURE TAB ====================
        with tab_infra:
            _render_asn_grouping(osint_data)
            st.markdown("---")
            _render_related_iocs(osint_data)

            # Threat actor attribution via OTX pulses
            st.markdown("---")
            st.markdown("#### Threat Intelligence Attribution")
            st.caption("Threat actors and campaigns linked to observed IOCs via OTX pulses.")

            pulse_rows = []
            for dom, obj in (osint_data.get("domains") or {}).items():
                otx = obj.get("otx") or {}
                pulse_info = otx.get("pulse_info", {})
                if isinstance(pulse_info, dict):
                    for pulse in pulse_info.get("pulses", [])[:10]:
                        tags = pulse.get("tags", [])
                        pulse_rows.append(
                            {
                                "IOC": dom,
                                "Pulse": pulse.get("name", ""),
                                "Author": pulse.get("author_name", ""),
                                "Created": str(pulse.get("created", ""))[:10],
                                "Tags": ", ".join(tags[:5]) if isinstance(tags, list) else "",
                                "TLP": pulse.get("TLP", ""),
                            }
                        )

            if pulse_rows:
                df_pulses = pd.DataFrame(pulse_rows)
                render_export_buttons(df_pulses, "otx_pulses", key_suffix="pulses", is_dataframe=True)
                st.dataframe(df_pulses, width="stretch", hide_index=True)
            else:
                st.caption("No threat intelligence attribution data available.")

        # ==================== EXPORT TAB ====================
        with tab_export:
            _render_ioc_export_panel(osint_data)

        # ==================== DEVICES TAB ====================
        with tab_devices:
            st.markdown("#### Device & MAC Identification")
            mac_data = osint_data.get("macs") or {}
            if mac_data:
                mac_rows = []
                for mac, info in mac_data.items():
                    mac_rows.append({"MAC Address": mac, "Manufacturer": info.get("manufacturer", "Unknown")})
                st.dataframe(pd.DataFrame(mac_rows), width="stretch", hide_index=True)
            else:
                st.info("No MAC address information available.")

        # ==================== NOTES TAB ====================
        with tab_notes:
            _render_analyst_notes(osint_data)


def render_flows(result_col, flows: list[dict] | None):
    """Render flows table with export buttons."""
    with result_col:
        with st.expander("Flow Data", expanded=False):
            if flows:
                df = pd.DataFrame(flows)
                # Select key columns if available
                display_cols = ["src", "dst", "sport", "dport", "proto", "count"]
                display_cols = [c for c in display_cols if c in df.columns]
                if display_cols:
                    render_export_buttons(df[display_cols], "flows", key_suffix="flows", is_dataframe=True)
                    st.dataframe(df[display_cols], width="stretch", hide_index=True)
                else:
                    render_export_buttons(df, "flows", key_suffix="flows_all", is_dataframe=True)
                    st.dataframe(df, width="stretch", hide_index=True)
            else:
                st.caption("No flow data available.")


def render_ja3(result_col, ja3_df, ja3_analysis: dict | None):
    """Render JA3 fingerprint analysis results."""
    with result_col:
        with st.expander("JA3 TLS Fingerprints", expanded=bool(ja3_analysis and ja3_analysis.get("malware_detected"))):
            if ja3_analysis and ja3_analysis.get("total_tls_sessions", 0) > 0:
                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("TLS Sessions", ja3_analysis.get("total_tls_sessions", 0))
                with col2:
                    st.metric("Unique JA3", ja3_analysis.get("unique_ja3", 0))
                with col3:
                    unknown = ja3_analysis.get("unknown_ja3", 0)
                    st.metric("Unknown", unknown)
                with col4:
                    if ja3_analysis.get("malware_detected"):
                        st.metric("Malware Detected", "YES", delta="Alert", delta_color="inverse")
                    else:
                        st.metric("Malware Detected", "No")

                # Malware warning
                if ja3_analysis.get("malware_detected"):
                    st.error("Malware JA3 fingerprints detected!")
                    malware_list = ja3_analysis.get("malware_ja3", [])
                    for m in malware_list:
                        st.warning(f"**{m.get('ja3_client')}** detected: {m.get('src')} -> {m.get('dst')}")

                # Top clients
                top_clients = ja3_analysis.get("top_clients", {})
                if top_clients:
                    st.markdown("**Top TLS Clients:**")
                    for client, count in list(top_clients.items())[:5]:
                        st.text(f"  {client}: {count}")

                # Full table
                if ja3_df is not None and not ja3_df.empty:
                    st.markdown("---")
                    display_cols = ["src", "dst", "server_name", "ja3", "ja3_client", "ja3_malware"]
                    display_cols = [c for c in display_cols if c in ja3_df.columns]
                    if display_cols:
                        render_export_buttons(ja3_df[display_cols], "ja3", key_suffix="ja3", is_dataframe=True)
                        st.dataframe(ja3_df[display_cols], width="stretch", hide_index=True)
            else:
                st.caption("No TLS/JA3 data available. Run analysis with PCAP containing TLS traffic.")


def render_report(result_col, report_md):
    with result_col:
        st.markdown("#### LLM Report")
        if report_md:
            st.markdown(report_md)
        else:
            st.caption("No report yet.")


def render_dns_analysis(result_col, dns_analysis: dict | None):
    """Render DNS analysis results with DGA, tunneling, and fast flux detection."""
    with result_col:
        expanded = bool(
            dns_analysis is not None
            and (
                dns_analysis.get("alerts", {}).get("dga_count", 0)
                or dns_analysis.get("alerts", {}).get("tunneling_count", 0)
                or dns_analysis.get("alerts", {}).get("fast_flux_count", 0)
            )
        )
        with st.expander("DNS Analysis", expanded=expanded):
            if dns_analysis is None or dns_analysis.get("error") or dns_analysis.get("skipped"):
                st.caption("No DNS analysis data available.")
                return

            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("DNS Records", dns_analysis.get("total_records", 0))
            with col2:
                st.metric("Unique Domains", dns_analysis.get("unique_domains", 0))
            with col3:
                st.metric("DNS Servers", dns_analysis.get("unique_dns_servers", 0))
            with col4:
                alerts = dns_analysis.get("alerts", {})
                total_alerts = (
                    alerts.get("dga_count", 0) + alerts.get("tunneling_count", 0) + alerts.get("fast_flux_count", 0)
                )
                if total_alerts:
                    st.metric("Alerts", total_alerts, delta="Warning", delta_color="inverse")
                else:
                    st.metric("Alerts", 0)

            # Alert sections
            alerts = dns_analysis.get("alerts", {})

            if alerts.get("dga_count", 0):
                st.error(f"**DGA Detection:** {alerts['dga_count']} potential DGA domains detected!")

            if alerts.get("tunneling_count", 0):
                st.error(f"**DNS Tunneling:** {alerts['tunneling_count']} potential tunneling patterns detected!")

            if alerts.get("fast_flux_count", 0):
                st.warning(f"**Fast Flux:** {alerts['fast_flux_count']} potential fast flux domains detected!")

            # Tabs for detailed data
            tab_dga, tab_tunnel, tab_flux, tab_stats = st.tabs(
                ["DGA Detection", "Tunneling", "Fast Flux", "Query Stats"]
            )

            with tab_dga:
                dga_list = dns_analysis.get("dga_detections", [])
                if dga_list:
                    df_dga = pd.DataFrame(dga_list)
                    display_cols = ["domain", "score", "entropy", "is_dga", "reason"]
                    display_cols = [c for c in display_cols if c in df_dga.columns]
                    render_export_buttons(df_dga[display_cols], "dns_dga", key_suffix="dga", is_dataframe=True)
                    st.dataframe(df_dga[display_cols], width="stretch", hide_index=True)
                else:
                    st.caption("No DGA-like domains detected.")

            with tab_tunnel:
                tunnel_list = dns_analysis.get("tunneling_detections", [])
                if tunnel_list:
                    df_tunnel = pd.DataFrame(tunnel_list)
                    display_cols = [
                        "domain",
                        "score",
                        "unique_subdomains",
                        "avg_subdomain_length",
                        "is_tunneling",
                        "reason",
                    ]
                    display_cols = [c for c in display_cols if c in df_tunnel.columns]
                    render_export_buttons(
                        df_tunnel[display_cols], "dns_tunneling", key_suffix="tunnel", is_dataframe=True
                    )
                    st.dataframe(df_tunnel[display_cols], width="stretch", hide_index=True)
                else:
                    st.caption("No tunneling patterns detected.")

            with tab_flux:
                flux_list = dns_analysis.get("fast_flux_detections", [])
                if flux_list:
                    df_flux = pd.DataFrame(flux_list)
                    display_cols = ["domain", "score", "unique_ips", "min_ttl", "is_fast_flux", "reason"]
                    display_cols = [c for c in display_cols if c in df_flux.columns]
                    render_export_buttons(df_flux[display_cols], "dns_fastflux", key_suffix="flux", is_dataframe=True)
                    st.dataframe(df_flux[display_cols], width="stretch", hide_index=True)
                else:
                    st.caption("No fast flux patterns detected.")

            with tab_stats:
                # Query types
                query_types = dns_analysis.get("query_types", {})
                if query_types:
                    st.markdown("**Query Types:**")
                    df_qtypes = pd.DataFrame([{"Type": k, "Count": v} for k, v in query_types.items()])
                    st.dataframe(df_qtypes, width="stretch", hide_index=True)

                # Top queried domains
                top_queried = dns_analysis.get("top_queried", [])
                if top_queried:
                    st.markdown("**Top Queried Domains:**")
                    df_top = pd.DataFrame(top_queried)
                    render_export_buttons(df_top, "dns_top_domains", key_suffix="top", is_dataframe=True)
                    st.dataframe(df_top, width="stretch", hide_index=True)


def render_tls_certificates(result_col, tls_analysis: dict | None):
    """Render TLS certificate analysis results."""
    with result_col:
        expanded = bool(
            tls_analysis is not None
            and (
                tls_analysis.get("alerts", {}).get("self_signed_count", 0)
                or tls_analysis.get("alerts", {}).get("expired_count", 0)
                or tls_analysis.get("alerts", {}).get("high_risk_count", 0)
            )
        )
        with st.expander("TLS Certificates", expanded=expanded):
            if tls_analysis is None or tls_analysis.get("skipped"):
                st.caption("No TLS certificate data available.")
                return

            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Certificates", tls_analysis.get("total_certificates", 0))
            with col2:
                st.metric("Self-Signed", tls_analysis.get("self_signed", 0))
            with col3:
                st.metric("Expired", tls_analysis.get("expired", 0))
            with col4:
                high_risk = tls_analysis.get("high_risk", 0)
                if high_risk:
                    st.metric(
                        "Trust Issues",
                        high_risk,
                        delta="Warning",
                        delta_color="inverse",
                        help="Certificates with a composite risk score ≥ 0.5 (expired, self-signed, weak keys, "
                        "suspicious CN patterns, etc.). Neither proves malice; all warrant review.",
                    )
                else:
                    st.metric(
                        "Trust Issues",
                        0,
                        help="Certificates with a composite risk score ≥ 0.5 (expired, self-signed, weak keys, "
                        "suspicious CN patterns, etc.). Neither proves malice; all warrant review.",
                    )

            # Alerts
            alerts = tls_analysis.get("alerts", {})
            if alerts.get("self_signed_count", 0):
                st.warning(f"**Self-Signed Certificates:** {alerts['self_signed_count']} detected")
            if alerts.get("expired_count", 0):
                st.error(f"**Expired Certificates:** {alerts['expired_count']} detected")
            if alerts.get("high_risk_count", 0):
                st.error(f"**High-Risk Certificates:** {alerts['high_risk_count']} detected")

            # Certificate table
            certs = tls_analysis.get("certificates", [])
            if certs:
                df_certs = pd.DataFrame(certs)
                display_cols = [
                    "subject_cn",
                    "issuer_cn",
                    "not_after",
                    "is_self_signed",
                    "is_expired",
                    "risk_score",
                    "risk_reasons",
                    "dst_ip",
                ]
                display_cols = [c for c in display_cols if c in df_certs.columns]

                render_export_buttons(df_certs, "tls_certs", key_suffix="certs", is_dataframe=True)

                # Color-code by risk score
                def highlight_risk(row):
                    risk = row.get("risk_score", 0)
                    if risk >= 0.5:
                        return [f"background-color: {severity_color('high', 'rgba')};"] * len(row)
                    elif risk >= 0.3:
                        return [f"background-color: {severity_color('medium', 'rgba')};"] * len(row)
                    return [""] * len(row)

                styled_df = df_certs[display_cols].style.apply(highlight_risk, axis=1)
                st.dataframe(styled_df, width="stretch", hide_index=True)
            else:
                st.caption("No certificates extracted from PCAP.")

            # Zeek SSL summary if available
            zeek_ssl = tls_analysis.get("zeek_ssl_summary", {})
            if zeek_ssl.get("total", 0) > 0:
                st.markdown("---")
                st.markdown(
                    f"**Zeek SSL Log:** {zeek_ssl['total']} connections, {zeek_ssl.get('with_issues', 0)} with issues"
                )
                entries = zeek_ssl.get("entries", [])
                if entries:
                    with st.expander("Zeek SSL Details", expanded=False):
                        df_zeek_ssl = pd.DataFrame(entries)
                        st.dataframe(df_zeek_ssl, width="stretch", hide_index=True)


def render_batch_summary(result_col, batch_summary: dict | None):
    """Render batch processing summary for multi-PCAP analysis."""
    with result_col:
        if not batch_summary:
            return

        st.markdown("#### Batch Analysis Summary")

        # File summary
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Files Processed", batch_summary.get("total_files", 0))
        with col2:
            st.metric("Total Packets", batch_summary.get("total_packets", 0))
        with col3:
            st.metric("Total Flows", batch_summary.get("total_flows", 0))
        with col4:
            failed = batch_summary.get("failed", 0)
            if failed:
                st.metric("Failed", failed, delta="Error", delta_color="inverse")
            else:
                st.metric("Successful", batch_summary.get("successful", 0))

        # Cross-file correlation
        st.markdown("---")
        st.markdown("**Cross-File Correlation:**")

        corr_col1, corr_col2, corr_col3 = st.columns(3)
        with corr_col1:
            st.metric("Shared IPs", batch_summary.get("shared_ip_count", 0))
        with corr_col2:
            st.metric("Shared Domains", batch_summary.get("shared_domain_count", 0))
        with corr_col3:
            st.metric("Shared JA3", batch_summary.get("shared_ja3_count", 0))

        # Alerts
        alerts = batch_summary.get("alerts", {})
        if any(alerts.values()):
            st.markdown("---")
            st.markdown("**Aggregated Alerts:**")
            alert_text = []
            if alerts.get("dga_detections"):
                alert_text.append(f"DGA: {alerts['dga_detections']}")
            if alerts.get("tunneling_detections"):
                alert_text.append(f"Tunneling: {alerts['tunneling_detections']}")
            if alerts.get("self_signed_certs"):
                alert_text.append(f"Self-signed: {alerts['self_signed_certs']}")
            if alerts.get("expired_certs"):
                alert_text.append(f"Expired certs: {alerts['expired_certs']}")
            if alert_text:
                st.warning(" | ".join(alert_text))

        # File list
        filenames = batch_summary.get("filenames", [])
        if filenames:
            with st.expander("Processed Files", expanded=False):
                for fname in filenames:
                    st.text(f"- {fname}")


def render_cross_file_correlation(result_col, correlation):
    """Render shared IPs, domains, JA3 across multiple PCAP files."""
    with result_col:
        if correlation is None:
            return

        common = getattr(correlation, "common_indicators", [])
        if not common:
            st.info("No shared indicators found across files.")
            return

        st.markdown("#### Cross-File Indicators")
        st.caption("Indicators observed in two or more PCAP files")

        rows = []
        for ind in common:
            rows.append(
                {
                    "Type": ind.get("type", "").upper(),
                    "Value": ind.get("value", ""),
                    "Files": ind.get("file_count", 0),
                    "Seen In": ", ".join(ind.get("files", [])),
                }
            )
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, hide_index=True, use_container_width=True)


def render_per_file_summary(result_col, pcap_results: list):
    """Render collapsible per-file result cards for batch processing."""
    with result_col:
        if not pcap_results:
            return

        st.markdown("#### Per-File Results")
        for r in pcap_results:
            status = "Failed" if r.error else "OK"
            icon = "\u274c" if r.error else "\u2705"
            label = f"{icon} {r.filename} \u2014 {status}"
            with st.expander(label, expanded=bool(r.error)):
                if r.error:
                    st.error(f"Error: {r.error}")
                    continue
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.metric("Packets", f"{r.packet_count:,}" if r.packet_count else "N/A")
                with c2:
                    st.metric("Flows", f"{len(r.features.get('flows', [])):,}")
                with c3:
                    st.metric("IPs", f"{len(r.features.get('artifacts', {}).get('ips', [])):,}")
                with c4:
                    st.metric("Domains", f"{len(r.features.get('artifacts', {}).get('domains', [])):,}")


def render_yara_results(result_col, yara_results: dict | None):
    """Render YARA scan results for carved files."""
    with result_col:
        expanded = bool(yara_results and yara_results.get("matched", 0) > 0)
        with st.expander("YARA Scan Results", expanded=expanded):
            if not yara_results:
                st.caption("No YARA scan data available.")
                return

            if not yara_results.get("yara_available"):
                st.warning("YARA scanning not available. Install `yara-python` to enable.")
                return

            if yara_results.get("error"):
                st.error(f"YARA Error: {yara_results['error']}")
                return

            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Files Scanned", yara_results.get("scanned", 0))
            with col2:
                matched = yara_results.get("matched", 0)
                if matched:
                    st.metric("Matches Found", matched, delta="Alert", delta_color="inverse")
                else:
                    st.metric("Matches Found", 0)
            with col3:
                st.metric("Rules Loaded", yara_results.get("rule_count", 0))
            with col4:
                st.metric("Scan Errors", yara_results.get("errors", 0))

            # Severity breakdown
            by_severity = yara_results.get("by_severity", {})
            if any(v > 0 for k, v in by_severity.items() if k != "clean"):
                st.markdown("**Severity Breakdown:**")
                sev_cols = st.columns(5)
                with sev_cols[0]:
                    critical = by_severity.get("critical", 0)
                    if critical:
                        st.error(f"Critical: {critical}")
                    else:
                        st.caption(f"Critical: {critical}")
                with sev_cols[1]:
                    high = by_severity.get("high", 0)
                    if high:
                        st.warning(f"High: {high}")
                    else:
                        st.caption(f"High: {high}")
                with sev_cols[2]:
                    medium = by_severity.get("medium", 0)
                    st.caption(f"Medium: {medium}")
                with sev_cols[3]:
                    low = by_severity.get("low", 0)
                    st.caption(f"Low: {low}")
                with sev_cols[4]:
                    clean = by_severity.get("clean", 0)
                    st.caption(f"Clean: {clean}")

            # Results table
            results = yara_results.get("results", [])
            if results:
                st.markdown("---")

                # Filter to show only matches first
                matches_only = [r for r in results if r.get("has_matches")]
                if matches_only:
                    st.markdown("**Files with Matches:**")
                    rows = []
                    for r in matches_only:
                        for m in r.get("matches", []):
                            rows.append(
                                {
                                    "File": r.get("file_path", "").split("/")[-1],
                                    "Rule": m.get("rule_name", ""),
                                    "Tags": ", ".join(m.get("rule_tags", [])),
                                    "Severity": r.get("severity", "unknown"),
                                    "SHA256": r.get("file_hash", "")[:16] + "...",
                                }
                            )

                    if rows:
                        df_matches = pd.DataFrame(rows)
                        render_export_buttons(df_matches, "yara_matches", key_suffix="yara", is_dataframe=True)

                        # Color-code by severity
                        def highlight_severity(row):
                            sev = (row.get("Severity") or "").lower()
                            if sev in ("critical", "high"):
                                return [f"background-color: {severity_color(sev, 'rgba')};"] * len(row)
                            return [""] * len(row)

                        styled_df = df_matches.style.apply(highlight_severity, axis=1)
                        st.dataframe(styled_df, width="stretch", hide_index=True)

                # All results in expandable section
                with st.expander("All Scan Results", expanded=False):
                    all_rows = []
                    for r in results:
                        all_rows.append(
                            {
                                "File": r.get("file_path", "").split("/")[-1],
                                "Size": r.get("file_size", 0),
                                "Severity": r.get("severity", "clean"),
                                "Matches": len(r.get("matches", [])),
                                "Scan Time": f"{r.get('scan_time', 0):.3f}s",
                                "Error": r.get("error") or "",
                            }
                        )
                    df_all = pd.DataFrame(all_rows)
                    st.dataframe(df_all, width="stretch", hide_index=True)
            else:
                st.caption("No files scanned.")


def render_attack_mapping(result_col, attack_mapping):
    """Render MITRE ATT&CK mapping results."""
    with result_col:
        if attack_mapping is None:
            return

        expanded = bool(attack_mapping.techniques)
        with st.expander("MITRE ATT&CK Mapping", expanded=expanded):
            if not attack_mapping.techniques:
                st.caption("No ATT&CK techniques detected.")
                return

            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Techniques", len(attack_mapping.techniques))
            with col2:
                st.metric("Kill Chain Phase", attack_mapping.kill_chain_phase)
            with col3:
                severity = attack_mapping.overall_severity
                if severity == "critical":
                    st.metric("Severity", severity.upper(), delta="Critical", delta_color="inverse")
                elif severity == "high":
                    st.metric("Severity", severity.upper(), delta="High", delta_color="inverse")
                else:
                    st.metric("Severity", severity.upper())
            with col4:
                tactics = attack_mapping.tactics_summary
                st.metric("Tactics", len(tactics))

            # Tactics breakdown
            if attack_mapping.tactics_summary:
                st.markdown("**Tactics Detected:**")
                tactic_text = ", ".join(
                    f"{t} ({c})" for t, c in sorted(attack_mapping.tactics_summary.items(), key=lambda x: -x[1])
                )
                st.info(tactic_text)

            # Techniques table
            st.markdown("---")
            st.markdown("**Detected Techniques:**")

            rows = []
            for tech in attack_mapping.techniques:
                rows.append(
                    {
                        "ID": tech.technique_id,
                        "Name": tech.technique_name,
                        "Tactic": tech.tactic,
                        "Confidence": f"{tech.confidence:.0%}",
                        "Evidence": "; ".join(tech.evidence[:2]),
                    }
                )

            if rows:
                df = pd.DataFrame(rows)

                def highlight_confidence(row):
                    conf_str = row.get("Confidence", "0%")
                    conf = float(conf_str.replace("%", "")) / 100
                    if conf >= 0.8:
                        return [f"background-color: {severity_color('high', 'rgba')};"] * len(row)
                    elif conf >= 0.6:
                        return [f"background-color: {severity_color('medium', 'rgba')};"] * len(row)
                    return [""] * len(row)

                styled_df = df.style.apply(highlight_confidence, axis=1)
                st.dataframe(styled_df, width="stretch", hide_index=True)

            # Navigator export button
            st.markdown("---")
            try:
                from app.utils.navigator_export import export_navigator_json

                nav_json = export_navigator_json(attack_mapping)
                st.download_button(
                    label="📥 Export ATT&CK Navigator Layer",
                    data=nav_json,
                    file_name="attack_navigator_layer.json",
                    mime="application/json",
                    key="export_navigator",
                )
                st.caption("Import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)")
            except Exception as e:
                st.error(f"Navigator export error: {e}")


def render_ioc_export(result_col, features: dict | None, osint: dict | None, scores: dict | None = None):
    """Render IOC export options."""
    with result_col:
        if features is None or not features.get("artifacts"):
            return

        artifacts = features.get("artifacts", {})
        total_iocs = (
            len(artifacts.get("ips", []))
            + len(artifacts.get("domains", []))
            + len(artifacts.get("hashes", []))
            + len(artifacts.get("ja3", []))
        )

        if total_iocs == 0:
            return

        with st.expander("IOC Export", expanded=False):
            st.markdown(f"**Total IOCs:** {total_iocs}")

            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                ioc_types = st.multiselect(
                    "IOC Types",
                    ["ip", "domain", "hash", "ja3", "url"],
                    default=["ip", "domain"],
                    key="ioc_export_types",
                )
            with col2:
                min_score = st.slider("Minimum Priority Score", 0.0, 1.0, 0.0, 0.1, key="ioc_min_score")

            st.markdown("---")

            try:
                from app.utils.ioc_export import IOCExporter

                exporter = IOCExporter(features, osint, scores)

                # Export buttons
                export_cols = st.columns(5)

                with export_cols[0]:
                    csv_data = exporter.export_csv(ioc_types, min_score)
                    st.download_button(
                        label="📄 CSV",
                        data=csv_data,
                        file_name="iocs.csv",
                        mime="text/csv",
                        key="export_ioc_csv",
                    )

                with export_cols[1]:
                    json_data = exporter.export_json(ioc_types, min_score)
                    st.download_button(
                        label="📋 JSON",
                        data=json_data,
                        file_name="iocs.json",
                        mime="application/json",
                        key="export_ioc_json",
                    )

                with export_cols[2]:
                    txt_data = exporter.export_txt(ioc_types, min_score)
                    st.download_button(
                        label="📝 TXT",
                        data=txt_data,
                        file_name="iocs.txt",
                        mime="text/plain",
                        key="export_ioc_txt",
                    )

                with export_cols[3]:
                    stix_data = exporter.export_stix(ioc_types, min_score)
                    st.download_button(
                        label="🔒 STIX",
                        data=stix_data,
                        file_name="iocs_stix.json",
                        mime="application/json",
                        key="export_ioc_stix",
                    )

                with export_cols[4]:
                    st.caption("TXT: Firewall blocklist")

            except Exception as e:
                st.error(f"IOC export error: {e}")


def render_attack_narrative(result_col, narrative: str | None):
    """Render attack narrative section."""
    with result_col:
        if not narrative:
            return

        with st.expander("Attack Narrative", expanded=True):
            st.markdown(narrative)


def render_ioc_scores(result_col, scored_iocs: list | None):
    """Render IOC priority scores."""
    with result_col:
        if not scored_iocs:
            return

        with st.expander("IOC Priority Scores", expanded=False):
            st.markdown("**Top Priority IOCs:**")

            rows = []
            for ioc in scored_iocs[:20]:  # Show top 20
                rows.append(
                    {
                        "Type": ioc.ioc_type,
                        "Value": ioc.value[:50] + "..." if len(ioc.value) > 50 else ioc.value,
                        "Priority": ioc.priority_label.upper(),
                        "Score": f"{ioc.priority_score:.1%}",
                        "Recommendation": ioc.recommendation,
                    }
                )

            if rows:
                df = pd.DataFrame(rows)

                def highlight_priority(row):
                    priority = row.get("Priority", "").lower()
                    if priority in ("critical", "high", "medium"):
                        return [f"background-color: {severity_color(priority, 'rgba')};"] * len(row)
                    return [""] * len(row)

                styled_df = df.style.apply(highlight_priority, axis=1)
                st.dataframe(styled_df, width="stretch", hide_index=True)


def render_qa_interface(result_col, qa_session):
    """Render interactive Q&A interface."""
    with result_col:
        if qa_session is None:
            return

        with st.expander("Ask Questions About Analysis", expanded=False):
            # Suggested questions
            suggested = qa_session.get_suggested_questions()
            if suggested:
                st.markdown("**Suggested Questions:**")
                for i, q in enumerate(suggested[:4]):
                    if st.button(q, key=f"qa_suggest_{i}"):
                        st.session_state["qa_question"] = q

            st.markdown("---")

            # Question input
            question = st.text_input(
                "Ask a question:",
                value=st.session_state.get("qa_question", ""),
                key="qa_input",
                placeholder="e.g., What are the most critical findings?",
            )

            if st.button("Ask", key="qa_ask"):
                if question:
                    with st.spinner("Analyzing..."):
                        answer = qa_session.ask(question)
                    st.markdown("**Answer:**")
                    st.markdown(answer)
                    st.session_state["qa_question"] = ""

            # Conversation history
            history = qa_session.get_conversation_history()
            if history:
                with st.expander("Conversation History", expanded=False):
                    for msg in history:
                        role = "🧑" if msg["role"] == "user" else "🤖"
                        st.markdown(f"{role} **{msg['role'].title()}:** {msg['content']}")

            # Clear history button
            if history:
                if st.button("Clear History", key="qa_clear"):
                    qa_session.clear_history()
                    st.rerun()


# -------------- New UI Components ------------------


def render_chart_hint(hint: str):
    """Render a subtle interaction hint below a chart."""
    st.markdown(f'<p class="chart-hint">{hint}</p>', unsafe_allow_html=True)


def render_active_filters(**filters):
    """Render active filter badges at the top of the dashboard.

    Args:
        **filters: keyword args like min_beacon=0.5, protocol="TCP"
    """
    active = {k: v for k, v in filters.items() if v is not None and v != "" and v != 0}
    if not active:
        return

    badges = " ".join(
        f'<span class="filter-badge">{k.replace("_", " ").title()}: {v}</span>' for k, v in active.items()
    )
    st.markdown(f"**Active Filters:** {badges}", unsafe_allow_html=True)


def render_ioc_search(
    result_col,
    features: dict | None,
    osint: dict | None,
    dns_analysis: dict | None = None,
    beacon_df=None,
):
    """Render a global IOC search bar that searches across all analysis results."""
    with result_col:
        query = st.text_input(
            "Search IOCs",
            placeholder="Search IPs, domains, JA3 hashes...",
            key="ioc_search_input",
        )

        if not query or len(query) < 2:
            return

        query_lower = query.lower().strip()
        results_found = False

        # Search IPs
        if features:
            ips = features.get("artifacts", {}).get("ips", [])
            matched_ips = [ip for ip in ips if query_lower in ip.lower()]
            if matched_ips:
                results_found = True
                with st.expander(f"IPs ({len(matched_ips)} matches)", expanded=True):
                    for ip in matched_ips[:10]:
                        osint_ip = (osint or {}).get("ips", {}).get(ip, {})
                        gn = osint_ip.get("greynoise", {}).get("classification", "n/a")
                        ptr = osint_ip.get("ptr", "n/a")
                        st.markdown(f"**{ip}** — PTR: {ptr}, GreyNoise: {gn}")

        # Search domains
        if features:
            domains = features.get("artifacts", {}).get("domains", [])
            matched_doms = [d for d in domains if query_lower in d.lower()]
            if matched_doms:
                results_found = True
                with st.expander(f"Domains ({len(matched_doms)} matches)", expanded=True):
                    for dom in matched_doms[:10]:
                        # Check DNS analysis
                        dga_hit = ""
                        if dns_analysis:
                            for dga in dns_analysis.get("dga_detections", []):
                                if dga.get("domain") == dom and dga.get("is_dga"):
                                    dga_hit = " **[DGA]**"
                                    break
                        st.markdown(f"**{dom}**{dga_hit}")

        # Search JA3 hashes
        if features:
            ja3s = features.get("artifacts", {}).get("ja3", [])
            if isinstance(ja3s, list):
                matched_ja3 = [j for j in ja3s if isinstance(j, str) and query_lower in j.lower()]
                if matched_ja3:
                    results_found = True
                    with st.expander(f"JA3 ({len(matched_ja3)} matches)", expanded=True):
                        for j in matched_ja3[:10]:
                            st.code(j)

        # Search beacon destinations
        if beacon_df is not None and not beacon_df.empty:
            try:
                mask = beacon_df["dst"].str.contains(query_lower, case=False, na=False)
                matched = beacon_df[mask]
                if not matched.empty:
                    results_found = True
                    with st.expander(
                        f"Beacon Candidates ({len(matched)} matches)",
                        expanded=True,
                    ):
                        st.dataframe(
                            matched[["src", "dst", "dport", "score"]],
                            hide_index=True,
                        )
            except Exception:
                pass

        if not results_found:
            st.caption(f"No results for '{query}'")


def render_hunting_checklist(
    result_col,
    features: dict | None = None,
    osint: dict | None = None,
    dns_analysis: dict | None = None,
    beacon_df=None,
    tls_analysis: dict | None = None,
    yara_results: dict | None = None,
):
    """Render an auto-generated threat hunting checklist based on findings."""
    with result_col:
        items: list[tuple[str, str]] = []

        # Beacon candidates
        if beacon_df is not None and not beacon_df.empty:
            high_beacons = beacon_df[beacon_df["score"] >= 0.5]
            if not high_beacons.empty:
                items.append(
                    (
                        f"Review {len(high_beacons)} beacon candidates (score >= 0.5)",
                        "beacon",
                    )
                )

        # DGA domains
        if dns_analysis:
            alerts = dns_analysis.get("alerts", {})
            dga_count = alerts.get("dga_count", 0)
            if dga_count:
                items.append(
                    (
                        f"Investigate {dga_count} potential DGA domains",
                        "dns",
                    )
                )
            tunnel_count = alerts.get("tunneling_count", 0)
            if tunnel_count:
                items.append(
                    (
                        f"Check {tunnel_count} DNS tunneling indicators",
                        "dns",
                    )
                )
            if alerts.get("nxdomain_suspicious"):
                ratio = alerts.get("nxdomain_ratio", 0)
                items.append(
                    (
                        f"High NXDOMAIN ratio ({ratio:.0%}) — possible DGA/C2",
                        "dns",
                    )
                )

        # TLS alerts
        if tls_analysis:
            self_signed = tls_analysis.get("self_signed", 0)
            expired = tls_analysis.get("expired", 0)
            if self_signed:
                items.append(
                    (
                        f"Examine {self_signed} self-signed certificates",
                        "tls",
                    )
                )
            if expired:
                items.append(
                    (
                        f"Check {expired} expired certificates",
                        "tls",
                    )
                )

        # YARA matches
        if yara_results and yara_results.get("matched", 0) > 0:
            matched = yara_results["matched"]
            items.append(
                (
                    f"Analyse {matched} YARA match(es) in carved payloads",
                    "yara",
                )
            )

        # OSINT high-risk
        if osint:
            malicious_ips = 0
            for ip, data in osint.get("ips", {}).items():
                gn = data.get("greynoise", {}).get("classification", "")
                if gn == "malicious":
                    malicious_ips += 1
            if malicious_ips:
                items.append(
                    (
                        f"Block/investigate {malicious_ips} malicious IPs (GreyNoise)",
                        "osint",
                    )
                )

        if not items:
            return

        with st.expander("Threat Hunting Checklist", expanded=True):
            for i, (text, category) in enumerate(items):
                key = f"hunt_check_{i}"
                st.checkbox(
                    text,
                    value=st.session_state.get(key, False),
                    key=key,
                )


def render_correlation_results(result_col, correlations: list | None):
    """Render cross-indicator correlation results."""
    with result_col:
        if not correlations:
            return

        with st.expander("Cross-Indicator Correlations", expanded=True):
            st.markdown("**Top Correlated Threats:**")

            rows = []
            for c in correlations[:20]:
                if hasattr(c, "to_dict"):
                    d = c.to_dict()
                else:
                    d = c
                rows.append(
                    {
                        "Indicator": d.get("indicator", ""),
                        "Type": d.get("type", ""),
                        "Score": f"{d.get('composite_score', 0):.1%}",
                        "Verdict": d.get("verdict", "").upper(),
                        "Signals": d.get("signal_count", 0),
                    }
                )

            if rows:
                df = pd.DataFrame(rows)

                def highlight_verdict(row):
                    v = row.get("Verdict", "").lower()
                    if v in ("critical", "high", "medium"):
                        return [f"background-color: {severity_color(v, 'rgba')};"] * len(row)
                    return [""] * len(row)

                styled_df = df.style.apply(highlight_verdict, axis=1)
                st.dataframe(styled_df, width="stretch", hide_index=True)


def render_flow_asymmetry(result_col, asymmetry_results: list | None):
    """Render flow asymmetry (data exfiltration) detection results."""
    with result_col:
        if not asymmetry_results:
            return

        suspicious = [
            r
            for r in asymmetry_results
            if (hasattr(r, "is_suspicious") and r.is_suspicious) or (isinstance(r, dict) and r.get("is_suspicious"))
        ]
        if not suspicious:
            return

        expanded = len(suspicious) > 0
        with st.expander(f"Flow Asymmetry ({len(suspicious)} suspicious)", expanded=expanded):
            st.warning(f"**Data Exfiltration Risk:** {len(suspicious)} flow pairs show asymmetric traffic patterns.")

            rows = []
            for r in suspicious[:20]:
                d = r.to_dict() if hasattr(r, "to_dict") else r
                out_mb = d.get("outbound_bytes", 0) / 1_000_000
                in_mb = d.get("inbound_bytes", 0) / 1_000_000
                rows.append(
                    {
                        "Source": d.get("src", ""),
                        "Destination": d.get("dst", ""),
                        "Outbound": f"{out_mb:.1f} MB",
                        "Inbound": f"{in_mb:.1f} MB",
                        "Ratio": f"{d.get('ratio', 0):.1f}:1",
                        "Score": f"{d.get('score', 0):.1%}",
                        "Reason": d.get("reason", ""),
                    }
                )

            if rows:
                df = pd.DataFrame(rows)
                render_export_buttons(
                    df,
                    "flow_asymmetry",
                    key_suffix="asymm",
                    is_dataframe=True,
                )
                st.dataframe(df, width="stretch", hide_index=True)


def render_port_anomalies(result_col, anomaly_results: list | None):
    """Render port/protocol anomaly detection results."""
    with result_col:
        if not anomaly_results:
            return

        with st.expander(f"Port Anomalies ({len(anomaly_results)})", expanded=bool(anomaly_results)):
            rows = []
            for r in anomaly_results[:30]:
                d = r.to_dict() if hasattr(r, "to_dict") else r
                rows.append(
                    {
                        "Source": d.get("src", ""),
                        "Destination": d.get("dst", ""),
                        "Port": d.get("port", ""),
                        "Proto": d.get("proto", ""),
                        "Type": d.get("anomaly_type", "").replace("_", " ").title(),
                        "Score": f"{d.get('score', 0):.1%}",
                        "Reason": d.get("reason", ""),
                    }
                )

            if rows:
                df = pd.DataFrame(rows)
                render_export_buttons(
                    df,
                    "port_anomalies",
                    key_suffix="port",
                    is_dataframe=True,
                )
                st.dataframe(df, width="stretch", hide_index=True)


def render_nxdomain_analysis(result_col, dns_analysis: dict | None):
    """Render NXDOMAIN analysis section."""
    with result_col:
        if not dns_analysis:
            return

        nxd = dns_analysis.get("nxdomain_analysis", {})
        if not nxd or nxd.get("nxdomain_count", 0) == 0:
            return

        expanded = nxd.get("is_suspicious", False)
        with st.expander("NXDOMAIN Analysis", expanded=expanded):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("NXDOMAIN Count", nxd.get("nxdomain_count", 0))
            with col2:
                ratio = nxd.get("nxdomain_ratio", 0)
                if nxd.get("is_suspicious"):
                    st.metric(
                        "NXDOMAIN Ratio",
                        f"{ratio:.1%}",
                        delta="Suspicious",
                        delta_color="inverse",
                    )
                else:
                    st.metric("NXDOMAIN Ratio", f"{ratio:.1%}")
            with col3:
                suspicious_src = sum(1 for s in nxd.get("sources", []) if s.get("is_suspicious"))
                st.metric("Suspicious Sources", suspicious_src)

            if nxd.get("is_suspicious"):
                st.warning(
                    "High NXDOMAIN ratio may indicate DGA activity, domain enumeration, or C2 communication attempts."
                )

            sources = nxd.get("sources", [])
            if sources:
                st.markdown("**Top NXDOMAIN Sources:**")
                df = pd.DataFrame(sources)
                st.dataframe(df, width="stretch", hide_index=True)


def render_query_velocity(result_col, dns_analysis: dict | None):
    """Render DNS query velocity analysis."""
    with result_col:
        if not dns_analysis:
            return

        velocity = dns_analysis.get("query_velocity", [])
        if not velocity:
            return

        suspicious = [v for v in velocity if v.get("is_suspicious")]
        if not suspicious:
            return

        with st.expander(
            f"DNS Query Velocity ({len(suspicious)} high-rate sources)",
            expanded=True,
        ):
            st.warning("Sustained high DNS query rates may indicate DNS tunneling or data exfiltration.")
            df = pd.DataFrame(suspicious)
            st.dataframe(df, width="stretch", hide_index=True)
