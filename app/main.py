from __future__ import annotations

import pathlib
import sys

# Ensure top-level repo path importable
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import os
import time

import pandas as pd
import streamlit as st

from app import config as C
from app.llm.client import generate_report
from app.pipeline.beacon import rank_beaconing
from app.pipeline.carve import carve_http_payloads
from app.pipeline.geoip import GeoIP
from app.pipeline.osint import enrich as osint_enrich
from app.pipeline.pcap_count import count_packets_fast
from app.pipeline.pyshark_pass import parse_pcap_pyshark
from app.pipeline.state import PhaseTracker, end_run, is_run_active, reset_run_state
from app.pipeline.zeek import load_zeek_any, run_zeek
from app.ui.charts import plot_flow_timeline, plot_protocol_distribution, plot_world_map
from app.ui.config_ui import init_config_defaults, render_config_tab
from app.ui.layout import (
    inject_css,
    make_progress_panel,
    make_results_panel,
    make_tabs,
    render_carved,
    render_dns_analysis,
    render_flows,
    render_ja3,
    render_osint,
    render_overview,
    render_report,
    render_tls_certificates,
    render_zeek,
)
from app.utils.common import ensure_dir, is_public_ipv4, make_slug, uniq_sorted


def get_df_state(key: str) -> pd.DataFrame:
    val = st.session_state.get(key, None)
    return val if isinstance(val, pd.DataFrame) else pd.DataFrame()


def _ss_default(key: str, value):
    if key not in st.session_state:
        st.session_state[key] = value


def cfg_get(name: str, env_key: str, default):
    return st.session_state.get(name) or os.getenv(env_key, default)


def pick_top_public_ips(features: dict, n: int) -> list[str]:
    """
    Return top-N public IPv4s by packet volume across flows.
    If n <= 0, return all public IPv4s from artifacts.
    """
    if not isinstance(features, dict) or n <= 0:
        return [ip for ip in (features or {}).get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]

    flows = (features or {}).get("flows", [])
    if not flows:
        return [ip for ip in (features or {}).get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]

    counts = {}
    for f in flows:
        pkts = int(f.get("count") or 0)
        src = f.get("src")
        dst = f.get("dst")
        if src and is_public_ipv4(src):
            counts[src] = counts.get(src, 0) + pkts
        if dst and is_public_ipv4(dst):
            counts[dst] = counts.get(dst, 0) + pkts

    if not counts:
        return [ip for ip in (features or {}).get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]

    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return [ip for ip, _ in ranked[: max(1, n)]]


# ---------------------------------------------------------------------------
# Streamlit App
# ---------------------------------------------------------------------------

st.set_page_config(page_title=C.APP_NAME, layout="wide")
inject_css()
st.title(C.APP_NAME)
init_config_defaults()

# Tabs
tab_upload, tab_progress, tab_dashboard, tab_osint, tab_results, tab_config = make_tabs()

# Defaults
for k, v in [
    ("features", None),
    ("osint", None),
    ("report", None),
    ("beacon_df", pd.DataFrame()),
    ("zeek_tables", {}),
    ("carved", []),
    ("__total_pkts", None),
    ("runtime_logs", []),
    ("map_reset_counter", 0),
    ("dns_analysis", None),
    ("tls_analysis", None),
]:
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------------- 1) Upload ----------------------
with tab_upload:
    st.subheader("1) Load PCAP")
    col_a, col_b = st.columns([1, 1])
    with col_a:
        uploaded = st.file_uploader("Upload a .pcap / .pcapng", type=["pcap", "pcapng"])
    with col_b:
        pcap_path_text = st.text_input("...or type a container path (e.g., /data/capture.pcap)", value="")

    ensure_dir(C.DATA_DIR)
    ensure_dir(C.ZEEK_DIR)
    ensure_dir(C.CARVE_DIR)

    pcap_path = None
    if uploaded is not None:
        pcap_path = str((C.DATA_DIR / f"upload_{int(time.time())}.pcap").resolve())
        pathlib.Path(pcap_path).write_bytes(uploaded.read())
        st.info(f"Uploaded PCAP saved to: {pcap_path}")
    elif pcap_path_text:
        pcap_path = pcap_path_text.strip()

    do_pyshark = bool(st.session_state.get("cfg_do_pyshark", True))
    do_zeek = bool(st.session_state.get("cfg_do_zeek", True))
    do_carve = bool(st.session_state.get("cfg_do_carve", True))
    pre_count = bool(st.session_state.get("cfg_pre_count", True))

    phases = [
        ("Packet counting (tshark)", pre_count and do_pyshark),
        ("Parsing Packets", do_pyshark),
        ("Zeek processing", do_zeek),
        ("DNS Analysis", do_zeek),  # Requires Zeek dns.log
        ("TLS Certificate Analysis", do_zeek),  # Requires Zeek ssl.log
        ("Beaconing ranking", True),
        ("HTTP carving (tshark)", do_carve),
        ("OSINT enrichment", True),
        ("LLM report", True),
    ]

    start = st.button("Extract & Analyze", type="primary", use_container_width=True)
    if start:
        if not pcap_path or not pathlib.Path(pcap_path).exists():
            st.error("Please upload a PCAP or provide a valid path.")
            st.stop()
        reset_run_state([t for (t, enabled) in phases if enabled])
        st.session_state.update(
            {
                "features": None,
                "osint": None,
                "report": None,
                "beacon_df": pd.DataFrame(),
                "zeek_tables": {},
                "carved": [],
                "__total_pkts": None,
                "__pcap_path": pcap_path,
                "dns_analysis": None,
                "tls_analysis": None,
            }
        )
        st.success("Analysis started. Switch to the **Progress** tab to monitor.")
        st.rerun()

# ---------------------- 2) Progress ----------------------
with tab_progress:
    progress_panel = make_progress_panel(st.container())
    if is_run_active():
        pcap_path = st.session_state.get("__pcap_path")

        base_url = cfg_get("cfg_lm_base_url", "LMSTUDIO_BASE_URL", C.LM_BASE_URL)
        api_key = cfg_get("cfg_lm_api_key", "LMSTUDIO_API_KEY", C.LM_API_KEY)
        model = cfg_get("cfg_lm_model", "LMSTUDIO_MODEL", C.LM_MODEL)

        limit_packets = int(st.session_state.get("cfg_limit_packets", C.DEFAULT_PYSHARK_LIMIT)) or None
        do_pyshark = bool(st.session_state.get("cfg_do_pyshark", True))
        do_zeek = bool(st.session_state.get("cfg_do_zeek", True))
        do_carve = bool(st.session_state.get("cfg_do_carve", True))
        pre_count = bool(st.session_state.get("cfg_pre_count", True))
        osint_top_n = int(st.session_state.get("cfg_osint_top_ips", C.OSINT_TOP_IPS_DEFAULT) or 0)

        osint_keys = {
            "OTX_KEY": st.session_state.get("cfg_otx", ""),
            "VT_KEY": st.session_state.get("cfg_vt", ""),
            "ABUSEIPDB_KEY": st.session_state.get("cfg_abuseipdb", ""),
            "GREYNOISE_KEY": st.session_state.get("cfg_greynoise", ""),
            "SHODAN_KEY": st.session_state.get("cfg_shodan", ""),
        }
        st.session_state["osint_keys"] = osint_keys

        phases = [
            ("Packet counting (tshark)", pre_count and do_pyshark),
            ("Parsing Packets", do_pyshark),
            ("Zeek processing", do_zeek),
            ("DNS Analysis", do_zeek),  # Requires Zeek dns.log
            ("TLS Certificate Analysis", do_zeek),  # Requires Zeek ssl.log
            ("Beaconing ranking", True),
            ("HTTP carving (tshark)", do_carve),
            ("OSINT enrichment", True),
            ("LLM report", True),
        ]
        total_phases = sum(1 for _, enabled in phases if enabled)
        tracker = PhaseTracker(total_phases, progress_container=progress_panel)
        tracker.update_overall("Running…")

        # Safe loads
        features = st.session_state.get("features") or {
            "flows": [],
            "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
        }
        zeek_tables = st.session_state.get("zeek_tables") or {}
        beacon_df = get_df_state("beacon_df")
        carved = st.session_state.get("carved") or []
        osint_data = st.session_state.get("osint") or {"ips": {}, "domains": {}, "ja3": {}}
        report_md = st.session_state.get("report")

        # Packet counting
        if dict(phases).get("Packet counting (tshark)", False):
            p = tracker.next_phase("Packet counting (tshark)")
            if not st.session_state.get(f"done_{make_slug('Packet counting (tshark)')}", False):
                if not st.session_state.get(f"skip_{make_slug('Packet counting (tshark)')}", False):
                    p.set(5, "Counting packets…")
                    st.session_state["__total_pkts"] = count_packets_fast(pcap_path)
                    p.done(
                        f"Found ~{st.session_state['__total_pkts']:,} packets."
                        if st.session_state["__total_pkts"]
                        else "Count unavailable."
                    )
                else:
                    p.done("Counting skipped.")

        # PyShark
        if dict(phases).get("Parsing Packets", False):
            p = tracker.next_phase("Parsing Packets")
            if not st.session_state.get(f"done_{make_slug('Parsing Packets')}", False):
                if not st.session_state.get(f"skip_{make_slug('Parsing Packets')}", False):
                    with st.spinner("Parsing packets…"):
                        features = parse_pcap_pyshark(
                            pcap_path,
                            limit_packets=limit_packets,
                            phase=p,
                            total_packets=st.session_state.get("__total_pkts"),
                            progress_every=250,
                        )
                p.done(
                    "Packet parsing complete."
                    if not st.session_state.get(f"skip_{make_slug('Parsing Packets')}", False)
                    else "Parsing skipped."
                )
            st.session_state["features"] = features

        # Zeek
        if dict(phases).get("Zeek processing", False):
            p = tracker.next_phase("Zeek processing")
            if not st.session_state.get(f"done_{make_slug('Zeek processing')}", False):
                if not st.session_state.get(f"skip_{make_slug('Zeek processing')}", False):
                    try:
                        logs = run_zeek(pcap_path, C.ZEEK_DIR, phase=p)
                    except Exception as e:
                        st.error(f"Zeek failed: {e}")
                        logs = {}
                        p.done("Zeek failed.")
                    if logs:
                        total = len(logs)
                        for i, (name, path) in enumerate(logs.items(), start=1):
                            try:
                                df = load_zeek_any(path)
                            except Exception:
                                df = pd.DataFrame()
                            zeek_tables[name] = df.head(2000)
                            p.set(80 + int(i / max(total, 1) * 20), f"Parsed {i}/{total} Zeek logs…")
                p.done(
                    "Zeek logs loaded."
                    if not st.session_state.get(f"skip_{make_slug('Zeek processing')}", False)
                    else "Zeek skipped."
                )
            st.session_state["zeek_tables"] = zeek_tables

            # Merge Zeek DNS queries into artifacts
            from app.pipeline.zeek import merge_zeek_dns

            features = merge_zeek_dns(zeek_tables, features)
            st.session_state["features"] = features

            # Extract JA3 fingerprints from ssl.log
            from app.pipeline.zeek import extract_ja3_from_zeek_tables

            zeek_log_paths = {name: str(C.ZEEK_DIR / name) for name in zeek_tables.keys()}
            ja3_df, ja3_analysis = extract_ja3_from_zeek_tables(zeek_log_paths)
            st.session_state["ja3_df"] = ja3_df
            st.session_state["ja3_analysis"] = ja3_analysis

        # DNS Analysis
        if dict(phases).get("DNS Analysis", False):
            p = tracker.next_phase("DNS Analysis")
            if not st.session_state.get(f"done_{make_slug('DNS Analysis')}", False):
                if not st.session_state.get(f"skip_{make_slug('DNS Analysis')}", False):
                    from app.pipeline.dns_analysis import analyze_dns

                    with st.spinner("Analyzing DNS traffic..."):
                        dns_result = analyze_dns(zeek_tables, features, phase=p)
                        st.session_state["dns_analysis"] = dns_result
                else:
                    p.done("DNS analysis skipped.")
                    st.session_state["dns_analysis"] = {"skipped": True}

        # TLS Certificate Analysis
        if dict(phases).get("TLS Certificate Analysis", False):
            p = tracker.next_phase("TLS Certificate Analysis")
            if not st.session_state.get(f"done_{make_slug('TLS Certificate Analysis')}", False):
                if not st.session_state.get(f"skip_{make_slug('TLS Certificate Analysis')}", False):
                    from app.pipeline.tls_certs import analyze_certificates

                    with st.spinner("Extracting TLS certificates..."):
                        tls_result = analyze_certificates(
                            pcap_path=pcap_path,
                            zeek_tables=zeek_tables,
                            phase=p,
                        )
                        st.session_state["tls_analysis"] = tls_result
                else:
                    p.done("TLS analysis skipped.")
                    st.session_state["tls_analysis"] = {"skipped": True}

        # Beaconing
        p = tracker.next_phase("Beaconing ranking")
        if not st.session_state.get(f"done_{make_slug('Beaconing ranking')}", False):
            if not st.session_state.get(f"skip_{make_slug('Beaconing ranking')}", False) and features.get("flows"):
                p.set(30, "Scoring flows…")
                beacon_df = rank_beaconing(features["flows"], top_n=20)
                if not isinstance(beacon_df, pd.DataFrame):
                    beacon_df = pd.DataFrame()
                p.set(90, "Sorting top candidates…")
            p.done(
                "Beaconing step complete."
                if not st.session_state.get(f"skip_{make_slug('Beaconing ranking')}", False)
                else "Beaconing skipped."
            )
        st.session_state["beacon_df"] = beacon_df

        # HTTP carving
        if dict(phases).get("HTTP carving (tshark)", False):
            p = tracker.next_phase("HTTP carving (tshark)")
            if not st.session_state.get(f"done_{make_slug('HTTP carving (tshark)')}", False):
                if not st.session_state.get(f"skip_{make_slug('HTTP carving (tshark)')}", False):
                    with st.spinner("Carving HTTP payloads…"):
                        carved = carve_http_payloads(pcap_path, C.CARVE_DIR, phase=p)
                        carved = carved if isinstance(carved, list) else []
                        for item in carved:
                            h = item.get("sha256")
                            if h:
                                features["artifacts"]["hashes"].append(h)
                        features["artifacts"]["hashes"] = uniq_sorted(features["artifacts"]["hashes"])
                p.done(
                    "HTTP carving complete."
                    if not st.session_state.get(f"skip_{make_slug('HTTP carving (tshark)')}", False)
                    else "HTTP carving skipped."
                )
            st.session_state["carved"] = carved
            st.session_state["features"] = features

        # OSINT
        p = tracker.next_phase("OSINT enrichment")
        if not st.session_state.get(f"done_{make_slug('OSINT enrichment')}", False):
            if not st.session_state.get(f"skip_{make_slug('OSINT enrichment')}", False):
                with st.spinner("OSINT enrichment…"):
                    feats = (
                        features
                        if isinstance(features, dict)
                        else {"flows": [], "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []}}
                    )
                    arts = dict(feats.get("artifacts", {}))
                    arts["ips"] = [ip for ip in arts.get("ips", []) if is_public_ipv4(ip)]
                    if osint_top_n > 0:
                        arts["ips"] = pick_top_public_ips(feats, osint_top_n)

                    osint_data = osint_enrich(arts, osint_keys, phase=p)
                    osint_data = osint_data if isinstance(osint_data, dict) else {"ips": {}, "domains": {}, "ja3": {}}
            p.done(
                "OSINT complete."
                if not st.session_state.get(f"skip_{make_slug('OSINT enrichment')}", False)
                else "OSINT skipped."
            )
        st.session_state["osint"] = osint_data

        # LLM — pass FULL CONTEXT
        p = tracker.next_phase("LLM report")
        if not st.session_state.get(f"done_{make_slug('LLM report')}", False):
            if not st.session_state.get(f"skip_{make_slug('LLM report')}", False):
                with st.spinner("Generating LLM report via LM Studio…"):
                    zeek_json = {
                        name: (df.to_dict(orient="records") if isinstance(df, pd.DataFrame) else [])
                        for name, df in (zeek_tables or {}).items()
                    }
                    beacon_rows = []
                    try:
                        if isinstance(beacon_df, pd.DataFrame):
                            beacon_rows = beacon_df.to_dict(orient="records")
                    except Exception:
                        beacon_rows = []

                    context = {
                        "features": features or {},
                        "osint": osint_data or {},
                        "zeek": zeek_json,
                        "beaconing": beacon_rows,
                        "carved": carved or [],
                        "packet_count": st.session_state.get("__total_pkts"),
                        "config": {
                            "limit_packets": limit_packets,
                            "do_pyshark": do_pyshark,
                            "do_zeek": do_zeek,
                            "do_carve": do_carve,
                            "pre_count": pre_count,
                            "osint_top_n": osint_top_n,
                        },
                    }

                    try:
                        report_md = generate_report(base_url, api_key, model, context)
                    except Exception as e:
                        st.error(f"LLM call failed: {e}")
                        report_md = "_LLM generation failed. Check server/model settings._"
            else:
                report_md = "_Report skipped by user._"
            p.done(
                "LLM report generated."
                if not st.session_state.get(f"skip_{make_slug('LLM report')}", False)
                else "LLM skipped."
            )
        st.session_state["report"] = report_md

        # End run
        all_done = True
        for title, enabled in phases:
            if enabled and not st.session_state.get(f"done_{make_slug(title)}", False):
                all_done = False
                break
        if all_done:
            end_run()
    else:
        st.info("Start in **Upload** tab, then return here to track progress.")

# ---------------------- 3) Dashboard ----------------------
# ---------------------- 3) Dashboard ----------------------
with tab_dashboard:
    st.markdown("### Dashboard")

    feats = st.session_state.get("features") or {}
    all_flows = feats.get("flows") or []

    # Initialize filter state
    if "filter_ips" not in st.session_state:
        st.session_state["filter_ips"] = set()
    if "filter_protos" not in st.session_state:
        st.session_state["filter_protos"] = set()
    if "filter_time" not in st.session_state:
        st.session_state["filter_time"] = None  # (start, end)

    # Apply Filters
    from app.utils.common import filter_flows_by_ips, filter_flows_by_protocol, filter_flows_by_time

    filtered_flows = all_flows

    # 1. IP Filter
    if st.session_state["filter_ips"]:
        filtered_flows = filter_flows_by_ips(filtered_flows, st.session_state["filter_ips"])

    # 2. Protocol Filter
    if st.session_state["filter_protos"]:
        filtered_flows = filter_flows_by_protocol(filtered_flows, st.session_state["filter_protos"])

    # 3. Time Filter
    if st.session_state["filter_time"]:
        start_t, end_t = st.session_state["filter_time"]
        filtered_flows = filter_flows_by_time(filtered_flows, start_t, end_t)

    # Display active filters
    active_filters = []
    if st.session_state["filter_ips"]:
        active_filters.append(f"{len(st.session_state['filter_ips'])} IPs")
    if st.session_state["filter_protos"]:
        active_filters.append(f"Protocols: {', '.join(st.session_state['filter_protos'])}")
    if st.session_state["filter_time"]:
        active_filters.append("Time Range")

    if active_filters:
        st.caption(
            f"Active Filters: {' + '.join(active_filters)} | Showing {len(filtered_flows)} of {len(all_flows)} flows"
        )
        if st.button("Clear All Filters", type="primary"):
            st.session_state["filter_ips"] = set()
            st.session_state["filter_protos"] = set()
            st.session_state["filter_time"] = None
            st.session_state["map_reset_counter"] += 1
            st.rerun()
    else:
        st.caption(f"Showing all {len(all_flows)} flows")

    # 1. World Map
    ip_locs = []
    if filtered_flows:
        # Collect all public IPs from FILTERED flows
        ips = set()
        for f in filtered_flows:
            if f.get("src") and is_public_ipv4(f["src"]):
                ips.add(f["src"])
            if f.get("dst") and is_public_ipv4(f["dst"]):
                ips.add(f["dst"])

        # Lookup locations
        for ip in ips:
            loc = GeoIP.lookup(ip)
            if loc:
                ip_locs.append(loc)

    if ip_locs:
        # Render map with selection enabled
        map_event = st.plotly_chart(
            plot_world_map(ip_locs, flows=filtered_flows),
            width="stretch",
            on_select="rerun",
            selection_mode=["points", "box", "lasso"],
            key=f"map_select_{st.session_state.get('map_reset_counter', 0)}",
        )

        # Handle Map Selection
        if map_event and "selection" in map_event:
            points = map_event["selection"].get("points", [])
            new_ips = set()
            for p in points:
                if "customdata" in p:
                    # customdata is a list of IPs for that location
                    new_ips.update(p["customdata"])

            if new_ips:
                st.session_state["filter_ips"] = new_ips
                st.rerun()
    else:
        st.info("No public IP locations found for map.")

    col1, col2 = st.columns(2)

    # 2. Protocol Distribution
    with col1:
        proto_counts = {}
        for f in filtered_flows:
            p = f.get("proto", "Unknown")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        if proto_counts:
            pie_event = st.plotly_chart(
                plot_protocol_distribution(proto_counts),
                width="stretch",
                on_select="rerun",
                selection_mode="points",
                key="pie_select",
            )

            # Handle Pie Selection
            if pie_event and "selection" in pie_event:
                points = pie_event["selection"].get("points", [])
                if points:
                    # Point index usually corresponds to the label order
                    # But safer to try to get label if available, or infer from index
                    # Plotly pie selection often gives pointNumber.
                    # We constructed the chart with keys() as names.
                    # Let's get the label from the point info if possible, or use index.
                    # Streamlit's event point dict usually has 'label' for pie charts?
                    # Let's check point structure. Usually it has pointIndex.
                    # We can map pointIndex back to the sorted keys.
                    # Keys in proto_counts are not ordered? dict is ordered in Py3.7+.
                    labels = list(proto_counts.keys())
                    selected_protos = set()
                    for p in points:
                        idx = p.get("point_index")
                        if idx is not None and 0 <= idx < len(labels):
                            selected_protos.add(labels[idx])

                    if selected_protos:
                        st.session_state["filter_protos"] = selected_protos
                        st.rerun()
        else:
            st.info("No protocol data available.")

    # 3. Flow Timeline
    with col2:
        if filtered_flows:
            timeline_event = st.plotly_chart(
                plot_flow_timeline(filtered_flows),
                width="stretch",
                on_select="rerun",
                selection_mode=["box", "lasso"],
                key="timeline_select",
            )

            # Handle Timeline Selection
            if timeline_event and "selection" in timeline_event:
                points = timeline_event["selection"].get("points", [])
                if points:
                    # Calculate time range from selected points
                    # Each point has x value (time)
                    # We want the min and max time of the selection
                    times = [p.get("x") for p in points if p.get("x")]
                    # Plotly returns strings for dates usually? Or timestamps?
                    # Pandas datetime objects might be serialized.
                    # Let's try to parse or use as is if they are comparable.
                    # If they are strings, we might need to convert.
                    # But wait, plot_flow_timeline uses datetime objects.
                    # Streamlit might return them as strings "2023-..."
                    if times:
                        try:
                            # Convert to timestamps
                            ts_values = [pd.to_datetime(t).timestamp() for t in times]
                            min_t = min(ts_values)
                            max_t = max(ts_values)
                            st.session_state["filter_time"] = (min_t, max_t)
                            st.rerun()
                        except Exception:
                            pass
        else:
            st.info("No flow data available.")

    st.markdown("---")
    render_report(st.container(), st.session_state.get("report"))

# 4) OSINT ----------------------
with tab_osint:
    st.markdown("### OSINT Investigation")
    render_osint(st.container(), st.session_state.get("osint") or {"ips": {}, "domains": {}, "ja3": {}})

# 5) Raw Data ----------------------
with tab_results:
    results_panel = make_results_panel(st.container())
    with results_panel:
        render_overview(results_panel, st.session_state.get("features"))
        feats = st.session_state.get("features") or {}
        render_flows(results_panel, feats.get("flows"))
        render_dns_analysis(results_panel, st.session_state.get("dns_analysis"))
        render_tls_certificates(results_panel, st.session_state.get("tls_analysis"))
        render_ja3(
            results_panel,
            st.session_state.get("ja3_df"),
            st.session_state.get("ja3_analysis"),
        )
        render_zeek(results_panel, st.session_state.get("zeek_tables") or {})
        render_carved(results_panel, st.session_state.get("carved") or [])

# 5) Config ----------------------
with tab_config:
    render_config_tab()

st.markdown("---")
with st.expander("Notes & OPSEC"):
    st.markdown("""
- **Tabs**: Upload → Progress → Results → Config.
- **Skip** is non-blocking; pipeline continues to next phase.
- **OSINT limit**: configurable Top-N IPs by traffic; 0 = enrich all.
- Zeek JSON-first with ASCII fallback; OSINT calls have safe timeouts.
- Carved binaries stored locally in `/data/carved`; no uploads.
""")
