from __future__ import annotations

import pathlib
import sys

# Ensure top-level repo path importable
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import logging
import os
import time

import pandas as pd
import streamlit as st

from app import config as C
from app.analysis.flow_aggregates import compute_flow_aggregates
from app.analysis.visibility import build_capture_metrics
from app.llm import providers as llm_providers
from app.pipeline.batch import BatchProcessor, PCAPResult
from app.pipeline.geoip import GeoIP
from app.pipeline.osint import enrich as osint_enrich
from app.pipeline.state import (
    BatchPhaseTracker,
    PhaseTracker,
    end_run,
    is_run_active,
)
from app.ui.background_analysis import (
    BACKGROUND_RUN_KEY,
    find_recoverable_background_run,
    render_background_progress,
    submit_background_analysis,
    submit_background_report,
)
from app.ui.charts import (
    build_sankey_html,
    plot_attack_timeline,
    plot_flow_timeline,
    plot_inter_arrival_histogram,
    plot_network_graph,
    plot_packet_size_histogram,
    plot_protocol_distribution,
    plot_top_n_charts,
    plot_traffic_timeline_heatmap,
    plot_world_map,
)
from app.ui.config_ui import init_config_defaults, render_config_tab, save_config
from app.ui.layout import (
    analysis_has_run,
    inject_css,
    make_progress_panel,
    make_results_panel,
    make_tabs,
    render_active_filters,
    render_analysis_snapshot,
    render_batch_summary,
    render_carved,
    render_chart_hint,
    render_correlation_results,
    render_cross_file_correlation,
    render_dns_analysis,
    render_flow_asymmetry,
    render_flows,
    render_hunting_checklist,
    render_ioc_search,
    render_ja3,
    render_nxdomain_analysis,
    render_osint,
    render_overview,
    render_per_file_summary,
    render_port_anomalies,
    render_query_velocity,
    render_report,
    render_severity_legend,
    render_threat_summary,
    render_tls_certificates,
    render_yara_results,
    render_zeek,
    resolve_logo_path,
)
from app.ui.mitre_page import build_attack_mapping, render_mitre_page
from app.ui.upload import UploadValidationError, save_uploaded_pcaps
from app.utils.common import ensure_dir, find_bin, is_public_ipv4, make_slug, uniq_sorted
from app.utils.network_utils import pick_top_public_ips

logger = logging.getLogger(__name__)


def validate_pcap_path(path_str: str) -> str | None:
    """Validate that a user-provided PCAP path is within allowed directories.

    Returns the resolved path string if valid, None otherwise.
    """
    try:
        p = pathlib.Path(path_str).resolve()
    except (OSError, ValueError):
        return None
    if not p.is_file():
        return None
    if p.suffix.lower() not in (".pcap", ".pcapng"):
        return None
    for allowed in C.ALLOWED_PCAP_DIRS:
        try:
            p.relative_to(allowed)
            return str(p)
        except ValueError:
            continue
    return None


def get_df_state(key: str) -> pd.DataFrame:
    val = st.session_state.get(key, None)
    return val if isinstance(val, pd.DataFrame) else pd.DataFrame()


def _precompute_dash_aggregates(flows: list | None) -> None:
    """Cache dashboard top-N aggregates for the unfiltered fast path.

    Flow-count semantics — one increment per flow row, matching the legacy
    dashboard behaviour.
    """
    st.session_state["dash_aggregates"] = compute_flow_aggregates(flows, top_n=10, weight="flows")


def _ss_default(key: str, value):
    if key not in st.session_state:
        st.session_state[key] = value


def cfg_get(name: str, env_key: str, default):
    return st.session_state.get(name) or os.getenv(env_key, default)


def _run_single_pcap_pipeline(
    pcap_path: str,
    tracker: PhaseTracker,
    phases: list[tuple[str, bool]],
    limit_packets: int | None,
    osint_keys: dict,
    osint_top_n: int,
    do_pyshark: bool,
    do_zeek: bool,
    do_carve: bool,
    pre_count: bool,
    do_yara: bool,
) -> PCAPResult:
    """Run stages 1-9 for a single PCAP file and return a PCAPResult.

    Stages 1-7 are delegated to the headless pipeline runner (which parallelizes
    PyShark+Zeek via ThreadPoolExecutor).  Stages 8-9 (YARA, OSINT) remain here
    because they interact with session_state or need OSINT API keys from the UI.
    """
    from app.pipeline.runner import PipelineOptions, run_pipeline
    from app.pipeline.state import StreamlitProgressAdapter

    filename = pathlib.Path(pcap_path).name

    options = PipelineOptions(
        osint_enabled=bool(osint_keys),
        llm_enabled=False,
        do_pyshark=do_pyshark,
        do_zeek=do_zeek,
        do_carve=do_carve,
        do_yara=do_yara,
        pre_count=pre_count,
        pyshark_packet_limit=limit_packets,
        osint_top_n=osint_top_n,
    )

    progress = StreamlitProgressAdapter(tracker)

    try:
        result = run_pipeline(
            pcap_path=pcap_path,
            case_id=pathlib.Path(pcap_path).stem,
            options=options,
            progress=progress,
        )

        features = result.features
        zeek_tables = result.zeek_tables
        beacon_df = pd.DataFrame.from_records(result.beacon_df_records) if result.beacon_df_records else pd.DataFrame()

        # --- Stage 8: YARA Scanning ---
        phase_dict = dict(phases)
        if phase_dict.get("YARA Scanning", False) and do_yara:
            p = tracker.next_phase("YARA Scanning")
            from app.pipeline.yara_scan import scan_carved_files

            _yara_dir = (st.session_state.get("cfg_yara_rules_dir") or "").strip()
            _yara = scan_carved_files(result.carved_items, rules_dirs=[_yara_dir] if _yara_dir else None, phase=p)
            st.session_state["yara_results"] = _yara

        # --- Stage 9: OSINT enrichment ---
        osint_data: dict = {"ips": {}, "domains": {}, "ja3": {}}
        p = tracker.next_phase("OSINT enrichment")
        feats = (
            features
            if isinstance(features, dict)
            else {
                "flows": [],
                "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
            }
        )
        arts = dict(feats.get("artifacts", {}))
        arts["ips"] = [ip for ip in arts.get("ips", []) if is_public_ipv4(ip)]
        if osint_top_n > 0:
            arts["ips"] = pick_top_public_ips(feats, osint_top_n)
        osint_data = osint_enrich(arts, osint_keys, phase=p)
        osint_data = osint_data if isinstance(osint_data, dict) else {"ips": {}, "domains": {}, "ja3": {}}
        p.done("OSINT complete.")

        # Bulk rDNS for all public IPs (cached, fast)
        from app.utils.network_utils import bulk_resolve_ips

        all_public = [ip for ip in features.get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]
        rdns_map = bulk_resolve_ips(all_public, max_workers=C.RDNS_MAX_WORKERS)
        for ip, hostname in rdns_map.items():
            if ip in osint_data.get("ips", {}) and "ptr" not in osint_data["ips"][ip]:
                osint_data["ips"][ip]["ptr"] = hostname

    except Exception as e:
        logger.error("Pipeline failed for %s: %s", filename, e)
        return PCAPResult(path=pcap_path, filename=filename, error=str(e))

    return PCAPResult(
        path=pcap_path,
        filename=filename,
        features=features,
        zeek_tables=zeek_tables,
        zeek_log_paths=result.zeek_log_paths,
        rdns_map=rdns_map,
        carved_items=result.carved_items,
        osint=osint_data,
        beacon_df=beacon_df if isinstance(beacon_df, pd.DataFrame) else None,
        dns_analysis=result.dns_analysis or {},
        tls_analysis=result.tls_analysis or {},
        packet_count=result.packet_count,
        duration_seconds=result.duration_seconds,
        stages_run=list(result.stages_run),
        warnings=list(result.warnings),
    )


# ---------------------------------------------------------------------------
# Streamlit App
# ---------------------------------------------------------------------------

# Resolve branding assets relative to this file so the app works regardless
# of the current working directory (Docker vs. local vs. Streamlit cloud).
_STATIC_DIR = pathlib.Path(__file__).resolve().parent / "static"
_FAVICON_PATH = _STATIC_DIR / "favicon-32.png"

st.set_page_config(
    page_title=C.APP_NAME,
    # page_icon accepts a file path; Streamlit embeds it as the browser tab icon.
    page_icon=str(_FAVICON_PATH) if _FAVICON_PATH.is_file() else "🔍",
    layout="wide",
)
inject_css()

# Header: logo + title side-by-side. Narrow left column for the mark so the
# wordmark dominates and the layout still looks right on smaller screens.
# The mark is theme-aware: the light-bg variant's navy strokes vanish on the
# dark theme (the icon read as "cut off"), so each theme has its own PNG.
# st.context.theme needs Streamlit >= 1.46 — fall back to the light asset.
_theme = getattr(getattr(st, "context", None), "theme", None)
_logo_path = resolve_logo_path(_STATIC_DIR, getattr(_theme, "type", None))
_hdr_logo, _hdr_title = st.columns([1, 11], gap="small", vertical_alignment="center")
with _hdr_logo:
    if _logo_path is not None:
        st.image(str(_logo_path), width=72)
with _hdr_title:
    st.title(C.APP_NAME)

# --- RE-RUN TRIGGER LOGIC ---
if st.session_state.get("trigger_llm_rerun"):
    restored_ids = st.session_state.get("restored_analysis_ids") or []
    if restored_ids:
        save_config()
        try:
            st.session_state[BACKGROUND_RUN_KEY] = submit_background_report(restored_ids)
        except Exception as exc:
            st.error(f"Could not queue report regeneration: {exc}")
        else:
            st.session_state["report"] = None
            st.session_state["llm_status"] = None
        st.session_state["trigger_llm_rerun"] = False
        st.rerun()
    else:
        # Legacy in-memory runs have no persisted analysis to hand to the
        # report-only worker, so retain the original fallback behavior.
        st.session_state["run_active"] = True
        llm_slug = make_slug("LLM report")
        st.session_state[f"done_{llm_slug}"] = False
        st.session_state[f"skip_{llm_slug}"] = False
        st.session_state["report"] = None
        st.session_state["llm_status"] = None
        st.session_state["trigger_llm_rerun"] = False
        st.rerun()
init_config_defaults()

# ---------------------- Dependency pre-flight check ----------------------
# Warn prominently if critical binaries are missing — the pipeline silently
# produces empty results without them, and users are left staring at a blank
# dashboard wondering what went wrong.
_missing_bins: list[str] = []
if not find_bin("tshark", cfg_key="cfg_tshark_bin"):
    _missing_bins.append("**tshark** (required for packet parsing)")
if not find_bin("zeek", env_key="ZEEK_BIN", cfg_key="cfg_zeek_bin"):
    _missing_bins.append("**zeek** (required for protocol analysis)")

if _missing_bins:
    # Show OS-appropriate install commands so users don't hunt for the right one.
    import sys as _sys

    if _sys.platform == "darwin":
        _install_help = "**Install on macOS:** `brew install wireshark zeek`"
    elif _sys.platform == "win32":
        _install_help = (
            "**Install on Windows:** `winget install WiresharkFoundation.Wireshark`  \n"
            "Zeek has no native Windows build — use **WSL2** (`wsl --install` → `sudo apt install zeek`) "
            "or the **Docker image** (`docker compose up`)."
        )
    else:
        _install_help = "**Install on Ubuntu/Debian:** `sudo apt install tshark zeek`"

    st.error(
        "⚠️ **Missing required binaries** — analysis will produce empty results until these are installed:\n\n"
        + "\n".join(f"- {b}" for b in _missing_bins)
        + "\n\n"
        + _install_help
        + "  \nOr set explicit paths in the **Settings** tab below."
    )

# Tabs
(
    tab_upload,
    tab_progress,
    tab_dashboard,
    tab_mitre,
    tab_llm,
    tab_osint,
    tab_results,
    tab_cases,
    tab_api_keys,
    tab_config,
) = make_tabs()

# Defaults
for k, v in [
    ("features", None),
    ("osint", None),
    ("report", None),
    ("llm_status", None),
    ("beacon_df", pd.DataFrame()),
    ("zeek_tables", {}),
    ("carved", []),
    ("__total_pkts", None),
    ("runtime_logs", []),
    ("map_reset_counter", 0),
    ("dns_analysis", None),
    ("tls_analysis", None),
    ("attack_mapping", None),
    ("capture_metrics", None),
    ("pipeline_warnings", []),
    ("pipeline_stages", []),
    ("yara_results", None),
    ("correlations", None),
    ("flow_asymmetry", None),
    ("port_anomalies", None),
    ("__pcap_paths", []),
    ("__batch_mode", False),
    ("__batch_result", None),
]:
    if k not in st.session_state:
        st.session_state[k] = v

# Browser reloads create a new Streamlit session, but durable job rows remain.
# Reattach the latest recent UI-owned run when there is no live analysis yet.
if BACKGROUND_RUN_KEY not in st.session_state and not analysis_has_run():
    recovered_run = find_recoverable_background_run()
    if recovered_run:
        st.session_state[BACKGROUND_RUN_KEY] = recovered_run

# ---------------------- 1) Upload ----------------------
with tab_upload:
    st.subheader("1) Load PCAP")

    # --- Getting-started panel (first-run onboarding, dismissable) ---
    if not st.session_state.get("_onboard_dismissed") and not analysis_has_run():
        with st.container(border=True):
            st.markdown("##### 🚀 Getting started")
            st.markdown(
                "1. **Upload a PCAP** below (or type a container path).\n"
                "2. Click **Extract & Analyze** — the 10-stage pipeline parses packets (tshark/PyShark), "
                "runs Zeek, hunts DNS/TLS/beaconing anomalies, carves HTTP payloads, scans with YARA, "
                "and enriches IOCs via OSINT.\n"
                "3. Review findings in **📊 Dashboard** (verdict + visuals), **🕵️ OSINT** (per-IOC triage), and "
                "**📋 Raw Data** (full evidence). Generate an AI report in **🤖 LLM Analysis**.\n\n"
                "*Optional:* add OSINT API keys (**🔑 API Keys** tab) and an LM Studio endpoint (**⚙️ Config** tab) "
                "to unlock enrichment and AI reports."
            )
            if st.button("Got it — don't show again", key="_onboard_dismiss_btn"):
                st.session_state["_onboard_dismissed"] = True
                st.rerun()

    col_a, col_b = st.columns([1, 1])
    with col_a:
        uploaded_files = st.file_uploader(
            "Upload .pcap / .pcapng files",
            type=["pcap", "pcapng"],
            accept_multiple_files=True,
        )
    with col_b:
        pcap_path_text = st.text_input("...or type a container path (e.g., /data/capture.pcap)", value="")

    ensure_dir(C.DATA_DIR)
    ensure_dir(C.ZEEK_DIR)
    ensure_dir(C.CARVE_DIR)

    pcap_path = None
    pcap_paths: list[str] = []
    if uploaded_files:
        try:
            saved_uploads = save_uploaded_pcaps(uploaded_files, C.DATA_DIR, timestamp=int(time.time()))
        except UploadValidationError as exc:
            st.error(str(exc))
            pcap_path = None
        else:
            pcap_paths = [item.path for item in saved_uploads]
            pcap_path = pcap_paths[0]
            st.session_state["__pcap_path"] = pcap_path
            st.session_state["__pcap_paths"] = pcap_paths
            st.session_state["__batch_mode"] = len(pcap_paths) > 1
            if len(pcap_paths) > 1:
                names = ", ".join(item.original_name for item in saved_uploads)
                source_msg = f"Uploaded {len(pcap_paths)} files: {names}"
            else:
                source_msg = f"Uploaded: {saved_uploads[0].original_name}"
    elif pcap_path_text.strip():
        validated = validate_pcap_path(pcap_path_text.strip())
        if validated:
            pcap_path = validated
            pcap_paths = [validated]
            st.session_state["__pcap_path"] = pcap_path
            st.session_state["__pcap_paths"] = pcap_paths
            st.session_state["__batch_mode"] = False
            source_msg = f"Manual Path: {pcap_path}"
        else:
            st.error("Path must point to a .pcap/.pcapng file inside an allowed directory (data/, pcaps/, or /data/).")
            pcap_path = None
    elif st.session_state.get("__pcap_paths"):
        pcap_paths = st.session_state["__pcap_paths"]
        pcap_path = pcap_paths[0] if pcap_paths else None
        if len(pcap_paths) > 1:
            source_msg = f"Last Source: {len(pcap_paths)} files"
        elif pcap_path:
            source_msg = f"Last Source: {pathlib.Path(pcap_path).name}"
    elif st.session_state.get("__pcap_path"):
        pcap_path = st.session_state["__pcap_path"]
        pcap_paths = [pcap_path]
        source_msg = f"Last Source: {pathlib.Path(pcap_path).name}"

    if pcap_path:
        st.info(f"**Active Source:** {source_msg}")
        if st.session_state.get("__batch_mode"):
            # Validate batch
            processor = BatchProcessor(pcap_paths)
            if processor.skipped_files:
                for name, err in processor.skipped_files:
                    st.warning(f"Skipped {name}: {err}")
            st.caption(
                f"Batch: {len(processor.pcap_paths)} valid file(s), {processor.total_size / (1024 * 1024):.1f} MB total"
            )

    do_pyshark = bool(st.session_state.get("cfg_do_pyshark", True))
    do_zeek = bool(st.session_state.get("cfg_do_zeek", True))
    do_carve = bool(st.session_state.get("cfg_do_carve", True))
    pre_count = bool(st.session_state.get("cfg_pre_count", True))
    do_yara = bool(st.session_state.get("cfg_do_yara", True))

    phases = [
        ("Packet counting (tshark)", pre_count and do_pyshark),
        ("Parsing Packets", do_pyshark),
        ("Zeek processing", do_zeek),
        ("DNS Analysis", do_zeek),  # Requires Zeek dns.log
        ("TLS Certificate Analysis", do_zeek),  # Requires Zeek ssl.log
        ("Beaconing ranking", True),
        ("HTTP carving (tshark)", do_carve),
        ("YARA Scanning", do_carve and do_yara),  # Requires carved files
        ("OSINT enrichment", True),
        ("LLM report", True),
    ]

    run_llm = st.checkbox(
        "Generate LLM report in the background",
        value=bool(st.session_state.get("cfg_run_llm", True)),
        key="cfg_run_llm",
        help="Disable this when you only need deterministic packet, Zeek, YARA, and OSINT results.",
    )
    start = st.button("Extract & Analyze", type="primary", width="stretch")
    if start:
        if not pcap_path or not pathlib.Path(pcap_path).exists():
            st.error("Please upload a PCAP or provide a valid path.")
            st.stop()
        try:
            limit_packets = int(st.session_state.get("cfg_limit_packets", C.DEFAULT_PYSHARK_LIMIT)) or None
        except (ValueError, TypeError):
            limit_packets = C.DEFAULT_PYSHARK_LIMIT
        try:
            osint_top_n = int(st.session_state.get("cfg_osint_top_ips", C.OSINT_TOP_IPS_DEFAULT) or 0)
        except (ValueError, TypeError):
            osint_top_n = C.OSINT_TOP_IPS_DEFAULT

        # Persist encrypted provider settings before the worker process loads
        # them. Job rows contain only non-sensitive execution options.
        if not save_config():
            st.warning(
                "Settings could not be saved; the background job will use environment/default provider settings."
            )
        try:
            background_run = submit_background_analysis(
                pcap_paths or [pcap_path],
                {
                    "osint_enabled": True,
                    "llm_enabled": run_llm,
                    "do_pyshark": do_pyshark,
                    "do_zeek": do_zeek,
                    "do_carve": do_carve,
                    "do_yara": do_yara,
                    "pre_count": pre_count,
                    "pyshark_packet_limit": limit_packets,
                    "osint_top_n": osint_top_n,
                },
            )
        except Exception as exc:
            st.error(f"Could not start the background analysis: {exc}")
            st.stop()
        end_run()
        st.session_state[BACKGROUND_RUN_KEY] = background_run
        st.session_state["__pcap_path"] = pcap_path
        st.session_state["__pcap_paths"] = pcap_paths or [pcap_path]
        st.session_state["__batch_mode"] = len(st.session_state["__pcap_paths"]) > 1
        st.toast("Analysis safely queued in the background", icon="🚀")
        st.success("Analysis started. It will continue even if this Streamlit page is stopped or reloaded.")
        st.rerun()

# ---------------------- 2) Progress ----------------------
with tab_progress:
    progress_panel = make_progress_panel(st.container())
    background_run = st.session_state.get(BACKGROUND_RUN_KEY)
    if background_run:

        @st.fragment(run_every="2s")
        def _background_progress_fragment():
            if render_background_progress(st.session_state[BACKGROUND_RUN_KEY]):
                st.rerun()

        _background_progress_fragment()
    elif is_run_active():
        pcap_path = st.session_state.get("__pcap_path")
        pcap_paths = st.session_state.get("__pcap_paths") or ([pcap_path] if pcap_path else [])
        batch_mode = st.session_state.get("__batch_mode", False) and len(pcap_paths) > 1

        llm_provider = cfg_get("cfg_llm_provider", "LLM_PROVIDER", C.LLM_PROVIDER_DEFAULT)
        if llm_provider not in llm_providers.PROVIDERS:
            llm_provider = C.LLM_PROVIDER_DEFAULT
        if llm_provider == llm_providers.PROVIDER_OPENAI:
            base_url = cfg_get("cfg_openai_base_url", "OPENAI_BASE_URL", "")
            api_key = cfg_get("cfg_openai_api_key", "OPENAI_API_KEY", "")
            model = cfg_get("cfg_openai_model", "OPENAI_MODEL", C.OPENAI_MODEL_DEFAULT)
        elif llm_provider == llm_providers.PROVIDER_ANTHROPIC:
            base_url = ""  # Anthropic SDK ignores base_url
            api_key = cfg_get("cfg_anthropic_api_key", "ANTHROPIC_API_KEY", "")
            model = cfg_get("cfg_anthropic_model", "ANTHROPIC_MODEL", C.ANTHROPIC_MODEL_DEFAULT)
        else:  # LM Studio
            base_url = cfg_get("cfg_lm_base_url", "LMSTUDIO_BASE_URL", C.LM_BASE_URL)
            api_key = cfg_get("cfg_lm_api_key", "LMSTUDIO_API_KEY", C.LM_API_KEY)
            model = cfg_get("cfg_lm_model", "LMSTUDIO_MODEL", C.LM_MODEL)
        language = cfg_get("cfg_lm_language", "LMSTUDIO_LANGUAGE", C.LM_LANGUAGE)
        provider_label = llm_providers.provider_label(llm_provider)

        try:
            limit_packets = int(st.session_state.get("cfg_limit_packets", C.DEFAULT_PYSHARK_LIMIT)) or None
        except (ValueError, TypeError):
            limit_packets = C.DEFAULT_PYSHARK_LIMIT
        do_pyshark = bool(st.session_state.get("cfg_do_pyshark", True))
        do_zeek = bool(st.session_state.get("cfg_do_zeek", True))
        do_carve = bool(st.session_state.get("cfg_do_carve", True))
        pre_count = bool(st.session_state.get("cfg_pre_count", True))
        do_yara = bool(st.session_state.get("cfg_do_yara", True))
        try:
            osint_top_n = int(st.session_state.get("cfg_osint_top_ips", C.OSINT_TOP_IPS_DEFAULT) or 0)
        except (ValueError, TypeError):
            osint_top_n = C.OSINT_TOP_IPS_DEFAULT

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
            ("DNS Analysis", do_zeek),
            ("TLS Certificate Analysis", do_zeek),
            ("Beaconing ranking", True),
            ("HTTP carving (tshark)", do_carve),
            ("YARA Scanning", do_carve and do_yara),
            ("OSINT enrichment", True),
            ("LLM report", True),
        ]
        active_phases = [t for t, enabled in phases if enabled]
        # LLM is handled separately after pipeline stages
        pipeline_phases = [p for p in active_phases if p != "LLM report"]

        # ---- BATCH MODE ----
        if batch_mode:
            processor = BatchProcessor(pcap_paths)
            batch_tracker = BatchPhaseTracker(
                total_files=len(processor.pcap_paths),
                phases_per_file=len(pipeline_phases),
                container=progress_panel,
            )

            for file_path in processor.pcap_paths:
                file_tracker = batch_tracker.start_file(str(file_path))
                file_tracker.update_overall("Running\u2026")

                result = _run_single_pcap_pipeline(
                    pcap_path=str(file_path),
                    tracker=file_tracker,
                    phases=[(t, e) for t, e in phases if t != "LLM report"],
                    limit_packets=limit_packets,
                    osint_keys=osint_keys,
                    osint_top_n=osint_top_n,
                    do_pyshark=do_pyshark,
                    do_zeek=do_zeek,
                    do_carve=do_carve,
                    pre_count=pre_count,
                    do_yara=do_yara,
                )
                processor.add_result(result)
                batch_tracker.finish_file()

            # Cross-file correlation
            batch_result = processor.merge_all()
            st.session_state["__batch_result"] = batch_result

            # Store merged results for dashboard compatibility
            # Use the first successful result's features as base, merged with correlation data
            first_ok = next((r for r in batch_result.pcap_results if not r.error), None)
            if first_ok:
                # Merge all features artifacts across files
                merged_ips = set()
                merged_domains = set()
                merged_hashes = set()
                merged_ja3 = set()
                merged_macs = set()
                all_flows = []
                for r in batch_result.pcap_results:
                    if r.error:
                        continue
                    arts = r.features.get("artifacts", {})
                    merged_ips.update(arts.get("ips", []))
                    merged_domains.update(arts.get("domains", []))
                    merged_hashes.update(arts.get("hashes", []))
                    merged_ja3.update(arts.get("ja3", []))
                    merged_macs.update(arts.get("macs", []))
                    all_flows.extend(r.features.get("flows", []))
                merged_features = {
                    "flows": all_flows,
                    "artifacts": {
                        "ips": uniq_sorted(merged_ips),
                        "domains": uniq_sorted(merged_domains),
                        "hashes": uniq_sorted(merged_hashes),
                        "ja3": uniq_sorted(merged_ja3),
                        "macs": uniq_sorted(merged_macs),
                        "urls": [],
                    },
                }
                st.session_state["features"] = merged_features
            else:
                st.session_state["features"] = {
                    "flows": [],
                    "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
                }

            st.session_state["zeek_tables"] = batch_result.merged_zeek
            st.session_state["osint"] = batch_result.merged_osint
            st.session_state["beacon_df"] = batch_result.merged_beacons
            st.session_state["dns_analysis"] = batch_result.aggregated_dns
            st.session_state["tls_analysis"] = batch_result.aggregated_tls
            st.session_state["__total_pkts"] = batch_result.correlation.total_packets
            st.session_state["pipeline_warnings"] = sorted(
                {warning for item in batch_result.pcap_results for warning in item.warnings}
            )
            st.session_state["pipeline_stages"] = sorted(
                {stage for item in batch_result.pcap_results for stage in item.stages_run}
            )
            # Carved payloads concatenated across all successful files
            st.session_state["carved"] = [
                item for r in batch_result.pcap_results if not r.error for item in r.carved_items
            ]

            _precompute_dash_aggregates((st.session_state.get("features") or {}).get("flows"))
            # a fresh run supersedes any restored case
            st.session_state.pop("restored_analysis_id", None)

            # rDNS for merged IPs
            from app.utils.network_utils import bulk_resolve_ips

            merged_feats = st.session_state.get("features") or {}
            _pub = [ip for ip in merged_feats.get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]
            st.session_state["rdns_map"] = bulk_resolve_ips(_pub, max_workers=C.RDNS_MAX_WORKERS)

            # Extract JA3 from every successful run's own zeek logs (each run
            # writes into its own ZEEK_DIR/<run_id> subdir) and combine them,
            # so batch JA3 reflects all files instead of only the last ssl.log.
            from app.pipeline.ja3 import extract_ja3_from_multiple_runs

            ja3_df, ja3_analysis = extract_ja3_from_multiple_runs(
                [r.zeek_log_paths for r in batch_result.pcap_results if not r.error]
            )
            st.session_state["ja3_df"] = ja3_df
            st.session_state["ja3_analysis"] = ja3_analysis

            # Post-analysis on merged data
            features = st.session_state.get("features") or {}
            osint_data = st.session_state.get("osint") or {}
            beacon_df = get_df_state("beacon_df")
            try:
                from app.analysis.correlation import correlate_indicators
                from app.analysis.flow_analysis import detect_flow_asymmetry, detect_port_anomalies

                correlations = correlate_indicators(
                    features=features,
                    osint=osint_data,
                    beacon_df=beacon_df,
                    dns_analysis=st.session_state.get("dns_analysis"),
                    tls_analysis=st.session_state.get("tls_analysis"),
                    yara_results=st.session_state.get("yara_results"),
                )
                st.session_state["correlations"] = correlations

                if features.get("flows"):
                    st.session_state["flow_asymmetry"] = detect_flow_asymmetry(features["flows"])
                    st.session_state["port_anomalies"] = detect_port_anomalies(features["flows"])
            except Exception as e:
                logger.warning("Post-analysis failed: %s", e)

            batch_tracker.finish_all(
                f"Batch complete: {batch_result.summary['successful']}/{batch_result.summary['total_files']} files."
            )

        # ---- SINGLE FILE MODE ----
        else:
            total_phases = len(active_phases)
            tracker = PhaseTracker(total_phases, progress_container=progress_panel)
            tracker.update_overall("Running\u2026")

            result = _run_single_pcap_pipeline(
                pcap_path=pcap_path,
                tracker=tracker,
                phases=[(t, e) for t, e in phases if t != "LLM report"],
                limit_packets=limit_packets,
                osint_keys=osint_keys,
                osint_top_n=osint_top_n,
                do_pyshark=do_pyshark,
                do_zeek=do_zeek,
                do_carve=do_carve,
                pre_count=pre_count,
                do_yara=do_yara,
            )

            # Store results in session state
            features = result.features
            zeek_tables = result.zeek_tables
            beacon_df = result.beacon_df if isinstance(result.beacon_df, pd.DataFrame) else pd.DataFrame()
            osint_data = result.osint

            st.session_state["features"] = features
            st.session_state["zeek_tables"] = zeek_tables
            st.session_state["beacon_df"] = beacon_df
            st.session_state["osint"] = osint_data
            st.session_state["carved"] = result.carved_items
            st.session_state["__total_pkts"] = result.packet_count
            st.session_state["dns_analysis"] = result.dns_analysis or None
            st.session_state["tls_analysis"] = result.tls_analysis or None
            st.session_state["pipeline_warnings"] = list(result.warnings)
            st.session_state["pipeline_stages"] = list(result.stages_run)

            _precompute_dash_aggregates(features.get("flows"))
            # a fresh run supersedes any restored case
            st.session_state.pop("restored_analysis_id", None)

            # rDNS map for dashboard hostname display — already resolved once
            # inside the pipeline; reuse it instead of re-resolving.
            st.session_state["rdns_map"] = result.rdns_map

            # Extract JA3 from this run's actual log paths (per-run ZEEK_DIR subdir)
            from app.pipeline.zeek import extract_ja3_from_zeek_tables

            ja3_df, ja3_analysis = extract_ja3_from_zeek_tables(result.zeek_log_paths)
            st.session_state["ja3_df"] = ja3_df
            st.session_state["ja3_analysis"] = ja3_analysis

            # Post-analysis
            try:
                from app.analysis.correlation import correlate_indicators
                from app.analysis.flow_analysis import detect_flow_asymmetry, detect_port_anomalies

                correlations = correlate_indicators(
                    features=features,
                    osint=osint_data,
                    beacon_df=beacon_df,
                    dns_analysis=st.session_state.get("dns_analysis"),
                    tls_analysis=st.session_state.get("tls_analysis"),
                    yara_results=st.session_state.get("yara_results"),
                )
                st.session_state["correlations"] = correlations

                if features.get("flows"):
                    st.session_state["flow_asymmetry"] = detect_flow_asymmetry(features["flows"])
                    st.session_state["port_anomalies"] = detect_port_anomalies(features["flows"])
            except Exception as e:
                logger.warning("Post-analysis failed: %s", e)

        # Build the ATT&CK view only after all available UI stages have joined.
        # Keeping this here prevents the dedicated MITRE page from showing a
        # partial mapping that predates YARA, OSINT, or correlation results.
        try:
            st.session_state["attack_mapping"] = build_attack_mapping(st.session_state)
            st.session_state["capture_metrics"] = build_capture_metrics(st.session_state)
        except Exception as exc:
            logger.warning("MITRE mapping failed: %s", exc)
            st.session_state["attack_mapping"] = None
            st.session_state["capture_metrics"] = build_capture_metrics(st.session_state)

        # ---- LLM REPORT (shared for single & batch) ----
        features = st.session_state.get("features") or {}
        zeek_tables = st.session_state.get("zeek_tables") or {}
        beacon_df = get_df_state("beacon_df")
        osint_data = st.session_state.get("osint") or {"ips": {}, "domains": {}, "ja3": {}}
        report_md = st.session_state.get("report")

        llm_tracker = PhaseTracker(1, progress_container=progress_panel)
        # Keep the phase KEY "LLM report" (stable slug / skip-state) but show a
        # generic, provider-agnostic label to the user.
        p = llm_tracker.next_phase("LLM report", display_title="LLM Report Analysis")

        llm_slug = make_slug("LLM report")
        llm_done = st.session_state.get(f"done_{llm_slug}", False)
        llm_skip = st.session_state.get(f"skip_{llm_slug}", False)

        if not llm_done:
            if not llm_skip:
                with st.spinner(f"Generating LLM report via {provider_label}\u2026"):
                    zeek_json = {
                        name: (df.to_dict(orient="records") if isinstance(df, pd.DataFrame) else [])
                        for name, df in zeek_tables.items()
                    }
                    beacon_rows = []
                    try:
                        if isinstance(beacon_df, pd.DataFrame):
                            beacon_rows = beacon_df.to_dict(orient="records")
                    except Exception as e:
                        logger.debug("beacon rows conversion for LLM context failed: %s", e)
                        beacon_rows = []

                    context = {
                        "features": features,
                        "osint": osint_data,
                        "zeek": zeek_json,
                        "beaconing": beacon_rows,
                        "carved": st.session_state.get("carved") or [],
                        "packet_count": st.session_state.get("__total_pkts"),
                        "correlations": st.session_state.get("correlations") or [],
                        "dns_analysis": st.session_state.get("dns_analysis"),
                        "tls_analysis": st.session_state.get("tls_analysis"),
                        "yara_results": st.session_state.get("yara_results"),
                        "flow_asymmetry": st.session_state.get("flow_asymmetry"),
                        "port_anomalies": st.session_state.get("port_anomalies"),
                        "ja3_analysis": st.session_state.get("ja3_analysis"),
                        "attack_mapping": st.session_state.get("attack_mapping"),
                        "capture_metrics": st.session_state.get("capture_metrics"),
                        "rdns_map": st.session_state.get("rdns_map"),
                        "config": {
                            "limit_packets": limit_packets,
                            "do_pyshark": do_pyshark,
                            "do_zeek": do_zeek,
                            "do_carve": do_carve,
                            "pre_count": pre_count,
                            "osint_top_n": osint_top_n,
                        },
                    }

                    # Include batch context if in batch mode
                    if batch_mode and st.session_state.get("__batch_result"):
                        br = st.session_state.get("__batch_result")
                        context["batch_summary"] = br.summary
                        context["cross_file_indicators"] = [ind for ind in br.correlation.common_indicators[:20]]

                    try:
                        current_lang = st.session_state.get("cfg_lm_language", "US English")
                        logger.debug("Generating report via provider='%s' language='%s'", llm_provider, current_lang)
                        st.toast(f"Generating report in {current_lang}...", icon="\U0001f4dd")

                        report_md = llm_providers.synthesize_report(
                            llm_provider,
                            base_url=base_url,
                            api_key=api_key,
                            model=model,
                            context=context,
                            language=current_lang,
                        )
                    except Exception as e:
                        st.error(f"LLM call failed: {e}")
                        report_md = "_LLM generation failed. Check server/model settings._"
            else:
                # Skipping the optional narrative must not replace the
                # deterministic evidence with a placeholder report.
                report_md = None
                st.session_state["llm_status"] = "skipped"
            if not llm_skip and report_md:
                st.session_state["llm_status"] = "generated"
            p.done(
                "LLM report generated."
                if not st.session_state.get(f"skip_{make_slug('LLM report')}", False)
                else "LLM skipped."
            )
        st.session_state["report"] = report_md

        # End run
        end_run()
    else:
        st.info("Start in **Upload** tab, then return here to track progress.")

# ---------------------- 3) Dashboard ----------------------
with tab_dashboard:
    st.markdown("### Dashboard")

    # Batch summary at the top when in batch mode
    if st.session_state.get("__batch_mode") and st.session_state.get("__batch_result"):
        batch_result = st.session_state["__batch_result"]
        render_batch_summary(st.container(), batch_result.summary)
        render_cross_file_correlation(st.container(), batch_result.correlation)
        with st.expander("Per-File Details", expanded=False):
            render_per_file_summary(st.container(), batch_result.pcap_results)
        st.markdown("---")

    # Threat summary at a glance
    render_threat_summary(
        st.container(),
        correlations=st.session_state.get("correlations"),
        beacon_df=get_df_state("beacon_df") if not get_df_state("beacon_df").empty else None,
        yara_results=st.session_state.get("yara_results"),
        tls_analysis=st.session_state.get("tls_analysis"),
        dns_analysis=st.session_state.get("dns_analysis"),
    )
    render_severity_legend()

    feats = st.session_state.get("features") or {}
    all_flows = feats.get("flows") or []

    # IOC search bar at the top
    render_ioc_search(
        st.container(),
        feats,
        st.session_state.get("osint"),
        st.session_state.get("dns_analysis"),
        get_df_state("beacon_df") if not get_df_state("beacon_df").empty else None,
    )

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
        render_active_filters(
            IPs=f"{len(st.session_state['filter_ips'])}" if st.session_state["filter_ips"] else None,
            Protocols=", ".join(st.session_state["filter_protos"]) if st.session_state["filter_protos"] else None,
            Time_Range="Active" if st.session_state["filter_time"] else None,
        )
        st.caption(f"Showing {len(filtered_flows)} of {len(all_flows)} flows")
        if st.button("Clear All Filters", type="primary"):
            st.session_state["filter_ips"] = set()
            st.session_state["filter_protos"] = set()
            st.session_state["filter_time"] = None
            st.session_state["map_reset_counter"] += 1
            if "dashboard_exclude_private" in st.session_state:
                st.session_state["dashboard_exclude_private"] = False
            st.rerun()
    else:
        st.caption(f"Showing all {len(all_flows)} flows")

    # Global toggle for excluding private IPs
    exclude_private = st.checkbox(
        "Exclude Private IPs from Analysis",
        value=False,
        key="dashboard_exclude_private",
        help="Ignore RFC1918 (local) addresses in Top 10 charts and map visualization.",
    )

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
        # Get home location from session state
        home_lat = st.session_state.get("cfg_home_lat", 0.0)
        home_lon = st.session_state.get("cfg_home_lon", 0.0)

        # Build threat scores lookup from correlations
        _threat_scores: dict[str, float] = {}
        for c in st.session_state.get("correlations") or []:
            if hasattr(c, "indicator") and hasattr(c, "composite_score"):
                _threat_scores[c.indicator] = c.composite_score
            elif isinstance(c, dict):
                _threat_scores[c.get("indicator", "")] = c.get("composite_score", 0)

        # Render map with selection enabled
        map_event = st.plotly_chart(
            plot_world_map(
                ip_locs,
                flows=filtered_flows,
                home_loc=(home_lat, home_lon),
                threat_scores=_threat_scores,
            ),
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
        render_chart_hint("Click markers for IP details. Drag to select IPs. Scroll to zoom. Red=high threat.")
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
                    selected_protos = set()
                    for p in points:
                        # plot_protocol_distribution now passes labels in customdata
                        proto = p.get("customdata")
                        if proto:
                            selected_protos.add(proto)

                    if selected_protos:
                        st.session_state["filter_protos"] = selected_protos
                        st.rerun()
            render_chart_hint("Click a slice to filter by protocol. Click legend to hide/show.")
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
                    times = []
                    for p in points:
                        tx = p.get("x")
                        if tx is not None:
                            try:
                                dt = pd.to_datetime(tx)
                                times.append(dt.timestamp())
                            except (ValueError, TypeError, OverflowError):
                                continue
                    if times:
                        st.session_state["filter_time"] = (min(times), max(times))
                        st.rerun()
            render_chart_hint("Hover for flow details. Drag to select time range. Bubble size = packet count.")
        else:
            st.info("No flow data available.")

    with st.container():
        st.markdown("---")

        # View mode toggle: IP-centric vs Domain-centric
        top10_hdr_col, top10_toggle_col = st.columns([3, 1])
        with top10_hdr_col:
            st.markdown("#### Top 10 Analysis")
        with top10_toggle_col:
            top10_view = st.radio(
                "View mode",
                ["IP", "Domain"],
                horizontal=True,
                key="top10_view_mode",
                label_visibility="collapsed",
            )

        if filtered_flows:
            # Calculate Top 10s — use precomputed aggregates when no filters
            # are active (avoid rescanning all flows on every Streamlit rerun).
            top_domains = {}
            top_src_domains = {}
            top_dst_domains = {}

            # Use the global toggle from session state
            exclude_private = st.session_state.get("dashboard_exclude_private", False)

            _any_filter_active = bool(
                st.session_state.get("filter_ips")
                or st.session_state.get("filter_protos")
                or st.session_state.get("filter_time")
            )
            _precomputed = st.session_state.get("dash_aggregates") if not _any_filter_active else None

            if _precomputed and not exclude_private:
                # Fast path: convert list-of-tuples back to dict for chart calls
                top_src_ips = dict(_precomputed["top_src_ips"])
                top_dst_ips = dict(_precomputed["top_dst_ips"])
                top_dst_ports = dict(_precomputed["top_dst_ports"])
                top_protos = dict(_precomputed["top_protos"])
            else:
                # Slow path: live one-pass scan (used when filters are active or
                # when exclude_private changes the IP set mid-session).
                _agg = compute_flow_aggregates(
                    filtered_flows, top_n=10, weight="flows", exclude_private=exclude_private
                )
                top_src_ips = dict(_agg["top_src_ips"])
                top_dst_ips = dict(_agg["top_dst_ips"])
                top_dst_ports = dict(_agg["top_dst_ports"])
                top_protos = dict(_agg["top_protos"])

            # Domains from DNS analysis or Zeek logs
            dns_data = st.session_state.get("dns_analysis")
            if dns_data and isinstance(dns_data, dict):
                for d in dns_data.get("top_queried", []):
                    top_domains[d.get("domain", "Unknown")] = d.get("count", 0)
            elif "dns.log" in st.session_state.get("zeek_tables", {}):
                dns_df = st.session_state["zeek_tables"]["dns.log"]
                if "query" in dns_df.columns:
                    domain_counts = dns_df["query"].value_counts().head(20).to_dict()
                    top_domains.update(domain_counts)

            # Build source/destination domain mappings from DNS responses
            _zt = st.session_state.get("zeek_tables", {})
            _dns_df = _zt.get("dns.log", pd.DataFrame())
            if not _dns_df.empty and "query" in _dns_df.columns:
                _orig_col = "id.orig_h" if "id.orig_h" in _dns_df.columns else "id_orig_h"
                _resp_col = "id.resp_h" if "id.resp_h" in _dns_df.columns else "id_resp_h"
                if _orig_col in _dns_df.columns:
                    # Top queried domains by source IP (who is querying)
                    _src_dom = _dns_df.groupby("query").size().sort_values(ascending=False).head(10).to_dict()
                    top_src_domains = _src_dom
                # Top resolved domains by answer count / query frequency
                if "answers" in _dns_df.columns:
                    _ans = _dns_df[_dns_df["answers"].notna() & (_dns_df["answers"] != "-")]
                    if not _ans.empty:
                        top_dst_domains = _ans["query"].value_counts().head(10).to_dict()
                    else:
                        top_dst_domains = dict(list(top_domains.items())[:10])
                else:
                    top_dst_domains = dict(list(top_domains.items())[:10])

            # rDNS map for hostname display
            rdns = st.session_state.get("rdns_map", {})

            # Render Top 10s in columns
            tcol1, tcol2 = st.columns(2)

            if top10_view == "IP":
                # --- IP-centric view ---
                with tcol1:
                    st.plotly_chart(plot_top_n_charts(top_src_ips, "Top 10 Source IPs"), width="stretch")
                    with st.expander("Source IP Table"):
                        df_src = pd.DataFrame(list(top_src_ips.items()), columns=["IP", "Count"])
                        df_src["Hostname"] = df_src["IP"].map(lambda ip: rdns.get(ip, ""))
                        st.dataframe(df_src.sort_values("Count", ascending=False).head(10), hide_index=True)

                    st.plotly_chart(plot_top_n_charts(top_dst_ports, "Top 10 Destination Ports"), width="stretch")
                    with st.expander("Destination Port Table"):
                        df_ports = pd.DataFrame(list(top_dst_ports.items()), columns=["Port", "Count"])
                        st.dataframe(df_ports.sort_values("Count", ascending=False).head(10), hide_index=True)

                with tcol2:
                    st.plotly_chart(plot_top_n_charts(top_dst_ips, "Top 10 Destination IPs"), width="stretch")
                    with st.expander("Destination IP Table"):
                        df_dst = pd.DataFrame(list(top_dst_ips.items()), columns=["IP", "Count"])
                        df_dst["Hostname"] = df_dst["IP"].map(lambda ip: rdns.get(ip, ""))
                        st.dataframe(df_dst.sort_values("Count", ascending=False).head(10), hide_index=True)

                    st.plotly_chart(plot_top_n_charts(top_protos, "Top 10 Protocols"), width="stretch")
                    with st.expander("Protocol Table"):
                        df_proto = pd.DataFrame(list(top_protos.items()), columns=["Protocol", "Count"])
                        st.dataframe(df_proto.sort_values("Count", ascending=False).head(10), hide_index=True)

            else:
                # --- Domain-centric view ---
                with tcol1:
                    if top_src_domains:
                        st.plotly_chart(
                            plot_top_n_charts(top_src_domains, "Top 10 Queried Domains"),
                            width="stretch",
                        )
                        with st.expander("Queried Domain Table"):
                            df_qdom = pd.DataFrame(list(top_src_domains.items()), columns=["Domain", "Queries"])
                            st.dataframe(
                                df_qdom.sort_values("Queries", ascending=False).head(10),
                                hide_index=True,
                            )
                    else:
                        st.info("No DNS query data available.")

                    st.plotly_chart(plot_top_n_charts(top_dst_ports, "Top 10 Destination Ports"), width="stretch")
                    with st.expander("Destination Port Table"):
                        df_ports = pd.DataFrame(list(top_dst_ports.items()), columns=["Port", "Count"])
                        st.dataframe(df_ports.sort_values("Count", ascending=False).head(10), hide_index=True)

                with tcol2:
                    if top_dst_domains:
                        st.plotly_chart(
                            plot_top_n_charts(top_dst_domains, "Top 10 Resolved Domains"),
                            width="stretch",
                        )
                        with st.expander("Resolved Domain Table"):
                            df_rdom = pd.DataFrame(list(top_dst_domains.items()), columns=["Domain", "Responses"])
                            st.dataframe(
                                df_rdom.sort_values("Responses", ascending=False).head(10),
                                hide_index=True,
                            )
                    else:
                        st.info("No DNS response data available.")

                    st.plotly_chart(plot_top_n_charts(top_protos, "Top 10 Protocols"), width="stretch")
                    with st.expander("Protocol Table"):
                        df_proto = pd.DataFrame(list(top_protos.items()), columns=["Protocol", "Count"])
                        st.dataframe(df_proto.sort_values("Count", ascending=False).head(10), hide_index=True)

        else:
            st.info("Start analysis to see Top 10 metrics.")

    # --- New Dashboard Sections ---
    st.markdown("---")

    # Sankey + Network graph side by side
    dash_col1, dash_col2 = st.columns(2)
    with dash_col1:
        # Sankey flow diagram (ECharts via HTML — draggable nodes, zoom & pan)
        if filtered_flows:
            import streamlit.components.v1 as components

            sankey_result = build_sankey_html(filtered_flows)
            if sankey_result:
                sankey_html, sankey_h = sankey_result
                components.html(sankey_html, height=sankey_h + 20, scrolling=True)
                render_chart_hint(
                    "Drag nodes to rearrange. Source IP → Port (Protocol) → Destination IP. Width = packet volume."
                )

    with dash_col2:
        # Network graph
        if filtered_flows:
            _ts = {}
            for c in st.session_state.get("correlations") or []:
                if hasattr(c, "indicator"):
                    _ts[c.indicator] = c.composite_score
                elif isinstance(c, dict):
                    _ts[c.get("indicator", "")] = c.get("composite_score", 0)
            fig = plot_network_graph(filtered_flows, threat_scores=_ts)
            if fig.data:
                st.plotly_chart(fig, use_container_width=True)
                render_chart_hint("Node size = connections. Color: blue=low, red=high threat.")

    # Attack timeline (full-width, if available)
    try:
        from app.analysis.narrator import AttackNarrator

        narrator = AttackNarrator()
        timeline = narrator.create_timeline(
            features=feats,
            dns_analysis=st.session_state.get("dns_analysis"),
            yara_results=st.session_state.get("yara_results"),
            beacon_results=(
                get_df_state("beacon_df").to_dict("records") if not get_df_state("beacon_df").empty else []
            ),
            tls_analysis=st.session_state.get("tls_analysis"),
        )
        if timeline:
            timeline_dicts = [e.to_dict() for e in timeline]
            st.plotly_chart(
                plot_attack_timeline(timeline_dicts),
                use_container_width=True,
            )
            render_chart_hint("Diamond markers show events by severity and time.")
    except Exception as e:
        logger.debug("chart rendering failed: %s", e)

    # --- Traffic profiling charts ---
    if filtered_flows:
        prof_col1, prof_col2 = st.columns(2)
        with prof_col1:
            pkt_hist = plot_packet_size_histogram(filtered_flows)
            if pkt_hist:
                st.plotly_chart(pkt_hist, use_container_width=True)
                render_chart_hint("Packet size distribution — small uniform packets may indicate C2.")
        with prof_col2:
            iat_hist = plot_inter_arrival_histogram(filtered_flows)
            if iat_hist:
                st.plotly_chart(iat_hist, use_container_width=True)
                render_chart_hint("Inter-arrival time distribution — spikes at regular intervals suggest beaconing.")

        # Timeline heatmap (full-width)
        heatmap_fig = plot_traffic_timeline_heatmap(filtered_flows)
        if heatmap_fig:
            st.plotly_chart(heatmap_fig, use_container_width=True)
            render_chart_hint(
                "Rows = IPs, columns = time. Bright cells = high activity. Spot bursty or persistent connections."
            )

    # --- Beaconing / YARA / TLS summaries on dashboard ---
    _beacon = get_df_state("beacon_df")
    _yara = st.session_state.get("yara_results")
    _tls = st.session_state.get("tls_analysis")

    detail_col1, detail_col2, detail_col3 = st.columns(3)

    with detail_col1:
        if not _beacon.empty and "score" in _beacon.columns:
            high_beacons = _beacon[_beacon["score"] >= 0.5]
            with st.expander(f"C2 Beaconing ({len(high_beacons)} candidates)", expanded=len(high_beacons) > 0):
                if high_beacons.empty:
                    st.caption("No high-confidence beacon candidates.")
                else:
                    show_cols = [c for c in ["dst", "score", "pkts", "mean_gap"] if c in high_beacons.columns]
                    # Fallback: older DataFrames may use "count" instead of "pkts"
                    if "pkts" not in show_cols and "count" in high_beacons.columns:
                        show_cols = [c for c in ["dst", "score", "count", "mean_gap"] if c in high_beacons.columns]
                    display_df = high_beacons[show_cols].head(10).copy()
                    if "dst" in display_df.columns:
                        display_df["Hostname"] = display_df["dst"].map(lambda ip: rdns.get(ip, ""))
                    beacon_col_cfg: dict = {
                        "score": st.column_config.ProgressColumn("Score", min_value=0.0, max_value=1.0, format="%.2f"),
                    }
                    if "pkts" in display_df.columns:
                        beacon_col_cfg["pkts"] = st.column_config.NumberColumn("Packets", format="%d")
                    if "count" in display_df.columns:
                        beacon_col_cfg["count"] = st.column_config.NumberColumn("Packets", format="%d")
                    if "mean_gap" in display_df.columns:
                        beacon_col_cfg["mean_gap"] = st.column_config.NumberColumn("Avg Gap (s)", format="%.1f")
                    st.dataframe(display_df, hide_index=True, use_container_width=True, column_config=beacon_col_cfg)

    with detail_col2:
        if _yara and isinstance(_yara, dict) and _yara.get("matched", 0) > 0:
            with st.expander(f"YARA Detections ({_yara['matched']})", expanded=True):
                matches = _yara.get("results", [])
                for m in matches[:5]:
                    rule = m.get("rule", "Unknown")
                    severity = m.get("severity", "info")
                    st.markdown(f"- **{rule}** ({severity})")
        else:
            with st.expander("YARA Detections (0)"):
                st.caption("No YARA matches.")

    with detail_col3:
        if _tls and isinstance(_tls, dict):
            ss = _tls.get("self_signed", 0) or 0
            exp = _tls.get("expired", 0) or 0
            total = ss + exp
            with st.expander(f"TLS Certificate Risks ({total})", expanded=total > 0):
                if total == 0:
                    st.caption("No certificate issues detected.")
                else:
                    if ss:
                        st.warning(f"{ss} self-signed certificate(s)")
                    if exp:
                        st.error(f"{exp} expired certificate(s)")
        else:
            with st.expander("TLS Certificate Risks (0)"):
                st.caption("No TLS analysis data.")

    st.markdown("---")

    # Cross-Indicator Correlations (own section)
    render_correlation_results(st.container(), st.session_state.get("correlations"))

    st.markdown("---")

    # Hunting checklist
    render_hunting_checklist(
        st.container(),
        features=feats,
        osint=st.session_state.get("osint"),
        dns_analysis=st.session_state.get("dns_analysis"),
        beacon_df=get_df_state("beacon_df") if not get_df_state("beacon_df").empty else None,
        tls_analysis=st.session_state.get("tls_analysis"),
        yara_results=st.session_state.get("yara_results"),
    )

    st.markdown("---")

# 4) MITRE ATT&CK Analysis ----------------------
with tab_mitre:
    render_mitre_page(st.session_state)

# 5) LLM Analysis ----------------------
with tab_llm:
    st.markdown("### LLM Analysis & Report")
    render_report(
        st.container(),
        st.session_state.get("report"),
        status=st.session_state.get("llm_status"),
    )
    if not st.session_state.get("report") and analysis_has_run():
        render_analysis_snapshot(st.container(), st.session_state)

    # PDF Export Section
    st.markdown("---")
    st.markdown("#### Export Report")
    pdf_col1, pdf_col2 = st.columns([2, 4])
    with pdf_col1:
        if st.button("Generate PDF Report", type="primary"):
            from app.reports.pdf_generator import PDFReportGenerator, ReportConfig

            features = st.session_state.get("features") or {}
            report_md = st.session_state.get("report") or "No report generated."

            if not features.get("flows") and not report_md:
                st.warning("No analysis data available. Run analysis first.")
            else:
                config = ReportConfig(
                    title="PCAP Analysis Report",
                    analyst=st.session_state.get("cfg_analyst_name", ""),
                    organization=st.session_state.get("cfg_organization", ""),
                )
                generator = PDFReportGenerator(config)

                if not generator.is_available:
                    import sys as _sys

                    from app.reports.pdf_generator import WEASYPRINT_ERROR

                    if _sys.platform == "darwin":
                        install_hint = "brew install pango glib cairo  (then restart the app)"
                    elif _sys.platform == "win32":
                        gtk_url = "https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer"
                        install_hint = f"Install GTK3 runtime ({gtk_url}) and ensure pip install weasyprint is complete"
                    else:
                        install_hint = "sudo apt install libpango1.0-dev libcairo2 libgdk-pixbuf2.0-0"

                    st.error(
                        "**PDF generation unavailable.**  \n"
                        f"Reason: `{WEASYPRINT_ERROR or 'weasyprint not installed'}`  \n\n"
                        f"**Fix:** `{install_hint}`"
                    )
                else:
                    # Pre-compute GeoIP data for the world map in the PDF.
                    # We only geo-locate public IPs and cap the list so kaleido
                    # renders quickly even on very large captures.
                    _geoip_data: list = []
                    try:
                        for ip in (features.get("artifacts", {}).get("ips") or [])[:200]:
                            if is_public_ipv4(ip):
                                geo = GeoIP.lookup(ip)
                                if geo:
                                    _geoip_data.append(geo)
                    except Exception as _ge:
                        logger.warning("GeoIP lookup for PDF failed: %s", _ge)

                    with st.spinner("Generating PDF report..."):
                        pdf_report = generator.generate(
                            report_md=report_md,
                            features=features,
                            osint=st.session_state.get("osint"),
                            yara_results=st.session_state.get("yara_results"),
                            dns_analysis=st.session_state.get("dns_analysis"),
                            tls_analysis=st.session_state.get("tls_analysis"),
                            beacon_df=st.session_state.get("beacon_df"),
                            correlations=st.session_state.get("correlations"),
                            geoip_data=_geoip_data or None,
                            attack_timeline=st.session_state.get("attack_timeline"),
                        )

                    if pdf_report:
                        st.session_state["pdf_report"] = pdf_report
                        st.success(f"PDF generated: {pdf_report.filename}")
                        st.toast("PDF report ready for download", icon="📄")
                    else:
                        st.error("PDF generation failed. Check logs.")

    # Download button (separate from generate to avoid rerun issues)
    if st.session_state.get("pdf_report"):
        pdf_report = st.session_state["pdf_report"]
        with pdf_col2:
            st.download_button(
                label=f"Download {pdf_report.filename}",
                data=pdf_report.content,
                file_name=pdf_report.filename,
                mime="application/pdf",
                key="download_pdf",
            )

# 6) OSINT ----------------------
with tab_osint:
    st.markdown("### OSINT Investigation")
    render_osint(
        st.container(),
        st.session_state.get("osint") or {"ips": {}, "domains": {}, "ja3": {}},
        correlations=st.session_state.get("correlations"),
        features=st.session_state.get("features"),
        beacon_df=st.session_state.get("beacon_df"),
    )

# 7) Raw Data ----------------------
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
        render_nxdomain_analysis(results_panel, st.session_state.get("dns_analysis"))
        render_query_velocity(results_panel, st.session_state.get("dns_analysis"))
        render_zeek(results_panel, st.session_state.get("zeek_tables") or {})
        render_carved(results_panel, st.session_state.get("carved") or [])
        render_yara_results(results_panel, st.session_state.get("yara_results"))
        render_flow_asymmetry(results_panel, st.session_state.get("flow_asymmetry"))
        render_port_anomalies(results_panel, st.session_state.get("port_anomalies"))

# 8) Cases ----------------------
with tab_cases:
    from app.ui.cases_tab import render_cases_tab

    render_cases_tab()

# 9) API Keys --------------------
with tab_api_keys:
    from app.ui.api_keys_tab import render_api_keys_tab

    render_api_keys_tab()

# 10) Config ----------------------
with tab_config:
    render_config_tab()

st.markdown("---")
with st.expander("Notes & OPSEC"):
    st.markdown("""
- **Tabs**: Upload → Progress → Dashboard → MITRE Analysis → LLM Analysis → OSINT → Raw Data → Cases →
  API Keys → Config.
- **Skip** is non-blocking; pipeline continues to next phase.
- **OSINT limit**: configurable Top-N IPs by traffic; 0 = enrich all.
- Zeek JSON-first with ASCII fallback; OSINT calls have safe timeouts.
- Carved binaries stored locally in per-run subfolders (`/data/carved/<run_id>/`); no uploads.
  Run folders are auto-pruned after 7 days — export anything you need to keep.
""")
