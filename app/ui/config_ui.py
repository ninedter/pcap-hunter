import logging
import os
import pathlib
import shutil

import streamlit as st

from app import config as C
from app.database.repository import CaseRepository
from app.llm import providers as llm_providers
from app.llm.client import fetch_models
from app.pipeline.osint import (
    PROBE_RESULT_INVALID_KEY,
    PROBE_RESULT_OK,
    PROBE_RESULT_RATE_LIMITED,
    PROBE_RESULT_UNREACHABLE,
    probe_providers,
)
from app.pipeline.osint_cache import get_osint_cache
from app.utils import geo_data
from app.utils.config_manager import get_config_manager

logger = logging.getLogger(__name__)

# Maximum upload size: 2 GB
MAX_UPLOAD_SIZE_BYTES = 2 * 1024 * 1024 * 1024
MAX_UPLOAD_SIZE_LABEL = "2 GB"

# Keys to persist (mapping session_state key -> config file key)
PERSIST_KEYS = {
    "cfg_lm_base_url": "cfg_llm_endpoint",
    "cfg_lm_api_key": "cfg_openai_key",
    "cfg_lm_model": "cfg_llm_model",
    "cfg_lm_language": "cfg_llm_language",
    # Multi-provider LLM settings
    "cfg_llm_provider": "cfg_llm_provider",
    "cfg_openai_api_key": "cfg_openai_cloud_key",
    "cfg_openai_model": "cfg_openai_model",
    "cfg_openai_base_url": "cfg_openai_base_url",
    "cfg_anthropic_api_key": "cfg_anthropic_key",
    "cfg_anthropic_model": "cfg_anthropic_model",
    "cfg_otx": "cfg_otx_key",
    "cfg_vt": "cfg_vt_key",
    "cfg_abuseipdb": "cfg_abuseipdb_key",
    "cfg_greynoise": "cfg_greynoise_key",
    "cfg_shodan": "cfg_shodan_key",
    "cfg_limit_packets": "cfg_pyshark_limit",
    "cfg_osint_top_ips": "cfg_osint_top_ips",
    "cfg_osint_cache_enabled": "cfg_osint_cache_enabled",
    "cfg_zeek_bin": "cfg_zeek_bin",
    "cfg_tshark_bin": "cfg_tshark_bin",
    "cfg_yara_rules_dir": "cfg_yara_rules_dir",
    "cfg_home_lat": "cfg_home_lat",
    "cfg_home_lon": "cfg_home_lon",
    "cfg_home_continent": "cfg_home_continent",
    "cfg_home_country": "cfg_home_country",
    "cfg_home_city": "cfg_home_city",
}


def init_config_defaults():
    """Initialize config defaults, loading from persistent storage first."""
    # Try to load saved config
    cm = get_config_manager()
    saved_config = cm.load()

    # LLM settings (check saved config first, then env, then defaults)
    lm_base = saved_config.get("cfg_llm_endpoint") or os.getenv("LMSTUDIO_BASE_URL", C.LM_BASE_URL)
    _ss_default("cfg_lm_base_url", lm_base)
    _ss_default("cfg_lm_api_key", saved_config.get("cfg_openai_key") or os.getenv("LMSTUDIO_API_KEY", C.LM_API_KEY))
    _ss_default("cfg_lm_model", saved_config.get("cfg_llm_model") or os.getenv("LMSTUDIO_MODEL", C.LM_MODEL))
    lm_lang = saved_config.get("cfg_llm_language") or os.getenv("LMSTUDIO_LANGUAGE", C.LM_LANGUAGE)
    _ss_default("cfg_lm_language", lm_lang)

    # Multi-provider LLM settings (saved config → env → defaults)
    _ss_default(
        "cfg_llm_provider",
        saved_config.get("cfg_llm_provider") or os.getenv("LLM_PROVIDER", C.LLM_PROVIDER_DEFAULT),
    )
    _ss_default(
        "cfg_openai_api_key",
        saved_config.get("cfg_openai_cloud_key") or os.getenv("OPENAI_API_KEY", ""),
    )
    _ss_default(
        "cfg_openai_model",
        saved_config.get("cfg_openai_model") or os.getenv("OPENAI_MODEL", C.OPENAI_MODEL_DEFAULT),
    )
    _ss_default(
        "cfg_openai_base_url",
        saved_config.get("cfg_openai_base_url") or os.getenv("OPENAI_BASE_URL", ""),
    )
    _ss_default(
        "cfg_anthropic_api_key",
        saved_config.get("cfg_anthropic_key") or os.getenv("ANTHROPIC_API_KEY", ""),
    )
    _ss_default(
        "cfg_anthropic_model",
        saved_config.get("cfg_anthropic_model") or os.getenv("ANTHROPIC_MODEL", C.ANTHROPIC_MODEL_DEFAULT),
    )

    # OSINT keys
    _ss_default("cfg_otx", saved_config.get("cfg_otx_key") or os.getenv("OTX_KEY", C.OTX_KEY))
    _ss_default("cfg_vt", saved_config.get("cfg_vt_key") or os.getenv("VT_KEY", C.VT_KEY))
    _ss_default("cfg_abuseipdb", saved_config.get("cfg_abuseipdb_key") or os.getenv("ABUSEIPDB_KEY", C.ABUSEIPDB_KEY))
    _ss_default("cfg_greynoise", saved_config.get("cfg_greynoise_key") or os.getenv("GREYNOISE_KEY", C.GREYNOISE_KEY))
    _ss_default("cfg_shodan", saved_config.get("cfg_shodan_key") or os.getenv("SHODAN_KEY", C.SHODAN_KEY))

    # Analysis settings
    _ss_default("cfg_limit_packets", saved_config.get("cfg_pyshark_limit") or C.DEFAULT_PYSHARK_LIMIT)
    _ss_default("cfg_do_pyshark", True)
    _ss_default("cfg_do_zeek", True)
    _ss_default("cfg_do_carve", True)
    _ss_default("cfg_do_yara", True)
    _ss_default("cfg_pre_count", C.PRECNT_DEFAULT)
    _ss_default("cfg_osint_top_ips", saved_config.get("cfg_osint_top_ips") or C.OSINT_TOP_IPS_DEFAULT)
    _ss_default("cfg_osint_cache_enabled", saved_config.get("cfg_osint_cache_enabled", False))

    # Binary paths
    _ss_default("cfg_zeek_bin", saved_config.get("cfg_zeek_bin") or "")
    _ss_default("cfg_tshark_bin", saved_config.get("cfg_tshark_bin") or "")

    # YARA rules directory
    _ss_default("cfg_yara_rules_dir", saved_config.get("cfg_yara_rules_dir") or "")

    # Map settings
    _ss_default("cfg_home_lat", saved_config.get("cfg_home_lat", 0.0))
    _ss_default("cfg_home_lon", saved_config.get("cfg_home_lon", 0.0))
    _ss_default("cfg_home_continent", saved_config.get("cfg_home_continent", ""))
    _ss_default("cfg_home_country", saved_config.get("cfg_home_country", ""))
    _ss_default("cfg_home_city", saved_config.get("cfg_home_city", ""))


def _ss_default(key: str, value):
    if key not in st.session_state:
        st.session_state[key] = value


def save_config() -> bool:
    """Save current session config to persistent storage."""
    cm = get_config_manager()
    config_to_save = {}

    for ss_key, cfg_key in PERSIST_KEYS.items():
        value = st.session_state.get(ss_key)
        if value is not None:
            config_to_save[cfg_key] = value

    try:
        cm.save(config_to_save)
        return True
    except Exception:
        return False


def load_config() -> bool:
    """Load config from persistent storage into session state."""
    cm = get_config_manager()
    try:
        saved_config = cm.load()

        for ss_key, cfg_key in PERSIST_KEYS.items():
            if cfg_key in saved_config and saved_config[cfg_key]:
                st.session_state[ss_key] = saved_config[cfg_key]
        return True
    except Exception:
        return False


def _active_provider() -> str:
    """Return the currently selected LLM provider id, defaulting to LM Studio."""
    prov = st.session_state.get("cfg_llm_provider", C.LLM_PROVIDER_DEFAULT)
    return prov if prov in llm_providers.PROVIDERS else C.LLM_PROVIDER_DEFAULT


def _active_provider_credentials() -> tuple[str, str, str]:
    """Return ``(base_url, api_key, model)`` for the active provider from session state.

    OpenAI/Anthropic carry no LM Studio base_url; Anthropic ignores base_url entirely.
    """
    provider = _active_provider()
    if provider == llm_providers.PROVIDER_OPENAI:
        return (
            st.session_state.get("cfg_openai_base_url", "") or "",
            st.session_state.get("cfg_openai_api_key", "") or "",
            st.session_state.get("cfg_openai_model", C.OPENAI_MODEL_DEFAULT) or C.OPENAI_MODEL_DEFAULT,
        )
    if provider == llm_providers.PROVIDER_ANTHROPIC:
        return (
            "",
            st.session_state.get("cfg_anthropic_api_key", "") or "",
            st.session_state.get("cfg_anthropic_model", C.ANTHROPIC_MODEL_DEFAULT) or C.ANTHROPIC_MODEL_DEFAULT,
        )
    # LM Studio
    return (
        st.session_state.get("cfg_lm_base_url", "") or "",
        st.session_state.get("cfg_lm_api_key", "") or "",
        st.session_state.get("cfg_lm_model", "") or "",
    )


def _render_llm_integration():
    """Render the provider selector and the active provider's fields."""
    st.markdown("#### LLM Integration")

    # Provider selector (horizontal). Maps display label ↔ provider id.
    provider_options = list(llm_providers.PROVIDERS)
    provider_captions = {
        llm_providers.PROVIDER_LMSTUDIO: "LM Studio (local)",
        llm_providers.PROVIDER_OPENAI: "OpenAI",
        llm_providers.PROVIDER_ANTHROPIC: "Anthropic",
    }
    current_provider = _active_provider()
    prov_idx = provider_options.index(current_provider)
    selected_provider = st.radio(
        "Provider",
        provider_options,
        index=prov_idx,
        horizontal=True,
        format_func=lambda p: provider_captions.get(p, p),
        key="widget_llm_provider",
    )
    st.session_state["cfg_llm_provider"] = selected_provider

    do_test = False

    # ---- Provider-specific fields (only the active provider's are shown) ----
    if selected_provider == llm_providers.PROVIDER_LMSTUDIO:
        c1, c2 = st.columns([2, 1])
        with c1:
            st.session_state["cfg_lm_base_url"] = st.text_input(
                "OpenAI-compatible base_url", value=st.session_state.get("cfg_lm_base_url")
            )
        with c2:
            st.session_state["cfg_lm_api_key"] = st.text_input("API Key", value=st.session_state.get("cfg_lm_api_key"))

        b1, b2, b3, _ = st.columns([1, 1, 1, 1])
        with b1:
            if st.button("Test Connection"):
                do_test = True
        with b2:
            do_fetch = st.button("Fetch Models")
        with b3:
            if st.button("Re-run Report"):
                st.session_state["trigger_llm_rerun"] = True
                st.success("Re-run triggered. Reloading...")
                st.rerun()

        if do_fetch:
            with st.spinner("Fetching models..."):
                models = fetch_models(
                    st.session_state.get("cfg_lm_base_url"),
                    st.session_state.get("cfg_lm_api_key"),
                )
                if models:
                    st.session_state["available_models"] = models
                    st.success(f"Found {len(models)} models.")
                else:
                    st.error("Could not fetch models. Check URL/Key.")

        available = st.session_state.get("available_models", [])
        current_model = st.session_state.get("cfg_lm_model", "")
        if available:
            index = available.index(current_model) if current_model in available else 0
            st.session_state["cfg_lm_model"] = st.selectbox("Model name", available, index=index)
        else:
            st.session_state["cfg_lm_model"] = st.text_input("Model name", value=current_model)

    elif selected_provider == llm_providers.PROVIDER_OPENAI:
        c1, c2 = st.columns([2, 1], vertical_alignment="bottom")
        with c1:
            st.session_state["cfg_openai_api_key"] = st.text_input(
                "OpenAI API Key", type="password", value=st.session_state.get("cfg_openai_api_key", "")
            )
        with c2:
            if st.button("Test Connection"):
                do_test = True
        st.session_state["cfg_openai_model"] = st.text_input(
            "Model", value=st.session_state.get("cfg_openai_model", C.OPENAI_MODEL_DEFAULT)
        )
        st.session_state["cfg_openai_base_url"] = st.text_input(
            "Base URL (optional — blank = api.openai.com)",
            value=st.session_state.get("cfg_openai_base_url", ""),
            placeholder="https://api.openai.com/v1",
        )
        if st.button("Fetch Models", key="openai_fetch_models"):
            with st.spinner("Fetching models..."):
                models = fetch_models(
                    st.session_state.get("cfg_openai_base_url") or "https://api.openai.com/v1",
                    st.session_state.get("cfg_openai_api_key"),
                )
                if models:
                    st.session_state["available_models"] = models
                    st.success(f"Found {len(models)} models.")
                else:
                    st.error("Could not fetch models. Check Key/Base URL.")

    elif selected_provider == llm_providers.PROVIDER_ANTHROPIC:
        c1, c2 = st.columns([2, 1], vertical_alignment="bottom")
        with c1:
            st.session_state["cfg_anthropic_api_key"] = st.text_input(
                "Anthropic API Key", type="password", value=st.session_state.get("cfg_anthropic_api_key", "")
            )
        with c2:
            if st.button("Test Connection"):
                do_test = True
        anth_models = list(llm_providers.ANTHROPIC_MODELS)
        current_anth = st.session_state.get("cfg_anthropic_model", C.ANTHROPIC_MODEL_DEFAULT)
        anth_idx = anth_models.index(current_anth) if current_anth in anth_models else 0
        st.session_state["cfg_anthropic_model"] = st.selectbox("Model", anth_models, index=anth_idx)

    # ---- Shared Test Connection result ----
    if do_test:
        with st.spinner("Testing connection..."):
            base_url, api_key, model = _active_provider_credentials()
            ok, msg = llm_providers.probe_provider(selected_provider, base_url=base_url, api_key=api_key, model=model)
        if ok:
            st.success(f"✅ {msg}")
        else:
            st.error(f"❌ {msg}")

    # ---- Language Selection (shared across providers) ----
    current_lang = st.session_state.get("cfg_lm_language", "US English")
    languages = [
        "US English",
        "Traditional Chinese (zh-tw)",
        "Simplified Chinese (zh-cn)",
        "Japanese",
        "Korean",
        "Italian",
        "Spanish",
        "French",
        "German",
    ]

    def _update_lang():
        st.session_state["cfg_lm_language"] = st.session_state["widget_lm_language"]

    try:
        lang_idx = languages.index(current_lang)
    except ValueError:
        lang_idx = 0

    st.selectbox("Report Language", languages, index=lang_idx, key="widget_lm_language", on_change=_update_lang)


def render_config_tab():
    st.markdown("### Configuration")
    _render_llm_integration()

    st.markdown("---")
    st.markdown("#### OSINT API Keys (optional)")
    oc1, oc2, oc3 = st.columns(3)
    with oc1:
        st.session_state["cfg_otx"] = st.text_input("OTX", type="password", value=st.session_state.get("cfg_otx"))
        st.session_state["cfg_vt"] = st.text_input("VirusTotal", type="password", value=st.session_state.get("cfg_vt"))
    with oc2:
        st.session_state["cfg_abuseipdb"] = st.text_input(
            "AbuseIPDB", type="password", value=st.session_state.get("cfg_abuseipdb")
        )
        st.session_state["cfg_greynoise"] = st.text_input(
            "GreyNoise", type="password", value=st.session_state.get("cfg_greynoise")
        )
    with oc3:
        st.session_state["cfg_shodan"] = st.text_input(
            "Shodan", type="password", value=st.session_state.get("cfg_shodan")
        )

    if st.button("Test Providers", help="Live-check each configured OSINT provider with a benign indicator"):
        probe_keys = {
            "OTX_KEY": st.session_state.get("cfg_otx", ""),
            "VT_KEY": st.session_state.get("cfg_vt", ""),
            "ABUSEIPDB_KEY": st.session_state.get("cfg_abuseipdb", ""),
            "GREYNOISE_KEY": st.session_state.get("cfg_greynoise", ""),
            "SHODAN_KEY": st.session_state.get("cfg_shodan", ""),
        }
        with st.spinner("Probing OSINT providers…"):
            probe_results = probe_providers(probe_keys)
        for row in probe_results:
            provider, status, detail = row["provider"], row["status"], row.get("detail", "")
            if status == PROBE_RESULT_OK:
                st.success(f"✅ {provider}: key valid, provider reachable")
            elif status == PROBE_RESULT_INVALID_KEY:
                st.error(f"🔑 {provider}: invalid key ({detail})")
            elif status == PROBE_RESULT_RATE_LIMITED:
                st.warning(f"⏳ {provider}: rate limited — {detail}")
            elif status == PROBE_RESULT_UNREACHABLE:
                st.error(f"🌐 {provider}: unreachable — {detail}")
            else:
                st.info(f"➖ {provider}: no API key configured")

    st.markdown("---")
    st.markdown("#### Binary Paths (optional)")
    bp1, bp2 = st.columns(2)
    with bp1:
        zeek_path = st.text_input(
            "Zeek Binary Path", value=st.session_state.get("cfg_zeek_bin", ""), placeholder="Auto-detect"
        )
        st.session_state["cfg_zeek_bin"] = zeek_path

        # Check status
        from app.utils.common import find_bin

        resolved_zeek = find_bin("zeek", env_key="ZEEK_BIN", cfg_key="cfg_zeek_bin")
        if resolved_zeek:
            st.success(f"Found: `{resolved_zeek}`")
        else:
            st.error("Not found. Install Zeek or set path.")

    with bp2:
        tshark_path = st.text_input(
            "Tshark Binary Path", value=st.session_state.get("cfg_tshark_bin", ""), placeholder="Auto-detect"
        )
        st.session_state["cfg_tshark_bin"] = tshark_path

        resolved_tshark = find_bin("tshark", cfg_key="cfg_tshark_bin")
        if resolved_tshark:
            st.success(f"Found: `{resolved_tshark}`")
        else:
            st.error("Not found. Install Wireshark/Tshark.")

    st.markdown("---")
    st.markdown("#### YARA Rules")
    yara_dir = st.text_input(
        "YARA rules directory",
        key="cfg_yara_rules_dir",
        value=st.session_state.get("cfg_yara_rules_dir", ""),
        help=(
            "Folder containing .yar/.yara rule files. Scanned recursively at analysis time. "
            "In Docker, put rules under ./data/yara_rules — the data folder is mounted into the container."
        ),
    )
    if yara_dir.strip():
        _yara_path = pathlib.Path(yara_dir.strip()).expanduser()
        if not _yara_path.exists():
            st.warning(f"Directory not found: {_yara_path}")
        else:
            _yara_count = len(list(_yara_path.rglob("*.yar"))) + len(list(_yara_path.rglob("*.yara")))
            if _yara_count > 0:
                st.caption(f"✓ {_yara_count} rule file(s) found")
            else:
                st.warning("No .yar/.yara files in this directory")
    else:
        st.caption("Leave blank to use ./data/yara_rules when present.")

    st.markdown("---")
    st.markdown("#### Extraction / Analysis")
    st.caption(f"Maximum PCAP upload size: **{MAX_UPLOAD_SIZE_LABEL}**")
    st.session_state["cfg_limit_packets"] = st.number_input(
        "PyShark packet limit (0 = no limit)",
        min_value=0,
        value=int(st.session_state.get("cfg_limit_packets", C.DEFAULT_PYSHARK_LIMIT)),
        step=10000,
    )
    tc1, tc2, tc3, tc4, tc5 = st.columns(5)
    with tc1:
        st.session_state["cfg_do_pyshark"] = st.checkbox(
            "Run Packet Parsing (Tshark)", value=bool(st.session_state.get("cfg_do_pyshark", True))
        )
    with tc2:
        st.session_state["cfg_do_zeek"] = st.checkbox("Run Zeek", value=bool(st.session_state.get("cfg_do_zeek", True)))
    with tc3:
        st.session_state["cfg_do_carve"] = st.checkbox(
            "Carve HTTP bodies", value=bool(st.session_state.get("cfg_do_carve", True))
        )
    with tc4:
        st.session_state["cfg_do_yara"] = st.checkbox(
            "YARA Scan",
            value=bool(st.session_state.get("cfg_do_yara", True)),
            help="Scan carved files with YARA rules for malware detection",
        )
    with tc5:
        st.session_state["cfg_pre_count"] = st.checkbox(
            "Pre-count packets", value=bool(st.session_state.get("cfg_pre_count", C.PRECNT_DEFAULT))
        )

    osint_col1, osint_col2 = st.columns([3, 1])
    with osint_col1:
        st.session_state["cfg_osint_top_ips"] = st.number_input(
            "OSINT: Top N public IPs to enrich (0 = all)",
            min_value=0,
            max_value=1000,
            value=int(st.session_state.get("cfg_osint_top_ips", 50)),
            step=5,
        )
        st.session_state["cfg_osint_cache_enabled"] = st.checkbox(
            "Enable OSINT Cache",
            value=bool(st.session_state.get("cfg_osint_cache_enabled", False)),
            help="Cache OSINT API responses to speed up repeated analysis. Disable for fresh results.",
        )

    st.markdown("---")
    st.markdown("#### Map Visualization")
    st.caption("Select your 'Home' location to draw connectivity links for local traffic on the world map.")

    continents = geo_data.get_continents()
    curr_cont = st.session_state.get("cfg_home_continent", "")
    cont_idx = continents.index(curr_cont) if curr_cont in continents else 0

    sel_cont = st.selectbox("Continent", continents, index=cont_idx)
    st.session_state["cfg_home_continent"] = sel_cont

    countries = geo_data.get_countries(sel_cont)
    curr_coun = st.session_state.get("cfg_home_country", "")
    coun_idx = countries.index(curr_coun) if curr_coun in countries else 0

    sel_coun = st.selectbox("Country", countries, index=coun_idx)
    st.session_state["cfg_home_country"] = sel_coun

    cities = geo_data.get_cities(sel_coun)
    curr_city = st.session_state.get("cfg_home_city", "")
    city_idx = cities.index(curr_city) if curr_city in cities else 0

    sel_city = st.selectbox("City", cities, index=city_idx)
    st.session_state["cfg_home_city"] = sel_city

    # Update lat/lon based on selected city
    if sel_city:
        lat, lon = geo_data.get_location_details(sel_city, sel_coun)
        st.session_state["cfg_home_lat"] = lat
        st.session_state["cfg_home_lon"] = lon

    mcol1, mcol2, _ = st.columns([1, 1, 2])
    with mcol1:
        st.number_input(
            "Resolved Latitude", value=float(st.session_state.get("cfg_home_lat", 0.0)), format="%.4f", disabled=True
        )
    with mcol2:
        st.number_input(
            "Resolved Longitude", value=float(st.session_state.get("cfg_home_lon", 0.0)), format="%.4f", disabled=True
        )

    st.markdown("---")
    st.markdown("#### Save / Load Configuration")
    st.caption("Save your settings to persist across sessions. API keys are encrypted.")

    col_buttons = st.columns([1, 1, 1, 1, 1, 3])
    with col_buttons[0]:
        if st.button("Save Config", type="primary"):
            if save_config():
                st.success("Config saved!")
            else:
                st.error("Failed to save config.")
    with col_buttons[1]:
        if st.button("Load Config"):
            if load_config():
                st.success("Config loaded!")
                st.rerun()
            else:
                st.error("Failed to load config.")
    with col_buttons[2]:
        if st.button("Apply & Rerun"):
            st.rerun()
    with col_buttons[3]:
        if st.button("Reset Defaults"):
            for k in list(st.session_state.keys()):
                if k.startswith("cfg_"):
                    del st.session_state[k]
            # Clear saved config
            get_config_manager().clear()
            init_config_defaults()
            st.success("Config reset to defaults.")
            st.rerun()
    st.markdown("---")
    st.markdown("#### Database & Data Management")
    st.caption("Granular controls to clear specific types of stored data. Use with caution.")

    @st.dialog("Confirm Clear PCAP Data")
    def _confirm_clear_pcap():
        st.warning("This will permanently delete all PCAP data. This cannot be undone.")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Cancel", use_container_width=True, key="cancel_clear_pcap"):
                st.rerun()
        with col2:
            if st.button("Confirm Delete", type="primary", use_container_width=True, key="confirm_clear_pcap"):
                try:
                    for item in C.DATA_DIR.iterdir():
                        if item.is_dir() and not item.is_symlink():
                            shutil.rmtree(item)
                        elif item.is_file() and not item.is_symlink() and item.suffix != ".db":
                            item.unlink()
                    C.CARVE_DIR.mkdir(parents=True, exist_ok=True)
                    C.ZEEK_DIR.mkdir(parents=True, exist_ok=True)
                    st.toast("PCAP data cleared")
                    st.rerun()
                except Exception as e:
                    logger.error("Error clearing PCAP data: %s", e)
                    st.error("Failed to clear PCAP data. Check logs for details.")

    @st.dialog("Confirm Clear OSINT Cache")
    def _confirm_clear_osint():
        st.warning("This will permanently delete the OSINT cache. This cannot be undone.")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Cancel", use_container_width=True, key="cancel_clear_osint"):
                st.rerun()
        with col2:
            if st.button("Confirm Delete", type="primary", use_container_width=True, key="confirm_clear_osint"):
                try:
                    count = get_osint_cache().invalidate()
                    st.toast(f"OSINT cache cleared ({count} entries)")
                    st.rerun()
                except Exception as e:
                    logger.error("Error clearing OSINT cache: %s", e)
                    st.error("Failed to clear OSINT cache. Check logs for details.")

    @st.dialog("Confirm Clear Cases")
    def _confirm_clear_cases():
        st.warning("This will permanently delete all cases, analyses, and notes. This cannot be undone.")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Cancel", use_container_width=True, key="cancel_clear_cases"):
                st.rerun()
        with col2:
            if st.button("Confirm Delete", type="primary", use_container_width=True, key="confirm_clear_cases"):
                try:
                    if CaseRepository().clear_all():
                        st.toast("Cases and analyses cleared")
                        st.rerun()
                    else:
                        st.error("Failed to clear cases.")
                except Exception as e:
                    logger.error("Error clearing cases: %s", e)
                    st.error("Failed to clear cases. Check logs for details.")

    dcol1, dcol2, dcol3 = st.columns(3)
    with dcol1:
        clear_help = "Delete all uploaded PCAPs and extracted files (Zeek, carved files)"
        if st.button("🗑️ Clear PCAP Data", type="secondary", help=clear_help):
            _confirm_clear_pcap()

    with dcol2:
        if st.button("🗑️ Clear OSINT Cache", type="secondary", help="Clear the OSINT cache in SQLite"):
            _confirm_clear_osint()

    with dcol3:
        if st.button("🗑️ Clear Cases", type="secondary", help="Clear all cases, analyses, and notes from database"):
            _confirm_clear_cases()

    st.markdown("---")
    with st.expander("Runtime Logs"):
        logs = st.session_state.get("runtime_logs", [])
        if logs:
            st.code("\n".join(logs))
        else:
            st.info("No runtime logs.")
