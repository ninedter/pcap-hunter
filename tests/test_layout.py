"""Tests for app/ui/layout.py helpers (theme-aware branding asset selection)."""

from __future__ import annotations

from streamlit.testing.v1 import AppTest

from app.ui.layout import resolve_logo_path

LIGHT = "logo-256.png"
DARK = "logo-dark-256.png"

# Production-shape dict, as stored in st.session_state["attack_mapping"]
# (AttackMapping.to_dict() output from the ATT&CK mapping pipeline stage).
PROD_ATTACK_MAPPING_DICT = {
    "techniques": [
        {
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "command-and-control",
            "confidence": 0.85,
            "evidence": ["Beaconing detected with score 0.85 to 203.0.113.5"],
        },
        {
            "technique_id": "T1568.002",
            "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
            "tactic": "command-and-control",
            "confidence": 0.6,
            "evidence": ["DGA domains detected: xk3jd9a.example.com"],
        },
    ],
    "tactics_summary": {"command-and-control": 2},
    "kill_chain_phase": "command-and-control",
    "overall_severity": "high",
}


def _render_attack_mapping_app():
    import streamlit as st

    from app.threat_intel import AttackMapping
    from app.ui.layout import render_attack_mapping

    attack_mapping = st.session_state.get("attack_mapping", {})
    render_attack_mapping(st.container(), AttackMapping.from_dict(attack_mapping))


class TestRenderAttackMappingFromDict:
    def test_renders_without_exception_and_shows_mitre_attck(self):
        at = AppTest.from_function(_render_attack_mapping_app, default_timeout=30)
        at.session_state["attack_mapping"] = PROD_ATTACK_MAPPING_DICT
        at.run()

        assert not at.exception
        expanders = [e for e in at.expander if "MITRE ATT&CK" in (e.label or "")]
        assert expanders, "Dashboard should render a MITRE ATT&CK Mapping expander"

    def test_empty_dict_renders_without_exception(self):
        at = AppTest.from_function(_render_attack_mapping_app, default_timeout=30)
        at.session_state["attack_mapping"] = {}
        at.run()

        assert not at.exception


# Production-shape dict, as stored in st.session_state["http_analysis"]
# (analyze_http() output from app/pipeline/http_analysis.py).
PROD_HTTP_ANALYSIS_DICT = {
    "total_requests": 7,
    "unique_hosts": 5,
    "methods": {"GET": 6, "POST": 1},
    "status_codes": {"200": 6, "401": 1},
    "suspicious_user_agents": [
        {"host": "10.0.0.5", "user_agent": "", "uri": "/", "reason": "missing user-agent"},
        {
            "host": "10.0.0.6",
            "user_agent": "python-requests/2.31",
            "uri": "/api",
            "reason": "known tool user-agent (python-requests)",
        },
    ],
    "cleartext_credentials": [
        {"host": "10.0.0.5", "uri": "/admin", "username": "admin"},
    ],
    "suspicious_uris": [
        {"host": "10.0.0.7", "uri": "/payload.exe", "reason": "risky file extension (.exe)"},
        {
            "host": "203.0.113.9",
            "uri": "/files/tool.dll",
            "reason": "risky file extension (.dll); raw-IP host serving file download",
        },
        {"host": "10.0.0.8", "uri": "/" + "a" * 600, "reason": "long URI (605 chars)"},
    ],
    "alerts": {
        "suspicious_ua_count": 2,
        "cleartext_cred_count": 1,
        "suspicious_uri_count": 3,
    },
}


def _render_http_analysis_app():
    import streamlit as st

    from app.ui.layout import render_http_analysis

    render_http_analysis(st.container(), st.session_state.get("http_analysis"))


class TestRenderHttpAnalysis:
    def test_production_shape_dict_renders_without_exception(self):
        at = AppTest.from_function(_render_http_analysis_app, default_timeout=30)
        at.session_state["http_analysis"] = PROD_HTTP_ANALYSIS_DICT
        at.run()

        assert not at.exception
        expanders = [e for e in at.expander if "HTTP Analysis" in (e.label or "")]
        assert expanders, "Raw Data tab should render an HTTP Analysis expander"
        assert expanders[0].proto.expanded, "alerts present -> expander should default to expanded"

    def test_none_shows_info_and_returns(self):
        at = AppTest.from_function(_render_http_analysis_app, default_timeout=30)
        at.session_state["http_analysis"] = None
        at.run()

        assert not at.exception
        assert at.info, "None http_analysis should render an info message, not crash"

    def test_skipped_shows_info(self):
        at = AppTest.from_function(_render_http_analysis_app, default_timeout=30)
        at.session_state["http_analysis"] = {"skipped": True}
        at.run()

        assert not at.exception
        assert at.info

    def test_error_shows_info(self):
        at = AppTest.from_function(_render_http_analysis_app, default_timeout=30)
        at.session_state["http_analysis"] = {"error": "No HTTP log data", "records": 0}
        at.run()

        assert not at.exception
        assert at.info

    def test_clean_run_no_alerts_not_expanded_and_shows_captions(self):
        at = AppTest.from_function(_render_http_analysis_app, default_timeout=30)
        at.session_state["http_analysis"] = {
            "total_requests": 3,
            "unique_hosts": 2,
            "methods": {"GET": 3},
            "status_codes": {"200": 3},
            "suspicious_user_agents": [],
            "cleartext_credentials": [],
            "suspicious_uris": [],
            "alerts": {"suspicious_ua_count": 0, "cleartext_cred_count": 0, "suspicious_uri_count": 0},
        }
        at.run()

        assert not at.exception
        expanders = [e for e in at.expander if "HTTP Analysis" in (e.label or "")]
        assert expanders
        assert not expanders[0].proto.expanded, "no alerts -> expander should default to collapsed"
        captions = [c.value for c in at.caption]
        assert any("No cleartext credentials" in c for c in captions)
        assert any("No suspicious user-agents" in c for c in captions)
        assert any("No suspicious URIs" in c for c in captions)


def _make_assets(tmp_path, *names):
    for name in names:
        (tmp_path / name).write_bytes(b"\x89PNG")


class TestResolveLogoPath:
    def test_dark_theme_picks_dark_variant(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, "dark") == tmp_path / DARK

    def test_light_theme_picks_light_variant(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, "light") == tmp_path / LIGHT

    def test_unknown_theme_defaults_to_light(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, None) == tmp_path / LIGHT
        assert resolve_logo_path(tmp_path, "") == tmp_path / LIGHT

    def test_theme_type_is_case_insensitive(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, "Dark") == tmp_path / DARK

    def test_dark_theme_falls_back_to_light_when_dark_missing(self, tmp_path):
        _make_assets(tmp_path, LIGHT)
        assert resolve_logo_path(tmp_path, "dark") == tmp_path / LIGHT

    def test_light_theme_falls_back_to_dark_when_light_missing(self, tmp_path):
        _make_assets(tmp_path, DARK)
        assert resolve_logo_path(tmp_path, "light") == tmp_path / DARK

    def test_returns_none_when_no_assets_exist(self, tmp_path):
        assert resolve_logo_path(tmp_path, "dark") is None
        assert resolve_logo_path(tmp_path, "light") is None
