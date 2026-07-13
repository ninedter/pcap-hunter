"""Tests for app/ui/cases_tab.py.

Focused on ``_session_mitre_techniques``, the helper that derives the
``Analysis.mitre_techniques`` list from ``st.session_state["attack_mapping"]``
for the two UI manual-save paths (``_quick_save_analysis`` and
``_add_current_analysis_to_case``). Without this, analyses saved through the
UI ship a permanently-empty ``mitre_techniques`` field even though the API
path (``app/api/queue.py``) populates it from ``result.mitre_techniques`` --
both share the same ``data/cases.db``, so the IOC feed's ``mitre_techniques``
column would be inconsistent depending on which path saved the case.

Uses Streamlit's AppTest harness (see ``tests/test_config_ui.py`` for the
established pattern) since the helper reads ``st.session_state`` directly.
"""

from streamlit.testing.v1 import AppTest


def _mitre_helper_app():
    import streamlit as st

    from app.ui.cases_tab import _session_mitre_techniques

    st.session_state["__result"] = _session_mitre_techniques()


def _make_app() -> AppTest:
    return AppTest.from_function(_mitre_helper_app, default_timeout=30)


class TestSessionMitreTechniques:
    def test_derives_technique_ids_from_attack_mapping(self):
        at = _make_app()
        at.session_state["attack_mapping"] = {
            "techniques": [
                {"technique_id": "T1071.001", "tactic": "command-and-control"},
                {"technique_id": "T1059", "tactic": "execution"},
            ]
        }
        at.run()

        assert at.session_state["__result"] == ["T1071.001", "T1059"]

    def test_empty_attack_mapping_yields_empty_list(self):
        at = _make_app()
        at.session_state["attack_mapping"] = {}
        at.run()

        assert at.session_state["__result"] == []

    def test_missing_attack_mapping_yields_empty_list(self):
        at = _make_app()
        at.run()

        assert at.session_state["__result"] == []

    def test_skips_techniques_missing_technique_id(self):
        at = _make_app()
        at.session_state["attack_mapping"] = {
            "techniques": [
                {"tactic": "execution"},
                {"technique_id": "T1105"},
            ]
        }
        at.run()

        assert at.session_state["__result"] == ["T1105"]
