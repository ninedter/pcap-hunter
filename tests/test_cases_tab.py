"""Tests for app/ui/cases_tab.py.

Focused on two session-state-derived helpers used by the UI manual-save paths
(``_quick_save_analysis`` and ``_add_current_analysis_to_case``), both of
which build an ``Analysis(...)`` from ``st.session_state`` rather than a
``PipelineResult`` (the API path's source, see ``app/api/queue.py``):

- ``_session_mitre_techniques`` derives ``Analysis.mitre_techniques`` from
  ``st.session_state["attack_mapping"]``. Without this, analyses saved
  through the UI ship a permanently-empty ``mitre_techniques`` field even
  though the API path populates it from ``result.mitre_techniques`` -- both
  share the same ``data/cases.db``, so the IOC feed's ``mitre_techniques``
  column would be inconsistent depending on which path saved the case.

- ``_session_analysis_features`` builds the ``features`` dict passed to
  ``Analysis(...)``, stashing ``http_analysis`` and ``beacon_records`` into
  it exactly as ``app/api/queue.py:_persist_analysis`` stashes them onto
  ``result.features`` (neither has a dedicated ``Analysis`` column). Without
  this, a case saved through the UI loses its HTTP findings (cleartext
  creds / suspicious UA / suspicious URIs) and beacon records on restore,
  while the same case saved via the API keeps them.

Uses Streamlit's AppTest harness (see ``tests/test_config_ui.py`` for the
established pattern) since the helpers read ``st.session_state`` directly.
"""

import pandas as pd
import streamlit as st
from streamlit.testing.v1 import AppTest

from app.ui.cases_tab import _session_analysis_features


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


class TestSessionAnalysisFeatures:
    """``_session_analysis_features`` builds the ``features`` dict for both UI
    manual-save paths, stashing ``http_analysis``/``beacon_records`` exactly as
    ``app/api/queue.py:_persist_analysis`` stashes them onto ``result.features``
    (see module docstring). Uses bare ``st.session_state`` directly (no AppTest
    script-run context needed), matching ``tests/test_case_restore.py``.
    """

    def setup_method(self):
        st.session_state.clear()

    def test_stashes_http_analysis_from_session(self):
        st.session_state["features"] = {"flows": []}
        st.session_state["http_analysis"] = {"cleartext_creds": ["user:pass@1.2.3.4"]}

        result = _session_analysis_features()

        assert result["http_analysis"] == {"cleartext_creds": ["user:pass@1.2.3.4"]}

    def test_http_analysis_none_when_absent_from_session(self):
        st.session_state["features"] = {"flows": []}

        result = _session_analysis_features()

        assert result["http_analysis"] is None

    def test_stashes_beacon_records_from_beacon_df(self):
        st.session_state["features"] = {"flows": []}
        st.session_state["beacon_df"] = pd.DataFrame([{"src": "10.0.0.5", "dst": "203.0.113.9", "score": 0.87}])

        result = _session_analysis_features()

        assert result["beacon_records"] == [{"src": "10.0.0.5", "dst": "203.0.113.9", "score": 0.87}]

    def test_beacon_records_empty_when_beacon_df_missing(self):
        st.session_state["features"] = {"flows": []}

        result = _session_analysis_features()

        assert result["beacon_records"] == []

    def test_beacon_records_empty_when_beacon_df_empty(self):
        st.session_state["features"] = {"flows": []}
        st.session_state["beacon_df"] = pd.DataFrame()

        result = _session_analysis_features()

        assert result["beacon_records"] == []

    def test_preserves_other_feature_keys(self):
        st.session_state["features"] = {"flows": [{"src": "1.1.1.1"}]}

        result = _session_analysis_features()

        assert result["flows"] == [{"src": "1.1.1.1"}]

    def test_does_not_mutate_live_session_features_dict(self):
        """The live ``st.session_state["features"]`` dict must not gain the
        stash keys in place -- it may be read elsewhere in the same rerun, and
        an in-place mutation would leak the stash into unrelated readers."""
        original = {"flows": []}
        st.session_state["features"] = original

        _session_analysis_features()

        assert "http_analysis" not in original
        assert "beacon_records" not in original
        assert st.session_state["features"] is original

    def test_missing_features_yields_stash_only(self):
        result = _session_analysis_features()

        assert result["http_analysis"] is None
        assert result["beacon_records"] == []
