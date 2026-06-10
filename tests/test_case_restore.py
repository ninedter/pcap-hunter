"""Restoring a saved case analysis must repopulate dashboard session state.

The Dashboard tab reads ``st.session_state["features"]`` / ``"dash_aggregates"``
/ ``"osint"`` / ``"dns_analysis"`` / ``"tls_analysis"``. Opening a saved case
loads Analysis objects from SQLite, but before this fix nothing wrote them back
into session state, so the Top-10 charts rendered empty for restored cases.

Streamlit session_state works as a plain dict in bare (non-``streamlit run``)
mode, so these tests exercise the real helper without a script run context.
"""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st

from app.database.models import Analysis
from app.ui.cases_tab import _restore_analysis_to_session


def _make_analysis(**overrides) -> Analysis:
    """Production-shape Analysis: flow dicts match parse_pcap_pyshark output."""
    base = dict(
        id="an-123",
        case_id="case-1",
        pcap_path="/tmp/sample.pcap",
        packet_count=42,
        analyzed_at=datetime(2026, 1, 2, 3, 4, 5),
        features={
            "flows": [
                {"src": "10.0.0.1", "dst": "8.8.8.8", "sport": "5000", "dport": "53", "proto": "dns", "count": 10},
                {"src": "10.0.0.1", "dst": "1.1.1.1", "sport": "5001", "dport": "53", "proto": "dns", "count": 5},
                {"src": "10.0.0.2", "dst": "8.8.8.8", "sport": "5002", "dport": "443", "proto": "tls", "count": 20},
            ],
        },
        osint={"8.8.8.8": {"abuse_score": 0}},
        dns_analysis={"top_queried": [{"domain": "example.com", "count": 7}]},
        tls_analysis={"certificates": []},
        yara_results={"matches": [{"rule": "apt_beacon", "file": "carved_1.bin"}]},
        report="# Threat Report\n\nSuspicious beaconing observed.",
    )
    base.update(overrides)
    return Analysis(**base)


class TestRestoreAnalysisToSession:
    def setup_method(self):
        st.session_state.clear()

    def test_features_restored(self):
        analysis = _make_analysis()
        _restore_analysis_to_session(analysis)
        assert st.session_state["features"] is analysis.features

    def test_dash_aggregates_computed_with_flow_weighting(self):
        """Aggregates must match the dashboard fast path: top_n=10, weight='flows'."""
        _restore_analysis_to_session(_make_analysis())
        agg = st.session_state["dash_aggregates"]
        # weight="flows" → one increment per flow row, NOT summed packet counts
        assert agg["top_src_ips"][0] == ("10.0.0.1", 2)
        assert agg["top_dst_ips"][0] == ("8.8.8.8", 2)
        assert ("53", 2) in agg["top_dst_ports"]
        assert agg["top_protos"][0] == ("dns", 2)

    def test_other_dashboard_keys_populated(self):
        analysis = _make_analysis()
        _restore_analysis_to_session(analysis)
        assert st.session_state["osint"] == {"8.8.8.8": {"abuse_score": 0}}
        assert st.session_state["dns_analysis"] == {"top_queried": [{"domain": "example.com", "count": 7}]}
        assert st.session_state["tls_analysis"] == {"certificates": []}

    def test_stale_beacon_df_reset(self):
        """beacon_df is not persisted on Analysis — stale rows from a previously
        analyzed capture must not survive a restore."""
        st.session_state["beacon_df"] = pd.DataFrame([{"src": "9.9.9.9"}])
        _restore_analysis_to_session(_make_analysis())
        assert isinstance(st.session_state["beacon_df"], pd.DataFrame)
        assert st.session_state["beacon_df"].empty

    def test_stale_dashboard_filters_cleared(self):
        """Filters reference IPs/time ranges from the prior capture; leaving them
        active would keep filtered_flows empty — the exact symptom being fixed."""
        st.session_state["filter_ips"] = {"172.16.0.9"}
        st.session_state["filter_protos"] = {"tcp"}
        st.session_state["filter_time"] = (0.0, 1.0)
        _restore_analysis_to_session(_make_analysis())
        assert st.session_state["filter_ips"] == set()
        assert st.session_state["filter_protos"] == set()
        assert st.session_state["filter_time"] is None

    def test_restore_marker_set(self):
        """Marker lets render code skip re-restoring on every Streamlit rerun."""
        _restore_analysis_to_session(_make_analysis(id="an-9"))
        assert st.session_state["restored_analysis_id"] == "an-9"

    def test_empty_features(self):
        _restore_analysis_to_session(_make_analysis(features={}))
        assert st.session_state["features"] == {}
        assert st.session_state["dash_aggregates"]["top_src_ips"] == []

    def test_none_features(self):
        _restore_analysis_to_session(_make_analysis(features=None))
        assert st.session_state["features"] == {}
        assert st.session_state["dash_aggregates"]["top_dst_ips"] == []

    def test_none_osint_normalized_to_empty_dict(self):
        _restore_analysis_to_session(_make_analysis(osint=None))
        assert st.session_state["osint"] == {}

    def test_none_dns_and_tls_passed_through(self):
        _restore_analysis_to_session(_make_analysis(dns_analysis=None, tls_analysis=None))
        assert st.session_state["dns_analysis"] is None
        assert st.session_state["tls_analysis"] is None
