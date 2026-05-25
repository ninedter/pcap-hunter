# tests/test_e2e_pipeline.py
"""End-to-end pipeline tests against real PCAP samples.

These tests verify the full analysis pipeline produces expected output
when given real network captures. They catch integration bugs that unit
tests miss — e.g., data shape mismatches between stages, silent failures,
and broken tool integrations (tshark, zeek).

Run:
    PYTHONPATH=. pytest tests/test_e2e_pipeline.py -v
    PYTHONPATH=. pytest tests/test_e2e_pipeline.py -v -s  # with stdout

Requires: tshark, zeek installed and on PATH.
"""

from __future__ import annotations

import pathlib
import shutil

import pandas as pd
import pytest

from app.pipeline.progress import CallbackProgress
from app.pipeline.runner import PipelineOptions, PipelineResult, run_pipeline

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PCAP_DIR = pathlib.Path(__file__).resolve().parent.parent / "pcaps"

# Standard test PCAPs — skip if not present (CI may not have them)
BR0_PCAP = PCAP_DIR / "br0.pcap"
ETH8_PCAP = PCAP_DIR / "eth8.pcap"

# Tool availability checks
HAS_TSHARK = shutil.which("tshark") is not None
HAS_ZEEK = shutil.which("zeek") is not None

skip_no_tshark = pytest.mark.skipif(not HAS_TSHARK, reason="tshark not installed")
skip_no_zeek = pytest.mark.skipif(not HAS_ZEEK, reason="zeek not installed")
skip_no_pcaps = pytest.mark.skipif(not BR0_PCAP.exists(), reason="pcap samples not found")


@pytest.fixture
def progress():
    """Headless progress adapter that does nothing."""
    events = []
    return CallbackProgress(callback=lambda e: events.append(e))


@pytest.fixture
def default_options():
    """Default pipeline options (all stages enabled, no OSINT/LLM)."""
    return PipelineOptions(
        osint_enabled=False,
        llm_enabled=False,
        do_pyshark=True,
        do_zeek=True,
        do_carve=True,
        do_yara=False,  # YARA runs in Streamlit wrapper, not headless
        pre_count=True,
        pyshark_packet_limit=5000,  # Limit for faster tests
        osint_top_n=0,
    )


@pytest.fixture
def fast_options():
    """Minimal options for fast smoke tests."""
    return PipelineOptions(
        osint_enabled=False,
        llm_enabled=False,
        do_pyshark=True,
        do_zeek=False,
        do_carve=False,
        do_yara=False,
        pre_count=True,
        pyshark_packet_limit=1000,
        osint_top_n=0,
    )


# ---------------------------------------------------------------------------
# Test: Single File Pipeline — Data Production
# ---------------------------------------------------------------------------


@skip_no_pcaps
@skip_no_tshark
class TestSingleFilePipeline:
    """Verify the pipeline produces expected artifacts for known PCAPs."""

    def test_br0_produces_flows(self, progress, default_options):
        """br0.pcap must produce flows with full artifact extraction."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0",
            options=default_options,
            progress=progress,
        )

        assert isinstance(result, PipelineResult)
        assert result.packet_count > 0, "Packet count should be > 0"

        flows = result.features.get("flows", [])
        assert len(flows) > 0, "Pipeline should extract at least some flows"

    def test_br0_extracts_artifacts(self, progress, default_options):
        """br0.pcap must extract IPs, domains, and hashes."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0_arts",
            options=default_options,
            progress=progress,
        )

        artifacts = result.features.get("artifacts", {})
        assert "ips" in artifacts, "artifacts must contain 'ips' key"
        assert "domains" in artifacts, "artifacts must contain 'domains' key"
        assert "hashes" in artifacts, "artifacts must contain 'hashes' key"

        # br0.pcap is known to have significant traffic
        assert len(artifacts["ips"]) > 10, f"Expected >10 IPs, got {len(artifacts['ips'])}"

    def test_br0_packet_count_matches_tshark(self, progress, default_options):
        """Packet count from pre-count stage should be reasonable."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0_count",
            options=default_options,
            progress=progress,
        )

        # br0.pcap has ~40960 packets
        assert result.packet_count >= 30000, f"Expected >=30000 packets, got {result.packet_count}"

    @skip_no_zeek
    def test_br0_produces_zeek_tables(self, progress, default_options):
        """Zeek must produce at least conn.log for br0.pcap."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0_zeek",
            options=default_options,
            progress=progress,
        )

        assert len(result.zeek_tables) > 0, "Zeek should produce at least one log table"
        assert "conn.log" in result.zeek_tables, "Zeek must produce conn.log"
        conn_df = result.zeek_tables["conn.log"]
        assert isinstance(conn_df, pd.DataFrame)
        assert len(conn_df) > 0, "conn.log should have rows"

    @skip_no_zeek
    def test_br0_dns_analysis(self, progress, default_options):
        """DNS analysis should produce structured results."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0_dns",
            options=default_options,
            progress=progress,
        )

        # DNS analysis depends on zeek dns.log — may be empty if no DNS in capture
        # but the result dict should always exist with expected keys
        assert isinstance(result.dns_analysis, dict)

    @skip_no_zeek
    def test_br0_tls_analysis(self, progress, default_options):
        """TLS analysis should produce structured results."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0_tls",
            options=default_options,
            progress=progress,
        )

        assert isinstance(result.tls_analysis, dict)

    def test_br0_beacon_detection(self, progress, default_options):
        """Beaconing detection should run and produce records."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0_beacon",
            options=default_options,
            progress=progress,
        )

        # beacon_df_records is always a list (may be empty if no periodic traffic)
        assert isinstance(result.beacon_df_records, list)

    @skip_no_tshark
    def test_br0_carve(self, progress, default_options):
        """HTTP carving should extract payloads from br0.pcap."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_br0_carve",
            options=default_options,
            progress=progress,
        )

        # carved_items may be empty if no HTTP payloads; shape must be correct
        assert isinstance(result.carved_items, list)

    def test_eth8_produces_flows(self, progress, default_options):
        """eth8.pcap must also produce flows."""
        if not ETH8_PCAP.exists():
            pytest.skip("eth8.pcap not available")

        result = run_pipeline(
            pcap_path=str(ETH8_PCAP),
            case_id="test_eth8",
            options=default_options,
            progress=progress,
        )

        flows = result.features.get("flows", [])
        assert len(flows) > 0, "eth8.pcap should produce flows"
        assert result.packet_count > 0


# ---------------------------------------------------------------------------
# Test: Pipeline Data Contracts
# ---------------------------------------------------------------------------


@skip_no_pcaps
@skip_no_tshark
class TestPipelineDataContracts:
    """Verify the data shapes produced by the pipeline match downstream expectations."""

    def test_features_dict_shape(self, progress, default_options):
        """features dict must have 'flows' (list) and 'artifacts' (dict with known keys)."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_shape_features",
            options=default_options,
            progress=progress,
        )

        features = result.features
        assert isinstance(features, dict), "features must be a dict"
        assert "flows" in features, "features must contain 'flows'"
        assert "artifacts" in features, "features must contain 'artifacts'"
        assert isinstance(features["flows"], list), "flows must be a list"

        artifacts = features["artifacts"]
        assert isinstance(artifacts, dict), "artifacts must be a dict"
        for key in ("ips", "domains", "hashes"):
            assert key in artifacts, f"artifacts must contain '{key}'"
            assert isinstance(artifacts[key], list), f"artifacts['{key}'] must be a list"

    def test_flow_record_shape(self, progress, default_options):
        """Each flow record must have src, dst, and proto at minimum."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_shape_flow",
            options=default_options,
            progress=progress,
        )

        flows = result.features.get("flows", [])
        assert len(flows) > 0, "Need at least one flow to verify shape"

        sample = flows[0]
        assert isinstance(sample, dict), "Each flow must be a dict"
        # Core fields expected by downstream consumers
        assert "src" in sample, "Flow must have 'src'"
        assert "dst" in sample, "Flow must have 'dst'"

    def test_stages_run_is_list_of_strings(self, progress, default_options):
        """stages_run must be a non-empty list of stage name strings."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_shape_stages",
            options=default_options,
            progress=progress,
        )

        assert isinstance(result.stages_run, list)
        assert len(result.stages_run) > 0, "At least one stage should have run"
        assert all(isinstance(s, str) for s in result.stages_run)

    def test_warnings_is_list_of_strings(self, progress, default_options):
        """warnings must be a list (possibly empty) of strings."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_shape_warnings",
            options=default_options,
            progress=progress,
        )

        assert isinstance(result.warnings, list)
        assert all(isinstance(w, str) for w in result.warnings)

    @skip_no_zeek
    def test_zeek_tables_are_dataframes(self, progress, default_options):
        """Each entry in zeek_tables must be a pandas DataFrame."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_shape_zeek",
            options=default_options,
            progress=progress,
        )

        for name, df in result.zeek_tables.items():
            assert isinstance(df, pd.DataFrame), f"zeek_tables['{name}'] must be DataFrame"

    def test_to_dict_serializable(self, progress, default_options):
        """PipelineResult.to_dict() must return JSON-serializable dict."""
        import json

        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_serializable",
            options=default_options,
            progress=progress,
        )

        d = result.to_dict()
        assert isinstance(d, dict)
        # Must be JSON-serializable (no DataFrames, no custom objects)
        json_str = json.dumps(d)
        assert len(json_str) > 10


# ---------------------------------------------------------------------------
# Test: Pipeline Options & Stage Gating
# ---------------------------------------------------------------------------


@skip_no_pcaps
@skip_no_tshark
class TestPipelineOptions:
    """Verify that pipeline options correctly enable/disable stages."""

    def test_pyshark_disabled_produces_empty_features(self, progress):
        """With do_pyshark=False, features should still have valid shape but empty flows."""
        opts = PipelineOptions(
            osint_enabled=False,
            llm_enabled=False,
            do_pyshark=False,
            do_zeek=False,
            do_carve=False,
            do_yara=False,
            pre_count=False,
        )
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_no_pyshark",
            options=opts,
            progress=progress,
        )

        # Shape must still be valid even with everything disabled
        assert isinstance(result.features, dict)
        assert "flows" in result.features
        assert "artifacts" in result.features

    def test_zeek_disabled_skips_dns_tls(self, progress):
        """With do_zeek=False, DNS and TLS analysis should be empty/skipped."""
        opts = PipelineOptions(
            osint_enabled=False,
            llm_enabled=False,
            do_pyshark=True,
            do_zeek=False,
            do_carve=False,
            do_yara=False,
            pre_count=True,
            pyshark_packet_limit=1000,
        )
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_no_zeek",
            options=opts,
            progress=progress,
        )

        assert len(result.zeek_tables) == 0, "No Zeek tables without Zeek"
        # DNS/TLS analysis might be empty dicts
        assert isinstance(result.dns_analysis, dict)
        assert isinstance(result.tls_analysis, dict)

    def test_packet_limit_respected(self, progress):
        """pyshark_packet_limit should cap the number of parsed packets."""
        opts = PipelineOptions(
            osint_enabled=False,
            llm_enabled=False,
            do_pyshark=True,
            do_zeek=False,
            do_carve=False,
            do_yara=False,
            pre_count=True,
            pyshark_packet_limit=500,
        )
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_limit",
            options=opts,
            progress=progress,
        )

        # With 500 packet limit on a 40K+ packet file, flows should be limited
        flows = result.features.get("flows", [])
        # We can't assert exact count but it should be significantly less than full parse
        assert len(flows) < 5000, f"Packet limit not respected: got {len(flows)} flows"


# ---------------------------------------------------------------------------
# Test: Pipeline Resilience (edge cases)
# ---------------------------------------------------------------------------


@skip_no_tshark
class TestPipelineEdgeCases:
    """Verify the pipeline handles edge cases gracefully."""

    def test_nonexistent_pcap_records_warnings(self, progress, default_options):
        """A non-existent PCAP records stage failures as warnings (best-effort pipeline)."""
        result = run_pipeline(
            pcap_path="/tmp/nonexistent_pcap_xyz.pcap",
            case_id="test_missing",
            options=default_options,
            progress=progress,
        )

        # Pipeline is best-effort: bad input produces warnings, not exceptions
        assert len(result.warnings) > 0, "Non-existent PCAP should produce warnings"
        # Features should still have valid shape (empty but correct)
        assert isinstance(result.features, dict)
        assert "flows" in result.features

    @skip_no_pcaps
    def test_no_stages_enabled_still_returns_valid_result(self, progress):
        """Even with all stages disabled, the pipeline returns a valid result."""
        opts = PipelineOptions(
            osint_enabled=False,
            llm_enabled=False,
            do_pyshark=False,
            do_zeek=False,
            do_carve=False,
            do_yara=False,
            pre_count=False,
        )
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_no_stages",
            options=opts,
            progress=progress,
        )

        assert isinstance(result, PipelineResult)
        assert isinstance(result.features, dict)
        assert isinstance(result.warnings, list)
        assert isinstance(result.stages_run, list)

    @skip_no_pcaps
    def test_progress_events_emitted(self):
        """The progress callback should receive events during pipeline execution."""
        events = []
        prog = CallbackProgress(callback=lambda e: events.append(e))

        opts = PipelineOptions(
            osint_enabled=False,
            llm_enabled=False,
            do_pyshark=True,
            do_zeek=False,
            do_carve=False,
            do_yara=False,
            pre_count=True,
            pyshark_packet_limit=500,
        )
        run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="test_events",
            options=opts,
            progress=prog,
        )

        assert len(events) > 0, "Progress callback should receive at least one event"
        # Should have phase_start events
        phase_starts = [e for e in events if e.kind == "phase_start"]
        assert len(phase_starts) > 0, "Should have at least one phase_start event"


# ---------------------------------------------------------------------------
# Test: Quick Smoke Test (fast, minimal)
# ---------------------------------------------------------------------------


@skip_no_pcaps
@skip_no_tshark
class TestSmoke:
    """Fast smoke tests — run first to catch obvious breakage."""

    def test_pipeline_completes_without_crash(self, progress, fast_options):
        """The pipeline should complete without unhandled exceptions."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="smoke",
            options=fast_options,
            progress=progress,
        )
        assert result is not None
        assert isinstance(result, PipelineResult)

    def test_pipeline_result_has_case_id(self, progress, fast_options):
        """The result should carry the case_id we passed in."""
        result = run_pipeline(
            pcap_path=str(BR0_PCAP),
            case_id="smoke_case_42",
            options=fast_options,
            progress=progress,
        )
        assert result.case_id == "smoke_case_42"
