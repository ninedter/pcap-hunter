# tests/test_pipeline_runner.py
"""Tests for the headless pipeline runner."""

from __future__ import annotations

from app.pipeline.runner import PipelineOptions, PipelineResult


def test_pipeline_options_defaults():
    opts = PipelineOptions()
    assert opts.osint_enabled is True
    assert opts.llm_enabled is True
    assert opts.do_pyshark is True
    assert opts.do_zeek is True
    assert opts.do_carve is True
    assert opts.do_yara is True
    assert opts.pyshark_packet_limit is None


def test_pipeline_result_round_trip():
    result = PipelineResult(
        case_id="abc12345",
        analysis_id="def67890",
        packet_count=12345,
        duration_seconds=42.5,
        stages_run=["pcap_count", "pyshark_pass"],
        warnings=["llm_unavailable"],
    )
    d = result.to_dict()
    assert d["case_id"] == "abc12345"
    assert d["stages_run"] == ["pcap_count", "pyshark_pass"]
    assert d["warnings"] == ["llm_unavailable"]
