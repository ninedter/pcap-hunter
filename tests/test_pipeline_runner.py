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


def test_pipeline_result_to_dict_is_json_serializable():
    """Guard against future fields that produce non-JSON-safe objects in to_dict()."""
    import json

    result = PipelineResult(
        case_id="abc12345",
        analysis_id="def67890",
        packet_count=12345,
        duration_seconds=42.5,
        stages_run=["pcap_count", "pyshark_pass"],
        warnings=["llm_unavailable"],
        summary_narrative="A short narrative.",
        mitre_techniques=["T1071.001", "T1568.002"],
    )
    # Round-trip through json to confirm every value type is JSON-safe.
    serialized = json.dumps(result.to_dict())
    restored = json.loads(serialized)
    assert restored["analysis_id"] == "def67890"
    assert restored["mitre_techniques"] == ["T1071.001", "T1568.002"]
    assert restored["summary_narrative"] == "A short narrative."


def test_run_pipeline_stub_raises_not_implemented():
    """Guard against future regressions where the stub silently returns instead of raising."""
    import pytest

    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import PipelineOptions, run_pipeline

    with pytest.raises(NotImplementedError):
        run_pipeline(
            pcap_path="nonexistent.pcap",
            case_id="case",
            options=PipelineOptions(),
            progress=CallbackProgress(callback=lambda _e: None),
        )
