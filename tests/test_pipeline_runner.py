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
        dns_analysis={"dga_count": 3, "tunneling": []},
        tls_analysis={"certs": [{"subject": "evil.example"}]},
        beacon_df_records=[{"src": "10.0.0.1", "dst": "1.2.3.4", "score": 0.91}],
    )
    serialized = json.dumps(result.to_dict())
    restored = json.loads(serialized)
    assert restored["analysis_id"] == "def67890"
    assert restored["mitre_techniques"] == ["T1071.001", "T1568.002"]
    assert restored["summary_narrative"] == "A short narrative."
    assert restored["dns_analysis"]["dga_count"] == 3
    assert restored["tls_analysis"]["certs"][0]["subject"] == "evil.example"
    assert restored["beacon_df_records"][0]["src"] == "10.0.0.1"


def test_run_pipeline_executes_sequential_stages_against_fixture():
    """Smoke test: run the headless pipeline against the tiny.pcap fixture.

    Confirms the lift wired the sequential path correctly. Stages like Zeek
    depend on a system binary; if it's missing the stage records a warning
    and the pipeline keeps going — we assert that PyShark at minimum ran.
    """
    import pathlib

    from app.pipeline.progress import CallbackProgress, ProgressEvent
    from app.pipeline.runner import PipelineOptions, PipelineResult, run_pipeline

    fixture = pathlib.Path(__file__).parent / "fixtures" / "tiny.pcap"
    assert fixture.exists(), "Run Task 4a first: tests/fixtures/tiny.pcap missing"

    events: list[ProgressEvent] = []
    heartbeats: list[int] = []

    options = PipelineOptions(
        osint_enabled=False,
        llm_enabled=False,
        do_pyshark=True,
        do_zeek=True,
        do_carve=False,  # tiny.pcap has only SYN packets, no HTTP — nothing to carve
        do_yara=False,
        pre_count=True,
        pyshark_packet_limit=50,
    )

    result = run_pipeline(
        pcap_path=str(fixture),
        case_id="testcase01",
        options=options,
        progress=CallbackProgress(callback=events.append, total_phases=7),
        heartbeat=lambda: heartbeats.append(1),
    )

    assert isinstance(result, PipelineResult)
    assert result.case_id == "testcase01"
    assert result.duration_seconds >= 0.0
    # PyShark either succeeds (stages_run) or fails (warnings)
    assert "pyshark_pass" in result.stages_run or "pyshark_failed" in result.warnings
    # pre_count requested — should have run unless tshark is missing
    assert "pcap_count" in result.stages_run or "pcap_count_unavailable" in result.warnings
    # Heartbeat should have been called at least once per executed stage
    assert len(heartbeats) >= 1
    # Some progress events should have fired
    assert any(e.kind == "phase_start" for e in events)
    assert any(e.kind == "phase_done" for e in events)


def test_run_pipeline_skips_disabled_stages():
    """If a stage's flag is False, it must not appear in stages_run."""
    import pathlib

    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import PipelineOptions, run_pipeline

    fixture = pathlib.Path(__file__).parent / "fixtures" / "tiny.pcap"
    if not fixture.exists():
        import pytest

        pytest.skip("tests/fixtures/tiny.pcap missing")

    options = PipelineOptions(
        osint_enabled=False,
        llm_enabled=False,
        do_pyshark=False,  # disabled
        do_zeek=False,  # disabled
        do_carve=False,
        do_yara=False,
        pre_count=False,
    )

    result = run_pipeline(
        pcap_path=str(fixture),
        case_id="skiptest",
        options=options,
        progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
    )

    assert "pyshark_pass" not in result.stages_run
    assert "zeek" not in result.stages_run
    assert "pcap_count" not in result.stages_run
    assert result.stages_run == []
    assert result.packet_count == 0


def test_streamlit_to_options_mapping():
    """Smoke check: the boolean flags PipelineOptions exposes match what main.py passes."""
    from app.pipeline.runner import PipelineOptions

    opts = PipelineOptions(
        osint_enabled=True,
        llm_enabled=False,
        do_pyshark=True,
        do_zeek=False,
        do_carve=True,
        do_yara=False,
        pre_count=True,
        pyshark_packet_limit=10000,
    )
    assert opts.do_zeek is False
    assert opts.pyshark_packet_limit == 10000
    assert opts.osint_top_n == 50


def test_run_pipeline_parallel_pyshark_zeek():
    """When both PyShark and Zeek are enabled, they run concurrently via ThreadPoolExecutor.

    We verify this by checking that:
    1. Both stages appear in stages_run (or warnings for missing binaries)
    2. The phase events show both stage starts before either finishes (overlap)
    """
    import pathlib

    from app.pipeline.progress import CallbackProgress, ProgressEvent
    from app.pipeline.runner import PipelineOptions, run_pipeline

    fixture = pathlib.Path(__file__).parent / "fixtures" / "tiny.pcap"
    if not fixture.exists():
        import pytest

        pytest.skip("tests/fixtures/tiny.pcap missing")

    events: list[ProgressEvent] = []
    options = PipelineOptions(
        osint_enabled=False,
        llm_enabled=False,
        do_pyshark=True,
        do_zeek=True,
        do_carve=False,
        do_yara=False,
        pre_count=True,
        pyshark_packet_limit=50,
    )

    result = run_pipeline(
        pcap_path=str(fixture),
        case_id="parallel_test",
        options=options,
        progress=CallbackProgress(callback=events.append, total_phases=7),
    )

    # Both stages either ran or warned — neither was silently skipped
    pyshark_ran = "pyshark_pass" in result.stages_run
    pyshark_warned = any(w.startswith("pyshark") for w in result.warnings)
    zeek_ran = "zeek" in result.stages_run
    zeek_warned = any(w.startswith("zeek") for w in result.warnings)
    assert pyshark_ran or pyshark_warned, "PyShark neither ran nor warned"
    assert zeek_ran or zeek_warned, "Zeek neither ran nor warned"

    # Check phase events show parallel start pattern — both "Parsing Packets"
    # and "Zeek processing" should start before either completes
    phase_starts = [e.title for e in events if e.kind == "phase_start"]
    if "Parsing Packets" in phase_starts and "Zeek processing" in phase_starts:
        pyshark_start_idx = next(
            i for i, e in enumerate(events) if e.kind == "phase_start" and e.title == "Parsing Packets"
        )
        zeek_start_idx = next(
            i for i, e in enumerate(events) if e.kind == "phase_start" and e.title == "Zeek processing"
        )
        # In parallel mode: both starts happen before either finishes
        first_done_idx = next(
            (
                i
                for i, e in enumerate(events)
                if e.kind == "phase_done" and e.title in ("Parsing Packets", "Zeek processing")
            ),
            len(events),
        )
        assert pyshark_start_idx < first_done_idx, "PyShark start should precede first done"
        assert zeek_start_idx < first_done_idx, "Zeek start should precede first done"
