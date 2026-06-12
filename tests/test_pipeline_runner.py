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


def test_run_pipeline_executes_all_stages_against_fixture():
    """Smoke test: run the headless pipeline against the tiny.pcap fixture.

    Confirms the runner wires all stages correctly. Stages like Zeek
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


def test_stages_4_to_7_run_concurrently(monkeypatch, tmp_path):
    """Stages 4 (DNS), 5 (TLS), 6 (beacon), 7 (carve) must overlap in time.

    All upstream stages are stubbed so only the post-parse fan-out is exercised.
    Each of the four stage functions increments a lock-protected counter, sleeps,
    then decrements — if they run sequentially the observed max concurrency is 1.
    """
    import threading
    import time

    import pandas as pd

    import app.pipeline.runner as R
    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import PipelineOptions, run_pipeline

    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    features = {
        "flows": [
            {
                "src": "1.1.1.1",
                "dst": "2.2.2.2",
                "sport": "1",
                "dport": "2",
                "proto": "tcp",
                "count": 1,
                "pkt_times": [1.0],
                "pkt_lens": [60],
            }
        ],
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": [], "macs": []},
    }

    monkeypatch.setattr(R, "count_packets_fast", lambda p: 10)
    monkeypatch.setattr(R, "parse_pcap_pyshark", lambda p, **kw: features)
    monkeypatch.setattr(R, "run_zeek", lambda p, d, phase=None: {"dns.log": str(tmp_path / "d.log")})
    monkeypatch.setattr(R, "load_zeek_any", lambda p: pd.DataFrame({"query": ["a.com"]}))
    monkeypatch.setattr(R, "merge_zeek_dns", lambda zt, f: f)

    lock = threading.Lock()
    state = {"current": 0, "max": 0}

    def _tracked(return_value):
        def _fn(*args, **kwargs):
            with lock:
                state["current"] += 1
                state["max"] = max(state["max"], state["current"])
            time.sleep(0.2)
            with lock:
                state["current"] -= 1
            return return_value

        return _fn

    monkeypatch.setattr(R, "analyze_dns", _tracked({}))
    monkeypatch.setattr(R, "analyze_certificates", _tracked({}))
    monkeypatch.setattr(R, "rank_beaconing", _tracked(pd.DataFrame()))
    monkeypatch.setattr(R, "carve_http_payloads", _tracked([]))

    result = run_pipeline(
        pcap_path=str(pcap),
        case_id="concurrency_test",
        options=PipelineOptions(osint_enabled=False, llm_enabled=False),
        progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
    )

    for stage in ("dns_analysis", "tls_certs", "beacon", "carve"):
        assert stage in result.stages_run, f"{stage} did not run"
    assert state["max"] >= 2, f"stages 4-7 ran sequentially (max concurrency observed: {state['max']})"


def test_stage_order_deterministic_and_carve_hashes_backfilled(monkeypatch, tmp_path):
    """stages_run keeps the canonical dns→tls→beacon→carve order and carve hashes land in features.

    Regression guard for the fan-out: workers record outcomes per stage, the main
    thread assembles stages_run in canonical order and backfills carved sha256
    hashes into features["artifacts"]["hashes"] after the join.
    """
    import pandas as pd

    import app.pipeline.runner as R
    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import PipelineOptions, run_pipeline

    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    features = {
        "flows": [
            {
                "src": "1.1.1.1",
                "dst": "2.2.2.2",
                "sport": "1",
                "dport": "2",
                "proto": "tcp",
                "count": 1,
                "pkt_times": [1.0],
                "pkt_lens": [60],
            }
        ],
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": [], "macs": []},
    }
    carved_sha = "ff" * 32

    monkeypatch.setattr(R, "count_packets_fast", lambda p: 10)
    monkeypatch.setattr(R, "parse_pcap_pyshark", lambda p, **kw: features)
    monkeypatch.setattr(R, "run_zeek", lambda p, d, phase=None: {"dns.log": str(tmp_path / "d.log")})
    monkeypatch.setattr(R, "load_zeek_any", lambda p: pd.DataFrame({"query": ["a.com"]}))
    monkeypatch.setattr(R, "merge_zeek_dns", lambda zt, f: f)
    monkeypatch.setattr(R, "analyze_dns", lambda *a, **kw: {})
    monkeypatch.setattr(R, "analyze_certificates", lambda *a, **kw: {})
    monkeypatch.setattr(R, "rank_beaconing", lambda *a, **kw: pd.DataFrame())
    monkeypatch.setattr(R, "carve_http_payloads", lambda *a, **kw: [{"sha256": carved_sha, "path": "x"}])

    result = run_pipeline(
        pcap_path=str(pcap),
        case_id="order_test",
        options=PipelineOptions(osint_enabled=False, llm_enabled=False),
        progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
    )

    canonical = ["dns_analysis", "tls_certs", "beacon", "carve"]
    observed = [s for s in result.stages_run if s in set(canonical)]
    assert observed == canonical, f"stage order not deterministic: {result.stages_run}"
    assert carved_sha in result.features["artifacts"]["hashes"], "carve sha256 backfill missing post-join"


def _stub_stage_dirs(monkeypatch, tmp_path, zeek_logs=None):
    """Redirect config dirs to tmp_path and stub zeek/carve to capture their out-dir args.

    Returns a dict collecting the directory each stubbed stage was invoked with.
    """
    import pandas as pd

    import app.config as config
    import app.pipeline.runner as R

    zeek_base = tmp_path / "zeek"
    carve_base = tmp_path / "carved"
    zeek_base.mkdir(parents=True, exist_ok=True)
    carve_base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "ZEEK_DIR", zeek_base)
    monkeypatch.setattr(config, "CARVE_DIR", carve_base)

    captured = {"zeek_dirs": [], "carve_dirs": []}

    def _fake_run_zeek(p, d, phase=None):
        captured["zeek_dirs"].append(d)
        return dict(zeek_logs or {})

    def _fake_carve(p, d, phase=None):
        captured["carve_dirs"].append(d)
        return []

    monkeypatch.setattr(R, "run_zeek", _fake_run_zeek)
    monkeypatch.setattr(R, "load_zeek_any", lambda p: pd.DataFrame({"query": ["a.com"]}))
    monkeypatch.setattr(R, "merge_zeek_dns", lambda zt, f: f)
    monkeypatch.setattr(R, "analyze_dns", lambda *a, **kw: {})
    monkeypatch.setattr(R, "analyze_certificates", lambda *a, **kw: {})
    monkeypatch.setattr(R, "carve_http_payloads", _fake_carve)
    return captured


def _zeek_carve_only_options():
    from app.pipeline.runner import PipelineOptions

    return PipelineOptions(
        osint_enabled=False,
        llm_enabled=False,
        do_pyshark=False,
        do_zeek=True,
        do_carve=True,
        do_yara=False,
        pre_count=False,
    )


def test_run_pipeline_uses_per_run_subdirs_for_zeek_and_carve(monkeypatch, tmp_path):
    """Zeek and carve must each receive a per-run subdirectory, never the shared base dir.

    Zeek writes fixed-name logs (conn.log, dns.log, ...) into its output cwd, so two
    concurrent jobs sharing C.ZEEK_DIR silently clobber each other's logs and
    load_zeek_any() can read the wrong pcap's data.
    """
    import pathlib

    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import run_pipeline

    captured = _stub_stage_dirs(monkeypatch, tmp_path)
    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    run_pipeline(
        pcap_path=str(pcap),
        case_id="case01",
        options=_zeek_carve_only_options(),
        progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
    )

    assert len(captured["zeek_dirs"]) == 1 and len(captured["carve_dirs"]) == 1
    zeek_dir = pathlib.Path(captured["zeek_dirs"][0])
    carve_dir = pathlib.Path(captured["carve_dirs"][0])
    assert zeek_dir != tmp_path / "zeek", "zeek received the shared base dir"
    assert carve_dir != tmp_path / "carved", "carve received the shared base dir"
    assert zeek_dir.parent == tmp_path / "zeek", "zeek dir is not an immediate subdir of the base"
    assert carve_dir.parent == tmp_path / "carved", "carve dir is not an immediate subdir of the base"
    # Both stages share the same run id so artifacts of one run can be correlated on disk
    assert zeek_dir.name == carve_dir.name
    assert "case01" in zeek_dir.name


def test_run_pipeline_per_run_dirs_unique_for_same_case(monkeypatch, tmp_path):
    """Two runs with the same case_id must not share output dirs (re-runs / concurrent jobs)."""
    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import run_pipeline

    captured = _stub_stage_dirs(monkeypatch, tmp_path)
    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    for _ in range(2):
        run_pipeline(
            pcap_path=str(pcap),
            case_id="same_case",
            options=_zeek_carve_only_options(),
            progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
        )

    assert captured["zeek_dirs"][0] != captured["zeek_dirs"][1]
    assert captured["carve_dirs"][0] != captured["carve_dirs"][1]


def test_run_pipeline_run_dir_is_path_safe_for_hostile_case_id(monkeypatch, tmp_path):
    """A hostile case_id (path traversal) must not escape the configured base dir."""
    import pathlib

    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import run_pipeline

    captured = _stub_stage_dirs(monkeypatch, tmp_path)
    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    run_pipeline(
        pcap_path=str(pcap),
        case_id="../../evil/../escape",
        options=_zeek_carve_only_options(),
        progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
    )

    zeek_base = (tmp_path / "zeek").resolve()
    zeek_dir = pathlib.Path(captured["zeek_dirs"][0]).resolve()
    assert zeek_dir.is_relative_to(zeek_base), f"run dir escaped base: {zeek_dir}"
    assert zeek_dir != zeek_base


def test_run_pipeline_records_zeek_log_paths(monkeypatch, tmp_path):
    """The actual zeek log paths must be exposed on the result so consumers (JA3
    extraction in main.py) stop reconstructing them from the shared base dir."""
    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import PipelineResult, run_pipeline

    log_path = str(tmp_path / "d.log")
    captured = _stub_stage_dirs(monkeypatch, tmp_path, zeek_logs={"dns.log": log_path})
    assert captured is not None
    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    result = run_pipeline(
        pcap_path=str(pcap),
        case_id="logpaths",
        options=_zeek_carve_only_options(),
        progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
    )

    assert result.zeek_log_paths == {"dns.log": log_path}
    # Default stays empty when zeek produced nothing
    assert PipelineResult().zeek_log_paths == {}


def test_prune_stale_run_dirs_removes_only_old_dirs(tmp_path):
    """Run dirs older than the retention window are removed; fresh dirs and loose files stay."""
    import os
    import time

    from app.pipeline.runner import _prune_stale_run_dirs

    old_dir = tmp_path / "old_run"
    old_dir.mkdir()
    (old_dir / "conn.log").write_text("stale")
    stale_ts = time.time() - 8 * 24 * 3600
    os.utime(old_dir, (stale_ts, stale_ts))

    fresh_dir = tmp_path / "fresh_run"
    fresh_dir.mkdir()

    loose_file = tmp_path / "legacy.log"
    loose_file.write_text("flat-layout leftover")
    os.utime(loose_file, (stale_ts, stale_ts))

    _prune_stale_run_dirs(tmp_path, max_age_seconds=7 * 24 * 3600)

    assert not old_dir.exists(), "stale run dir not pruned"
    assert fresh_dir.exists(), "fresh run dir must be retained"
    assert loose_file.exists(), "loose files must not be touched"


def test_run_pipeline_prunes_stale_run_dirs(monkeypatch, tmp_path):
    """run_pipeline prunes expired run dirs under both base dirs on entry."""
    import os
    import time

    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import run_pipeline

    _stub_stage_dirs(monkeypatch, tmp_path)
    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"")

    stale_ts = time.time() - 8 * 24 * 3600
    stale_dirs = []
    for base in (tmp_path / "zeek", tmp_path / "carved"):
        stale = base / "ancient_run"
        stale.mkdir()
        os.utime(stale, (stale_ts, stale_ts))
        stale_dirs.append(stale)

    run_pipeline(
        pcap_path=str(pcap),
        case_id="prune_test",
        options=_zeek_carve_only_options(),
        progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
    )

    for stale in stale_dirs:
        assert not stale.exists(), f"stale run dir survived: {stale}"


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
