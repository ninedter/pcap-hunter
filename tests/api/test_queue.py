# tests/api/test_queue.py
"""Tests for the JobQueue interface and InProcessJobQueue."""

from __future__ import annotations

import json
import pathlib
import time
from datetime import datetime, timedelta

import pytest

import app.api.queue as queue_mod
from app.api.queue import (
    WARNING_OSINT_NOT_CONFIGURED,
    WARNING_PERSISTENCE_FAILED,
    WARNING_YARA_FAILED,
    InProcessJobQueue,
    JobQueue,
    JobSubmission,
    QueueFullError,
    _worker_run,
    cancel_queued_job,
    recover_stale_running_jobs,
)
from app.database.models import Analysis, Case, CaseStatus, Job, JobStatus, Severity
from app.database.repository import CaseRepository


def test_jobqueue_is_abstract():
    assert hasattr(JobQueue, "enqueue")
    assert hasattr(JobQueue, "shutdown")


def test_job_submission_has_required_fields():
    sub = JobSubmission(
        case_id="abc12345",
        pcap_path="/tmp/x.pcap",
        options={"osint_enabled": True},
    )
    assert sub.case_id == "abc12345"
    assert sub.options["osint_enabled"] is True


FIXTURE_PCAP = pathlib.Path(__file__).parent.parent / "fixtures" / "tiny.pcap"


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason="tests/fixtures/tiny.pcap not present")
def test_inprocess_queue_runs_a_job(tmp_path):
    """Submit a real (tiny) pcap through the queue and verify the job lands in DONE."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))

    queue = InProcessJobQueue(repo=repo, max_workers=1, queue_depth=10)
    try:
        job_id = queue.enqueue(
            JobSubmission(
                case_id=case_id,
                pcap_path=str(FIXTURE_PCAP),
                options={
                    "osint_enabled": False,
                    "do_yara": False,
                    "do_carve": False,
                    "pyshark_packet_limit": 50,
                },
            )
        )

        deadline = time.time() + 60
        while time.time() < deadline:
            j = repo.get_job(job_id)
            if j and j.status in (JobStatus.DONE, JobStatus.FAILED):
                break
            time.sleep(0.5)

        j = repo.get_job(job_id)
        assert j.status == JobStatus.DONE, f"expected DONE, got {j.status}: {j.error_detail}"
    finally:
        queue.shutdown(wait=True)


def test_inprocess_queue_rejects_when_full(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))

    queue = InProcessJobQueue(repo=repo, max_workers=1, queue_depth=1)
    try:
        # Pre-fill with a queued job
        repo.create_job(Job(case_id=case_id, pcap_path="/tmp/dummy.pcap"))

        with pytest.raises(QueueFullError):
            queue.enqueue(JobSubmission(case_id=case_id, pcap_path="/tmp/dummy2.pcap"))
    finally:
        queue.shutdown(wait=False)


def test_recover_stale_running_jobs_marks_them_failed(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)

    # Force stale heartbeat
    conn = repo._get_conn()
    try:
        old = (datetime.now() - timedelta(minutes=5)).isoformat()
        conn.execute("UPDATE jobs SET heartbeat_at=? WHERE id=?", (old, job_id))
        conn.commit()
    finally:
        conn.close()

    n = recover_stale_running_jobs(repo, stale_after_seconds=120)
    assert n == 1

    j = repo.get_job(job_id)
    assert j.status == JobStatus.FAILED
    assert j.error_code == "interrupted_restart"


def test_recover_stale_does_nothing_for_fresh_jobs(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)
    repo.touch_job_heartbeat(job_id)

    n = recover_stale_running_jobs(repo, stale_after_seconds=120)
    assert n == 0

    j = repo.get_job(job_id)
    assert j.status == JobStatus.RUNNING


def test_cancel_queued_job(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    ok = cancel_queued_job(repo, job_id)
    assert ok is True

    j = repo.get_job(job_id)
    assert j.status == JobStatus.CANCELLED


def test_cancel_running_job_returns_false(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)

    ok = cancel_queued_job(repo, job_id)
    assert ok is False
    assert repo.get_job(job_id).status == JobStatus.RUNNING


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason="tiny.pcap fixture missing")
def test_worker_persists_analysis_and_iocs(tmp_path):
    """_worker_run must save an Analysis row + IOCs and fill analysis_id in the blob."""
    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0001", title="persist-test", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0001", pcap_path=str(FIXTURE_PCAP), options_json="{}"))

    _worker_run(job_id, db, str(FIXTURE_PCAP), {"osint_enabled": False})

    job = repo.get_job(job_id)
    assert job.status.value == "done"
    result = json.loads(job.result_json)
    assert result["analysis_id"], "worker must persist the analysis and report its id"

    analysis = repo.get_analysis(result["analysis_id"])
    assert analysis is not None
    assert analysis.case_id == "cafe0001"
    assert analysis.packet_count == 20
    assert analysis.pcap_hash and len(analysis.pcap_hash) == 64
    assert analysis.features.get("flows"), "features must be persisted"

    case = repo.get_case("cafe0001")
    assert len(case.analyses) == 1, "case must show the persisted analysis"
    # tiny.pcap has 10.0.0.x endpoints -> extract_iocs yields ip IOCs
    assert analysis.iocs, "heuristic IOC extraction must run on the API path"


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason="tiny.pcap fixture missing")
def test_worker_runs_osint_when_enabled(tmp_path, monkeypatch):
    """osint_enabled=True with keys configured must enrich and persist osint."""
    captured = {}

    def fake_enrich(arts, keys, phase=None):
        captured["arts"] = arts
        captured["keys"] = keys
        return {"ips": {"8.8.8.8": {"vt": {}}}, "domains": {}, "ja3": {}}

    monkeypatch.setattr(queue_mod, "osint_enrich", fake_enrich)
    monkeypatch.setattr(queue_mod, "_load_osint_keys", lambda: {"VT_KEY": "x"})
    monkeypatch.setattr(queue_mod, "bulk_resolve_ips", lambda ips, max_workers=8: {})

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0002", title="osint-test", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0002", pcap_path=str(FIXTURE_PCAP), options_json="{}"))

    _worker_run(job_id, db, str(FIXTURE_PCAP), {"osint_enabled": True})

    job = repo.get_job(job_id)
    result = json.loads(job.result_json)
    assert "osint" in result["stages_run"]
    assert captured["keys"] == {"VT_KEY": "x"}, "worker must pass the loaded provider keys to enrich"
    analysis = repo.get_analysis(result["analysis_id"])
    assert analysis.osint.get("ips") == {"8.8.8.8": {"vt": {}}}


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason="tiny.pcap fixture missing")
def test_worker_warns_when_osint_enabled_but_unconfigured(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_mod, "_load_osint_keys", lambda: {})

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0003", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0003", pcap_path=str(FIXTURE_PCAP), options_json="{}"))

    _worker_run(job_id, db, str(FIXTURE_PCAP), {"osint_enabled": True})

    result = json.loads(repo.get_job(job_id).result_json)
    assert WARNING_OSINT_NOT_CONFIGURED in result["warnings"]


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason="tiny.pcap fixture missing")
def test_worker_keeps_job_done_when_persistence_fails(tmp_path, monkeypatch):
    """save_analysis raising must not fail the job: warn + analysis_id stays None."""

    def boom(self, analysis):
        raise RuntimeError("disk full")

    monkeypatch.setattr(CaseRepository, "save_analysis", boom)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0005", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0005", pcap_path=str(FIXTURE_PCAP), options_json="{}"))

    _worker_run(job_id, db, str(FIXTURE_PCAP), {"osint_enabled": False})

    job = repo.get_job(job_id)
    assert job.status == JobStatus.DONE
    result = json.loads(job.result_json)
    assert result["analysis_id"] is None
    assert WARNING_PERSISTENCE_FAILED in result["warnings"]


def test_worker_beacon_records_round_trip(tmp_path, monkeypatch):
    """beacon_df_records must survive persistence into features['beacon_records']."""
    import app.pipeline.runner as runner_mod
    from app.pipeline.runner import PipelineResult

    records = [{"src": "10.0.0.1", "dst": "8.8.8.8", "score": 0.9}]

    def fake_run_pipeline(pcap_path, case_id, options, progress, heartbeat=None):
        return PipelineResult(
            case_id=case_id,
            packet_count=1,
            features={
                "flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "TCP", "count": 9}],
                "artifacts": {"ips": ["10.0.0.1", "8.8.8.8"], "domains": [], "urls": [], "hashes": [], "ja3": []},
            },
            beacon_df_records=list(records),
            zeek_tables={"conn": [{"uid": "x"}]},
        )

    # _worker_run imports run_pipeline from app.pipeline.runner at call time,
    # so the patch must target the source module, not queue_mod.
    monkeypatch.setattr(runner_mod, "run_pipeline", fake_run_pipeline)

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0006", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0006", pcap_path=str(fake_pcap), options_json="{}"))

    _worker_run(job_id, db, str(fake_pcap), {"osint_enabled": False})

    result = json.loads(repo.get_job(job_id).result_json)
    assert result["analysis_id"], "persistence must succeed with the faked pipeline result"
    assert result["capture_metrics"]["detectors"]["zeek"] == "available"
    persisted = repo.get_analysis(result["analysis_id"])
    assert persisted.features["beacon_records"] == records
    assert persisted.session_artifacts["beacon_records"] == records
    assert persisted.session_artifacts["zeek_tables"] == {"conn": [{"uid": "x"}]}


def test_worker_llm_opt_in_persists_report(tmp_path, monkeypatch):
    """Streamlit background jobs keep the LLM result outside Session State."""
    import app.llm.providers as provider_mod
    import app.pipeline.runner as runner_mod
    from app.pipeline.runner import PipelineResult

    def fake_run_pipeline(pcap_path, case_id, options, progress, heartbeat=None):
        return PipelineResult(
            case_id=case_id,
            packet_count=1,
            features={
                "flows": [],
                "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
            },
        )

    monkeypatch.setattr(runner_mod, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(
        queue_mod,
        "_load_llm_settings",
        lambda: ("lmstudio", "http://localhost:1234/v1", "", "test-model", "US English", 32_000, False),
    )
    captured_llm_context = {}

    def fake_synthesize_report(*args, **kwargs):
        captured_llm_context.update(kwargs["context"])
        return "# Durable report"

    monkeypatch.setattr(provider_mod, "synthesize_report", fake_synthesize_report)

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0007", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0007", pcap_path=str(fake_pcap), options_json="{}"))

    _worker_run(
        job_id,
        db,
        str(fake_pcap),
        {"osint_enabled": False, "llm_enabled": True, "do_yara": False},
    )

    result = json.loads(repo.get_job(job_id).result_json)
    persisted = repo.get_analysis(result["analysis_id"])
    assert result["summary_narrative"] == "# Durable report"
    assert persisted.report == "# Durable report"
    assert "llm" in persisted.session_artifacts["pipeline_stages"]
    assert "correlations" in captured_llm_context
    assert "flow_asymmetry" in captured_llm_context
    assert "port_anomalies" in captured_llm_context
    assert "ja3_analysis" in captured_llm_context
    assert captured_llm_context["capture_metrics"]["detectors"]["correlation"] == "available"
    assert "pipeline_warnings" in captured_llm_context


def test_report_only_job_updates_existing_analysis(tmp_path, monkeypatch):
    import app.llm.providers as provider_mod

    monkeypatch.setattr(
        queue_mod,
        "_load_llm_settings",
        lambda: ("lmstudio", "http://localhost:1234/v1", "", "test-model", "US English", 32_000, False),
    )
    monkeypatch.setattr(provider_mod, "synthesize_report", lambda *args, **kwargs: "# Updated report")

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    case_id = repo.create_case(Case(title="report-only", status=CaseStatus.IN_PROGRESS))
    analysis = Analysis(
        case_id=case_id,
        pcap_path=str(fake_pcap),
        features={"flows": [], "artifacts": {"ips": []}},
        report="# Old report",
        session_artifacts={"pipeline_stages": ["pyshark_pass"]},
    )
    analysis_id = repo.save_analysis(analysis)
    options = {
        "_job_type": "llm_report",
        "_analysis_id": analysis_id,
        "llm_enabled": True,
    }
    job_id = repo.create_job(Job(case_id=case_id, pcap_path=str(fake_pcap), options_json=json.dumps(options)))

    _worker_run(job_id, db, str(fake_pcap), options)

    result = json.loads(repo.get_job(job_id).result_json)
    persisted = repo.get_analysis(analysis_id)
    assert result["analysis_id"] == analysis_id
    assert persisted.report == "# Updated report"
    assert persisted.features == {"flows": [], "artifacts": {"ips": []}}
    assert repo.get_case(case_id).analysis_count == 1


# ---------------------------------------------------------------------------
# Task 3: progress reconciliation on completion
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason="tiny.pcap fixture missing")
def test_done_job_reports_complete_progress(tmp_path):
    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0005", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0005", pcap_path=str(FIXTURE_PCAP), options_json="{}"))

    _worker_run(job_id, db, str(FIXTURE_PCAP), {"osint_enabled": False})

    job = repo.get_job(job_id)
    assert job.status.value == "done"
    assert job.progress_done == job.progress_total
    assert job.progress_stage == "Complete"


# ---------------------------------------------------------------------------
# Carry-over A: YARA stage coverage
# ---------------------------------------------------------------------------


def test_worker_runs_yara_when_carved_items_exist(tmp_path, monkeypatch):
    """Worker must call scan_carved_files and persist yara_results when carved_items is non-empty."""
    import app.pipeline.runner as runner_mod
    from app.pipeline.runner import PipelineResult

    carved = [{"path": "x.bin", "sha256": "ab" * 32}]
    yara_call_args = {}

    def fake_run_pipeline(pcap_path, case_id, options, progress, heartbeat=None):
        return PipelineResult(
            case_id=case_id,
            packet_count=1,
            features={
                "flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "TCP", "count": 9}],
                "artifacts": {"ips": ["10.0.0.1", "8.8.8.8"], "domains": [], "urls": [], "hashes": [], "ja3": []},
            },
            carved_items=list(carved),
        )

    def fake_scan(items, rules_dirs=None):
        yara_call_args["items"] = items
        return {"matches": [], "scanned": 1}

    monkeypatch.setattr(runner_mod, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr("app.pipeline.yara_scan.scan_carved_files", fake_scan)

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0010", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0010", pcap_path=str(fake_pcap), options_json="{}"))

    _worker_run(job_id, db, str(fake_pcap), {"osint_enabled": False, "do_yara": True})

    result = json.loads(repo.get_job(job_id).result_json)
    assert "yara_scan" in result["stages_run"], "yara_scan must be recorded in stages_run"
    assert yara_call_args.get("items") == carved, "scan_carved_files must receive the carved_items list"
    analysis = repo.get_analysis(result["analysis_id"])
    assert analysis.yara_results == {"matches": [], "scanned": 1}


def test_worker_yara_failure_degrades_to_warning(tmp_path, monkeypatch):
    """A crash in scan_carved_files must not fail the job — warn + yara_results stays None."""
    import app.pipeline.runner as runner_mod
    from app.pipeline.runner import PipelineResult

    carved = [{"path": "x.bin", "sha256": "ab" * 32}]

    def fake_run_pipeline(pcap_path, case_id, options, progress, heartbeat=None):
        return PipelineResult(
            case_id=case_id,
            packet_count=1,
            features={
                "flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "TCP", "count": 9}],
                "artifacts": {"ips": ["10.0.0.1", "8.8.8.8"], "domains": [], "urls": [], "hashes": [], "ja3": []},
            },
            carved_items=list(carved),
        )

    def fake_scan_boom(items, rules_dirs=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(runner_mod, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr("app.pipeline.yara_scan.scan_carved_files", fake_scan_boom)

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0011", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0011", pcap_path=str(fake_pcap), options_json="{}"))

    _worker_run(job_id, db, str(fake_pcap), {"osint_enabled": False, "do_yara": True})

    job = repo.get_job(job_id)
    assert job.status.value == "done", "job must remain done despite YARA failure"
    result = json.loads(job.result_json)
    assert WARNING_YARA_FAILED in result["warnings"]
    analysis = repo.get_analysis(result["analysis_id"])
    assert analysis.yara_results is None


# ---------------------------------------------------------------------------
# Task 5b: worker cancel guard
# ---------------------------------------------------------------------------


def _instrumented_pipeline(calls: dict):
    """Build a run_pipeline stand-in that records invocation (production-shape result)."""
    from app.pipeline.runner import PipelineResult

    def fake_run_pipeline(pcap_path, case_id, options, progress, heartbeat=None):
        calls["ran"] = True
        return PipelineResult(
            case_id=case_id,
            packet_count=1,
            features={
                "flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "TCP", "count": 9}],
                "artifacts": {"ips": ["10.0.0.1", "8.8.8.8"], "domains": [], "urls": [], "hashes": [], "ja3": []},
            },
        )

    return fake_run_pipeline


def test_worker_skips_cancelled_job(tmp_path, monkeypatch):
    """A job cancelled between enqueue and execution must not run the pipeline."""
    import app.pipeline.runner as runner_mod

    calls: dict = {}
    monkeypatch.setattr(runner_mod, "run_pipeline", _instrumented_pipeline(calls))

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0020", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0020", pcap_path=str(fake_pcap), options_json="{}"))
    assert cancel_queued_job(repo, job_id) is True

    _worker_run(job_id, db, str(fake_pcap), {"osint_enabled": False})

    job = repo.get_job(job_id)
    assert job.status == JobStatus.CANCELLED, f"cancelled job must stay cancelled, got {job.status.value}"
    assert "ran" not in calls, "pipeline must not run for a cancelled job"
    assert repo.get_case("cafe0020").analyses == [], "no analysis may be persisted for a cancelled job"


def test_worker_skips_deleted_job(tmp_path, monkeypatch):
    """delete_case explicitly deletes the job row (FK pragma is off, so nothing
    cascades) — the already-submitted future must no-op."""
    import app.pipeline.runner as runner_mod

    calls: dict = {}
    monkeypatch.setattr(runner_mod, "run_pipeline", _instrumented_pipeline(calls))

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0021", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0021", pcap_path=str(fake_pcap), options_json="{}"))
    assert repo.delete_case("cafe0021") is True

    _worker_run(job_id, db, str(fake_pcap), {"osint_enabled": False})

    assert repo.get_job(job_id) is None, "the explicitly-deleted job row must stay gone"
    assert "ran" not in calls, "pipeline must not run for a deleted job"
    conn = repo._get_conn()
    try:
        orphans = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        assert orphans == 0, "no orphan analysis may be created for a deleted case"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Task 8b: CAS status transitions + atomic finalize
# ---------------------------------------------------------------------------


def test_start_job_if_queued_flips_exactly_once(tmp_path):
    """The CAS RUNNING flip succeeds once on a queued job and loses thereafter."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    assert repo.start_job_if_queued(job_id) is True
    j = repo.get_job(job_id)
    assert j.status == JobStatus.RUNNING
    assert j.started_at is not None
    assert j.heartbeat_at is not None

    # A second contender loses: the job is no longer queued.
    assert repo.start_job_if_queued(job_id) is False
    assert repo.get_job(job_id).status == JobStatus.RUNNING


def test_start_job_if_queued_false_on_cancelled(tmp_path):
    """A job cancelled before the flip must stay cancelled — the flip loses."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    assert repo.cancel_job_if_queued(job_id) is True

    assert repo.start_job_if_queued(job_id) is False
    assert repo.get_job(job_id).status == JobStatus.CANCELLED


def test_start_job_if_queued_false_on_missing(tmp_path):
    """A deleted/never-created job id must not be resurrected by the flip."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    assert repo.start_job_if_queued("j_missing0") is False


def test_cancel_job_if_queued_false_on_running(tmp_path):
    """Cancel-if-queued must lose against a job that already started."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    assert repo.start_job_if_queued(job_id) is True

    assert repo.cancel_job_if_queued(job_id) is False
    assert repo.get_job(job_id).status == JobStatus.RUNNING


def test_cancel_job_if_queued_false_on_missing(tmp_path):
    """cancel_queued_job must return False (not raise) for a nonexistent job id."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    ok = cancel_queued_job(repo, "j_nonexistent_99")
    assert ok is False


def test_complete_job_noop_on_deleted_row(tmp_path):
    """complete_job on a nonexistent job id must not raise; the jobs table stays empty."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    # Must not raise even when the row is gone.
    repo.complete_job("j_ghost_00", b'{"ok": true}')
    conn = repo._get_conn()
    try:
        count = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    finally:
        conn.close()
    assert count == 0


def test_complete_job_sets_done_and_reconciles_progress(tmp_path):
    """complete_job must finalize status, result, and progress in one write."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    assert repo.start_job_if_queued(job_id) is True
    repo.update_job_progress(job_id, "Parsing", 5, 10)

    repo.complete_job(job_id, b'{"ok": true}')

    j = repo.get_job(job_id)
    assert j.status == JobStatus.DONE
    assert j.finished_at is not None
    assert json.loads(j.result_json) == {"ok": True}
    assert j.progress_stage == "Complete"
    assert j.progress_done == j.progress_total == 10
