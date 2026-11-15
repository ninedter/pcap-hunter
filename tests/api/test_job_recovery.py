"""Restart recovery for the in-process job queue.

Every test drives the real ``CaseRepository`` against a temp SQLite file; only
the worker pool (a real ``ProcessPoolExecutor``) and the pipeline are stubbed.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from datetime import datetime, timedelta

import pytest

import app.api.queue as queue_mod
from app.api.queue import (
    ERROR_INPUT_MISSING,
    ERROR_INTERRUPTED_RESTART,
    InProcessJobQueue,
    JobSubmission,
    _JobHeartbeat,
    _worker_run,
    job_sweep_loop,
    parse_owner_token,
    process_owner_token,
    recover_jobs_at_boot,
    recover_stale_running_jobs,
    redispatch_orphaned_queued_jobs,
    set_process_role,
)
from app.database.models import Analysis, Case, Job, JobStatus
from app.database.repository import CaseRepository


@pytest.fixture(autouse=True)
def _restore_process_role():
    original = queue_mod._process_role
    yield
    queue_mod._process_role = original


@pytest.fixture
def repo(tmp_path) -> CaseRepository:
    return CaseRepository(db_path=str(tmp_path / "jobs.db"))


def _token(role: str, pid: int, boot: str = "oldboot00000") -> str:
    host = parse_owner_token(process_owner_token()).host
    return f"{role}@{host}:{pid}:{boot}"


def _dead_pid() -> int:
    """A pid that is certainly not running: a child we already reaped."""
    import subprocess
    import sys

    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    return child.pid


def _job(repo: CaseRepository, *, pcap: str, owner: str | None, options: dict | None = None) -> str:
    case_id = repo.create_case(Case(title="T"))
    return repo.create_job(
        Job(case_id=case_id, pcap_path=pcap, options_json=json.dumps(options or {}), owner_token=owner)
    )


def _set_heartbeat(repo: CaseRepository, job_id: str, age_seconds: float) -> None:
    stamp = (datetime.now() - timedelta(seconds=age_seconds)).isoformat()
    with repo._get_conn() as conn:
        conn.execute("UPDATE jobs SET heartbeat_at=? WHERE id=?", (stamp, job_id))
        conn.commit()


class _RecordingQueue:
    """Stands in for the worker pool: records dispatches instead of forking."""

    def __init__(self) -> None:
        self.dispatched: list[str] = []

    def dispatch(self, job_id: str) -> None:
        self.dispatched.append(job_id)


# ── (a) heartbeat for the whole life of a job ────────────────────────────────


def test_heartbeat_thread_keeps_a_silent_stage_fresh(repo):
    """A stage that never reports progress must not let the heartbeat go stale."""
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id)
    _set_heartbeat(repo, job_id, age_seconds=600)
    assert [job.id for job in repo.find_stale_running_jobs(stale_after_seconds=120)] == [job_id]

    with _JobHeartbeat(repo, job_id, interval=0.05):
        deadline = time.monotonic() + 5
        while repo.find_stale_running_jobs(stale_after_seconds=120) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert repo.find_stale_running_jobs(stale_after_seconds=120) == []
        assert recover_stale_running_jobs(repo, stale_after_seconds=120) == 0

    assert repo.get_job(job_id).status == JobStatus.RUNNING


def test_heartbeat_thread_stops_with_the_job(repo):
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id)
    heartbeat = _JobHeartbeat(repo, job_id, interval=0.05)
    with heartbeat:
        assert repo.complete_job(job_id, b"{}")
        heartbeat._thread.join(timeout=5)
        assert not heartbeat._thread.is_alive(), "a terminal job needs no heartbeat"
    assert repo.touch_job_heartbeat(job_id) is False


def test_worker_beats_while_the_pipeline_is_silent(repo, tmp_path, monkeypatch):
    """_worker_run itself must run the timer: the fake pipeline never calls its heartbeat hook."""
    import app.pipeline.runner as runner_mod
    from app.pipeline.runner import PipelineResult

    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    job_id = _job(repo, pcap=str(pcap), owner=None)
    monkeypatch.setattr(queue_mod, "HEARTBEAT_INTERVAL_SECONDS", 0.05)
    seen: list[bool] = []

    def silent_pipeline(pcap_path, case_id, options, progress, heartbeat=None):
        _set_heartbeat(repo, job_id, age_seconds=600)
        deadline = time.monotonic() + 5
        while repo.find_stale_running_jobs(stale_after_seconds=120) and time.monotonic() < deadline:
            time.sleep(0.02)
        seen.append(repo.find_stale_running_jobs(stale_after_seconds=120) == [])
        return PipelineResult(case_id=case_id, features={"flows": [], "artifacts": {}})

    monkeypatch.setattr(runner_mod, "run_pipeline", silent_pipeline)
    _worker_run(job_id, str(repo._db_path), str(pcap), {"osint_enabled": False, "do_yara": False}, "web@h:1:b")

    assert seen == [True]
    job = repo.get_job(job_id)
    assert job.status == JobStatus.DONE
    assert job.owner_token == "web@h:1:b"


# ── (b) ownership: only fail what is provably dead ───────────────────────────


def test_boot_fails_running_job_of_previous_boot_even_with_fresh_heartbeat(repo):
    """restart: unless-stopped brings the process back in seconds - the heartbeat still looks fresh."""
    set_process_role("web")
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", os.getpid()))  # same pid, older boot
    repo.touch_job_heartbeat(job_id)

    stats = recover_jobs_at_boot(repo, lambda: pytest.fail("no dispatch expected"), role="web")

    assert stats["failed_running"] == 1
    job = repo.get_job(job_id)
    assert (job.status, job.error_code) == (JobStatus.FAILED, ERROR_INTERRUPTED_RESTART)


def test_boot_fails_running_job_whose_owner_process_is_gone(repo):
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", _dead_pid()))
    repo.touch_job_heartbeat(job_id)

    assert recover_jobs_at_boot(repo, _RecordingQueue, role="web")["failed_running"] == 1
    assert repo.get_job(job_id).status == JobStatus.FAILED


def test_boot_leaves_the_other_services_live_job_alone(repo):
    """UI and API share one database: restarting the API must not fail the UI's running job."""
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    # Same host and even the same pid number (both containers pin one hostname) - only the role differs.
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", os.getpid()))
    repo.touch_job_heartbeat(job_id)

    stats = recover_jobs_at_boot(repo, _RecordingQueue, role="api")

    assert stats == {"failed_running": 0, "redispatched": 0, "failed_missing_input": 0}
    assert repo.get_job(job_id).status == JobStatus.RUNNING


def test_boot_leaves_a_live_sibling_process_alone(repo):
    """Another live process of the same role (different pid, still running) keeps its job."""
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", os.getppid()))
    repo.touch_job_heartbeat(job_id)

    assert recover_jobs_at_boot(repo, _RecordingQueue, role="web")["failed_running"] == 0
    assert repo.get_job(job_id).status == JobStatus.RUNNING


def test_other_services_job_is_failed_once_its_heartbeat_is_genuinely_stale(repo):
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", os.getpid()))
    _set_heartbeat(repo, job_id, age_seconds=600)

    assert recover_jobs_at_boot(repo, _RecordingQueue, role="api")["failed_running"] == 1
    assert repo.get_job(job_id).error_code == ERROR_INTERRUPTED_RESTART


def test_legacy_running_row_without_owner_uses_heartbeat_only(repo):
    fresh = _job(repo, pcap="/tmp/a.pcap", owner=None)
    stale = _job(repo, pcap="/tmp/b.pcap", owner=None)
    for job_id in (fresh, stale):
        assert repo.start_job_if_queued(job_id)
    _set_heartbeat(repo, stale, age_seconds=600)

    assert recover_jobs_at_boot(repo, _RecordingQueue, role="web")["failed_running"] == 1
    assert repo.get_job(fresh).status == JobStatus.RUNNING
    assert repo.get_job(stale).status == JobStatus.FAILED


def test_agent_jobs_are_never_touched(repo, tmp_path):
    running = _job(repo, pcap="/tmp/a.pcap", owner=None, options={"_agent_id": "agent-1"})
    queued = _job(repo, pcap=str(tmp_path / "gone.pcap"), owner=None, options={"_agent_id": "agent-1"})
    assert repo.start_job_if_queued(running)
    _set_heartbeat(repo, running, age_seconds=600)
    queue = _RecordingQueue()

    stats = recover_jobs_at_boot(repo, lambda: queue, role="api")

    assert stats == {"failed_running": 0, "redispatched": 0, "failed_missing_input": 0}
    assert queue.dispatched == []
    assert repo.get_job(running).status == JobStatus.RUNNING
    assert repo.get_job(queued).status == JobStatus.QUEUED


# ── (c) periodic sweep ───────────────────────────────────────────────────────


def test_periodic_sweep_fails_a_job_that_goes_stale_after_boot(repo):
    """The boot sweep saw a fresh heartbeat; the loop must catch it once it really is stale."""
    set_process_role("api")
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", os.getpid()))
    repo.touch_job_heartbeat(job_id)
    assert recover_jobs_at_boot(repo, _RecordingQueue, role="api")["failed_running"] == 0

    async def run_loop() -> None:
        task = asyncio.create_task(job_sweep_loop(repo, interval_seconds=0.02, stale_after_seconds=120))
        try:
            await asyncio.sleep(0.1)
            assert repo.get_job(job_id).status == JobStatus.RUNNING, "fresh job survives sweeps"
            _set_heartbeat(repo, job_id, age_seconds=600)
            for _ in range(200):
                if repo.get_job(job_id).status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.02)
        finally:
            task.cancel()

    asyncio.run(run_loop())
    job = repo.get_job(job_id)
    assert (job.status, job.error_code) == (JobStatus.FAILED, ERROR_INTERRUPTED_RESTART)


def test_sweep_does_not_fail_a_job_that_beat_between_read_and_write(repo, monkeypatch):
    """The stale check is repeated inside the UPDATE, so a heartbeat landing mid-sweep wins."""
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id)
    _set_heartbeat(repo, job_id, age_seconds=600)
    original = repo.list_jobs

    def list_then_beat(**kwargs):
        rows = original(**kwargs)
        repo.touch_job_heartbeat(job_id)
        return rows

    monkeypatch.setattr(repo, "list_jobs", list_then_beat)
    assert recover_stale_running_jobs(repo, stale_after_seconds=120) == 0
    assert repo.get_job(job_id).status == JobStatus.RUNNING


# ── (d) orphaned queued jobs ─────────────────────────────────────────────────


def test_boot_redispatches_orphaned_queued_jobs_and_fails_missing_inputs(repo, tmp_path):
    present = tmp_path / "present.pcap"
    present.write_bytes(b"\xd4\xc3\xb2\xa1")
    old_owner = _token("web", os.getpid())
    first = _job(repo, pcap=str(present), owner=old_owner)
    legacy = _job(repo, pcap=str(present), owner=None)
    gone = _job(repo, pcap=str(tmp_path / "deleted.pcap"), owner=old_owner)
    queue = _RecordingQueue()

    stats = recover_jobs_at_boot(repo, lambda: queue, role="web")

    assert stats == {"failed_running": 0, "redispatched": 2, "failed_missing_input": 1}
    assert queue.dispatched == [first, legacy], "oldest first"
    for job_id in (first, legacy):
        job = repo.get_job(job_id)
        assert job.status == JobStatus.QUEUED
        assert job.owner_token == process_owner_token(), "adopted by this boot"
    failed = repo.get_job(gone)
    assert (failed.status, failed.error_code) == (JobStatus.FAILED, ERROR_INPUT_MISSING)
    assert "resubmit" in failed.error_detail

    # A second pass in the same boot has nothing left to adopt.
    assert redispatch_orphaned_queued_jobs(repo, lambda: queue) == (0, 0)
    assert queue.dispatched == [first, legacy]


def test_boot_does_not_adopt_queued_jobs_of_other_owners(repo, tmp_path):
    present = tmp_path / "present.pcap"
    present.write_bytes(b"\xd4\xc3\xb2\xa1")
    other_service = _job(repo, pcap=str(present), owner=_token("api", os.getpid()))
    live_sibling = _job(repo, pcap=str(present), owner=_token("web", os.getppid()))
    streamlit = _job(repo, pcap=str(tmp_path / "missing.pcap"), owner=_token("local", os.getpid()))
    queue = _RecordingQueue()

    stats = recover_jobs_at_boot(repo, lambda: queue, role="web")

    assert stats == {"failed_running": 0, "redispatched": 0, "failed_missing_input": 0}
    assert queue.dispatched == []
    for job_id in (other_service, live_sibling, streamlit):
        assert repo.get_job(job_id).status == JobStatus.QUEUED


def test_boot_does_not_build_a_worker_pool_when_nothing_is_orphaned(repo):
    recover_jobs_at_boot(repo, lambda: pytest.fail("worker pool must stay lazy"), role="web")


def test_report_only_job_is_redispatched_when_its_analysis_exists(repo):
    case_id = repo.create_case(Case(title="T"))
    analysis_id = repo.save_analysis(Analysis(case_id=case_id, pcap_path="x.pcap"))
    owner = _token("web", os.getpid())
    kept = repo.create_job(
        Job(
            case_id=case_id,
            pcap_path=analysis_id,  # not a file: report jobs read the saved analysis
            options_json=json.dumps({"_job_type": "llm_report", "_analysis_id": analysis_id}),
            owner_token=owner,
        )
    )
    lost = repo.create_job(
        Job(
            case_id=case_id,
            pcap_path="missing",
            options_json=json.dumps({"_job_type": "llm_report", "_analysis_id": "nope"}),
            owner_token=owner,
        )
    )
    queue = _RecordingQueue()

    stats = recover_jobs_at_boot(repo, lambda: queue, role="web")

    assert (stats["redispatched"], stats["failed_missing_input"]) == (1, 1)
    assert queue.dispatched == [kept]
    assert repo.get_job(lost).error_code == ERROR_INPUT_MISSING


def test_two_booting_processes_adopt_a_legacy_queued_job_once(repo, tmp_path):
    present = tmp_path / "present.pcap"
    present.write_bytes(b"\xd4\xc3\xb2\xa1")
    job_id = _job(repo, pcap=str(present), owner=None)
    assert repo.claim_queued_job(job_id, "web@h:1:a", expected_owner=None) is True
    assert repo.claim_queued_job(job_id, "api@h:1:b", expected_owner=None) is False
    assert repo.get_job(job_id).owner_token == "web@h:1:a"


def test_enqueue_records_the_dispatching_process(repo, tmp_path, monkeypatch):
    set_process_role("web")
    queue = InProcessJobQueue(repo=repo, max_workers=1, queue_depth=5)
    submitted: list[tuple] = []
    try:
        monkeypatch.setattr(queue._executor, "submit", lambda *args: submitted.append(args))
        case_id = repo.create_case(Case(title="T"))
        job_id = queue.enqueue(JobSubmission(case_id=case_id, pcap_path=str(tmp_path / "x.pcap"), options={}))
    finally:
        queue.shutdown(wait=False)

    owner = parse_owner_token(repo.get_job(job_id).owner_token)
    assert (owner.role, owner.pid) == ("web", os.getpid())
    assert submitted[0][0] is _worker_run
    assert submitted[0][-1] == process_owner_token(), "the worker is told who owns the job"


def test_dispatch_rebuilds_a_broken_worker_pool(repo, tmp_path):
    from concurrent.futures.process import BrokenProcessPool

    queue = InProcessJobQueue(repo=repo, max_workers=1, queue_depth=5)
    real_executor_cls = queue_mod.ProcessPoolExecutor
    submitted: list[tuple] = []

    class _Broken:
        def submit(self, *args):
            raise BrokenProcessPool("worker died")

        def shutdown(self, wait=True):
            pass

    class _Fresh:
        def __init__(self, max_workers):
            self.max_workers = max_workers

        def submit(self, *args):
            submitted.append(args)

        def shutdown(self, wait=True):
            pass

    queue._executor.shutdown(wait=False)
    queue._executor = _Broken()
    queue_mod.ProcessPoolExecutor = _Fresh
    try:
        job_id = _job(repo, pcap=str(tmp_path / "x.pcap"), owner=None)
        queue.dispatch(job_id)
    finally:
        queue_mod.ProcessPoolExecutor = real_executor_cls
    assert [args[1] for args in submitted] == [job_id]


# ── (e) compare-and-set terminal writes ──────────────────────────────────────


def test_late_done_does_not_resurrect_a_failed_job(repo):
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id)
    assert repo.fail_job_if_active(job_id, ERROR_INTERRUPTED_RESTART, "restarted") is True

    assert repo.complete_job(job_id, b'{"late": true}') is False
    assert repo.update_job_status(job_id, JobStatus.DONE, result_json=b"{}") is False
    assert repo.update_job_status(job_id, JobStatus.RUNNING) is False

    job = repo.get_job(job_id)
    assert (job.status, job.error_code, job.result_json) == (JobStatus.FAILED, ERROR_INTERRUPTED_RESTART, None)


def test_late_failure_does_not_overwrite_done_or_cancelled(repo):
    done = _job(repo, pcap="/tmp/a.pcap", owner=None)
    cancelled = _job(repo, pcap="/tmp/b.pcap", owner=None)
    assert repo.start_job_if_queued(done)
    assert repo.complete_job(done, b'{"ok": true}') is True
    assert repo.cancel_job_if_queued(cancelled) is True

    for job_id in (done, cancelled):
        assert repo.fail_job_if_active(job_id, "pipeline_error", "late") is False
        assert repo.update_job_status(job_id, JobStatus.FAILED, error_code="pipeline_error") is False
        assert repo.complete_job(job_id, b'{"second": true}') is False

    assert repo.get_job(done).status == JobStatus.DONE
    assert json.loads(repo.get_job(done).result_json) == {"ok": True}
    assert repo.get_job(done).error_code is None
    assert repo.get_job(cancelled).status == JobStatus.CANCELLED


def test_worker_finishing_after_recovery_keeps_the_recovered_outcome(repo, tmp_path, monkeypatch):
    """The exact reviewed race: recovery marks the job failed, then the worker reaches its final write."""
    import app.pipeline.runner as runner_mod
    from app.pipeline.runner import PipelineResult

    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    job_id = _job(repo, pcap=str(pcap), owner=None)

    def pipeline_interrupted_by_recovery(pcap_path, case_id, options, progress, heartbeat=None):
        assert repo.fail_job_if_active(job_id, ERROR_INTERRUPTED_RESTART, "restarted")
        return PipelineResult(case_id=case_id, features={"flows": [], "artifacts": {}})

    monkeypatch.setattr(runner_mod, "run_pipeline", pipeline_interrupted_by_recovery)
    _worker_run(job_id, str(repo._db_path), str(pcap), {"osint_enabled": False, "do_yara": False})

    job = repo.get_job(job_id)
    assert (job.status, job.error_code) == (JobStatus.FAILED, ERROR_INTERRUPTED_RESTART)


def test_worker_error_after_cancellation_keeps_the_cancellation(repo, tmp_path, monkeypatch):
    import app.pipeline.runner as runner_mod

    job_id = _job(repo, pcap=str(tmp_path / "x.pcap"), owner=None)

    def cancelled_then_crashes(pcap_path, case_id, options, progress, heartbeat=None):
        with repo._get_conn() as conn:
            conn.execute("UPDATE jobs SET status='cancelled' WHERE id=?", (job_id,))
            conn.commit()
        raise RuntimeError("boom")

    monkeypatch.setattr(runner_mod, "run_pipeline", cancelled_then_crashes)
    _worker_run(job_id, str(repo._db_path), str(tmp_path / "x.pcap"), {})

    job = repo.get_job(job_id)
    assert (job.status, job.error_code) == (JobStatus.CANCELLED, None)


def test_concurrent_terminal_writers_produce_exactly_one_winner(repo):
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id)
    barrier = threading.Barrier(8)
    wins: list[str] = []

    def finish(index: int) -> None:
        barrier.wait()
        if index % 2:
            won = repo.complete_job(job_id, b"{}")
        else:
            won = repo.fail_job_if_active(job_id, "pipeline_error", "x")
        if won:
            wins.append("done" if index % 2 else "failed")

    threads = [threading.Thread(target=finish, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(wins) == 1
    assert repo.get_job(job_id).status.value == wins[0]


# ── schema: existing databases keep working ──────────────────────────────────


def test_owner_column_is_added_to_an_existing_database(tmp_path):
    import sqlite3

    db = tmp_path / "legacy.db"
    CaseRepository(db_path=str(db))
    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE jobs DROP COLUMN owner_token")
    conn.execute(
        "INSERT INTO jobs (id, pcap_path, status, submitted_at, heartbeat_at) VALUES "
        "('j_legacy', '/tmp/x.pcap', 'running', '2026-01-01T00:00:00', '2026-01-01T00:00:00')"
    )
    conn.commit()
    conn.close()

    repo = CaseRepository(db_path=str(db))
    CaseRepository(db_path=str(db))  # idempotent

    job = repo.get_job("j_legacy")
    assert job.owner_token is None
    assert recover_stale_running_jobs(repo, owner_token=process_owner_token()) == 1
    assert repo.get_job("j_legacy").status == JobStatus.FAILED


# ── (f) periodic sweep needs two consecutive stale observations ──────────────


@pytest.fixture
def _clean_observations():
    queue_mod._stale_observed.clear()
    yield
    queue_mod._stale_observed.clear()


def test_periodic_sweep_needs_two_stale_observations_of_the_same_heartbeat(repo, _clean_observations):
    """After a host suspend or clock jump every heartbeat looks stale for one sweep."""
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", os.getpid()))
    _set_heartbeat(repo, job_id, age_seconds=600)

    assert recover_stale_running_jobs(repo, stale_after_seconds=120, confirm_stale=True) == 0
    assert repo.get_job(job_id).status == JobStatus.RUNNING, "one stale sighting is not proof"

    # The worker was only late: its heartbeat moved, although it still looks old
    # to a clock that jumped. That is a new observation, not a confirmation.
    _set_heartbeat(repo, job_id, age_seconds=500)
    assert recover_stale_running_jobs(repo, stale_after_seconds=120, confirm_stale=True) == 0
    assert repo.get_job(job_id).status == JobStatus.RUNNING

    # Unchanged on the next sweep: the worker really is gone.
    assert recover_stale_running_jobs(repo, stale_after_seconds=120, confirm_stale=True) == 1
    job = repo.get_job(job_id)
    assert (job.status, job.error_code) == (JobStatus.FAILED, ERROR_INTERRUPTED_RESTART)
    assert not queue_mod._stale_observed


def test_stale_observation_is_forgotten_once_the_worker_ticks(repo, _clean_observations):
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id)
    _set_heartbeat(repo, job_id, age_seconds=600)
    stale_stamp = repo.get_job(job_id).heartbeat_at.isoformat()
    assert recover_stale_running_jobs(repo, stale_after_seconds=120, confirm_stale=True) == 0

    repo.touch_job_heartbeat(job_id)  # the resumed worker ticks
    assert recover_stale_running_jobs(repo, stale_after_seconds=120, confirm_stale=True) == 0
    assert not queue_mod._stale_observed, "observations must be consecutive"

    # Stale again later with the very same old value: counting starts over.
    with repo._get_conn() as conn:
        conn.execute("UPDATE jobs SET heartbeat_at=? WHERE id=?", (stale_stamp, job_id))
        conn.commit()
    assert recover_stale_running_jobs(repo, stale_after_seconds=120, confirm_stale=True) == 0
    assert repo.get_job(job_id).status == JobStatus.RUNNING


def test_previous_boot_jobs_are_still_failed_immediately_by_a_confirming_sweep(repo, _clean_observations):
    set_process_role("web")
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id, owner_token=_token("web", _dead_pid()))
    repo.touch_job_heartbeat(job_id)

    assert recover_stale_running_jobs(repo, owner_token=process_owner_token(), confirm_stale=True) == 1


def test_boot_recovery_of_a_stale_heartbeat_stays_immediate(repo, _clean_observations):
    job_id = _job(repo, pcap="/tmp/x.pcap", owner=None)
    assert repo.start_job_if_queued(job_id)
    _set_heartbeat(repo, job_id, age_seconds=600)
    assert recover_stale_running_jobs(repo, stale_after_seconds=120) == 1


# ── (g) worker-pool rebuild ──────────────────────────────────────────────────


from concurrent.futures.process import BrokenProcessPool as BrokenProcessPoolError  # noqa: E402


class _BrokenPool:
    def __init__(self) -> None:
        self.shut_down = False

    def submit(self, *args):
        raise BrokenProcessPoolError("worker died")

    def shutdown(self, wait=True):
        self.shut_down = True


def test_pool_rebuild_redispatches_this_process_own_queued_jobs(repo, tmp_path, monkeypatch):
    set_process_role("web")
    present = tmp_path / "present.pcap"
    present.write_bytes(b"\xd4\xc3\xb2\xa1")
    mine = process_owner_token()
    waiting_a = _job(repo, pcap=str(present), owner=mine)  # were waiting inside the dead pool
    waiting_b = _job(repo, pcap=str(present), owner=mine)
    lost_input = _job(repo, pcap=str(tmp_path / "deleted.pcap"), owner=mine)
    other_service = _job(repo, pcap=str(present), owner=_token("api", os.getpid()))
    agent = _job(repo, pcap=str(present), owner=mine, options={"_agent_id": "a_test"})
    running = _job(repo, pcap=str(present), owner=mine)
    assert repo.start_job_if_queued(running, owner_token=mine)
    trigger = _job(repo, pcap=str(present), owner=mine)

    submitted: list[str] = []

    class _Fresh:
        def __init__(self, max_workers):
            pass

        def submit(self, *args):
            submitted.append(args[1])

        def shutdown(self, wait=True):
            pass

    queue = InProcessJobQueue(repo=repo, max_workers=1, queue_depth=50)
    queue._executor.shutdown(wait=False)
    queue._executor = _BrokenPool()
    monkeypatch.setattr(queue_mod, "ProcessPoolExecutor", _Fresh)

    queue.dispatch(trigger)

    assert submitted == [trigger, waiting_a, waiting_b], "the triggering job once, then the stranded ones in order"
    assert repo.get_job(lost_input).error_code == ERROR_INPUT_MISSING
    for untouched in (other_service, agent):
        assert repo.get_job(untouched).status == JobStatus.QUEUED
    assert repo.get_job(running).status == JobStatus.RUNNING
    assert queue._redispatching is False


def test_concurrent_dispatch_never_submits_to_an_executor_another_thread_shut_down(repo, tmp_path, monkeypatch):
    """Rebuild and submit happen under one lock; exactly one rebuild, no lost submission."""
    import threading

    present = tmp_path / "present.pcap"
    present.write_bytes(b"\xd4\xc3\xb2\xa1")
    jobs = [_job(repo, pcap=str(present), owner=None) for _ in range(8)]
    built: list[object] = []
    errors: list[BaseException] = []
    submitted: list[str] = []
    start = threading.Barrier(len(jobs))

    class _Pool:
        def __init__(self, max_workers=1, broken=False):
            self.broken, self.shut_down = broken, False
            if not broken:
                built.append(self)

        def submit(self, *args):
            if self.shut_down:
                raise RuntimeError("cannot schedule new futures after shutdown")
            if self.broken:
                time.sleep(0.01)  # widen the window in which a second thread arrives
                raise BrokenProcessPoolError("worker died")
            submitted.append(args[1])

        def shutdown(self, wait=True):
            time.sleep(0.01)
            self.shut_down = True

    queue = InProcessJobQueue(repo=repo, max_workers=1, queue_depth=50)
    queue._executor.shutdown(wait=False)
    queue._executor = _Pool(broken=True)
    monkeypatch.setattr(queue_mod, "ProcessPoolExecutor", _Pool)

    def dispatch(job_id: str) -> None:
        try:
            start.wait(timeout=5)
            queue.dispatch(job_id)
        except BaseException as error:  # noqa: BLE001 - collected for the assertion below
            errors.append(error)

    threads = [threading.Thread(target=dispatch, args=(job_id,)) for job_id in jobs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    assert len(built) == 1, "one rebuild, not one per thread"
    assert sorted(submitted) == sorted(jobs)
