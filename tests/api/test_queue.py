# tests/api/test_queue.py
"""Tests for the JobQueue interface and InProcessJobQueue."""

from __future__ import annotations

import pathlib
import time
from datetime import datetime, timedelta

import pytest

from app.api.queue import (
    InProcessJobQueue,
    JobQueue,
    JobSubmission,
    QueueFullError,
    cancel_queued_job,
    recover_stale_running_jobs,
)
from app.database.models import Case, Job, JobStatus
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
                    "llm_enabled": False,
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
