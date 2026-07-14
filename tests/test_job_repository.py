# tests/test_job_repository.py
"""Tests for Job CRUD operations in the repository."""

from __future__ import annotations

from datetime import datetime, timedelta

from app.database.models import Case, Job, JobStatus, Severity
from app.database.repository import CaseRepository


def _setup_repo(tmp_path) -> CaseRepository:
    return CaseRepository(db_path=str(tmp_path / "t.db"))


def test_create_and_get_job(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T", severity=Severity.MEDIUM))

    job = Job(case_id=case_id, pcap_path="/tmp/x.pcap")
    job_id = repo.create_job(job)
    assert job_id.startswith("j_")

    got = repo.get_job(job_id)
    assert got is not None
    assert got.case_id == case_id
    assert got.status == JobStatus.QUEUED


def test_update_job_status_and_heartbeat(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    repo.update_job_status(job_id, JobStatus.RUNNING)
    repo.touch_job_heartbeat(job_id)
    job = repo.get_job(job_id)
    assert job.status == JobStatus.RUNNING
    assert job.heartbeat_at is not None


def test_update_job_status_done_with_result(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    repo.update_job_status(job_id, JobStatus.RUNNING)
    repo.update_job_status(job_id, JobStatus.DONE, result_json=b'{"ok": true}')
    job = repo.get_job(job_id)
    assert job.status == JobStatus.DONE
    assert job.finished_at is not None


def test_update_job_status_failed_with_error(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    repo.update_job_status(job_id, JobStatus.FAILED, error_code="TIMEOUT", error_detail="Took too long")
    job = repo.get_job(job_id)
    assert job.status == JobStatus.FAILED
    assert job.error_code == "TIMEOUT"
    assert job.error_detail == "Took too long"


def test_update_job_progress(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    repo.update_job_progress(job_id, "zeek", 3, 10)
    job = repo.get_job(job_id)
    assert job.progress_stage == "zeek"
    assert job.progress_done == 3
    assert job.progress_total == 10


def test_find_stale_running_jobs(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)

    # Force a stale heartbeat
    conn = repo._get_conn()
    try:
        old = (datetime.now() - timedelta(minutes=5)).isoformat()
        conn.execute("UPDATE jobs SET heartbeat_at = ? WHERE id = ?", (old, job_id))
        conn.commit()
    finally:
        conn.close()

    stale = repo.find_stale_running_jobs(stale_after_seconds=120)
    assert any(j.id == job_id for j in stale)


def test_find_stale_running_jobs_ignores_fresh(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)
    repo.touch_job_heartbeat(job_id)

    stale = repo.find_stale_running_jobs(stale_after_seconds=120)
    assert not any(j.id == job_id for j in stale)


def test_count_active_jobs(tmp_path):
    repo = _setup_repo(tmp_path)
    case_id = repo.create_case(Case(title="T"))
    repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.create_job(Job(case_id=case_id, pcap_path="/tmp/y.pcap"))
    assert repo.count_active_jobs() == 2

    # Complete one — active count should drop
    conn = repo._get_conn()
    try:
        row = conn.execute("SELECT id FROM jobs LIMIT 1").fetchone()
    finally:
        conn.close()
    repo.update_job_status(row["id"], JobStatus.DONE)
    assert repo.count_active_jobs() == 1


def test_list_jobs_filters_by_case_and_status(tmp_path):
    repo = _setup_repo(tmp_path)
    case_a = repo.create_case(Case(title="A"))
    case_b = repo.create_case(Case(title="B"))
    queued_a = repo.create_job(Job(case_id=case_a, pcap_path="/tmp/a.pcap"))
    done_a = repo.create_job(Job(case_id=case_a, pcap_path="/tmp/b.pcap"))
    repo.create_job(Job(case_id=case_b, pcap_path="/tmp/c.pcap"))
    repo.update_job_status(done_a, JobStatus.DONE)

    jobs = repo.list_jobs(case_id=case_a, statuses=[JobStatus.QUEUED])

    assert [job.id for job in jobs] == [queued_a]
