# tests/api/test_jobs.py
"""Tests for GET /api/v1/jobs/{id} and /result endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client_with_job(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_queue, get_repo, get_settings

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()

    from app.api.app import create_app
    from app.api.deps import get_repo as _get_repo
    from app.database.models import Case, Job

    app = create_app()
    repo = _get_repo()
    case_id = repo.create_case(Case(title="t"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    yield TestClient(app), job_id, case_id

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


def test_get_job_returns_status(client_with_job):
    client, job_id, case_id = client_with_job
    r = client.get(f"/api/v1/jobs/{job_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200
    body = r.json()
    assert body["job_id"] == job_id
    assert body["case_id"] == case_id
    assert body["status"] == "queued"


def test_get_unknown_job_returns_404(client_with_job):
    client, *_ = client_with_job
    r = client.get("/api/v1/jobs/j_doesnotex", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404


def test_get_result_returns_409_when_not_done(client_with_job):
    client, job_id, _ = client_with_job
    r = client.get(f"/api/v1/jobs/{job_id}/result", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "result_not_ready"
    assert body["current_status"] == "queued"


def test_job_to_response_done_percent_is_100():
    from datetime import datetime

    from app.api.routers.jobs import _job_to_response
    from app.database.models import Job, JobStatus

    job = Job(
        case_id="c1",
        pcap_path="x.pcap",
        status=JobStatus.DONE,
        progress_stage="Complete",
        progress_done=10,
        progress_total=10,
        submitted_at=datetime.now(),
    )
    job.id = "j_test"
    resp = _job_to_response(job)
    assert resp.progress.percent == 100
    assert resp.progress.stage == "Complete"


def test_job_to_response_includes_active_stage_progress():
    from app.api.routers.jobs import _job_to_response
    from app.database.models import Job, JobStatus

    job = Job(
        id="j_partial",
        case_id="case-1",
        pcap_path="/tmp/x.pcap",
        status=JobStatus.RUNNING,
        progress_stage="OSINT enrichment",
        progress_done=8,
        progress_total=10,
        progress_percent=50,
    )

    resp = _job_to_response(job)
    assert resp.progress.percent == 85
    assert resp.progress.stage == "OSINT enrichment"
