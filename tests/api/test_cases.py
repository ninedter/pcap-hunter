# tests/api/test_cases.py
"""Tests for GET/DELETE /api/v1/cases/{id} and /report.pdf endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_queue, get_repo, get_settings

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()

    from app.api.app import create_app

    yield TestClient(create_app())

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


def test_get_case_returns_dict(client):
    from app.api.deps import get_repo
    from app.database.models import Case

    case_id = get_repo().create_case(Case(title="x"))

    r = client.get(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == case_id
    assert body["title"] == "x"


def test_get_unknown_case_returns_404(client):
    r = client.get("/api/v1/cases/zzzz9999", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404


def test_report_pdf_returns_404_when_missing(client):
    from app.api.deps import get_repo
    from app.database.models import Case

    case_id = get_repo().create_case(Case(title="x"))

    r = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404


def test_delete_case_no_job(client):
    from app.api.deps import get_repo
    from app.database.models import Case

    case_id = get_repo().create_case(Case(title="x"))

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 204
    assert get_repo().get_case(case_id) is None


def test_delete_case_with_queued_job_cancels_it(client):
    from app.api.deps import get_repo
    from app.database.models import Case, Job

    repo = get_repo()
    case_id = repo.create_case(Case(title="x"))
    repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 204
    assert repo.get_case(case_id) is None


def test_delete_case_with_running_job_returns_409(client):
    from app.api.deps import get_repo
    from app.database.models import Case, Job, JobStatus

    repo = get_repo()
    case_id = repo.create_case(Case(title="x"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "case_has_running_job"
