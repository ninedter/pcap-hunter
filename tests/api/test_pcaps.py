# tests/api/test_pcaps.py
"""Tests for POST /api/v1/pcaps endpoint."""

from __future__ import annotations

import os
import pathlib

import pytest
from fastapi.testclient import TestClient

FIXTURE = pathlib.Path(__file__).parent.parent / "fixtures" / "tiny.pcap"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("PCAP_HUNTER_API_UPLOADS_DIR", str(tmp_path / "uploads"))

    from app.api.deps import get_queue, get_repo, get_settings

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()

    from app.api.app import create_app

    app = create_app()
    yield TestClient(app)

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_post_pcap_returns_202_and_ids(client):
    with FIXTURE.open("rb") as f:
        r = client.post(
            "/api/v1/pcaps",
            headers={"Authorization": "Bearer MAIN"},
            files={"pcap": ("tiny.pcap", f, "application/vnd.tcpdump.pcap")},
            data={"name": "smoke", "osint_enabled": "false"},
        )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "queued"
    assert body["job_id"].startswith("j_")
    assert body["case_id"]
    assert body["links"]["status"].endswith(body["job_id"])


def test_post_without_auth_returns_401(client):
    r = client.post("/api/v1/pcaps", files={"pcap": ("a.pcap", b"\x00" * 100)})
    assert r.status_code == 401


def test_post_with_feed_key_returns_403(client, monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_FEED_KEY", "FEED")
    from app.api.deps import get_settings

    get_settings.cache_clear()
    r = client.post(
        "/api/v1/pcaps",
        headers={"Authorization": "Bearer FEED"},
        files={"pcap": ("a.pcap", b"\x00" * 100)},
    )
    assert r.status_code == 403


def test_post_with_invalid_magic_returns_415(client):
    r = client.post(
        "/api/v1/pcaps",
        headers={"Authorization": "Bearer MAIN"},
        files={"pcap": ("not.pcap", b"PK\x03\x04" + b"\x00" * 200)},
    )
    assert r.status_code == 415


def test_invalid_magic_does_not_initialize_queue(client, monkeypatch):
    def fail_if_called():
        raise AssertionError("queue should not be initialized before upload validation")

    monkeypatch.setattr("app.api.routers.pcaps.get_queue", fail_if_called)
    r = client.post(
        "/api/v1/pcaps",
        headers={"Authorization": "Bearer MAIN"},
        files={"pcap": ("not.pcap", b"PK\x03\x04" + b"\x00" * 200)},
    )
    assert r.status_code == 415


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_post_returns_503_when_queue_full(client, monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_QUEUE_DEPTH", "1")
    from app.api.deps import get_queue, get_repo, get_settings

    get_settings.cache_clear()
    get_queue.cache_clear()

    from app.database.models import Case, Job

    repo = get_repo()
    pre_case = repo.create_case(Case(title="pre"))
    repo.create_job(Job(case_id=pre_case, pcap_path="/tmp/dummy.pcap"))

    with FIXTURE.open("rb") as f:
        r = client.post(
            "/api/v1/pcaps",
            headers={"Authorization": "Bearer MAIN"},
            files={"pcap": ("tiny.pcap", f, "application/vnd.tcpdump.pcap")},
            data={"osint_enabled": "false"},
        )
    assert r.status_code == 503
    assert r.headers.get("Retry-After") == "60"
    assert len(repo.list_cases()) == 1
    uploads_dir = pathlib.Path(os.environ["PCAP_HUNTER_API_UPLOADS_DIR"])
    assert not list(uploads_dir.glob("*.pcap"))


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_queue_initialization_failure_cleans_upload_and_case(client, monkeypatch):
    def boom():
        raise RuntimeError("queue init failed")

    monkeypatch.setattr("app.api.routers.pcaps.get_queue", boom)

    with FIXTURE.open("rb") as f:
        with pytest.raises(RuntimeError, match="queue init failed"):
            client.post(
                "/api/v1/pcaps",
                headers={"Authorization": "Bearer MAIN"},
                files={"pcap": ("tiny.pcap", f, "application/vnd.tcpdump.pcap")},
                data={"osint_enabled": "false"},
            )

    from app.api.deps import get_repo

    assert get_repo().list_cases() == []
    uploads_dir = pathlib.Path(os.environ["PCAP_HUNTER_API_UPLOADS_DIR"])
    assert not list(uploads_dir.glob("*.pcap"))


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_case_persistence_failure_cleans_upload(client, monkeypatch):
    from app.database.repository import CaseRepository

    def boom(self, case):
        raise RuntimeError("case save failed")

    monkeypatch.setattr(CaseRepository, "create_case", boom)

    with FIXTURE.open("rb") as f:
        with pytest.raises(RuntimeError, match="case save failed"):
            client.post(
                "/api/v1/pcaps",
                headers={"Authorization": "Bearer MAIN"},
                files={"pcap": ("tiny.pcap", f, "application/vnd.tcpdump.pcap")},
                data={"osint_enabled": "false"},
            )

    from app.api.deps import get_repo

    assert get_repo().list_cases() == []
    uploads_dir = pathlib.Path(os.environ["PCAP_HUNTER_API_UPLOADS_DIR"])
    assert not list(uploads_dir.glob("*.pcap"))
