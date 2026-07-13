# tests/api/test_pcaps.py
"""Tests for POST /api/v1/pcaps endpoint."""

from __future__ import annotations

import json
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
            data={"name": "smoke", "osint_enabled": "false", "llm_enabled": "false"},
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


# ---------------------------------------------------------------------------
# Task 4.4: SSRF-safe completion webhook on submit
# ---------------------------------------------------------------------------


def test_post_with_private_webhook_url_returns_422(client):
    """Fail fast (before upload I/O) on a webhook_url that fails the SSRF guard."""
    r = client.post(
        "/api/v1/pcaps",
        headers={"Authorization": "Bearer MAIN"},
        files={"pcap": ("a.pcap", b"\x00" * 100)},
        data={"webhook_url": "http://10.0.0.5/hook"},
    )
    assert r.status_code == 422
    assert r.json()["detail"] == "invalid_webhook_url"


def test_post_with_loopback_webhook_url_returns_422(client):
    r = client.post(
        "/api/v1/pcaps",
        headers={"Authorization": "Bearer MAIN"},
        files={"pcap": ("a.pcap", b"\x00" * 100)},
        data={"webhook_url": "http://127.0.0.1:9000/hook"},
    )
    assert r.status_code == 422
    assert r.json()["detail"] == "invalid_webhook_url"


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_post_with_public_webhook_url_returns_202_and_persists_option(client, monkeypatch):
    """A public https webhook_url must be accepted and carried into the job's options_json."""
    monkeypatch.setattr("app.api.routers.pcaps.is_safe_webhook_url", lambda url: True)

    with FIXTURE.open("rb") as f:
        r = client.post(
            "/api/v1/pcaps",
            headers={"Authorization": "Bearer MAIN"},
            files={"pcap": ("tiny.pcap", f, "application/vnd.tcpdump.pcap")},
            data={
                "osint_enabled": "false",
                "llm_enabled": "false",
                "webhook_url": "https://example.com/hook",
            },
        )
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]

    from app.api.deps import get_repo

    job = get_repo().get_job(job_id)
    assert json.loads(job.options_json)["webhook_url"] == "https://example.com/hook"


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
            data={"osint_enabled": "false", "llm_enabled": "false"},
        )
    assert r.status_code == 503
    assert r.headers.get("Retry-After") == "60"
