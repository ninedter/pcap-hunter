# tests/api/test_errors.py
"""Tests for RFC 7807 problem+json error responses."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_key_repo, get_queue, get_rate_limiter, get_repo, get_settings, get_usage_tracker

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()

    from app.api.app import create_app

    yield TestClient(create_app())

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()


def test_error_response_is_problem_json(client):
    r = client.get("/api/v1/cases/zzzz9999", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["status"] == 404
    assert body["code"] == "case_not_found"
    assert "request_id" in body


def test_validation_error_is_problem_json(client):
    r = client.get("/api/v1/iocs.json?min_score=200", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 422
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["code"] == "validation_error"
    assert body["status"] == 422
    assert isinstance(body["errors"], list) and body["errors"]


def test_method_not_allowed_is_problem_json(client):
    r = client.delete("/api/v1/iocs.json", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 405
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["status"] == 405
    assert "GET" in r.headers.get("allow", "")


def test_401_includes_www_authenticate(client):
    r = client.get("/api/v1/iocs.json")
    assert r.status_code == 401
    assert r.headers.get("www-authenticate") == "Bearer"


def test_error_includes_request_id_when_provided(client):
    r = client.get(
        "/api/v1/cases/zzzz9999",
        headers={"Authorization": "Bearer MAIN", "X-Request-ID": "rid-test-123"},
    )
    body = r.json()
    assert body["request_id"] == "rid-test-123"


def test_401_is_problem_json(client):
    r = client.get("/api/v1/cases/zzzz9999")
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["code"] == "missing_or_malformed_auth"
