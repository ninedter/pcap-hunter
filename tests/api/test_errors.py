# tests/api/test_errors.py
"""Tests for RFC 7807 problem+json error responses."""

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


def test_error_response_is_problem_json(client):
    r = client.get("/api/v1/cases/zzzz9999", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["status"] == 404
    assert body["code"] == "case_not_found"
    assert "request_id" in body


def test_validation_error_is_problem_json(client):
    r = client.get("/api/v1/cases/x", headers={"Authorization": "Bearer MAIN"})
    # 404 from get_case, but the path itself is valid; this just confirms shape
    assert r.headers["content-type"].startswith("application/problem+json")


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
    assert body["code"] == "missing_or_invalid_auth"
