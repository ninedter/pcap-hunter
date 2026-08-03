# tests/api/test_health.py
"""Tests for health and readiness endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "test-main")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

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


def test_healthz_returns_200(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_readyz_returns_200_when_ready(client):
    r = client.get("/readyz")
    assert r.status_code == 200


def test_readyz_does_not_initialize_job_queue(client):
    from app.api.deps import get_queue

    assert get_queue.cache_info().currsize == 0
    r = client.get("/readyz")
    assert r.status_code == 200
    assert get_queue.cache_info().currsize == 0


def test_healthz_no_auth_required(client):
    r = client.get("/healthz", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 200


def test_openapi_reports_package_version(client):
    from app import __version__

    response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["version"] == __version__ == "3.0.0"


def test_openapi_operation_ids_are_unique(client):
    schema = client.get("/api/v1/openapi.json").json()
    operation_ids = [
        operation["operationId"]
        for path in schema["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict) and "operationId" in operation
    ]

    assert len(operation_ids) == len(set(operation_ids))


def test_request_id_header_echoed(client):
    r = client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert r.headers.get("X-Request-ID") == "abc-123"


def test_request_id_generated_if_absent(client):
    r = client.get("/healthz")
    assert "X-Request-ID" in r.headers
    assert len(r.headers["X-Request-ID"]) > 0
