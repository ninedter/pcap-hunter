# tests/api/test_key_e2e.py
"""End-to-end tests: create DB key -> use it -> verify usage -> revoke -> verify 401."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "e2e.db"))

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


ADMIN_AUTH = {"Authorization": "Bearer MAIN"}


def test_full_lifecycle(client):
    """Create a DB key, use it to call an endpoint, then revoke it."""
    # 1. Create a feed-scoped key via admin API
    cr = client.post(
        "/api/v1/admin/keys",
        json={"name": "e2e-test", "scope": "feed"},
        headers=ADMIN_AUTH,
    )
    assert cr.status_code == 201
    raw_key = cr.json()["key"]
    key_id = cr.json()["id"]
    assert raw_key.startswith("phk_")

    # 2. Use the DB key to call a feed endpoint
    db_auth = {"Authorization": f"Bearer {raw_key}"}
    r = client.get("/api/v1/iocs.json", headers=db_auth)
    assert r.status_code in (200, 304)

    # 3. Revoke the key
    rv = client.delete(f"/api/v1/admin/keys/{key_id}", headers=ADMIN_AUTH)
    assert rv.status_code == 200
    assert rv.json()["status"] == "revoked"

    # 4. Verify the revoked key gets 401
    r2 = client.get("/api/v1/iocs.json", headers=db_auth)
    assert r2.status_code == 401


def test_db_key_scope_enforcement(client):
    """Feed-scoped DB key cannot access full-scope endpoints."""
    cr = client.post(
        "/api/v1/admin/keys",
        json={"name": "feed-only", "scope": "feed"},
        headers=ADMIN_AUTH,
    )
    raw_key = cr.json()["key"]
    db_auth = {"Authorization": f"Bearer {raw_key}"}

    # Feed endpoint works
    r = client.get("/api/v1/iocs.json", headers=db_auth)
    assert r.status_code in (200, 304)

    # Admin endpoint (full scope) should fail
    r2 = client.get("/api/v1/admin/keys", headers=db_auth)
    assert r2.status_code == 403


def test_db_key_rate_limiting(client):
    """DB key with rate_limit_rpm=2 gets 429 on third request."""
    cr = client.post(
        "/api/v1/admin/keys",
        json={"name": "rate-limited", "scope": "feed", "rate_limit_rpm": 2},
        headers=ADMIN_AUTH,
    )
    raw_key = cr.json()["key"]
    db_auth = {"Authorization": f"Bearer {raw_key}"}

    # First 2 requests succeed
    assert client.get("/api/v1/iocs.json", headers=db_auth).status_code in (200, 304)
    assert client.get("/api/v1/iocs.json", headers=db_auth).status_code in (200, 304)

    # Third should be rate-limited
    r3 = client.get("/api/v1/iocs.json", headers=db_auth)
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
