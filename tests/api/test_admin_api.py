# tests/api/test_admin_api.py
"""Tests for admin key management API endpoints."""

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


AUTH = {"Authorization": "Bearer MAIN"}


class TestCreateKey:
    """Tests for POST /api/v1/admin/keys."""

    def test_create_key_returns_raw_key(self, client):
        r = client.post("/api/v1/admin/keys", json={"name": "test-key", "scope": "feed"}, headers=AUTH)
        assert r.status_code == 201
        body = r.json()
        assert body["key"].startswith("phk_")
        assert body["name"] == "test-key"
        assert body["scope"] == "feed"
        assert body["id"].startswith("k_")

    def test_create_key_default_scope_is_feed(self, client):
        r = client.post("/api/v1/admin/keys", json={"name": "default-scope"}, headers=AUTH)
        assert r.status_code == 201
        assert r.json()["scope"] == "feed"

    def test_create_key_with_rate_limit_and_expiry(self, client):
        r = client.post(
            "/api/v1/admin/keys",
            json={
                "name": "limited-key",
                "scope": "feed",
                "rate_limit_rpm": 30,
                "expires_in_days": 90,
            },
            headers=AUTH,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["rate_limit_rpm"] == 30
        assert body["expires_at"] is not None

    def test_create_key_requires_name(self, client):
        r = client.post("/api/v1/admin/keys", json={"scope": "feed"}, headers=AUTH)
        assert r.status_code == 422

    def test_create_key_requires_full_scope(self, client):
        r = client.post(
            "/api/v1/admin/keys",
            json={"name": "nope"},
            headers={"Authorization": "Bearer WRONG"},
        )
        assert r.status_code == 401


class TestListKeys:
    """Tests for GET /api/v1/admin/keys."""

    def test_list_keys_hides_raw_key(self, client):
        client.post("/api/v1/admin/keys", json={"name": "hidden-key"}, headers=AUTH)
        r = client.get("/api/v1/admin/keys", headers=AUTH)
        assert r.status_code == 200
        keys = r.json()
        assert len(keys) >= 1
        for k in keys:
            assert "key" not in k
            assert "key_hash" not in k

    def test_list_keys_empty(self, client):
        r = client.get("/api/v1/admin/keys", headers=AUTH)
        assert r.status_code == 200
        assert r.json() == []


class TestGetKey:
    """Tests for GET /api/v1/admin/keys/{key_id}."""

    def test_get_key_detail(self, client):
        cr = client.post("/api/v1/admin/keys", json={"name": "detail-key"}, headers=AUTH)
        key_id = cr.json()["id"]
        r = client.get(f"/api/v1/admin/keys/{key_id}", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["name"] == "detail-key"

    def test_get_nonexistent_key_returns_404(self, client):
        r = client.get("/api/v1/admin/keys/k_nonexist", headers=AUTH)
        assert r.status_code == 404


class TestUpdateKey:
    """Tests for PATCH /api/v1/admin/keys/{key_id}."""

    def test_update_key_name_and_scope(self, client):
        cr = client.post("/api/v1/admin/keys", json={"name": "old-name", "scope": "feed"}, headers=AUTH)
        key_id = cr.json()["id"]
        r = client.patch(f"/api/v1/admin/keys/{key_id}", json={"name": "new-name", "scope": "full"}, headers=AUTH)
        assert r.status_code == 200
        assert r.json()["name"] == "new-name"
        assert r.json()["scope"] == "full"

    def test_update_nonexistent_key_returns_404(self, client):
        r = client.patch("/api/v1/admin/keys/k_nonexist", json={"name": "x"}, headers=AUTH)
        assert r.status_code == 404


class TestRevokeKey:
    """Tests for DELETE /api/v1/admin/keys/{key_id}."""

    def test_revoke_key(self, client):
        cr = client.post("/api/v1/admin/keys", json={"name": "to-revoke"}, headers=AUTH)
        key_id = cr.json()["id"]
        r = client.delete(f"/api/v1/admin/keys/{key_id}", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"
        # Verify it's revoked via GET
        detail = client.get(f"/api/v1/admin/keys/{key_id}", headers=AUTH)
        assert detail.json()["status"] == "revoked"

    def test_revoke_nonexistent_key_returns_404(self, client):
        r = client.delete("/api/v1/admin/keys/k_nonexist", headers=AUTH)
        assert r.status_code == 404


class TestUsageEndpoints:
    """Tests for usage tracking endpoints."""

    def test_usage_endpoint(self, client):
        cr = client.post("/api/v1/admin/keys", json={"name": "usage-key"}, headers=AUTH)
        key_id = cr.json()["id"]
        r = client.get(f"/api/v1/admin/keys/{key_id}/usage", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert "usage" in body
        assert body["key_id"] == key_id

    def test_usage_nonexistent_key_returns_404(self, client):
        r = client.get("/api/v1/admin/keys/k_nonexist/usage", headers=AUTH)
        assert r.status_code == 404

    def test_usage_summary(self, client):
        r = client.get("/api/v1/admin/usage/summary", headers=AUTH)
        assert r.status_code == 200
        assert "usage" in r.json()


class TestAdminAuth:
    """Tests for admin endpoint authentication requirements."""

    def test_admin_endpoints_require_auth(self, client):
        assert client.get("/api/v1/admin/keys").status_code == 401
        assert client.post("/api/v1/admin/keys", json={"name": "x"}).status_code == 401
        assert client.get("/api/v1/admin/usage/summary").status_code == 401

    def test_revoked_key_detail_still_accessible_by_env_key(self, client):
        cr = client.post("/api/v1/admin/keys", json={"name": "revoke-check"}, headers=AUTH)
        key_id = cr.json()["id"]
        client.delete(f"/api/v1/admin/keys/{key_id}", headers=AUTH)
        # Default list excludes revoked keys
        keys = client.get("/api/v1/admin/keys", headers=AUTH).json()
        revoked_ids = [k["id"] for k in keys]
        assert key_id not in revoked_ids
        # But explicit GET still returns it
        detail = client.get(f"/api/v1/admin/keys/{key_id}", headers=AUTH)
        assert detail.status_code == 200
        assert detail.json()["status"] == "revoked"
