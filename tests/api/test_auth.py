# tests/api/test_auth.py
"""Tests for bearer-token auth and FastAPI auth dependencies."""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient


def test_auth_dependency_403_on_wrong_scope(monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_FEED_KEY", "FEED")

    from app.api.deps import get_settings, require_feed_scope, require_full_scope

    get_settings.cache_clear()
    app = FastAPI()
    r = APIRouter()

    @r.get("/full")
    def full(_=Depends(require_full_scope)):
        return {"ok": True}

    @r.get("/feed")
    def feed(_=Depends(require_feed_scope)):
        return {"ok": True}

    app.include_router(r)
    client = TestClient(app)

    assert client.get("/full", headers={"Authorization": "Bearer FEED"}).status_code == 403
    assert client.get("/full", headers={"Authorization": "Bearer MAIN"}).status_code == 200
    assert client.get("/feed", headers={"Authorization": "Bearer FEED"}).status_code == 200
    assert client.get("/feed", headers={"Authorization": "Bearer MAIN"}).status_code == 200
    assert client.get("/full").status_code == 401

    get_settings.cache_clear()
