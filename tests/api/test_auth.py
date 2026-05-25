# tests/api/test_auth.py
"""Tests for bearer-token auth and FastAPI auth dependencies."""

from __future__ import annotations

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.auth import Scope, check_bearer
from app.api.settings import APISettings


def _settings(main: str | None = "MAIN_KEY", feed: str | None = "FEED_KEY") -> APISettings:
    return APISettings(
        main_key=main,
        feed_key=feed,
        host="127.0.0.1",
        port=8000,
        workers=1,
        queue_depth=10,
        max_pcap_bytes=10**9,
        upload_timeout_seconds=60,
        pcap_ttl_days=7,
        artifact_ttl_days=30,
        job_ttl_days=30,
        require_https=False,
        cors_origins=[],
    )


def test_main_key_grants_full_scope():
    settings = _settings()
    scope = check_bearer("Bearer MAIN_KEY", settings, required=Scope.FULL)
    assert scope == Scope.FULL


def test_feed_key_grants_feed_scope():
    settings = _settings()
    scope = check_bearer("Bearer FEED_KEY", settings, required=Scope.FEED)
    assert scope == Scope.FEED


def test_feed_key_cannot_use_full_endpoint():
    settings = _settings()
    with pytest.raises(PermissionError):
        check_bearer("Bearer FEED_KEY", settings, required=Scope.FULL)


def test_missing_header_raises():
    settings = _settings()
    with pytest.raises(ValueError):
        check_bearer(None, settings, required=Scope.FULL)


def test_wrong_key_raises_unauthorized():
    settings = _settings()
    with pytest.raises(ValueError):
        check_bearer("Bearer WRONG", settings, required=Scope.FULL)


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
