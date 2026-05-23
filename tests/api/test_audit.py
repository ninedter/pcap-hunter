# tests/api/test_audit.py
"""Tests for CORS middleware and key_name in audit logs."""

from __future__ import annotations

import logging

from fastapi.testclient import TestClient


def test_audit_log_includes_key_name(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_FEED_KEY", "FEED")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_key_repo, get_queue, get_rate_limiter, get_repo, get_settings, get_usage_tracker

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()

    from app.api.app import create_app

    client = TestClient(create_app())

    with caplog.at_level(logging.INFO, logger="app.api.app"):
        client.get("/healthz")  # no auth -> key_name=-
        client.get("/api/v1/iocs.json", headers={"Authorization": "Bearer FEED"})

    messages = [r.message for r in caplog.records]
    assert any("key_name=env:feed" in m for m in messages)

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


def test_cors_disabled_by_default(monkeypatch, tmp_path):
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

    client = TestClient(create_app())

    r = client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {h.lower() for h in r.headers}

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


def test_cors_enabled_when_origins_set(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_CORS_ORIGINS", "https://dashboard.internal")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_key_repo, get_queue, get_rate_limiter, get_repo, get_settings, get_usage_tracker

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()

    from app.api.app import create_app

    client = TestClient(create_app())

    r = client.get("/healthz", headers={"Origin": "https://dashboard.internal"})
    assert r.headers.get("access-control-allow-origin") == "https://dashboard.internal"

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
