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


def test_request_id_sanitized(monkeypatch, tmp_path):
    """Malicious X-Request-ID values are stripped to safe characters."""
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

    # Inject CRLF and special chars — should be stripped
    r = client.get("/healthz", headers={"X-Request-ID": "rid\r\nEvil: header"})
    # Should get a sanitized version back (only safe chars kept)
    returned_rid = r.headers.get("X-Request-ID", "")
    assert "\r" not in returned_rid
    assert "\n" not in returned_rid
    assert ":" not in returned_rid
    assert returned_rid == "ridEvilheader"

    # Overly long ID should be truncated to 128 chars
    long_rid = "a" * 300
    r2 = client.get("/healthz", headers={"X-Request-ID": long_rid})
    assert len(r2.headers.get("X-Request-ID", "")) <= 128

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


def test_create_app_warns_when_no_full_scope_source(monkeypatch, tmp_path, caplog):
    monkeypatch.delenv("PCAP_HUNTER_API_KEY", raising=False)
    monkeypatch.setenv("PCAP_HUNTER_FEED_KEY", "FEEDONLY")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_key_repo, get_queue, get_rate_limiter, get_repo, get_settings, get_usage_tracker

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()

    from app.api.app import create_app

    with caplog.at_level(logging.WARNING, logger="app.api.app"):
        create_app()

    messages = [r.message for r in caplog.records]
    assert any("full-scope" in m for m in messages)
    # The feed env key exists, so the "no env keys at all" warning must NOT fire.
    assert not any("DB-backed" in m for m in messages)

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()


def test_create_app_warns_when_env_keyless_with_db_keys(monkeypatch, tmp_path, caplog):
    monkeypatch.delenv("PCAP_HUNTER_API_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_FEED_KEY", raising=False)
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    # One active feed-scope DB key: the app boots, but no full-scope source exists.
    from app.api.auth import Scope
    from app.api.key_models import APIKey, generate_api_key
    from app.api.key_repository import KeyRepository

    _, key_hash, prefix = generate_api_key()
    KeyRepository(db_path=str(tmp_path / "t.db")).create_key(
        APIKey(key_hash=key_hash, key_prefix=prefix, name="db-feed", scope=Scope.FEED)
    )

    from app.api.deps import get_key_repo, get_queue, get_rate_limiter, get_repo, get_settings, get_usage_tracker

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()

    from app.api.app import create_app

    with caplog.at_level(logging.WARNING, logger="app.api.app"):
        create_app()

    messages = [r.message for r in caplog.records]
    assert any("full-scope" in m for m in messages)
    assert any("relies entirely on 1 DB-backed key(s)" in m for m in messages)

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()


def test_create_app_no_keyless_warnings_with_main_key(monkeypatch, tmp_path, caplog):
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

    with caplog.at_level(logging.WARNING, logger="app.api.app"):
        create_app()

    messages = [r.message for r in caplog.records]
    assert not any("full-scope" in m for m in messages)
    assert not any("DB-backed" in m for m in messages)

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()


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
