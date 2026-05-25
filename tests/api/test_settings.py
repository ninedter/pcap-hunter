# tests/api/test_settings.py
"""Tests for API settings module."""

from __future__ import annotations

import pytest

from app.api.settings import APISettings, NoKeysConfiguredError


def test_loads_main_key_from_env(monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "sekret")
    monkeypatch.delenv("PCAP_HUNTER_FEED_KEY", raising=False)
    s = APISettings.from_env()
    assert s.main_key == "sekret"
    assert s.feed_key is None


def test_loads_both_keys(monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "main")
    monkeypatch.setenv("PCAP_HUNTER_FEED_KEY", "feed")
    s = APISettings.from_env()
    assert s.main_key == "main"
    assert s.feed_key == "feed"


def test_allows_no_env_keys_when_db_keys_may_exist(monkeypatch):
    """Env-var keys are optional when DB-backed keys might exist."""
    monkeypatch.delenv("PCAP_HUNTER_API_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_FEED_KEY", raising=False)
    s = APISettings.from_env()
    assert s.main_key is None
    assert s.feed_key is None


def test_max_pcap_bytes_default_2gb(monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "x")
    s = APISettings.from_env()
    assert s.max_pcap_bytes == 2 * 1024 * 1024 * 1024


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "x")
    monkeypatch.setenv("PCAP_HUNTER_API_PORT", "9000")
    monkeypatch.setenv("PCAP_HUNTER_API_QUEUE_DEPTH", "50")
    monkeypatch.setenv("PCAP_HUNTER_API_REQUIRE_HTTPS", "true")
    s = APISettings.from_env()
    assert s.port == 9000
    assert s.queue_depth == 50
    assert s.require_https is True


def test_create_app_refuses_start_without_any_auth(monkeypatch, tmp_path):
    """create_app() raises NoKeysConfiguredError when no auth sources exist."""
    monkeypatch.delenv("PCAP_HUNTER_API_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_FEED_KEY", raising=False)
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_key_repo, get_queue, get_rate_limiter, get_repo, get_settings, get_usage_tracker

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()

    from app.api.app import create_app

    with pytest.raises(NoKeysConfiguredError):
        create_app()

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()
    get_key_repo.cache_clear()
    get_rate_limiter.cache_clear()
    get_usage_tracker.cache_clear()
