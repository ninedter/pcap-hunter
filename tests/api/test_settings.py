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


def test_refuses_to_start_when_no_keys(monkeypatch):
    monkeypatch.delenv("PCAP_HUNTER_API_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_FEED_KEY", raising=False)
    with pytest.raises(NoKeysConfiguredError):
        APISettings.from_env()


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
