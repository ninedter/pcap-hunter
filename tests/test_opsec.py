"""Tests for OPSEC hardening utilities."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.security.opsec import _check_scheme_downgrade, hardened_session, redact


class TestRedact:
    def test_short_string(self):
        assert redact("ab") == "***"

    def test_normal_string(self):
        assert redact("secret_key_12345") == "sec…"

    def test_empty_string(self):
        assert redact("") == ""

    def test_custom_keep(self):
        assert redact("abcdef", keep=4) == "abcd…"

    def test_exact_keep_length(self):
        assert redact("abc", keep=3) == "***"


class TestCheckSchemeDowngrade:
    def test_blocks_https_to_http(self):
        response = MagicMock()
        response.is_redirect = True
        response.url = "https://example.com/api"
        response.headers = {"Location": "http://example.com/api"}

        try:
            _check_scheme_downgrade(response)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "downgrade" in str(e).lower()

    def test_allows_https_to_https(self):
        response = MagicMock()
        response.is_redirect = True
        response.url = "https://example.com/api"
        response.headers = {"Location": "https://example.com/other"}

        _check_scheme_downgrade(response)  # Should not raise

    def test_allows_non_redirect(self):
        response = MagicMock()
        response.is_redirect = False

        _check_scheme_downgrade(response)  # Should not raise


class TestHardenedSession:
    def test_returns_session(self):
        session = hardened_session()
        assert session is not None
        assert session.verify is True

    def test_user_agent_set(self):
        session = hardened_session()
        assert "pcap-hunter" in session.headers.get("User-Agent", "")

    def test_max_redirects(self):
        session = hardened_session()
        assert session.max_redirects == 3

    def test_trust_env_disabled(self):
        session = hardened_session()
        assert session.trust_env is False

    def test_custom_timeout(self):
        session = hardened_session(timeout=30)
        assert session is not None
