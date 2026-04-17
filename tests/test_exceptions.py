"""Tests for the custom exception hierarchy."""

from __future__ import annotations

import pytest

from app.exceptions import (
    CarveError,
    ConfigError,
    ExportError,
    LLMError,
    LLMTimeoutError,
    OSINTError,
    ParseError,
    PCAPHunterError,
    ProviderError,
    RateLimitError,
    YARAScanError,
    ZeekError,
)


class TestExceptionInheritance:
    """Verify correct MRO for all exception classes."""

    @pytest.mark.parametrize(
        "exc_class",
        [
            ParseError,
            ZeekError,
            CarveError,
            YARAScanError,
            OSINTError,
            ProviderError,
            RateLimitError,
            LLMError,
            LLMTimeoutError,
            ExportError,
            ConfigError,
        ],
    )
    def test_inherits_from_base(self, exc_class):
        assert issubclass(exc_class, PCAPHunterError)
        assert issubclass(exc_class, Exception)

    def test_zeek_is_parse_error(self):
        assert issubclass(ZeekError, ParseError)

    def test_llm_timeout_is_llm_error(self):
        assert issubclass(LLMTimeoutError, LLMError)

    def test_provider_is_osint_error(self):
        assert issubclass(ProviderError, OSINTError)

    def test_rate_limit_is_osint_error(self):
        assert issubclass(RateLimitError, OSINTError)


class TestProviderError:
    def test_attributes(self):
        err = ProviderError("virustotal", "1.2.3.4", "rate limited")
        assert err.provider == "virustotal"
        assert err.indicator == "1.2.3.4"

    def test_str_contains_details(self):
        err = ProviderError("shodan", "evil.com", "timeout")
        msg = str(err)
        assert "shodan" in msg
        assert "evil.com" in msg
        assert "timeout" in msg

    def test_catch_as_osint_error(self):
        with pytest.raises(OSINTError):
            raise ProviderError("vt", "1.1.1.1", "fail")

    def test_catch_as_base(self):
        with pytest.raises(PCAPHunterError):
            raise ProviderError("vt", "1.1.1.1")


class TestRateLimitError:
    def test_with_retry_after(self):
        err = RateLimitError("abuseipdb", retry_after=30)
        assert err.provider == "abuseipdb"
        assert err.retry_after == 30
        assert "30s" in str(err)

    def test_without_retry_after(self):
        err = RateLimitError("shodan")
        assert err.retry_after is None
        assert "rate limit" in str(err).lower()


class TestExceptionCatching:
    """Test real-world exception handling patterns."""

    def test_broad_catch(self):
        """Callers can catch PCAPHunterError for all app errors."""
        errors = [
            ParseError("bad pcap"),
            ZeekError("zeek not found"),
            CarveError("no payload"),
            OSINTError("api down"),
            LLMError("model unavailable"),
            ConfigError("missing key"),
        ]
        for err in errors:
            with pytest.raises(PCAPHunterError):
                raise err

    def test_narrow_catch_doesnt_catch_siblings(self):
        """Catching ParseError should not catch LLMError."""
        with pytest.raises(LLMError):
            try:
                raise LLMError("timeout")
            except ParseError:
                pytest.fail("ParseError handler should not catch LLMError")
