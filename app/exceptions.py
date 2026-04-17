"""Custom exception hierarchy for PCAP Hunter.

All application-specific exceptions inherit from PCAPHunterError,
enabling callers to catch broad or narrow failure categories.

Usage::

    from app.exceptions import ParseError, OSINTError

    try:
        result = parse_pcap(path)
    except ParseError as exc:
        logger.error("Parse failed: %s", exc)
"""

from __future__ import annotations


class PCAPHunterError(Exception):
    """Base exception for all PCAP Hunter errors."""


# ---- Pipeline errors ----


class ParseError(PCAPHunterError):
    """PCAP parsing failure (tshark, PyShark, or Zeek)."""


class ZeekError(ParseError):
    """Zeek-specific execution or log-parsing failure."""


class CarveError(PCAPHunterError):
    """HTTP payload carving failure."""


class YARAScanError(PCAPHunterError):
    """YARA rule compilation or scan failure."""


# ---- OSINT errors ----


class OSINTError(PCAPHunterError):
    """OSINT enrichment failure."""


class ProviderError(OSINTError):
    """Single OSINT provider query failure."""

    def __init__(self, provider: str, indicator: str, detail: str = ""):
        self.provider = provider
        self.indicator = indicator
        super().__init__(f"{provider} failed for {indicator}: {detail}")


class RateLimitError(OSINTError):
    """API rate limit exceeded."""

    def __init__(self, provider: str, retry_after: int | None = None):
        self.provider = provider
        self.retry_after = retry_after
        msg = f"{provider} rate limit exceeded"
        if retry_after:
            msg += f" (retry after {retry_after}s)"
        super().__init__(msg)


# ---- LLM errors ----


class LLMError(PCAPHunterError):
    """LLM report generation failure."""


class LLMTimeoutError(LLMError):
    """LLM API call timed out."""


# ---- Export errors ----


class ExportError(PCAPHunterError):
    """Report/data export failure (PDF, CSV, STIX, etc.)."""


# ---- Config errors ----


class ConfigError(PCAPHunterError):
    """Configuration or API key error."""
