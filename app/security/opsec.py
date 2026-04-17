"""OPSEC hardening utilities.

Provides a hardened HTTP session with SSL verification, redirect safety,
and consistent defaults, plus string redaction for log safety.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import requests


def _check_scheme_downgrade(response: requests.Response, *args: Any, **kwargs: Any) -> None:
    """Block HTTPS → HTTP redirect downgrades."""
    if response.is_redirect:
        location = response.headers.get("Location", "")
        if response.url.startswith("https://") and location.startswith("http://"):
            raise ValueError("Blocked HTTPS to HTTP redirect downgrade")


def hardened_session(timeout: int = 15) -> requests.Session:
    """Create a hardened :class:`requests.Session` with security defaults.

    Features:
        - SSL verification enforced
        - Maximum 3 redirects (no cross-scheme)
        - System proxy ignored
        - Default timeout on all requests
        - Consistent ``User-Agent``

    Args:
        timeout: Default request timeout in seconds.

    Returns:
        A configured session instance.
    """
    s = requests.Session()
    s.headers.update({"User-Agent": "pcap-hunter/1.0"})
    s.verify = True
    # No redirects across schemes
    s.max_redirects = 3
    s.trust_env = False  # ignore system proxies by default
    s.hooks["response"].append(_check_scheme_downgrade)
    s.request = _wrap_request(s.request, timeout=timeout)  # type: ignore[assignment]
    return s


def _wrap_request(fn: Callable[..., Any], timeout: int = 15) -> Callable[..., Any]:
    """Wrap a request function to inject a default timeout."""

    def _inner(method: str, url: str, **kwargs: Any) -> Any:
        kwargs.setdefault("timeout", timeout)
        return fn(method, url, **kwargs)

    return _inner


def redact(text: str, keep: int = 3) -> str:
    """Redact a string for safe logging, keeping only the first *keep* chars.

    Args:
        text: The string to redact.
        keep: Number of leading characters to preserve.

    Returns:
        Redacted string or the original if empty.
    """
    if not text:
        return text
    if len(text) <= keep:
        return "***"
    return text[:keep] + "…"
