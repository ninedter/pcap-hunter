"""In-memory sliding-window rate limiter."""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """Per-key sliding-window rate limiter.

    Tracks request timestamps per key_id in a 60-second window.
    Thread-safe. State is lost on process restart (acceptable for
    a 1-minute window).
    """

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key_id: str, limit_rpm: int | None) -> tuple[bool, int]:
        """Check if a request is allowed under the rate limit.

        Args:
            key_id: The API key identifier.
            limit_rpm: Requests per minute limit. None means unlimited.

        Returns:
            Tuple of (allowed, retry_after_seconds).
            If allowed is False, retry_after_seconds indicates when to retry.
        """
        if limit_rpm is None:
            return True, 0

        now = time.monotonic()
        with self._lock:
            window = self._windows.setdefault(key_id, deque())
            # Evict entries older than 60 seconds
            while window and window[0] < now - 60:
                window.popleft()

            if len(window) >= limit_rpm:
                retry_after = int(window[0] + 60 - now) + 1
                return False, max(retry_after, 1)

            window.append(now)
            return True, 0

    def reset(self, key_id: str) -> None:
        """Reset the rate limit window for a key (e.g., after revocation)."""
        with self._lock:
            self._windows.pop(key_id, None)

    def clear(self) -> None:
        """Clear all rate limit state."""
        with self._lock:
            self._windows.clear()
