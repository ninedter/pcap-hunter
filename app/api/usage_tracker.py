"""In-memory usage tracker with periodic DB flush."""

from __future__ import annotations

import logging
import threading
import time
from datetime import date

logger = logging.getLogger(__name__)


class UsageTracker:
    """Accumulates per-key request counts in memory.

    Call record() on each successful API request.
    Call flush() periodically (every 60s) to persist to the database.
    Call flush() on shutdown to avoid losing the last batch.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._last_used: dict[str, float] = {}
        self._lock = threading.Lock()

    def record(self, key_id: str) -> None:
        """Record a successful API request for a key.

        Args:
            key_id: The API key identifier.
        """
        with self._lock:
            self._counts[key_id] = self._counts.get(key_id, 0) + 1
            self._last_used[key_id] = time.time()

    def flush(self, key_repo) -> None:
        """Flush accumulated counts to the database.

        On per-key failure the entry is restored to the in-memory maps so it
        will be retried on the next flush cycle instead of being silently lost.

        Args:
            key_repo: KeyRepository instance for DB writes.
        """
        with self._lock:
            counts = dict(self._counts)
            last_used = dict(self._last_used)
            self._counts.clear()
            self._last_used.clear()

        if not counts:
            return

        today = date.today().isoformat()
        failed_counts: dict[str, int] = {}
        failed_last_used: dict[str, float] = {}

        for key_id, count in counts.items():
            try:
                key_repo.increment_usage(key_id, today, count)
                ts = last_used.get(key_id)
                if ts is not None:
                    key_repo.touch_key_last_used(key_id, ts)
            except Exception:
                logger.warning("Failed to flush usage for key %s", key_id, exc_info=True)
                failed_counts[key_id] = count
                if key_id in last_used:
                    failed_last_used[key_id] = last_used[key_id]

        # Restore failed entries so they are retried on the next flush
        if failed_counts:
            with self._lock:
                for key_id, count in failed_counts.items():
                    self._counts[key_id] = self._counts.get(key_id, 0) + count
                for key_id, ts in failed_last_used.items():
                    existing = self._last_used.get(key_id)
                    if existing is None or existing < ts:
                        self._last_used[key_id] = ts

    def get_pending_count(self, key_id: str) -> int:
        """Get unflushed request count for a key (for testing/debugging)."""
        with self._lock:
            return self._counts.get(key_id, 0)
