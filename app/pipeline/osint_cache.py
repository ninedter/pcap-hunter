"""OSINT response caching using SQLite."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger(__name__)


class OSINTCache:
    """
    Cache OSINT API responses in SQLite database.

    Features:
    - TTL-based expiration
    - Thread-safe with WAL mode and connection pooling
    - Provider-specific caching
    - Automatic corruption recovery
    - Enable/disable toggle for fresh queries
    """

    def __init__(self, db_path: str | Path, ttl_hours: int = 24, enabled: bool = True):
        """
        Initialize the OSINT cache.

        Args:
            db_path: Path to SQLite database file
            ttl_hours: Time-to-live in hours (default: 24)
            enabled: Whether caching is enabled (default: True)
        """
        self.db_path = Path(db_path)
        self.ttl_seconds = ttl_hours * 3600
        self.enabled = enabled
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema with corruption recovery."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with self._get_conn() as conn:
                # Check database integrity
                result = conn.execute("PRAGMA integrity_check").fetchone()
                if result[0] != "ok":
                    raise sqlite3.DatabaseError("Database integrity check failed")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS osint_cache (
                        indicator TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        data TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        PRIMARY KEY (indicator, provider)
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_created_at ON osint_cache(created_at)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_provider ON osint_cache(provider)
                """)
                conn.commit()
        except sqlite3.DatabaseError as e:
            logger.warning("Database corrupted, recreating: %s", e)
            self._recreate_db()

    def _recreate_db(self) -> None:
        """Recreate database from scratch."""
        if self.db_path.exists():
            self.db_path.unlink()
        # Also remove WAL and SHM files if they exist
        for suffix in ["-wal", "-shm"]:
            wal_path = Path(str(self.db_path) + suffix)
            if wal_path.exists():
                wal_path.unlink()
        self._init_db()

    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Get thread-safe database connection.

        Uses thread-local storage for connection reuse within same thread.
        """
        # Get or create thread-local connection
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
            )
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=30000")

        try:
            yield self._local.conn
        except sqlite3.Error as e:
            logger.error("SQLite error: %s", e)
            # Reset connection on error
            try:
                self._local.conn.close()
            except Exception as close_err:
                logger.debug("osint cache operation failed: %s", close_err)
            self._local.conn = None
            raise

    def close(self) -> None:
        """Close thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            try:
                self._local.conn.close()
            except Exception as e:
                logger.debug("osint cache operation failed: %s", e)
            self._local.conn = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> "OSINTCache":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable caching at runtime."""
        self.enabled = enabled
        logger.info("OSINT cache %s", "enabled" if enabled else "disabled")

    def invalidate_on_key_change(self, keys_hash: str) -> None:
        """Invalidate cache if API keys have changed since last run.

        Compares a hash of the current API key set against the stored hash.
        If they differ, all cached responses are cleared to prevent serving
        stale results from a different API key.

        Args:
            keys_hash: Hash of the current API key configuration.
        """
        try:
            with self._get_conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)
                row = conn.execute("SELECT value FROM cache_meta WHERE key = 'keys_hash'").fetchone()
                stored_hash = row[0] if row else None

                if stored_hash and stored_hash != keys_hash:
                    count = self.invalidate()
                    logger.warning("API keys changed — invalidated %d cached OSINT entries", count)

                conn.execute(
                    "INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('keys_hash', ?)",
                    (keys_hash,),
                )
                conn.commit()
        except Exception as e:
            logger.warning("Cache key-change check failed: %s", e)

    def get(self, indicator: str, provider: str) -> dict | None:
        """
        Get cached response for an indicator and provider.

        Args:
            indicator: IP address, domain, or hash
            provider: OSINT provider name (e.g., "greynoise", "vt")

        Returns:
            Cached data dict or None if not found/expired/disabled
        """
        if not self.enabled:
            return None

        cutoff = time.time() - self.ttl_seconds

        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                SELECT data FROM osint_cache
                WHERE indicator = ? AND provider = ? AND created_at > ?
                """,
                (indicator.lower(), provider.lower(), cutoff),
            )
            row = cursor.fetchone()

            if row:
                try:
                    return json.loads(row[0])
                except json.JSONDecodeError:
                    return None

        return None

    def set(self, indicator: str, provider: str, data: dict, *, commit: bool = True) -> None:
        """
        Store response in cache.

        Args:
            indicator: IP address, domain, or hash
            provider: OSINT provider name
            data: Response data to cache
            commit: Whether to commit immediately (default True).
                Set to False when batching multiple writes, then call
                ``flush()`` or ``set_batch()`` to commit once.
        """
        if not self.enabled:
            return

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO osint_cache (indicator, provider, data, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (indicator.lower(), provider.lower(), json.dumps(data), time.time()),
            )
            if commit:
                conn.commit()

    def set_batch(self, entries: list[tuple[str, str, dict]]) -> None:
        """
        Store multiple responses in cache with a single commit.

        Args:
            entries: List of (indicator, provider, data) tuples to cache.
        """
        if not self.enabled or not entries:
            return

        now = time.time()
        with self._get_conn() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO osint_cache (indicator, provider, data, created_at)
                VALUES (?, ?, ?, ?)
                """,
                [(indicator.lower(), provider.lower(), json.dumps(data), now) for indicator, provider, data in entries],
            )
            conn.commit()

    def flush(self) -> None:
        """Commit any pending writes from ``set(..., commit=False)`` calls."""
        with self._get_conn() as conn:
            conn.commit()

    def invalidate(self, indicator: str | None = None, provider: str | None = None) -> int:
        """
        Invalidate cache entries.

        Args:
            indicator: Specific indicator to invalidate (None = all)
            provider: Specific provider to invalidate (None = all)

        Returns:
            Number of entries removed
        """
        with self._get_conn() as conn:
            if indicator and provider:
                cursor = conn.execute(
                    "DELETE FROM osint_cache WHERE indicator = ? AND provider = ?",
                    (indicator.lower(), provider.lower()),
                )
            elif indicator:
                cursor = conn.execute(
                    "DELETE FROM osint_cache WHERE indicator = ?",
                    (indicator.lower(),),
                )
            elif provider:
                cursor = conn.execute(
                    "DELETE FROM osint_cache WHERE provider = ?",
                    (provider.lower(),),
                )
            else:
                cursor = conn.execute("DELETE FROM osint_cache")

            conn.commit()
            return cursor.rowcount

    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        cutoff = time.time() - self.ttl_seconds

        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM osint_cache WHERE created_at < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict with cache stats (total entries, entries by provider, etc.)
        """
        with self._get_conn() as conn:
            # Total entries
            total = conn.execute("SELECT COUNT(*) FROM osint_cache").fetchone()[0]

            # Entries by provider
            by_provider = {}
            for row in conn.execute("SELECT provider, COUNT(*) FROM osint_cache GROUP BY provider"):
                by_provider[row[0]] = row[1]

            # Expired count
            cutoff = time.time() - self.ttl_seconds
            expired = conn.execute("SELECT COUNT(*) FROM osint_cache WHERE created_at < ?", (cutoff,)).fetchone()[0]

            # Database size
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0

        return {
            "total_entries": total,
            "by_provider": by_provider,
            "expired_entries": expired,
            "db_size_bytes": db_size,
            "ttl_hours": self.ttl_seconds / 3600,
        }


# Global cache instance
_cache: OSINTCache | None = None


def get_osint_cache(db_path: str | Path | None = None, ttl_hours: int = 24) -> OSINTCache:
    """Get or create the global OSINT cache instance."""
    global _cache
    if _cache is None:
        if db_path is None:
            db_path = Path("data") / "osint_cache.db"
        _cache = OSINTCache(db_path, ttl_hours)
    return _cache
