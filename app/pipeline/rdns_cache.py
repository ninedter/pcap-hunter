"""Reverse DNS response caching using SQLite.

Lightweight cache for PTR lookup results, following the same WAL + thread-local
pattern used in ``osint_cache.py`` but with a simpler schema (no provider key).
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# Default TTL — PTR records change less often than threat intel
_DEFAULT_TTL_HOURS = 168  # 7 days


class RDNSCache:
    """Cache reverse-DNS results in a local SQLite database.

    Features:
        - TTL-based expiration (default 7 days)
        - Thread-safe with WAL mode
        - Batch get/set for bulk resolution
        - Automatic corruption recovery
    """

    def __init__(self, db_path: str | Path, ttl_hours: int = _DEFAULT_TTL_HOURS):
        self.db_path = Path(db_path)
        self.ttl_seconds = ttl_hours * 3600
        self._local = threading.local()
        self._init_db()

    # ------------------------------------------------------------------
    # Database lifecycle
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._get_conn() as conn:
                result = conn.execute("PRAGMA integrity_check").fetchone()
                if result[0] != "ok":
                    raise sqlite3.DatabaseError("integrity check failed")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS rdns_cache (
                        ip TEXT PRIMARY KEY,
                        hostname TEXT NOT NULL,
                        created_at REAL NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_rdns_created ON rdns_cache(created_at)")
                conn.commit()
        except sqlite3.DatabaseError as e:
            logger.warning("rDNS cache corrupted, recreating: %s", e)
            self._recreate_db()

    def _recreate_db(self) -> None:
        if self.db_path.exists():
            self.db_path.unlink()
        for suffix in ["-wal", "-shm"]:
            p = Path(str(self.db_path) + suffix)
            if p.exists():
                p.unlink()
        self._init_db()

    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
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
            logger.error("rDNS cache SQLite error: %s", e)
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None
            raise

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> "RDNSCache":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, ip: str) -> str | None:
        """Return cached hostname for *ip*, or ``None`` if missing/expired."""
        cutoff = time.time() - self.ttl_seconds
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT hostname FROM rdns_cache WHERE ip = ? AND created_at > ?",
                (ip, cutoff),
            ).fetchone()
            return row[0] if row else None

    def get_batch(self, ips: list[str]) -> dict[str, str]:
        """Return ``{ip: hostname}`` for all cached (non-expired) entries."""
        if not ips:
            return {}
        cutoff = time.time() - self.ttl_seconds
        result: dict[str, str] = {}
        with self._get_conn() as conn:
            # SQLite placeholder limit is 999; chunk if needed
            for start in range(0, len(ips), 900):
                chunk = ips[start : start + 900]
                placeholders = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT ip, hostname FROM rdns_cache WHERE ip IN ({placeholders}) AND created_at > ?",
                    [*chunk, cutoff],
                ).fetchall()
                for ip, hostname in rows:
                    result[ip] = hostname
        return result

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def set(self, ip: str, hostname: str) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO rdns_cache (ip, hostname, created_at) VALUES (?, ?, ?)",
                (ip, hostname, time.time()),
            )
            conn.commit()

    def set_batch(self, entries: list[tuple[str, str]]) -> None:
        """Store multiple ``(ip, hostname)`` pairs in a single commit."""
        if not entries:
            return
        now = time.time()
        with self._get_conn() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO rdns_cache (ip, hostname, created_at) VALUES (?, ?, ?)",
                [(ip, hostname, now) for ip, hostname in entries],
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        cutoff = time.time() - self.ttl_seconds
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM rdns_cache WHERE created_at < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_cache: RDNSCache | None = None


def get_rdns_cache(db_path: str | Path | None = None, ttl_hours: int = _DEFAULT_TTL_HOURS) -> RDNSCache:
    """Get or create the global rDNS cache instance."""
    global _cache
    if _cache is None:
        if db_path is None:
            db_path = Path("data") / "rdns_cache.db"
        _cache = RDNSCache(db_path, ttl_hours)
    return _cache
