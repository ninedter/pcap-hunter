"""Repository layer for API key management."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from app.api.auth import Scope
from app.api.key_models import APIKey
from app.utils.logger import get_logger

logger = get_logger(__name__)


class KeyRepository:
    """Repository for API key CRUD and usage tracking."""

    def __init__(self, db_path: str | None = None):
        """Initialize repository with database path.

        Args:
            db_path: Path to SQLite database. Defaults to data/api_keys.db
        """
        if db_path:
            self._db_path = Path(db_path)
        else:
            self._db_path = Path(__file__).parent.parent.parent / "data" / "api_keys.db"

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Initialize database schema."""
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    name TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'feed',
                    description TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    revoked_at TIMESTAMP,
                    last_used_at TIMESTAMP,
                    total_requests INTEGER DEFAULT 0,
                    rate_limit_rpm INTEGER,
                    source TEXT DEFAULT 'admin'
                );

                CREATE TABLE IF NOT EXISTS api_key_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
                    date TEXT NOT NULL,
                    requests INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(key_id, date)
                );

                CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_api_key_usage_key_date ON api_key_usage(key_id, date);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ==================== Key CRUD ====================

    def create_key(self, key: APIKey) -> str:
        """Create a new API key record.

        Args:
            key: APIKey object to persist.

        Returns:
            Generated key ID.
        """
        if not key.id:
            key.id = f"k_{uuid.uuid4().hex[:8]}"

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO api_keys
                (id, key_hash, key_prefix, name, scope, description,
                 created_at, expires_at, revoked_at, last_used_at,
                 total_requests, rate_limit_rpm, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key.id,
                    key.key_hash,
                    key.key_prefix,
                    key.name,
                    key.scope.value,
                    key.description,
                    key.created_at.isoformat(),
                    key.expires_at.isoformat() if key.expires_at else None,
                    key.revoked_at.isoformat() if key.revoked_at else None,
                    key.last_used_at.isoformat() if key.last_used_at else None,
                    key.total_requests,
                    key.rate_limit_rpm,
                    key.source,
                ),
            )
            conn.commit()
            logger.info("Created API key: %s (prefix=%s)", key.id, key.key_prefix)
            return key.id
        finally:
            conn.close()

    def get_key_by_id(self, key_id: str) -> APIKey | None:
        """Get an API key by its ID.

        Args:
            key_id: The key ID.

        Returns:
            APIKey object or None if not found.
        """
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if not row:
                return None
            return self._row_to_key(dict(row))
        finally:
            conn.close()

    def get_key_by_hash(self, key_hash: str) -> APIKey | None:
        """Look up an API key by its SHA-256 hash (used during auth).

        Args:
            key_hash: SHA-256 hex digest of the raw key.

        Returns:
            APIKey object or None if not found.
        """
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
            if not row:
                return None
            return self._row_to_key(dict(row))
        finally:
            conn.close()

    def list_keys(self, include_revoked: bool = False) -> list[APIKey]:
        """List API keys sorted by creation date (newest first).

        Args:
            include_revoked: If True, include revoked keys in results.

        Returns:
            List of APIKey objects.
        """
        conn = self._get_conn()
        try:
            if include_revoked:
                rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC"
                ).fetchall()
            return [self._row_to_key(dict(row)) for row in rows]
        finally:
            conn.close()

    def update_key(self, key_id: str, **fields: object) -> APIKey | None:
        """Partially update an API key.

        Only the following fields may be updated: name, scope, description,
        rate_limit_rpm, expires_at.

        Args:
            key_id: The key ID to update.
            **fields: Field names and their new values.

        Returns:
            Updated APIKey object, or None if not found.
        """
        allowed = {"name", "scope", "description", "rate_limit_rpm", "expires_at"}
        to_set = {k: v for k, v in fields.items() if k in allowed}
        if not to_set:
            return self.get_key_by_id(key_id)

        conn = self._get_conn()
        try:
            set_clauses = []
            params: list[object] = []
            for col, val in to_set.items():
                set_clauses.append(f"{col} = ?")
                if col == "scope" and isinstance(val, Scope):
                    params.append(val.value)
                elif col == "expires_at" and isinstance(val, datetime):
                    params.append(val.isoformat())
                else:
                    params.append(val)

            params.append(key_id)
            conn.execute(
                f"UPDATE api_keys SET {', '.join(set_clauses)} WHERE id = ?",  # noqa: S608
                params,
            )
            conn.commit()
            logger.info("Updated API key: %s fields=%s", key_id, list(to_set.keys()))
            return self.get_key_by_id(key_id)
        finally:
            conn.close()

    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key by setting its revoked_at timestamp.

        Args:
            key_id: The key ID to revoke.

        Returns:
            True if the key was found and revoked, False otherwise.
        """
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (datetime.now().isoformat(), key_id),
            )
            conn.commit()
            if cursor.rowcount > 0:
                logger.info("Revoked API key: %s", key_id)
                return True
            return False
        finally:
            conn.close()

    # ==================== Usage Tracking ====================

    def increment_usage(self, key_id: str, date_str: str, count: int = 1) -> None:
        """Increment the daily request counter for a key.

        Uses INSERT OR UPDATE (upsert) on the api_key_usage table and also
        increments total_requests on the api_keys row.

        Args:
            key_id: The key ID.
            date_str: Date string in YYYY-MM-DD format.
            count: Number of requests to add.
        """
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO api_key_usage (key_id, date, requests)
                VALUES (?, ?, ?)
                ON CONFLICT(key_id, date) DO UPDATE SET requests = requests + excluded.requests
                """,
                (key_id, date_str, count),
            )
            conn.execute(
                "UPDATE api_keys SET total_requests = total_requests + ? WHERE id = ?",
                (count, key_id),
            )
            conn.commit()
        finally:
            conn.close()

    def touch_key_last_used(self, key_id: str, timestamp: float | None = None) -> None:
        """Update the last_used_at field for a key.

        Args:
            key_id: The key ID.
            timestamp: Unix timestamp. If None, uses current time.
        """
        if timestamp is not None:
            dt = datetime.fromtimestamp(timestamp)
        else:
            dt = datetime.now()

        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (dt.isoformat(), key_id),
            )
            conn.commit()
        finally:
            conn.close()

    def get_usage(self, key_id: str, days: int = 30) -> list[dict]:
        """Get daily usage history for a single key.

        Args:
            key_id: The key ID.
            days: Number of past days to retrieve.

        Returns:
            List of dicts with "date" and "requests" keys, ordered by date.
        """
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT date, requests FROM api_key_usage WHERE key_id = ? AND date >= ? ORDER BY date",
                (key_id, cutoff),
            ).fetchall()
            return [{"date": row["date"], "requests": row["requests"]} for row in rows]
        finally:
            conn.close()

    def get_usage_summary(self, days: int = 30) -> list[dict]:
        """Get aggregated daily usage across all keys.

        Args:
            days: Number of past days to aggregate.

        Returns:
            List of dicts with "date" and "requests" keys, ordered by date.
        """
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """
                SELECT date, SUM(requests) as requests
                FROM api_key_usage
                WHERE date >= ?
                GROUP BY date
                ORDER BY date
                """,
                (cutoff,),
            ).fetchall()
            return [{"date": row["date"], "requests": row["requests"]} for row in rows]
        finally:
            conn.close()

    def count_active_keys(self) -> int:
        """Count keys that are neither revoked nor expired.

        Returns:
            Number of currently active keys.
        """
        now = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            row = conn.execute(
                """
                SELECT COUNT(*) FROM api_keys
                WHERE revoked_at IS NULL
                AND (expires_at IS NULL OR expires_at > ?)
                """,
                (now,),
            ).fetchone()
            return int(row[0])
        finally:
            conn.close()

    def get_expiring_keys(self, within_days: int = 7) -> list[APIKey]:
        """Get active keys that will expire within the given window.

        Args:
            within_days: Number of days to look ahead.

        Returns:
            List of APIKey objects expiring soon.
        """
        now = datetime.now()
        deadline = (now + timedelta(days=within_days)).isoformat()
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM api_keys
                WHERE revoked_at IS NULL
                AND expires_at IS NOT NULL
                AND expires_at > ?
                AND expires_at <= ?
                ORDER BY expires_at
                """,
                (now.isoformat(), deadline),
            ).fetchall()
            return [self._row_to_key(dict(row)) for row in rows]
        finally:
            conn.close()

    # ==================== Helpers ====================

    @staticmethod
    def _row_to_key(row: dict) -> APIKey:
        """Convert a database row dict to an APIKey dataclass.

        Args:
            row: Dict from sqlite3.Row.

        Returns:
            Populated APIKey instance.
        """
        created_at = row.get("created_at")
        expires_at = row.get("expires_at")
        revoked_at = row.get("revoked_at")
        last_used_at = row.get("last_used_at")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if isinstance(revoked_at, str):
            revoked_at = datetime.fromisoformat(revoked_at)
        if isinstance(last_used_at, str):
            last_used_at = datetime.fromisoformat(last_used_at)

        scope_str = row.get("scope", "feed")
        try:
            scope = Scope(scope_str)
        except ValueError:
            scope = Scope.FEED

        return APIKey(
            id=row["id"],
            key_hash=row.get("key_hash") or "",
            key_prefix=row.get("key_prefix") or "",
            name=row.get("name") or "",
            scope=scope,
            description=row.get("description") or "",
            created_at=created_at or datetime.now(),
            expires_at=expires_at,
            revoked_at=revoked_at,
            last_used_at=last_used_at,
            total_requests=row.get("total_requests") or 0,
            rate_limit_rpm=row.get("rate_limit_rpm"),
            source=row.get("source") or "admin",
        )
