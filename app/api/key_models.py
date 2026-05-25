"""API key data models and generation utilities."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.api.auth import Scope


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (raw_key, key_hash, key_prefix).
        raw_key: Full key string like "phk_a1b2c3..."
        key_hash: SHA-256 hex digest of the raw key
        key_prefix: First 8 chars of raw_key for display
    """
    token = secrets.token_hex(16)
    raw_key = f"phk_{token}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    key_prefix = raw_key[:8]
    return raw_key, key_hash, key_prefix


@dataclass
class APIKey:
    """Database-backed API key."""

    id: str = ""
    key_hash: str = ""
    key_prefix: str = ""
    name: str = ""
    scope: Scope = Scope.FEED
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    total_requests: int = 0
    rate_limit_rpm: int | None = None
    source: str = "admin"

    @property
    def is_active(self) -> bool:
        """Check whether the key is currently usable."""
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and datetime.now() > self.expires_at:
            return False
        return True

    @property
    def status(self) -> str:
        """Human-readable status label.

        Returns:
            One of "revoked", "expired", "expiring_soon", or "active".
        """
        if self.revoked_at is not None:
            return "revoked"
        if self.expires_at is not None and datetime.now() > self.expires_at:
            return "expired"
        if self.expires_at is not None:
            if datetime.now() > self.expires_at - timedelta(days=7):
                return "expiring_soon"
        return "active"

    def to_dict(self, include_hash: bool = False) -> dict:
        """Convert to dict for API responses.

        Args:
            include_hash: If True, include key_hash (internal use only).
        """
        d = {
            "id": self.id,
            "prefix": self.key_prefix,
            "name": self.name,
            "scope": self.scope.value,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "total_requests": self.total_requests,
            "rate_limit_rpm": self.rate_limit_rpm,
            "status": self.status,
            "source": self.source,
        }
        if include_hash:
            d["key_hash"] = self.key_hash
        return d
