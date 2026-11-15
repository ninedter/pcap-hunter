"""API key data models and generation utilities."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.api.auth import Scope

# Accepted range for a key expiry (wall-clock value, any offset). Platform time
# conversion fails outside roughly 1970..9999 and a common "never expires" sentinel
# such as 9999-12-31T23:59:59 overflows on hosts east or west of UTC, so the boundary
# accepts 1971-01-01 up to (not including) 9000-01-01. To make a key never expire,
# leave ``expires_at`` unset.
MIN_EXPIRES_AT = datetime(1971, 1, 1)
MAX_EXPIRES_AT = datetime(9000, 1, 1)
# Stored form used for an unreadable or out-of-range expiry: already expired (fail closed).
EXPIRED_SENTINEL = datetime(1971, 1, 2)
_CONVERSION_ERRORS = (ValueError, OverflowError, OSError)


def expiry_in_range(value: datetime) -> bool:
    """Whether the wall-clock part of ``value`` is inside the accepted expiry range."""
    return MIN_EXPIRES_AT <= value.replace(tzinfo=None) < MAX_EXPIRES_AT


def expiry_instant(value: datetime) -> datetime | None:
    """``value`` as an offset-aware instant, or None when it cannot be represented.

    Read-side code uses this instead of ``as_aware`` so one bad row can never raise
    out of an expiry check; callers treat None as already expired.
    """
    try:
        if not expiry_in_range(value):
            return None
        return as_aware(value)
    except _CONVERSION_ERRORS:
        return None


def as_aware(value: datetime) -> datetime:
    """Return ``value`` as an offset-aware datetime.

    Key timestamps have always been written with naive ``datetime.now()``, so a
    naive value means local time. Offset-aware values pass through unchanged.
    """
    return value if value.tzinfo is not None else value.astimezone()


def to_stored_local(value: datetime) -> datetime:
    """Normalise a key timestamp to the stored form: naive local time.

    Keeping one stored form keeps SQL text comparisons, legacy rows, and the
    legacy key-management tab consistent; comparisons still go through
    ``as_aware`` so a stray offset-aware value can never raise.
    """
    return value.astimezone().replace(tzinfo=None) if value.tzinfo is not None else value


def parse_key_timestamp(text: str) -> datetime:
    """Parse a client-supplied ISO 8601 instant into the stored form.

    Accepts offsets and a trailing ``Z``; a value without an offset is read as
    server-local time (how keys have always been stored).

    Raises:
        ValueError: If ``text`` is not a valid ISO 8601 datetime, or lies outside
            ``MIN_EXPIRES_AT`` .. ``MAX_EXPIRES_AT``.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty timestamp")
    parsed = datetime.fromisoformat(text.strip())
    if not expiry_in_range(parsed):
        raise ValueError("timestamp out of range")
    try:
        stored = to_stored_local(parsed)
    except (OverflowError, OSError) as exc:
        raise ValueError("timestamp out of range") from exc
    if not expiry_in_range(stored) or expiry_instant(stored) is None:
        raise ValueError("timestamp out of range")
    return stored


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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

    def _expired(self, margin: timedelta = timedelta(0)) -> bool:
        """Whether the key expires within ``margin``; an unrepresentable expiry counts as expired."""
        if self.expires_at is None:
            return False
        instant = expiry_instant(self.expires_at)
        return instant is None or _utc_now() > instant - margin

    @property
    def is_active(self) -> bool:
        """Check whether the key is currently usable."""
        return self.revoked_at is None and not self._expired()

    @property
    def status(self) -> str:
        """Human-readable status label.

        Returns:
            One of "revoked", "expired", "expiring_soon", or "active".
        """
        if self.revoked_at is not None:
            return "revoked"
        if self._expired():
            return "expired"
        if self._expired(timedelta(days=7)):
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
