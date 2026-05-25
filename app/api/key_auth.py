"""DB-aware bearer token authentication with rate limiting."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime

from app.api.auth import Scope
from app.api.key_models import APIKey
from app.api.key_repository import KeyRepository
from app.api.rate_limiter import RateLimiter
from app.api.settings import APISettings
from app.api.usage_tracker import UsageTracker


@dataclass
class AuthResult:
    """Result of a successful authentication."""

    scope: Scope
    key_name: str  # human-readable name for audit log
    api_key: APIKey | None  # None for env-var keys
    source: str  # "env:main", "env:feed", or "db"


def _const_eq(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def authenticate(
    authorization: str | None,
    settings: APISettings,
    key_repo: KeyRepository,
    rate_limiter: RateLimiter,
    usage_tracker: UsageTracker,
    required: Scope,
) -> AuthResult:
    """Authenticate a request and enforce rate limits.

    Auth flow:
    1. Parse Bearer token from Authorization header
    2. Try env-var keys first (constant-time compare, no DB hit)
    3. Fall back to DB key lookup (SHA-256 hash -> query)
    4. Check key status (expired, revoked)
    5. Check scope requirements
    6. Check rate limit (in-memory sliding window)
    7. Record usage

    Args:
        authorization: Authorization header value.
        settings: API settings with env-var keys.
        key_repo: Key repository for DB lookups.
        rate_limiter: Rate limiter instance.
        usage_tracker: Usage tracker instance.
        required: Minimum required scope.

    Returns:
        AuthResult with scope, key name, and optional APIKey.

    Raises:
        ValueError: Missing/invalid auth, expired key, revoked key (-> 401)
        PermissionError: Valid key but insufficient scope (-> 403)
        RateLimitError: Too many requests (-> 429)
    """
    # Step 1: Parse Bearer token
    if not authorization or not authorization.startswith("Bearer "):
        raise ValueError("missing_or_malformed_auth")

    presented = authorization.removeprefix("Bearer ").strip()
    if not presented:
        raise ValueError("missing_or_malformed_auth")

    # Step 2: Try env-var keys first (fast path, no DB)
    if settings.main_key and _const_eq(presented, settings.main_key):
        result = AuthResult(scope=Scope.FULL, key_name="env:main", api_key=None, source="env:main")
        _check_scope(result.scope, required)
        return result

    if settings.feed_key and _const_eq(presented, settings.feed_key):
        result = AuthResult(scope=Scope.FEED, key_name="env:feed", api_key=None, source="env:feed")
        _check_scope(result.scope, required)
        return result

    # Step 3: DB lookup by SHA-256 hash
    key_hash = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    api_key = key_repo.get_key_by_hash(key_hash)

    if api_key is None:
        raise ValueError("invalid_key")

    # Step 4: Check key status — use the same generic error for expired
    # and revoked keys so callers cannot distinguish key states.
    if api_key.revoked_at is not None:
        raise ValueError("invalid_key")

    if api_key.expires_at is not None:
        if datetime.now() > api_key.expires_at:
            raise ValueError("invalid_key")

    # Step 5: Check scope
    _check_scope(api_key.scope, required)

    # Step 6: Rate limit check (env keys are never rate-limited)
    allowed, retry_after = rate_limiter.check(api_key.id, api_key.rate_limit_rpm)
    if not allowed:
        raise RateLimitError(retry_after=retry_after)

    # Step 7: Record usage
    usage_tracker.record(api_key.id)

    return AuthResult(
        scope=api_key.scope,
        key_name=api_key.name,
        api_key=api_key,
        source="db",
    )


def _check_scope(granted: Scope, required: Scope) -> None:
    """Verify the granted scope meets the requirement."""
    if required == Scope.FULL and granted != Scope.FULL:
        raise PermissionError("insufficient_scope")


class RateLimitError(Exception):
    """Raised when a key exceeds its rate limit."""

    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after}s.")
