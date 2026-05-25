"""FastAPI dependency injection — repo, queue, settings, auth."""

from __future__ import annotations

import os
from functools import lru_cache

from fastapi import Header, HTTPException

from app.api.auth import Scope
from app.api.key_auth import RateLimitError, authenticate
from app.api.key_repository import KeyRepository
from app.api.queue import InProcessJobQueue
from app.api.rate_limiter import RateLimiter
from app.api.settings import APISettings
from app.api.usage_tracker import UsageTracker
from app.database.repository import CaseRepository


@lru_cache(maxsize=1)
def get_settings() -> APISettings:
    return APISettings.from_env()


@lru_cache(maxsize=1)
def get_repo() -> CaseRepository:
    db_path = os.environ.get("PCAP_HUNTER_API_DB_PATH")
    return CaseRepository(db_path=db_path)


@lru_cache(maxsize=1)
def get_queue() -> InProcessJobQueue:
    settings = get_settings()
    return InProcessJobQueue(
        repo=get_repo(),
        max_workers=settings.workers,
        queue_depth=settings.queue_depth,
    )


@lru_cache(maxsize=1)
def get_key_repo() -> KeyRepository:
    """Singleton KeyRepository for API key management."""
    db_path = os.environ.get("PCAP_HUNTER_API_DB_PATH")
    return KeyRepository(db_path=db_path)


@lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    """Singleton in-memory rate limiter."""
    return RateLimiter()


@lru_cache(maxsize=1)
def get_usage_tracker() -> UsageTracker:
    """Singleton in-memory usage tracker."""
    return UsageTracker()


def _do_auth(authorization: str | None, required: Scope) -> Scope:
    """Shared auth logic for both scope levels."""
    settings = get_settings()
    key_repo = get_key_repo()
    rate_limiter = get_rate_limiter()
    usage_tracker = get_usage_tracker()
    try:
        result = authenticate(
            authorization=authorization,
            settings=settings,
            key_repo=key_repo,
            rate_limiter=rate_limiter,
            usage_tracker=usage_tracker,
            required=required,
        )
        return result.scope
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except PermissionError:
        raise HTTPException(status_code=403, detail="insufficient_scope")
    except RateLimitError as exc:
        raise HTTPException(
            status_code=429,
            detail={"code": "rate_limit_exceeded", "title": "Too Many Requests", "detail": str(exc)},
            headers={"Retry-After": str(exc.retry_after)},
        )


def require_full_scope(
    authorization: str | None = Header(default=None),
) -> Scope:
    return _do_auth(authorization, Scope.FULL)


def require_feed_scope(
    authorization: str | None = Header(default=None),
) -> Scope:
    return _do_auth(authorization, Scope.FEED)
