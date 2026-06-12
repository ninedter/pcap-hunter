"""Admin endpoints — API key management and usage metrics."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.auth import Scope
from app.api.deps import get_key_repo, get_rate_limiter, get_settings, require_full_scope
from app.api.key_models import APIKey, generate_api_key
from app.api.key_repository import KeyRepository
from app.api.rate_limiter import RateLimiter
from app.api.settings import FULL_SCOPE_RECOVERY_HINT, APISettings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

_LOCKOUT_WARNING = (
    "No full-scope auth source remains — ingress and admin endpoints (including key "
    "creation) will reject every request. " + FULL_SCOPE_RECOVERY_HINT
)


def _full_scope_lockout_warning(settings: APISettings, repo: KeyRepository) -> str | None:
    """After a key mutation: warn if no full-scope auth source remains.

    Args:
        settings: Current API settings (checked for env main_key).
        repo: KeyRepository for counting active full-scope DB keys.

    Returns:
        Warning message string if a lockout condition is detected, else None.
    """
    if settings.main_key:
        return None
    # Advisory check only — post-mutation count on a separate connection; gates no enforcement.
    if repo.count_active_keys(scope=Scope.FULL.value) > 0:
        return None
    logger.warning(_LOCKOUT_WARNING)
    return _LOCKOUT_WARNING


# ==================== Request schemas ====================


class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scope: str = Field(default="feed", pattern=r"^(full|feed)$")
    description: str = Field(default="", max_length=500)
    rate_limit_rpm: int | None = Field(default=None, ge=1)
    expires_in_days: int | None = Field(default=None, ge=1)


class UpdateKeyRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    scope: str | None = Field(default=None, pattern=r"^(full|feed)$")
    description: str | None = Field(default=None, max_length=500)
    rate_limit_rpm: int | None = Field(default=None, ge=0)  # 0 = clear to unlimited
    expires_at: str | None = Field(default=None)


# ==================== Endpoints ====================


@router.post("/keys", status_code=201)
def create_key(
    body: CreateKeyRequest,
    _scope: Scope = Depends(require_full_scope),
    repo: KeyRepository = Depends(get_key_repo),
) -> dict:
    """Create a new API key. The raw key is only shown once in the response."""
    raw_key, key_hash, key_prefix = generate_api_key()

    expires_at = None
    if body.expires_in_days is not None:
        expires_at = datetime.now() + timedelta(days=body.expires_in_days)

    api_key = APIKey(
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=body.name,
        scope=Scope(body.scope),
        description=body.description,
        created_at=datetime.now(),
        expires_at=expires_at,
        rate_limit_rpm=body.rate_limit_rpm,
    )

    key_id = repo.create_key(api_key)

    return {
        "id": key_id,
        "key": raw_key,
        "name": api_key.name,
        "prefix": key_prefix,
        "scope": api_key.scope.value,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "rate_limit_rpm": api_key.rate_limit_rpm,
    }


@router.get("/keys")
def list_keys(
    include_revoked: bool = Query(default=False),
    _scope: Scope = Depends(require_full_scope),
    repo: KeyRepository = Depends(get_key_repo),
) -> list[dict]:
    """List all API keys (no raw key or hash exposed)."""
    keys = repo.list_keys(include_revoked=include_revoked)
    return [k.to_dict(include_hash=False) for k in keys]


@router.get("/keys/{key_id}")
def get_key(
    key_id: str,
    _scope: Scope = Depends(require_full_scope),
    repo: KeyRepository = Depends(get_key_repo),
) -> dict:
    """Get details for a single API key."""
    key = repo.get_key_by_id(key_id)
    if key is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "key_not_found", "title": "Not Found", "detail": f"No key with id '{key_id}'."},
        )
    return key.to_dict(include_hash=False)


@router.patch("/keys/{key_id}")
def update_key(
    key_id: str,
    body: UpdateKeyRequest,
    _scope: Scope = Depends(require_full_scope),
    repo: KeyRepository = Depends(get_key_repo),
    settings: APISettings = Depends(get_settings),
) -> dict:
    """Partially update an API key's mutable fields."""
    existing = repo.get_key_by_id(key_id)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "key_not_found", "title": "Not Found", "detail": f"No key with id '{key_id}'."},
        )

    updates: dict[str, object] = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.scope is not None:
        updates["scope"] = Scope(body.scope)
    if body.description is not None:
        updates["description"] = body.description
    if body.rate_limit_rpm is not None:
        # 0 means "clear to unlimited" (stored as NULL in DB)
        updates["rate_limit_rpm"] = body.rate_limit_rpm if body.rate_limit_rpm > 0 else None
    if body.expires_at is not None:
        try:
            updates["expires_at"] = datetime.fromisoformat(body.expires_at)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "invalid_expires_at",
                    "title": "Bad Request",
                    "detail": "expires_at must be a valid ISO 8601 datetime string.",
                },
            )

    updated = repo.update_key(key_id, **updates)
    if updated is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "key_not_found", "title": "Not Found", "detail": f"No key with id '{key_id}'."},
        )
    response = dict(updated.to_dict(include_hash=False))
    warning = _full_scope_lockout_warning(settings, repo)
    if warning:
        response["warning"] = warning
    return response


@router.delete("/keys/{key_id}")
def revoke_key(
    key_id: str,
    _scope: Scope = Depends(require_full_scope),
    repo: KeyRepository = Depends(get_key_repo),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    settings: APISettings = Depends(get_settings),
) -> dict:
    """Revoke an API key (soft delete) and clear its rate limit state."""
    existing = repo.get_key_by_id(key_id)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "key_not_found", "title": "Not Found", "detail": f"No key with id '{key_id}'."},
        )

    repo.revoke_key(key_id)
    rate_limiter.reset(key_id)
    response: dict = {"status": "revoked", "id": key_id}
    warning = _full_scope_lockout_warning(settings, repo)
    if warning:
        response["warning"] = warning
    return response


@router.get("/keys/{key_id}/usage")
def get_key_usage(
    key_id: str,
    days: int = Query(default=30, ge=1, le=365),
    _scope: Scope = Depends(require_full_scope),
    repo: KeyRepository = Depends(get_key_repo),
) -> dict:
    """Get daily usage history for a single API key."""
    existing = repo.get_key_by_id(key_id)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "key_not_found", "title": "Not Found", "detail": f"No key with id '{key_id}'."},
        )

    usage = repo.get_usage(key_id, days=days)
    return {"key_id": key_id, "usage": usage}


@router.get("/usage/summary")
def get_usage_summary(
    days: int = Query(default=30, ge=1, le=365),
    _scope: Scope = Depends(require_full_scope),
    repo: KeyRepository = Depends(get_key_repo),
) -> dict:
    """Get aggregated daily usage across all API keys."""
    usage = repo.get_usage_summary(days=days)
    return {"usage": usage}
