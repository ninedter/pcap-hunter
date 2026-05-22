"""FastAPI dependency injection — repo, queue, settings, auth."""

from __future__ import annotations

import os
from functools import lru_cache

from fastapi import Header, HTTPException

from app.api.auth import Scope, check_bearer
from app.api.queue import InProcessJobQueue
from app.api.settings import APISettings
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


def require_full_scope(
    authorization: str | None = Header(default=None),
) -> Scope:
    settings = get_settings()
    try:
        return check_bearer(authorization, settings, required=Scope.FULL)
    except ValueError:
        raise HTTPException(status_code=401, detail="missing_or_invalid_auth")
    except PermissionError:
        raise HTTPException(status_code=403, detail="insufficient_scope")


def require_feed_scope(
    authorization: str | None = Header(default=None),
) -> Scope:
    settings = get_settings()
    try:
        return check_bearer(authorization, settings, required=Scope.FEED)
    except ValueError:
        raise HTTPException(status_code=401, detail="missing_or_invalid_auth")
    except PermissionError:
        raise HTTPException(status_code=403, detail="insufficient_scope")
