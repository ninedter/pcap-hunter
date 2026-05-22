"""Bearer-token auth with scope-based access control."""

from __future__ import annotations

import secrets
from enum import Enum

from app.api.settings import APISettings


class Scope(str, Enum):
    FULL = "full"
    FEED = "feed"


def _const_eq(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def check_bearer(authorization: str | None, settings: APISettings, required: Scope) -> Scope:
    """Validate the Authorization header and return the granted scope.

    Raises:
        ValueError: missing/malformed header or wrong key (-> 401)
        PermissionError: valid key, insufficient scope (-> 403)
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise ValueError("missing_or_malformed_auth")

    presented = authorization.removeprefix("Bearer ").strip()
    if not presented:
        raise ValueError("missing_or_malformed_auth")

    granted: Scope | None = None
    if settings.main_key and _const_eq(presented, settings.main_key):
        granted = Scope.FULL
    elif settings.feed_key and _const_eq(presented, settings.feed_key):
        granted = Scope.FEED

    if granted is None:
        raise ValueError("invalid_key")

    if required == Scope.FULL and granted != Scope.FULL:
        raise PermissionError("insufficient_scope")
    return granted
