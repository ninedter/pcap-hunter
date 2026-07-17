"""Bearer-token auth with scope-based access control."""

from __future__ import annotations

from enum import Enum


class Scope(str, Enum):
    FULL = "full"
    FEED = "feed"
