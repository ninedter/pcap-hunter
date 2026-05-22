"""FastAPI application factory."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app.api.deps import get_settings
from app.api.queue import recover_stale_running_jobs
from app.api.routers import health

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hook — recover stale jobs on boot."""
    from app.api.deps import get_repo

    n = recover_stale_running_jobs(get_repo(), stale_after_seconds=120)
    if n:
        logger.warning("Recovered %d stale running jobs at startup", n)
    yield


def create_app() -> FastAPI:
    """Build the FastAPI app. Reads APISettings from env (refuses to start without keys)."""
    get_settings()  # raises NoKeysConfiguredError if neither key is set

    app = FastAPI(
        title="PCAP Hunter Integrations API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/v1/openapi.json",
        lifespan=_lifespan,
    )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        start = time.monotonic()
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "%s %s -> %d (%dms) request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            rid,
        )
        return response

    app.include_router(health.router)
    return app
