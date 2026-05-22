"""FastAPI application factory."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.api.deps import get_settings
from app.api.queue import recover_stale_running_jobs
from app.api.routers import cases, health, iocs, jobs, pcaps

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hook — recover stale jobs on boot."""
    from app.api.deps import get_repo

    n = recover_stale_running_jobs(get_repo(), stale_after_seconds=120)
    if n:
        logger.warning("Recovered %d stale running jobs at startup", n)
    yield


def _title_for_status(status: int) -> str:
    return {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        410: "Gone",
        413: "Payload Too Large",
        415: "Unsupported Media Type",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(status, "Error")


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

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict):
            code = detail.get("code", "http_error")
            title = detail.get("title", _title_for_status(exc.status_code))
            detail_text = detail.get("detail", "")
            extras = {k: v for k, v in detail.items() if k not in {"code", "title", "detail"}}
        else:
            code = str(detail) if isinstance(detail, str) else "http_error"
            title = _title_for_status(exc.status_code)
            detail_text = str(detail) if not isinstance(detail, str) else detail
            extras = {}

        rid = request.headers.get("X-Request-ID", "")
        body = {
            "type": f"https://pcap-hunter.io/errors/{code}",
            "title": title,
            "status": exc.status_code,
            "detail": detail_text,
            "instance": str(request.url.path),
            "code": code,
            "request_id": rid,
            **extras,
        }
        headers = dict(exc.headers) if exc.headers else {}
        return JSONResponse(
            status_code=exc.status_code,
            content=body,
            media_type="application/problem+json",
            headers=headers,
        )

    app.include_router(health.router)
    app.include_router(pcaps.router)
    app.include_router(jobs.router)
    app.include_router(cases.router)
    app.include_router(iocs.router)
    return app
