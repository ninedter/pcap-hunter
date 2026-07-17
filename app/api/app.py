"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import logging
import os
import pathlib
import re
import secrets
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.auth import Scope
from app.api.deps import get_key_repo, get_settings, get_usage_tracker
from app.api.queue import recover_stale_running_jobs
from app.api.routers import admin, cases, health, iocs, jobs, pcaps
from app.api.settings import FULL_SCOPE_RECOVERY_HINT, NoKeysConfiguredError

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hook — recover stale jobs on boot, schedule GC."""
    from app.api.deps import get_repo

    n = recover_stale_running_jobs(get_repo(), stale_after_seconds=120)
    if n:
        logger.warning("Recovered %d stale running jobs at startup", n)

    # Schedule hourly GC sweep
    gc_task = asyncio.create_task(_gc_loop())

    # Schedule usage tracker flush every 60 seconds
    flush_task = asyncio.create_task(_usage_flush_loop())

    yield

    # Shutdown: final flush before stopping
    flush_task.cancel()
    gc_task.cancel()
    try:
        tracker = get_usage_tracker()
        key_repo = get_key_repo()
        tracker.flush(key_repo)
    except Exception:
        logger.exception("Final usage flush failed")


async def _usage_flush_loop() -> None:
    """Flush in-memory usage counters to DB every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        try:
            tracker = get_usage_tracker()
            key_repo = get_key_repo()
            tracker.flush(key_repo)
        except Exception:
            logger.exception("Usage flush failed")


async def _gc_loop() -> None:
    """Hourly garbage collection for retention policies."""
    from app.api.deps import get_repo
    from app.api.gc import gc_sweep

    settings = get_settings()
    uploads = pathlib.Path(os.environ.get("PCAP_HUNTER_API_UPLOADS_DIR", "data/api_uploads"))
    artifacts = pathlib.Path(os.environ.get("PCAP_HUNTER_API_ARTIFACTS_DIR", "data/carved"))
    reports = pathlib.Path(
        os.environ.get("PCAP_HUNTER_API_REPORTS_DIR") or os.environ.get("PCAP_HUNTER_REPORTS_DIR", "data/reports")
    )

    while True:
        try:
            gc_sweep(
                repo=get_repo(), settings=settings, uploads_dir=uploads, artifacts_dir=artifacts, reports_dir=reports
            )
        except Exception:
            logger.exception("gc_sweep failed")
        await asyncio.sleep(3600)


def _title_for_status(status: int) -> str:
    return {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        410: "Gone",
        413: "Payload Too Large",
        415: "Unsupported Media Type",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(status, "Error")


def _identify_env_key(request: Request, settings) -> str:
    """Identify environment-backed keys without duplicating database authentication."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "-"
    presented = auth.removeprefix("Bearer ").strip()
    if settings.main_key and secrets.compare_digest(presented, settings.main_key):
        return "env:main"
    if settings.feed_key and secrets.compare_digest(presented, settings.feed_key):
        return "env:feed"
    return "-"


_REQUEST_ID_RE = re.compile(r"[^a-zA-Z0-9\-_.]")
_REQUEST_ID_MAX_LEN = 128


def _sanitize_request_id(value: str) -> str:
    """Sanitize X-Request-ID to prevent header injection and log forging."""
    return _REQUEST_ID_RE.sub("", value)[:_REQUEST_ID_MAX_LEN]


def _request_id_of(request: Request) -> str:
    """Sanitized request ID stored by the middleware, or sanitize the raw header if it hasn't run yet."""
    rid = getattr(request.state, "request_id", None) or ""
    if not rid:
        raw = request.headers.get("X-Request-ID", "")
        rid = _sanitize_request_id(raw) if raw else ""
    return rid


def create_app() -> FastAPI:
    """Build the FastAPI app. Reads APISettings from env (refuses to start without keys)."""
    settings = get_settings()

    # Ensure at least one auth source exists (env vars OR DB keys).
    key_repo = get_key_repo()
    if not settings.main_key and not settings.feed_key and key_repo.count_active_keys() == 0:
        raise NoKeysConfiguredError(
            "No auth keys configured. Set PCAP_HUNTER_API_KEY / PCAP_HUNTER_FEED_KEY "
            "env vars, or create at least one DB-backed key before starting."
        )

    # Make app.* logs (audit middleware, repository, worker stages) visible under
    # uvicorn, which configures only its own loggers.
    from app.utils.logger import get_logger

    get_logger("app")

    if not settings.main_key and key_repo.count_active_keys(scope=Scope.FULL.value) == 0:
        logger.warning(
            "No full-scope auth source configured (no PCAP_HUNTER_API_KEY env var and no active "
            "full-scope DB key) — ingress and admin endpoints will reject every request until one exists. %s",
            FULL_SCOPE_RECOVERY_HINT,
        )
    if not settings.main_key and not settings.feed_key:
        logger.warning(
            "Booting without env-var API keys — auth relies entirely on %d DB-backed key(s). "
            "If this is unintentional, the compose file may have been re-upped without the key env vars.",
            key_repo.count_active_keys(),
        )

    app = FastAPI(
        title="PCAP Hunter Integrations API",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/v1/openapi.json",
        lifespan=_lifespan,
    )

    # Conditional CORS middleware
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "If-None-Match", "X-Request-ID"],
        )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        raw_rid = request.headers.get("X-Request-ID")
        rid = _sanitize_request_id(raw_rid) if raw_rid else uuid.uuid4().hex
        if not rid:  # sanitisation stripped everything
            rid = uuid.uuid4().hex
        request.state.request_id = rid  # stash for exception handler
        fallback_key_name = _identify_env_key(request, settings)
        start = time.monotonic()
        response = await call_next(request)
        key_name = getattr(request.state, "key_name", fallback_key_name)
        response.headers["X-Request-ID"] = rid
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "%s %s -> %d (%dms) request_id=%s key_name=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            rid,
            key_name,
        )
        return response

    # Registered for the *Starlette* base class so routing-raised errors
    # (405 method-not-allowed, 404 no-route) get problem+json too —
    # fastapi.HTTPException subclasses it, so app-raised errors still match.
    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict):
            code = detail.get("code", "http_error")
            title = detail.get("title", _title_for_status(exc.status_code))
            detail_text = detail.get("detail", "")
            extras = {k: v for k, v in detail.items() if k not in {"code", "title", "detail"}}
        else:
            code = (
                re.sub(r"[^a-z0-9_.\-]+", "_", detail.lower()).strip("_") if isinstance(detail, str) else "http_error"
            )
            title = _title_for_status(exc.status_code)
            detail_text = str(detail) if not isinstance(detail, str) else detail
            extras = {}

        rid = _request_id_of(request)
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

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        rid = _request_id_of(request)
        # Deliberately drop the raw `input` values — submitted secrets must
        # not echo back into error bodies.
        errors = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()
        ]
        body = {
            "type": "https://pcap-hunter.io/errors/validation_error",
            "title": "Unprocessable Entity",
            "status": 422,
            "detail": "Request validation failed.",
            "instance": str(request.url.path),
            "code": "validation_error",
            "request_id": rid,
            "errors": errors,
        }
        return JSONResponse(status_code=422, content=body, media_type="application/problem+json")

    app.include_router(health.router)
    app.include_router(pcaps.router)
    app.include_router(jobs.router)
    app.include_router(cases.router)
    app.include_router(iocs.router)
    app.include_router(admin.router)
    return app
