"""Bound JSON requests and record agent operations without capture content.

Audit-failure policy (deliberate): the audit trail is a security control, so an
authenticated agent request whose audit record cannot be written **fails
closed**. The prepared response is discarded and the agent receives
``503 agent_audit_unavailable`` instead, which means evidence is never disclosed
without a record. A mutation that already committed stays committed; every agent
write is idempotent (``Idempotency-Key`` or a repeatable cancel), so the agent
retries and the retry is audited. The failure is logged, never swallowed.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.agents.registry import AgentRegistry
from app.api.deps import get_repo

logger = logging.getLogger(__name__)

AUDIT_UNAVAILABLE = "agent_audit_unavailable"


def write_audit(actor_id, action, case_id, status, request_id):
    """Append one audit row. Runs in a worker thread, never on the event loop."""
    AgentRegistry(get_repo()).audit(actor_id, action, case_id, status, request_id)


class AgentBoundaryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.headers.get("content-type", "").lower()
            if not content_type.startswith("multipart/form-data"):
                body, length = [], 0
                async for chunk in request.stream():
                    length += len(chunk)
                    if length > 65536:
                        return JSONResponse({"detail": "json_request_too_large"}, status_code=413)
                    body.append(chunk)
                request._body = b"".join(body)
        status, recorded = 500, True
        try:
            response = await call_next(request)
            status = response.status_code
        finally:
            # Also reached when the handler raised: that failure is audited as a
            # 500 and then propagates unchanged.
            recorded = await self._audit(request, status)
        if not recorded:
            return JSONResponse(
                {"detail": AUDIT_UNAVAILABLE},
                status_code=503,
                headers={"Cache-Control": "no-store", "Retry-After": "5"},
            )
        if getattr(request.state, "agent_id", None):
            response.headers["Cache-Control"] = "no-store"
        return response

    @staticmethod
    async def _audit(request, status):
        """Record an authenticated agent operation.

        The insert takes SQLite's write lock (up to the 30 s busy timeout), so
        it runs in a worker thread instead of stalling the event loop.

        Returns:
            False only when an agent request could not be audited; the caller
            then withholds the response.
        """
        actor_id = getattr(request.state, "agent_id", None)
        if not actor_id:
            return True
        try:
            await asyncio.to_thread(
                write_audit,
                actor_id,
                request.method + " " + request.url.path,
                getattr(request.state, "agent_case", None),
                status,
                getattr(request.state, "request_id", ""),
            )
        except (sqlite3.Error, OSError):
            logger.exception(
                "Agent audit write failed; withholding the response (actor=%s request=%s outcome=%s)",
                actor_id,
                getattr(request.state, "request_id", ""),
                status,
            )
            return False
        return True
