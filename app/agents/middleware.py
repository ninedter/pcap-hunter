"""Bound JSON requests and record agent operations without capture content."""

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.agents.registry import AgentRegistry
from app.api.deps import get_repo


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
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            if getattr(request.state, "agent_id", None):
                response.headers["Cache-Control"] = "no-store"
            return response
        finally:
            actor_id = getattr(request.state, "agent_id", None)
            if actor_id:
                AgentRegistry(get_repo()).audit(
                    actor_id,
                    request.method + " " + request.url.path,
                    getattr(request.state, "agent_case", None),
                    status,
                    getattr(request.state, "request_id", ""),
                )
