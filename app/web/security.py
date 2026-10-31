"""Browser request boundaries for the loopback-only workbench."""

from __future__ import annotations

from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            return None
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


class LocalWorkbenchMiddleware(BaseHTTPMiddleware):
    """Reject rebinding hosts, cross-origin API calls, and simple form writes.

    This process deliberately trusts local clients. Agents and remote clients
    must use the authenticated integrations API rather than this browser API.
    """

    async def dispatch(self, request: Request, call_next):
        target = _origin(f"{request.scope['scheme']}://{request.headers.get('host', '')}")
        if target is None or target[1] not in _LOCAL_HOSTS:
            return JSONResponse({"detail": "local_workbench_host_required"}, status_code=400)

        if request.url.path.startswith("/api/ui/"):
            origin = request.headers.get("origin")
            fetch_site = request.headers.get("sec-fetch-site")
            if (origin is not None and _origin(origin) != target) or fetch_site in {"cross-site", "same-site"}:
                return JSONResponse({"detail": "same_origin_required"}, status_code=403)
            if request.method not in _SAFE_METHODS and request.url.path != "/api/ui/uploads":
                content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    return JSONResponse({"detail": "json_content_type_required"}, status_code=415)
                chunks, length = [], 0
                async for chunk in request.stream():
                    length += len(chunk)
                    if length > 65536:
                        return JSONResponse({"detail": "json_request_too_large"}, status_code=413)
                    chunks.append(chunk)
                request._body = b"".join(chunks)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.url.path.startswith("/api/ui/"):
            response.headers["Cache-Control"] = "no-store"
        return response
