"""Browser request boundaries for the loopback-only workbench."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Content-Security-Policy for the built React workbench and its UI API.
#
# The AI report is attacker-influenced text rendered as markdown in this
# origin, next to an unauthenticated local API. The policy makes the browser
# refuse anything the shipped bundle does not need, so a rendering bug cannot
# run injected script, load or post to another origin, or be framed.
#
# Every source is same-origin. What the built client was checked to need
# (prototype-friendly-ui: index.html, vite.config.mjs, src/, and the dist
# bundle loaded in headless Chrome with violations logged):
#   - scripts: one module entry plus same-origin chunks; no inline script,
#     no eval/new Function, no workers.
#   - styles: one same-origin stylesheet. React applies ``style`` props through
#     the CSSOM, which CSP does not restrict. 'unsafe-inline' is the single
#     allowance beyond 'self': it was NOT needed on the pages exercised, and is
#     kept only as a compatibility margin for markup-level styles that chart or
#     map library updates and React's <style> hoisting can introduce. Inline
#     *script* stays blocked either way.
#   - images: only the same-origin logo. Report markdown images are replaced by
#     placeholders in the client, and data:/blob: images are not allowed here.
#   - network: only same-origin /api/ui calls. The world map uses the bundled
#     world-atlas geometry (the map library's remote-URL loader is never given
#     a URL); fonts are system fonts.
#   - evidence exports are blob: downloads through <a download>, and the PDF
#     report is served as an attachment; CSP governs neither.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self'",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
)


def _harden(response: Response, *, api: bool) -> Response:
    """Attach the browser-hardening headers to any response this app sends."""
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if api:
        response.headers["Cache-Control"] = "no-store"
    return response


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
        api = request.url.path.startswith("/api/ui/")

        def reject(detail: str, status_code: int) -> Response:
            return _harden(JSONResponse({"detail": detail}, status_code=status_code), api=api)

        target = _origin(f"{request.scope['scheme']}://{request.headers.get('host', '')}")
        if target is None or target[1] not in _LOCAL_HOSTS:
            return reject("local_workbench_host_required", 400)

        if api:
            origin = request.headers.get("origin")
            fetch_site = request.headers.get("sec-fetch-site")
            if (origin is not None and _origin(origin) != target) or fetch_site in {"cross-site", "same-site"}:
                return reject("same_origin_required", 403)
            if request.method not in _SAFE_METHODS and request.url.path != "/api/ui/uploads":
                content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    return reject("json_content_type_required", 415)
                chunks, length = [], 0
                async for chunk in request.stream():
                    length += len(chunk)
                    if length > 65536:
                        return reject("json_request_too_large", 413)
                    chunks.append(chunk)
                request._body = b"".join(chunks)

        try:
            response = await call_next(request)
        except Exception:
            # Without this, Starlette's outermost error handler answers with a bare
            # text/plain 500 that carries none of the hardening headers. The exception
            # text stays in the log and is never sent to the browser.
            logger.exception("Unhandled error in %s %s", request.method, request.url.path)
            failure = JSONResponse({"detail": "internal_server_error"}, status_code=500)
            return _harden(failure, api=True)  # an error page is never cacheable
        return _harden(response, api=api)
