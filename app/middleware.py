"""Cross-cutting HTTP middleware for request IDs and security headers."""

from __future__ import annotations

import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_DOCS_PATHS = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}

_CSP = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "object-src 'none'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "font-src 'self'"
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _request_id(request: Request) -> str:
    supplied = request.headers.get("X-Request-ID", "").strip()
    if _REQUEST_ID_RE.fullmatch(supplied):
        return supplied
    return uuid.uuid4().hex


def _metric_path(path: str) -> str:
    return _UUID_RE.sub("{report_id}", path)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request ID, record metrics, and echo the ID to the client."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = _request_id(request)
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - started
        path = _metric_path(request.url.path)
        HTTP_REQUESTS.labels(request.method, path, str(response.status_code)).inc()
        HTTP_REQUEST_DURATION.labels(request.method, path).observe(elapsed)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add browser hardening headers without breaking Swagger/ReDoc."""

    def __init__(self, app, *, environment: str) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.environment = environment

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if request.url.path not in _DOCS_PATHS:
            response.headers.setdefault("Content-Security-Policy", _CSP)
        if self.environment == "production":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response


__all__ = ["RequestContextMiddleware", "SecurityHeadersMiddleware"]
