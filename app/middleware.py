"""Cross-cutting HTTP middleware for request IDs and security headers."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.errors import error_payload
from app.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_DOCS_PATHS = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}

# Every unmatched path would otherwise become its own Prometheus time series, so
# internet scanners hitting random URLs could mint unbounded label values.
_KNOWN_PATH_PREFIXES = ("/api/v1/", "/static/", "/r/", "/health/")

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

# Only these methods can carry a request body worth bounding.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _request_id(request: Request) -> str:
    supplied = request.headers.get("X-Request-ID", "").strip()
    if _REQUEST_ID_RE.fullmatch(supplied):
        return supplied
    return uuid.uuid4().hex


def _metric_path(path: str) -> str:
    """Collapse dynamic path segments so label cardinality stays bounded."""

    collapsed = _UUID_RE.sub("{id}", path)
    if collapsed in {"/", "/metrics", "/favicon.ico", *_DOCS_PATHS}:
        return collapsed
    if collapsed.startswith(_KNOWN_PATH_PREFIXES):
        return collapsed
    return "{unmatched}"


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return str(value.decode("latin-1"))
    return None


class BodySizeLimitMiddleware:
    """Reject request bodies larger than a fixed budget.

    Pydantic caps individual fields, but the JSON body is parsed before any of
    that runs, so an oversized payload is still read and decoded in full. This
    bounds that work.

    The body is buffered up to the limit and replayed to the application, which
    is appropriate because this service only accepts small JSON documents. A
    streaming upload endpoint would need a different approach.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        # Fast path: a declared length over budget is rejected without reading.
        declared = _header(scope, b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                # A malformed length is left for the framework to handle.
                pass

        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        request_id = scope.get("state", {}).get("request_id")
        response = JSONResponse(
            status_code=413,
            content=error_payload(
                "PAYLOAD_TOO_LARGE",
                f"Request body must not exceed {self.max_bytes} bytes.",
                request_id=request_id,
            ),
        )
        await response(scope, receive, send)


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

    def __init__(self, app: Any, *, environment: str) -> None:
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


__all__ = [
    "BodySizeLimitMiddleware",
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
]
