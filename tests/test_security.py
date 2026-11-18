"""Security headers, request IDs, and metrics endpoint tests."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from pydantic import SecretStr

from app.api.deps import get_settings
from app.config import get_settings as load_settings
from app.main import create_app
from app.middleware import BodySizeLimitMiddleware, _metric_path


@pytest.fixture
async def security_client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def test_app_responses_include_security_headers(
    security_client: httpx.AsyncClient,
) -> None:
    response = await security_client.get("/")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


async def test_docs_keep_security_headers_without_breaking_swagger_assets(
    security_client: httpx.AsyncClient,
) -> None:
    response = await security_client.get("/docs")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" not in response.headers


async def test_request_id_is_echoed_and_added_to_error_envelopes(
    security_client: httpx.AsyncClient,
) -> None:
    response = await security_client.get(
        "/api/v1/not-a-route",
        headers={"X-Request-ID": "trace-123"},
    )

    assert response.status_code == 404
    assert response.headers["x-request-id"] == "trace-123"
    assert response.json()["error"]["request_id"] == "trace-123"


async def test_invalid_request_id_is_replaced(
    security_client: httpx.AsyncClient,
) -> None:
    response = await security_client.get(
        "/health/live",
        headers={"X-Request-ID": "<script>alert(1)</script>"},
    )

    request_id = response.headers["x-request-id"]
    assert request_id != "<script>alert(1)</script>"
    assert len(request_id) == 32


async def test_metrics_endpoint_exposes_prometheus_text(
    security_client: httpx.AsyncClient,
) -> None:
    response = await security_client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "webalizer_http_requests_total" in response.text
    assert "webalizer_http_request_duration_seconds" in response.text


async def test_metrics_requires_the_api_key_when_auth_is_enabled() -> None:
    app = create_app()
    secure_settings = load_settings().model_copy(
        update={"triage_api_key": SecretStr("metrics-key")}
    )
    app.dependency_overrides[get_settings] = lambda: secure_settings
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unauthorized = await client.get("/metrics")
        authorized = await client.get(
            "/metrics",
            headers={"X-API-Key": "metrics-key"},
        )

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            "/api/v1/triage/status/3f2a1b4c-1111-2222-3333-444455556666",
            "/api/v1/triage/status/{id}",
        ),
        (
            "/api/v1/triage/report/3f2a1b4c-1111-2222-3333-444455556666",
            "/api/v1/triage/report/{id}",
        ),
        ("/r/3f2a1b4c-1111-2222-3333-444455556666", "/r/{id}"),
        ("/health/ready", "/health/ready"),
        ("/static/app.js", "/static/app.js"),
        ("/", "/"),
        ("/wp-admin.php", "{unmatched}"),
        ("/random-scanner-path-abc123", "{unmatched}"),
        ("/.env", "{unmatched}"),
    ],
)
def test_metric_paths_collapse_unmatched_routes(path: str, expected: str) -> None:
    """Scanner traffic must not mint unbounded Prometheus label values."""

    assert _metric_path(path) == expected


@pytest.fixture
async def body_limit_client() -> AsyncIterator[httpx.AsyncClient]:
    """An app wired with its real configured body budget.

    The limit is read when the app is constructed, so it cannot be changed
    through a dependency override; these tests exercise the real default.
    """

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


def _oversized_payload() -> dict[str, str]:
    budget = load_settings().max_request_body_bytes
    return {"target": "example.com", "padding": "x" * (budget + 1_000)}


async def test_oversized_body_is_rejected_with_413(
    body_limit_client: httpx.AsyncClient,
) -> None:
    response = await body_limit_client.post(
        "/api/v1/triage/scan",
        json=_oversized_payload(),
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


async def test_oversized_body_is_rejected_before_the_endpoint_runs(
    body_limit_client: httpx.AsyncClient,
) -> None:
    """A 413 must not be a validation error dressed up: no scan may be queued."""

    response = await body_limit_client.post(
        "/api/v1/triage/scan",
        json=_oversized_payload(),
    )

    assert response.status_code == 413
    # A queued scan returns 202 with a task id; a cache failure returns 503.
    assert "task_id" not in response.json()


async def test_body_within_the_limit_still_reaches_the_endpoint(
    body_limit_client: httpx.AsyncClient,
) -> None:
    response = await body_limit_client.post(
        "/api/v1/triage/scan",
        json={"target": "example.com"},
    )

    # Past the body check: this is the normal scan path (no cache in this app).
    assert response.status_code != 413


async def test_get_requests_are_not_body_limited(
    body_limit_client: httpx.AsyncClient,
) -> None:
    response = await body_limit_client.get("/health/live")

    assert response.status_code == 200


def test_body_limit_rejects_a_non_positive_budget() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        BodySizeLimitMiddleware(lambda *a: None, max_bytes=0)  # type: ignore[arg-type]


async def test_chunked_body_without_content_length_is_still_bounded() -> None:
    """A client can omit Content-Length, so the stream itself must be counted."""

    async def app(scope: object, receive: object, send: object) -> None:  # pragma: no cover
        raise AssertionError("the endpoint must not be reached")

    middleware = BodySizeLimitMiddleware(app, max_bytes=10)  # type: ignore[arg-type]

    chunks = [b"a" * 6, b"b" * 6]
    sent: list[dict[str, object]] = []
    received = False

    async def receive() -> dict[str, object]:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": chunks[0], "more_body": True}
        return {"type": "http.request", "body": chunks[1], "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": [], "state": {}}
    await middleware(scope, receive, send)  # type: ignore[arg-type]

    status = next(m for m in sent if m["type"] == "http.response.start")
    assert status["status"] == 413


async def test_declared_content_length_over_budget_is_rejected_without_reading() -> None:
    """The declared length is a fast path: reject before buffering anything."""

    read_attempted = False

    async def app(scope: object, receive: object, send: object) -> None:  # pragma: no cover
        raise AssertionError("the endpoint must not be reached")

    middleware = BodySizeLimitMiddleware(app, max_bytes=10)  # type: ignore[arg-type]

    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        nonlocal read_attempted
        read_attempted = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-length", b"9999")],
        "state": {},
    }
    await middleware(scope, receive, send)  # type: ignore[arg-type]

    status = next(m for m in sent if m["type"] == "http.response.start")
    assert status["status"] == 413
    # The body was never read at all.
    assert read_attempted is False


async def test_get_with_a_body_is_not_limited() -> None:
    """Only methods that can carry a meaningful body are bounded."""

    reached = False

    async def app(scope: object, receive: object, send: object) -> None:
        nonlocal reached
        reached = True
        await send({"type": "http.response.start", "status": 200, "headers": []})  # type: ignore[operator]
        await send({"type": "http.response.body", "body": b""})  # type: ignore[operator]

    middleware = BodySizeLimitMiddleware(app, max_bytes=10)  # type: ignore[arg-type]

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"x" * 5_000, "more_body": False}

    async def send(message: dict[str, object]) -> None:
        pass

    scope = {"type": "http", "method": "GET", "headers": [], "state": {}}
    await middleware(scope, receive, send)  # type: ignore[arg-type]

    assert reached is True


async def test_body_is_replayed_to_the_endpoint_intact() -> None:
    """Buffering must not truncate what the endpoint finally reads."""

    seen: dict[str, object] = {}

    async def app(scope: object, receive: object, send: object) -> None:
        message = await receive()  # type: ignore[operator]
        seen["body"] = message["body"]
        await send({"type": "http.response.start", "status": 200, "headers": []})  # type: ignore[operator]
        await send({"type": "http.response.body", "body": b""})  # type: ignore[operator]

    middleware = BodySizeLimitMiddleware(app, max_bytes=100)  # type: ignore[arg-type]

    sent: list[dict[str, object]] = []
    delivered = False

    async def receive() -> dict[str, object]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": b'{"target":"x"}', "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": [], "state": {}}
    await middleware(scope, receive, send)  # type: ignore[arg-type]

    assert seen["body"] == b'{"target":"x"}'
    status = next(m for m in sent if m["type"] == "http.response.start")
    assert status["status"] == 200
