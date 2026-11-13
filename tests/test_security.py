"""Security headers, request IDs, and metrics endpoint tests."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from pydantic import SecretStr

from app.api.deps import get_settings
from app.config import get_settings as load_settings
from app.main import create_app


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
