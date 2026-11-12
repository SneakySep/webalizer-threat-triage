"""Tests for the browser UI served by the FastAPI application."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from app.main import create_app


@pytest.fixture
async def ui_client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def test_root_serves_the_web_ui(ui_client: httpx.AsyncClient) -> None:
    response = await ui_client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<title>Webalizer — Check a link before you click</title>" in response.text
    assert "/static/styles.css" in response.text
    assert "/static/app.js" in response.text


@pytest.mark.parametrize(
    ("path", "content_type", "marker"),
    [
        ("/static/styles.css", "text/css", "--accent"),
        ("/static/app.js", "text/javascript", "API_ROOT"),
        ("/static/favicon.svg", "image/svg+xml", "<svg"),
    ],
)
async def test_static_assets_are_served(
    ui_client: httpx.AsyncClient,
    path: str,
    content_type: str,
    marker: str,
) -> None:
    response = await ui_client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(content_type)
    assert marker in response.text


async def test_favicon_alias_serves_the_svg_mark(ui_client: httpx.AsyncClient) -> None:
    response = await ui_client.get("/favicon.ico")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")


async def test_health_and_api_routes_survive_the_ui_mount(
    ui_client: httpx.AsyncClient,
) -> None:
    health = await ui_client.get("/health/live")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    missing = await ui_client.get("/api/v1/not-a-route")
    assert missing.status_code == 404
    assert missing.headers["content-type"].startswith("application/json")
    assert missing.json()["error"]["code"] == "NOT_FOUND"
