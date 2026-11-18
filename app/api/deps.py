"""FastAPI dependencies for database sessions, cache, and optional auth."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from typing import Annotated, cast

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.database import AsyncSessionLocal
from app.errors import AppError
from app.services.cache import AsyncCache
from app.services.dispatcher import TaskDispatcher, get_task_dispatcher


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session


# Declaring the header as a security scheme (rather than a plain Header) is what
# gives Swagger UI an Authorize button and marks these endpoints as key-protected
# in the generated OpenAPI document. auto_error=False keeps the dependency's own
# 401 envelope, so errors stay in the app's consistent shape.
api_key_header = APIKeyHeader(
    name="X-API-Key",
    scheme_name="ApiKeyAuth",
    description=(
        "Static API key. Required only when TRIAGE_API_KEY or TRIAGE_API_KEYS is "
        "configured on the server."
    ),
    auto_error=False,
)


def get_cache(request: Request) -> AsyncCache:
    cache = getattr(request.app.state, "cache", None)
    if cache is None:
        raise AppError(
            503,
            "CACHE_UNAVAILABLE",
            "The cache service is not available.",
        )
    return cast("AsyncCache", cache)


async def require_api_key(
    x_api_key: Annotated[str | None, Security(api_key_header)] = None,
    settings: Settings = Depends(get_settings),
) -> None:
    expected_keys = settings.triage_api_key_values.values()
    if not expected_keys:
        return

    if x_api_key is None:
        raise AppError(
            401,
            "UNAUTHORIZED",
            "A valid X-API-Key header is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Compare against every configured key without short-circuiting, so timing
    # does not reveal which key matched or how far it got.
    valid = False
    for expected in expected_keys:
        if secrets.compare_digest(x_api_key, expected):
            valid = True
    if not valid:
        raise AppError(
            401,
            "UNAUTHORIZED",
            "A valid X-API-Key header is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


__all__ = [
    "TaskDispatcher",
    "api_key_header",
    "get_cache",
    "get_session",
    "get_settings",
    "get_task_dispatcher",
    "require_api_key",
]
