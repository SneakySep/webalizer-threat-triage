"""FastAPI dependencies for database sessions, cache, and optional auth."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.database import AsyncSessionLocal
from app.errors import AppError
from app.services.cache import AsyncCache
from app.services.dispatcher import TaskDispatcher, get_task_dispatcher


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session


def get_cache(request: Request) -> AsyncCache:
    cache = getattr(request.app.state, "cache", None)
    if cache is None:
        raise AppError(
            503,
            "CACHE_UNAVAILABLE",
            "The cache service is not available.",
        )
    return cache


async def require_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    settings: Settings = Depends(get_settings),
) -> None:
    expected_keys = settings.triage_api_key_values.values()
    if not expected_keys:
        return

    valid = False
    if x_api_key is not None:
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
    "get_cache",
    "get_session",
    "get_settings",
    "get_task_dispatcher",
    "require_api_key",
]
