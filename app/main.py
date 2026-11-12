"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis as AsyncRedis

from app.api.v1.router import api_router
from app.config import get_settings
from app.database import check_database, close_database
from app.errors import register_exception_handlers
from app.services.cache import AsyncCache

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    redis_client = AsyncRedis.from_url(settings.redis_url, decode_responses=True)
    app.state.cache = AsyncCache(redis_client)
    logger.info("Threat triage API started")
    try:
        yield
    finally:
        await app.state.cache.close()
        await close_database()
        logger.info("Threat triage API stopped")


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Asynchronous URL and domain threat triage backed by VirusTotal, "
            "Celery, Redis, and PostgreSQL."
        ),
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )

    if settings.cors_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-API-Key"],
        )

    register_exception_handlers(application)
    application.include_router(api_router, prefix=settings.api_v1_prefix)

    @application.get("/health/live", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready", include_in_schema=False)
    async def readiness(request: Request, response: Response) -> dict[str, Any]:
        checks: dict[str, str] = {}
        try:
            await check_database()
            checks["database"] = "ok"
        except Exception:
            logger.exception("Readiness database check failed")
            checks["database"] = "error"

        cache: AsyncCache | None = getattr(request.app.state, "cache", None)
        try:
            if cache is None or not await cache.ping():
                raise RuntimeError("cache unavailable")
            checks["redis"] = "ok"
        except Exception:
            logger.exception("Readiness Redis check failed")
            checks["redis"] = "error"

        ready = all(value == "ok" for value in checks.values())
        if not ready:
            response.status_code = 503
        return {"status": "ok" if ready else "degraded", "checks": checks}

    @application.get("/", include_in_schema=False)
    async def index() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs" if settings.docs_enabled else "disabled",
        }

    return application


app = create_app()
