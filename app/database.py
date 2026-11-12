"""Database engines and session factories.

The API uses SQLAlchemy's async engine; Celery workers use a synchronous engine.
Both use psycopg 3 by sharing the ``postgresql+psycopg`` URL scheme.
"""

from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings

settings = get_settings()


class Base(DeclarativeBase):
    pass


async_engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_recycle=1800,
)
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    expire_on_commit=False,
    autoflush=False,
)

sync_engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=max(2, settings.db_pool_size // 2),
    max_overflow=settings.db_max_overflow,
    pool_recycle=1800,
)
SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    expire_on_commit=False,
    autoflush=False,
)


async def check_database() -> None:
    async with async_engine.connect() as connection:
        await connection.execute(text("SELECT 1"))


async def close_database() -> None:
    await async_engine.dispose()
    sync_engine.dispose()


def dispose_worker_engine() -> None:
    """Drop inherited connections after a Celery worker process forks."""

    sync_engine.dispose(close=False)
