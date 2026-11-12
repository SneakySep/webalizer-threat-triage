"""Redis-backed result cache, task status store, and in-flight deduplication."""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, ValidationError
from redis import Redis
from redis.asyncio import Redis as AsyncRedis

from app.schemas.triage import TargetType, TaskState, TriageResult
from app.utils.helpers import compute_cache_key, utcnow

logger = logging.getLogger(__name__)

CACHE_VERSION = 1
_RELEASE_LOCK_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""


class CachedTriage(BaseModel):
    """Envelope stored under a VirusTotal cache key."""

    version: int = CACHE_VERSION
    task_id: UUID
    report_id: UUID
    normalized: TriageResult
    cached_at: datetime = Field(default_factory=utcnow)


class TaskRecord(BaseModel):
    """Internal task state stored in Redis."""

    task_id: UUID
    status: TaskState
    stage: str | None = None
    target: str
    target_type: TargetType
    attempt: int = 0
    report_id: UUID | None = None
    analysis_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    error_retryable: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


def status_key(task_id: str | UUID) -> str:
    return f"triage:status:{task_id}"


def lock_key(cache_key: str) -> str:
    return f"triage:lock:{cache_key}"


def _validate_cached(raw: str | None) -> CachedTriage | None:
    if raw is None:
        return None
    try:
        cached = CachedTriage.model_validate_json(raw)
    except (ValidationError, ValueError):
        logger.warning("Discarding malformed cached triage payload")
        return None
    if cached.version != CACHE_VERSION:
        logger.info("Discarding cache entry with version %s", cached.version)
        return None
    return cached


def _validate_status(raw: str | None) -> TaskRecord | None:
    if raw is None:
        return None
    try:
        return TaskRecord.model_validate_json(raw)
    except (ValidationError, ValueError):
        logger.warning("Discarding malformed task status payload")
        return None


class AsyncCache:
    """Async Redis access for FastAPI request handlers."""

    def __init__(self, redis_client: AsyncRedis) -> None:
        self.redis = redis_client

    async def get_cached(self, target_type: TargetType, target: str) -> CachedTriage | None:
        key = compute_cache_key(target_type, target)
        raw = await self.redis.get(key)
        cached = _validate_cached(raw)
        if raw is not None and cached is None:
            await self.redis.delete(key)
        return cached

    async def set_cached(
        self,
        cached: CachedTriage,
        *,
        ttl_seconds: int,
    ) -> None:
        key = compute_cache_key(cached.normalized.target_type, cached.normalized.target)
        await self.redis.set(key, cached.model_dump_json(), ex=ttl_seconds)

    async def delete_cached(self, target_type: TargetType, target: str) -> None:
        await self.redis.delete(compute_cache_key(target_type, target))

    async def get_task_status(self, task_id: str | UUID) -> TaskRecord | None:
        raw = await self.redis.get(status_key(task_id))
        return _validate_status(raw)

    async def set_task_status(self, record: TaskRecord, *, ttl_seconds: int) -> None:
        await self.redis.set(
            status_key(record.task_id),
            record.model_dump_json(),
            ex=ttl_seconds,
        )

    async def delete_task_status(self, task_id: str | UUID) -> None:
        await self.redis.delete(status_key(task_id))

    async def acquire_lock(self, cache_key: str, owner: str, *, ttl_seconds: int) -> bool:
        result = await self.redis.set(
            lock_key(cache_key),
            owner,
            nx=True,
            ex=ttl_seconds,
        )
        return bool(result)

    async def get_lock_owner(self, cache_key: str) -> str | None:
        return await self.redis.get(lock_key(cache_key))

    async def release_lock(self, cache_key: str, owner: str) -> bool:
        result = await self.redis.eval(
            _RELEASE_LOCK_SCRIPT,
            1,
            lock_key(cache_key),
            owner,
        )
        return bool(result)

    async def ping(self) -> bool:
        return bool(await self.redis.ping())

    async def close(self) -> None:
        await self.redis.aclose()


class SyncCache:
    """Synchronous Redis access for Celery workers."""

    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    def get_cached(self, target_type: TargetType, target: str) -> CachedTriage | None:
        key = compute_cache_key(target_type, target)
        raw = self.redis.get(key)
        cached = _validate_cached(raw)
        if raw is not None and cached is None:
            self.redis.delete(key)
        return cached

    def set_cached(self, cached: CachedTriage, *, ttl_seconds: int) -> None:
        key = compute_cache_key(cached.normalized.target_type, cached.normalized.target)
        self.redis.set(key, cached.model_dump_json(), ex=ttl_seconds)

    def get_task_status(self, task_id: str | UUID) -> TaskRecord | None:
        raw = self.redis.get(status_key(task_id))
        return _validate_status(raw)

    def set_task_status(self, record: TaskRecord, *, ttl_seconds: int) -> None:
        self.redis.set(
            status_key(record.task_id),
            record.model_dump_json(),
            ex=ttl_seconds,
        )

    def delete_task_status(self, task_id: str | UUID) -> None:
        self.redis.delete(status_key(task_id))

    def acquire_lock(self, cache_key: str, owner: str, *, ttl_seconds: int) -> bool:
        return bool(
            self.redis.set(
                lock_key(cache_key),
                owner,
                nx=True,
                ex=ttl_seconds,
            )
        )

    def get_lock_owner(self, cache_key: str) -> str | None:
        return self.redis.get(lock_key(cache_key))

    def release_lock(self, cache_key: str, owner: str) -> bool:
        result = self.redis.eval(
            _RELEASE_LOCK_SCRIPT,
            1,
            lock_key(cache_key),
            owner,
        )
        return bool(result)

    def ping(self) -> bool:
        return bool(self.redis.ping())

    def close(self) -> None:
        self.redis.close()
