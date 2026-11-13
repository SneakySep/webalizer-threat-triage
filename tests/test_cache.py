"""Tests for Redis cache, task state, and lock primitives."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import fakeredis
import fakeredis.aioredis
import pytest

from app.schemas.triage import TargetType, TaskState, TriageResult
from app.services.cache import AsyncCache, CachedTriage, SyncCache, TaskRecord
from app.utils.helpers import compute_cache_key


@pytest.fixture
async def async_cache() -> AsyncCache:
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache = AsyncCache(client)
    yield cache
    await cache.close()


@pytest.fixture
def sync_cache() -> SyncCache:
    cache = SyncCache(fakeredis.FakeRedis(decode_responses=True))
    yield cache
    cache.close()


def _cached(result: TriageResult) -> CachedTriage:
    return CachedTriage(
        task_id=uuid.uuid4(),
        report_id=uuid.uuid4(),
        normalized=result,
        cached_at=datetime.now(UTC),
    )


async def test_async_cache_roundtrip(
    async_cache: AsyncCache,
    normalized_domain_result: TriageResult,
) -> None:
    cached = _cached(normalized_domain_result)
    await async_cache.set_cached(cached, ttl_seconds=60)

    restored = await async_cache.get_cached(TargetType.DOMAIN, "example.com")
    assert restored is not None
    assert restored.task_id == cached.task_id
    assert restored.report_id == cached.report_id
    assert restored.normalized.verdict == normalized_domain_result.verdict
    assert await async_cache.redis.ttl(compute_cache_key(TargetType.DOMAIN, "example.com")) > 0


async def test_async_cache_discards_malformed_entry(async_cache: AsyncCache) -> None:
    key = compute_cache_key(TargetType.DOMAIN, "example.com")
    await async_cache.redis.set(key, "not-json")
    assert await async_cache.get_cached(TargetType.DOMAIN, "example.com") is None
    assert await async_cache.redis.exists(key) == 0


async def test_async_task_status_and_locking(async_cache: AsyncCache) -> None:
    task_id = uuid.uuid4()
    now = datetime.now(UTC)
    record = TaskRecord(
        task_id=task_id,
        status=TaskState.QUEUED,
        stage="queued",
        target="example.com",
        target_type=TargetType.DOMAIN,
        created_at=now,
        updated_at=now,
    )
    await async_cache.set_task_status(record, ttl_seconds=60)
    restored = await async_cache.get_task_status(task_id)
    assert restored is not None
    assert restored.status is TaskState.QUEUED

    key = compute_cache_key(TargetType.DOMAIN, "example.com")
    assert await async_cache.acquire_lock(key, "owner-a", ttl_seconds=60) is True
    assert await async_cache.acquire_lock(key, "owner-b", ttl_seconds=60) is False
    assert await async_cache.get_lock_owner(key) == "owner-a"
    assert await async_cache.release_lock(key, "owner-b") is False
    assert await async_cache.release_lock(key, "owner-a") is True


async def test_async_rate_window_and_short_lived_markers(async_cache: AsyncCache) -> None:
    count, ttl = await async_cache.increment_window("triage:test:window", window_seconds=60)
    assert count == 1
    assert 0 < ttl <= 60

    count, ttl = await async_cache.increment_window("triage:test:window", window_seconds=60)
    assert count == 2
    assert 0 < ttl <= 60

    assert await async_cache.set_if_absent("triage:test:marker", ttl_seconds=60) is True
    assert await async_cache.set_if_absent("triage:test:marker", ttl_seconds=60) is False
    assert 0 < await async_cache.get_ttl("triage:test:marker") <= 60

    await async_cache.delete_key("triage:test:marker")
    assert await async_cache.get_ttl("triage:test:marker") == 0


def test_sync_cache_roundtrip_and_status(
    sync_cache: SyncCache,
    normalized_domain_result: TriageResult,
) -> None:
    cached = _cached(normalized_domain_result)
    sync_cache.set_cached(cached, ttl_seconds=60)
    restored = sync_cache.get_cached(TargetType.DOMAIN, "example.com")
    assert restored is not None
    assert restored.normalized == normalized_domain_result

    task_id = uuid.uuid4()
    now = datetime.now(UTC)
    sync_cache.set_task_status(
        TaskRecord(
            task_id=task_id,
            status=TaskState.PROCESSING,
            target="example.com",
            target_type=TargetType.DOMAIN,
            created_at=now,
            updated_at=now,
        ),
        ttl_seconds=60,
    )
    status = sync_cache.get_task_status(task_id)
    assert status is not None
    assert status.status is TaskState.PROCESSING
