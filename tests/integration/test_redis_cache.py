"""Redis integration tests for rate windows, markers, and locks."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from redis.asyncio import Redis as AsyncRedis

from app.services.cache import AsyncCache

pytestmark = pytest.mark.integration


@pytest.fixture
async def integration_cache() -> AsyncIterator[AsyncCache]:
    redis_url = os.getenv("INTEGRATION_REDIS_URL", "").strip()
    if not redis_url:
        pytest.skip("Set INTEGRATION_REDIS_URL to run Redis integration tests")

    redis_client = AsyncRedis.from_url(redis_url, decode_responses=True)
    await redis_client.flushdb()
    cache = AsyncCache(redis_client)
    try:
        yield cache
    finally:
        await redis_client.flushdb()
        await cache.close()


async def test_rate_window_markers_and_locks_use_real_redis(
    integration_cache: AsyncCache,
) -> None:
    count, ttl = await integration_cache.increment_window(
        "triage:test:minute",
        window_seconds=60,
    )
    assert count == 1
    assert 0 < ttl <= 60

    count, _ = await integration_cache.increment_window(
        "triage:test:minute",
        window_seconds=60,
    )
    assert count == 2

    assert await integration_cache.set_if_absent("triage:test:marker", ttl_seconds=60)
    assert not await integration_cache.set_if_absent("triage:test:marker", ttl_seconds=60)
    assert 0 < await integration_cache.get_ttl("triage:test:marker") <= 60

    assert await integration_cache.acquire_lock(
        "integration-cache-key",
        "owner-a",
        ttl_seconds=60,
    )
    assert not await integration_cache.acquire_lock(
        "integration-cache-key",
        "owner-b",
        ttl_seconds=60,
    )
    assert await integration_cache.get_lock_owner("integration-cache-key") == "owner-a"
    assert await integration_cache.release_lock("integration-cache-key", "owner-a")

    await integration_cache.delete_key("triage:test:marker")
    assert await integration_cache.get_ttl("triage:test:marker") == 0
