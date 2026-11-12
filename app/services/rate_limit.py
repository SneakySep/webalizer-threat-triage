"""A Redis-backed global token bucket for VirusTotal request pacing."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Protocol

from redis import Redis

logger = logging.getLogger(__name__)

_TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_second = tonumber(ARGV[2])
local ttl_ms = tonumber(ARGV[3])

local current_time = redis.call('TIME')
local now = tonumber(current_time[1]) + tonumber(current_time[2]) / 1000000
local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local last_refill = tonumber(state[2])

if tokens == nil then
    tokens = capacity
    last_refill = now
end

local elapsed = math.max(0, now - last_refill)
tokens = math.min(capacity, tokens + (elapsed * refill_per_second))

if tokens >= 1 then
    tokens = tokens - 1
    redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
    redis.call('PEXPIRE', key, ttl_ms)
    return {1, 0}
end

local wait_ms = math.ceil(((1 - tokens) / refill_per_second) * 1000)
redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', key, ttl_ms)
return {0, wait_ms}
"""


class RateLimiter(Protocol):
    def acquire(self) -> None:
        """Block until one request slot is available."""


class RedisTokenBucket:
    """Process-shared limiter so multiple Celery workers respect the VT quota."""

    def __init__(
        self,
        redis_client: Redis,
        *,
        capacity: int,
        window_seconds: float = 60.0,
        key: str = "vt:rate_limit:requests",
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self.refill_per_second = capacity / window_seconds
        self.key = key
        self._redis = redis_client
        self._sleep = sleeper
        self._script = redis_client.register_script(_TOKEN_BUCKET_SCRIPT)

    def acquire(self) -> None:
        while True:
            allowed, wait_ms = self._script(
                keys=[self.key],
                args=[self.capacity, self.refill_per_second, 120_000],
            )
            if int(allowed) == 1:
                return
            wait_seconds = min(max(int(wait_ms) / 1000.0, 0.05), 60.0)
            logger.debug("VirusTotal request slot unavailable; waiting %.2fs", wait_seconds)
            self._sleep(wait_seconds)
