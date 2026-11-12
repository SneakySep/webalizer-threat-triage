"""Tests for the global rate limiter wrapper."""

from __future__ import annotations

from typing import Any

import pytest

from app.services.rate_limit import RedisTokenBucket


class FakeScript:
    def __init__(self, responses: list[list[int]]) -> None:
        self.responses = responses

    def __call__(self, **_kwargs: Any) -> list[int]:
        return self.responses.pop(0)


class FakeRedis:
    def __init__(self, responses: list[list[int]]) -> None:
        self.script = FakeScript(responses)

    def register_script(self, _script: str) -> FakeScript:
        return self.script


def test_limiter_returns_immediately_when_a_token_is_available() -> None:
    redis = FakeRedis([[1, 0]])
    sleeps: list[float] = []
    limiter = RedisTokenBucket(redis, capacity=4, sleeper=sleeps.append)  # type: ignore[arg-type]

    limiter.acquire()
    assert sleeps == []


def test_limiter_waits_and_retries_when_exhausted() -> None:
    redis = FakeRedis([[0, 500], [1, 0]])
    sleeps: list[float] = []
    limiter = RedisTokenBucket(redis, capacity=4, sleeper=sleeps.append)  # type: ignore[arg-type]

    limiter.acquire()
    assert sleeps == [0.5]


def test_limiter_requires_positive_capacity() -> None:
    with pytest.raises(ValueError):
        RedisTokenBucket(FakeRedis([]), capacity=0)  # type: ignore[arg-type]
