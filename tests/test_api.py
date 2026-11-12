"""API contract tests with an in-memory Redis and fake dispatcher."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from app.api.deps import get_cache, get_session, get_settings
from app.config import get_settings as load_settings
from app.main import create_app
from app.models.triage_report import TriageReport
from app.schemas.triage import TargetType, TaskState, TriageResult
from app.services.cache import AsyncCache, CachedTriage, TaskRecord
from app.services.dispatcher import get_task_dispatcher
from app.utils.helpers import compute_cache_key


class FakeDispatcher:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def send_scan(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


@dataclass
class ApiHarness:
    app: FastAPI
    client: httpx.AsyncClient
    cache: AsyncCache
    dispatcher: FakeDispatcher


@pytest.fixture
async def api_harness() -> ApiHarness:
    app = create_app()
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache = AsyncCache(redis_client)
    dispatcher = FakeDispatcher()
    app.dependency_overrides[get_cache] = lambda: cache
    app.dependency_overrides[get_task_dispatcher] = lambda: dispatcher
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield ApiHarness(app=app, client=client, cache=cache, dispatcher=dispatcher)
    await cache.close()


async def test_new_scan_is_queued_and_deduplicated(api_harness: ApiHarness) -> None:
    response = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "new-scan.example", "force_refresh": False},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["cached"] is False
    assert body["deduplicated"] is False
    assert body["task_id"]
    assert len(api_harness.dispatcher.calls) == 1

    status_response = await api_harness.client.get(f"/api/v1/triage/status/{body['task_id']}")
    assert status_response.status_code == 200
    status_body = status_response.json()
    assert status_body["status"] == "queued"
    assert status_body["target"] == "new-scan.example"
    assert status_body["target_type"] == "domain"

    duplicate = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "new-scan.example"},
    )
    assert duplicate.status_code == 202
    duplicate_body = duplicate.json()
    assert duplicate_body["deduplicated"] is True
    assert duplicate_body["task_id"] == body["task_id"]
    assert len(api_harness.dispatcher.calls) == 1


async def test_active_lock_without_status_is_never_released(
    api_harness: ApiHarness,
) -> None:
    cache_key = compute_cache_key(TargetType.DOMAIN, "race-check.example")
    await api_harness.cache.acquire_lock(cache_key, "owner-task", ttl_seconds=60)

    response = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "race-check.example"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SCAN_IN_PROGRESS"
    assert await api_harness.cache.get_lock_owner(cache_key) == "owner-task"
    assert api_harness.dispatcher.calls == []


async def test_stale_lock_from_finished_task_is_reclaimed(
    api_harness: ApiHarness,
) -> None:
    cache_key = compute_cache_key(TargetType.DOMAIN, "stale-check.example")
    owner = uuid.uuid4()
    await api_harness.cache.acquire_lock(cache_key, str(owner), ttl_seconds=60)
    now = datetime.now(UTC)
    await api_harness.cache.set_task_status(
        TaskRecord(
            task_id=owner,
            status=TaskState.FAILED,
            stage="failed",
            target="stale-check.example",
            target_type=TargetType.DOMAIN,
            created_at=now,
            updated_at=now,
        ),
        ttl_seconds=60,
    )

    response = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "stale-check.example"},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["deduplicated"] is False
    assert body["task_id"] != str(owner)
    assert len(api_harness.dispatcher.calls) == 1
    assert await api_harness.cache.get_lock_owner(cache_key) == body["task_id"]


async def test_cache_hit_returns_completed_result(
    api_harness: ApiHarness,
    normalized_domain_result: TriageResult,
) -> None:
    cached = CachedTriage(
        task_id=uuid.uuid4(),
        report_id=uuid.uuid4(),
        normalized=normalized_domain_result,
        cached_at=datetime.now(UTC),
    )
    await api_harness.cache.set_cached(cached, ttl_seconds=60)

    response = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "example.com"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["cached"] is True
    assert body["status"] == "completed"
    assert body["task_id"] == str(cached.task_id)
    assert body["report_id"] == str(cached.report_id)
    assert body["result"]["verdict"] == "malicious"
    assert api_harness.dispatcher.calls == []

    force_refresh = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "example.com", "force_refresh": True},
    )
    assert force_refresh.status_code == 202
    assert force_refresh.json()["cached"] is False
    assert len(api_harness.dispatcher.calls) == 1


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [
        ({"target": "ftp://example.com"}, "INVALID_TARGET"),
        ({"target": "http://127.0.0.1/"}, "INVALID_TARGET"),
        ({"force_refresh": False}, "VALIDATION_ERROR"),
    ],
)
async def test_invalid_requests_use_error_envelope(
    api_harness: ApiHarness,
    payload: dict[str, Any],
    expected_code: str,
) -> None:
    response = await api_harness.client.post("/api/v1/triage/scan", json=payload)
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == expected_code
    assert body["error"]["message"]


async def test_unknown_task_returns_404(api_harness: ApiHarness) -> None:
    response = await api_harness.client.get(f"/api/v1/triage/status/{uuid.uuid4()}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TASK_NOT_FOUND"


async def test_failed_task_status_exposes_safe_error(api_harness: ApiHarness) -> None:
    task_id = uuid.uuid4()
    now = datetime.now(UTC)
    await api_harness.cache.set_task_status(
        TaskRecord(
            task_id=task_id,
            status=TaskState.FAILED,
            stage="failed",
            target="example.com",
            target_type="domain",  # type: ignore[arg-type]
            error_code="VT_AUTH_FAILED",
            error_message="VirusTotal authentication failed.",
            created_at=now,
            updated_at=now,
        ),
        ttl_seconds=60,
    )
    response = await api_harness.client.get(f"/api/v1/triage/status/{task_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert body["error"]["code"] == "VT_AUTH_FAILED"
    assert body["error"]["retryable"] is False


class FakeSession:
    def __init__(self, report: TriageReport | None) -> None:
        self.report = report

    async def get(self, _model: Any, report_id: uuid.UUID) -> TriageReport | None:
        if self.report is not None and self.report.id == report_id:
            return self.report
        return None


def _report(normalized: TriageResult) -> TriageReport:
    return TriageReport(
        id=uuid.uuid4(),
        target=normalized.target,
        target_type=normalized.target_type.value,
        risk_score=Decimal(str(normalized.risk_score)),
        verdict=normalized.verdict.value,
        raw_vt_response={"data": {"id": "raw"}},
        normalized_data=normalized.model_dump(mode="json"),
        created_at=datetime.now(UTC),
    )


async def test_report_is_retrieved_from_postgres(
    api_harness: ApiHarness,
    normalized_domain_result: TriageResult,
) -> None:
    report = _report(normalized_domain_result)
    fake_session = FakeSession(report)

    async def override_session():
        yield fake_session

    api_harness.app.dependency_overrides[get_session] = override_session
    response = await api_harness.client.get(f"/api/v1/triage/report/{report.id}?include_raw=true")
    assert response.status_code == 200
    body = response.json()
    assert body["report_id"] == str(report.id)
    assert body["verdict"] == "malicious"
    assert body["raw_vt_response"] == {"data": {"id": "raw"}}
    assert body["categories"] == ["Malware", "Phishing"]


async def test_missing_report_returns_404(
    api_harness: ApiHarness,
    normalized_domain_result: TriageResult,
) -> None:
    report = _report(normalized_domain_result)

    async def override_session():
        yield FakeSession(None)

    api_harness.app.dependency_overrides[get_session] = override_session
    response = await api_harness.client.get(f"/api/v1/triage/report/{report.id}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "REPORT_NOT_FOUND"


async def test_optional_api_key_protection(api_harness: ApiHarness) -> None:
    secure_settings = load_settings().model_copy(update={"triage_api_key": SecretStr("secret-key")})
    api_harness.app.dependency_overrides[get_settings] = lambda: secure_settings

    unauthorized = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "secured.example"},
    )
    assert unauthorized.status_code == 401
    assert unauthorized.json()["error"]["code"] == "UNAUTHORIZED"

    authorized = await api_harness.client.post(
        "/api/v1/triage/scan",
        json={"target": "secured.example"},
        headers={"X-API-Key": "secret-key"},
    )
    assert authorized.status_code == 202
