"""Tests for the synchronous worker orchestration service."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import fakeredis
import pytest
from sqlalchemy.exc import IntegrityError

from app.config import Settings, get_settings
from app.models.triage_report import TriageReport
from app.schemas.triage import TargetType, TaskState, TriageResult
from app.services.cache import CachedTriage, SyncCache, TaskRecord
from app.services.triage import (
    TriageService,
    mark_task_failed,
    mark_task_retrying,
)


class FakeVirusTotal:
    def __init__(self, domain_payload: dict[str, Any], *, fail: bool = False) -> None:
        self.domain_payload = domain_payload
        self.fail = fail
        self.domain_calls: list[str] = []

    def scan_domain(self, domain: str) -> dict[str, Any]:
        if self.fail:
            raise AssertionError("VirusTotal should not be called")
        self.domain_calls.append(domain)
        return self.domain_payload


class FakeSession:
    def __init__(self, reports: list[TriageReport]) -> None:
        self.reports = reports

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def add(self, report: TriageReport) -> None:
        if report.id is None:
            report.id = uuid.uuid4()
        if report.created_at is None:
            report.created_at = datetime.now(UTC)
        self.reports.append(report)

    def commit(self) -> None:
        return None

    def refresh(self, _report: TriageReport) -> None:
        return None


@pytest.fixture
def sync_cache() -> SyncCache:
    cache = SyncCache(fakeredis.FakeRedis(decode_responses=True))
    yield cache
    cache.close()


@pytest.fixture
def reports() -> list[TriageReport]:
    return []


def _service(
    cache: SyncCache,
    reports: list[TriageReport],
    *,
    settings: Settings | None = None,
) -> TriageService:
    return TriageService(
        cache=cache,
        session_factory=lambda: FakeSession(reports),
        settings=settings or get_settings(),
    )


def test_domain_scan_persists_report_and_cache(
    sync_cache: SyncCache,
    reports: list[TriageReport],
    domain_vt_payload: dict[str, Any],
) -> None:
    vt = FakeVirusTotal(domain_vt_payload)
    task_id = str(uuid.uuid4())

    outcome = _service(sync_cache, reports).execute(
        task_id=task_id,
        target="example.com",
        target_type=TargetType.DOMAIN,
        force_refresh=False,
        attempt=0,
        vt_client=vt,  # type: ignore[arg-type]
    )

    assert outcome.cached is False
    assert len(vt.domain_calls) == 1
    assert len(reports) == 1
    report = reports[0]
    assert report.target == "example.com"
    assert report.target_type == "domain"
    assert report.verdict == "malicious"
    assert report.task_id == uuid.UUID(task_id)
    assert report.normalized_data["confidence"] == "medium"
    assert report.raw_vt_response["domain"] == domain_vt_payload
    assert outcome.report_id == report.id

    status = sync_cache.get_task_status(task_id)
    assert status is not None
    assert status.status is TaskState.COMPLETED
    assert status.report_id == report.id

    cached = sync_cache.get_cached(TargetType.DOMAIN, "example.com")
    assert cached is not None
    assert cached.report_id == report.id


def test_worker_cache_hit_skips_virustotal(
    sync_cache: SyncCache,
    reports: list[TriageReport],
    normalized_domain_result: TriageResult,
    domain_vt_payload: dict[str, Any],
) -> None:
    task_id = str(uuid.uuid4())
    cached = CachedTriage(
        task_id=uuid.uuid4(),
        report_id=uuid.uuid4(),
        normalized=normalized_domain_result,
    )
    sync_cache.set_cached(cached, ttl_seconds=60)
    vt = FakeVirusTotal(domain_vt_payload, fail=True)

    outcome = _service(sync_cache, reports).execute(
        task_id=task_id,
        target="example.com",
        target_type=TargetType.DOMAIN,
        force_refresh=False,
        attempt=0,
        vt_client=vt,  # type: ignore[arg-type]
    )

    assert outcome.cached is True
    assert outcome.report_id == cached.report_id
    assert reports == []
    status = sync_cache.get_task_status(task_id)
    assert status is not None
    assert status.status is TaskState.COMPLETED


def test_force_refresh_bypasses_cache(
    sync_cache: SyncCache,
    reports: list[TriageReport],
    normalized_domain_result: TriageResult,
    domain_vt_payload: dict[str, Any],
) -> None:
    sync_cache.set_cached(
        CachedTriage(
            task_id=uuid.uuid4(),
            report_id=uuid.uuid4(),
            normalized=normalized_domain_result,
        ),
        ttl_seconds=60,
    )
    vt = FakeVirusTotal(domain_vt_payload)

    outcome = _service(sync_cache, reports).execute(
        task_id=str(uuid.uuid4()),
        target="example.com",
        target_type=TargetType.DOMAIN,
        force_refresh=True,
        attempt=0,
        vt_client=vt,  # type: ignore[arg-type]
    )

    assert outcome.cached is False
    assert len(vt.domain_calls) == 1
    assert len(reports) == 1


def test_raw_vt_response_can_be_disabled(
    sync_cache: SyncCache,
    reports: list[TriageReport],
    domain_vt_payload: dict[str, Any],
) -> None:
    settings = get_settings().model_copy(update={"store_raw_vt_response": False})
    vt = FakeVirusTotal(domain_vt_payload)

    _service(sync_cache, reports, settings=settings).execute(
        task_id=str(uuid.uuid4()),
        target="example.com",
        target_type=TargetType.DOMAIN,
        force_refresh=False,
        attempt=0,
        vt_client=vt,  # type: ignore[arg-type]
    )

    assert reports[0].raw_vt_response == {}
    assert reports[0].normalized_data["verdict"] == "malicious"


class DuplicateReportSession(FakeSession):
    def __init__(self, existing: TriageReport) -> None:
        super().__init__([])
        self.existing = existing
        self.rolled_back = False

    def commit(self) -> None:
        raise IntegrityError("INSERT INTO triage_reports", {}, Exception("duplicate task"))

    def rollback(self) -> None:
        self.rolled_back = True

    def scalar(self, _statement: object) -> TriageReport:
        return self.existing


def test_persist_report_reuses_the_row_for_a_duplicate_task(
    sync_cache: SyncCache,
    normalized_domain_result: TriageResult,
) -> None:
    task_id = uuid.uuid4()
    existing = TriageReport(
        id=uuid.uuid4(),
        task_id=task_id,
        target=normalized_domain_result.target,
        target_type=normalized_domain_result.target_type.value,
        risk_score=normalized_domain_result.risk_score,
        verdict=normalized_domain_result.verdict.value,
        raw_vt_response={},
        normalized_data=normalized_domain_result.model_dump(mode="json"),
        created_at=datetime.now(UTC),
    )
    session = DuplicateReportSession(existing)
    service = TriageService(
        cache=sync_cache,
        session_factory=lambda: session,
        settings=get_settings(),
    )

    report = service._persist_report(
        normalized_domain_result,
        {"data": {"id": "raw"}},
        task_id=task_id,
    )

    assert report is existing
    assert session.rolled_back is True


def test_retry_and_failure_status_helpers(sync_cache: SyncCache) -> None:
    settings = get_settings()
    task_id = uuid.uuid4()
    now = datetime.now(UTC)
    sync_cache.set_task_status(
        TaskRecord(
            task_id=task_id,
            status=TaskState.QUEUED,
            target="example.com",
            target_type=TargetType.DOMAIN,
            created_at=now,
            updated_at=now,
        ),
        ttl_seconds=60,
    )

    mark_task_retrying(
        sync_cache,
        settings,
        task_id=str(task_id),
        attempt=1,
        code="VT_RATE_LIMITED",
        message="Rate limited.",
        retry_in_seconds=30,
    )
    retrying = sync_cache.get_task_status(task_id)
    assert retrying is not None
    assert retrying.status is TaskState.RETRYING
    assert retrying.error_retryable is True

    mark_task_failed(
        sync_cache,
        settings,
        task_id=str(task_id),
        code="VT_AUTH_FAILED",
        message="Invalid key.",
        retryable=False,
    )
    failed = sync_cache.get_task_status(task_id)
    assert failed is not None
    assert failed.status is TaskState.FAILED
    assert failed.error_code == "VT_AUTH_FAILED"
