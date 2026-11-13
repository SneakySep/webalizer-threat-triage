"""Synchronous triage orchestration shared by the Celery worker."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID

from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.triage_report import TriageReport
from app.schemas.triage import TargetType, TaskState, TriageResult
from app.services.cache import CachedTriage, SyncCache, TaskRecord
from app.services.normalizer import normalize_domain_result, normalize_url_result
from app.services.virustotal import VirusTotalClient
from app.utils.helpers import utcnow

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TriageOutcome:
    report_id: UUID
    normalized: TriageResult
    cached: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "report_id": str(self.report_id),
            "cached": self.cached,
            "verdict": self.normalized.verdict.value,
            "risk_score": self.normalized.risk_score,
        }


class TriageService:
    def __init__(
        self,
        *,
        cache: SyncCache,
        session_factory: Callable[[], Session],
        settings: Settings,
    ) -> None:
        self.cache = cache
        self.session_factory = session_factory
        self.settings = settings

    def execute(
        self,
        *,
        task_id: str,
        target: str,
        target_type: TargetType,
        force_refresh: bool,
        attempt: int,
        vt_client: VirusTotalClient,
    ) -> TriageOutcome:
        status = self.cache.get_task_status(task_id)
        if status is None:
            now = utcnow()
            status = TaskRecord(
                task_id=UUID(task_id),
                status=TaskState.QUEUED,
                stage="queued",
                target=target,
                target_type=target_type,
                created_at=now,
                updated_at=now,
            )
        self._update(
            status,
            status=TaskState.PROCESSING,
            stage="checking_cache",
            attempt=attempt,
            error_code=None,
            error_message=None,
            error_retryable=False,
        )

        if not force_refresh:
            cached = self.cache.get_cached(target_type, target)
            if cached is not None:
                self._update(
                    status,
                    status=TaskState.COMPLETED,
                    stage="cache_hit",
                    report_id=cached.report_id,
                )
                logger.info("Task %s completed from cache", task_id)
                return TriageOutcome(
                    report_id=cached.report_id,
                    normalized=cached.normalized,
                    cached=True,
                )

        if target_type is TargetType.URL:
            self._update(status, stage="analyzing_url")
            analysis_id = status.analysis_id

            def remember_analysis_id(new_analysis_id: str) -> None:
                self._update(status, analysis_id=new_analysis_id)

            analysis, url_report = vt_client.scan_url(
                target,
                analysis_id=analysis_id,
                on_analysis_id=remember_analysis_id,
            )
            raw_vt_response: dict[str, Any] = {
                "analysis": analysis,
                "url": url_report,
            }
            self._update(status, stage="normalizing")
            normalized = normalize_url_result(
                target,
                analysis,
                url_report,
                malicious_min_engines=self.settings.malicious_min_engines,
                suspicious_min_engines=self.settings.suspicious_min_engines,
            )
        else:
            self._update(status, stage="fetching_domain")
            domain_report = vt_client.scan_domain(target)
            raw_vt_response = {"domain": domain_report}
            self._update(status, stage="normalizing")
            normalized = normalize_domain_result(
                target,
                domain_report,
                malicious_min_engines=self.settings.malicious_min_engines,
                suspicious_min_engines=self.settings.suspicious_min_engines,
            )

        self._update(status, stage="saving_report")
        report = self._persist_report(
            normalized,
            raw_vt_response,
            task_id=UUID(task_id),
        )

        try:
            self.cache.set_cached(
                CachedTriage(
                    task_id=UUID(task_id),
                    report_id=report.id,
                    normalized=normalized,
                ),
                ttl_seconds=self.settings.cache_ttl_seconds,
            )
        except RedisError:
            logger.warning("Failed to cache completed report %s", report.id, exc_info=True)

        self._update(
            status,
            status=TaskState.COMPLETED,
            stage="completed",
            report_id=report.id,
            analysis_id=None,
        )
        logger.info("Task %s completed with report %s", task_id, report.id)
        return TriageOutcome(report_id=report.id, normalized=normalized, cached=False)

    def _persist_report(
        self,
        normalized: TriageResult,
        raw_vt_response: dict[str, Any],
        *,
        task_id: UUID,
    ) -> TriageReport:
        report = TriageReport(
            task_id=task_id,
            target=normalized.target,
            target_type=normalized.target_type.value,
            risk_score=Decimal(str(normalized.risk_score)),
            verdict=normalized.verdict.value,
            raw_vt_response=raw_vt_response if self.settings.store_raw_vt_response else {},
            normalized_data=normalized.model_dump(mode="json"),
        )
        with self.session_factory() as session:
            session.add(report)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = session.scalar(
                    select(TriageReport).where(TriageReport.task_id == task_id)
                )
                if existing is None:
                    raise
                logger.info(
                    "Task %s already has report %s; reusing the stored row",
                    task_id,
                    existing.id,
                )
                return existing
            session.refresh(report)
        return report

    def _update(self, record: TaskRecord, **fields: Any) -> None:
        for field, value in fields.items():
            setattr(record, field, value)
        record.updated_at = utcnow()
        self.cache.set_task_status(
            record,
            ttl_seconds=self.settings.task_status_ttl_seconds,
        )


def mark_task_retrying(
    cache: SyncCache,
    settings: Settings,
    *,
    task_id: str,
    attempt: int,
    code: str,
    message: str,
    retry_in_seconds: float,
) -> None:
    record = cache.get_task_status(task_id)
    if record is None:
        return
    record.status = TaskState.RETRYING
    record.stage = "retry_scheduled"
    record.attempt = attempt
    record.error_code = code
    record.error_message = message
    record.error_retryable = True
    record.updated_at = utcnow()
    cache.set_task_status(record, ttl_seconds=settings.task_status_ttl_seconds)
    logger.warning(
        "Task %s scheduled for retry in %.1fs (%s)",
        task_id,
        retry_in_seconds,
        code,
    )


def mark_task_failed(
    cache: SyncCache,
    settings: Settings,
    *,
    task_id: str,
    code: str,
    message: str,
    retryable: bool,
) -> None:
    record = cache.get_task_status(task_id)
    if record is None:
        return
    record.status = TaskState.FAILED
    record.stage = "failed"
    record.error_code = code
    record.error_message = message
    record.error_retryable = retryable
    record.analysis_id = None
    record.updated_at = utcnow()
    cache.set_task_status(record, ttl_seconds=settings.task_status_ttl_seconds)
    logger.error("Task %s failed: %s - %s", task_id, code, message)
