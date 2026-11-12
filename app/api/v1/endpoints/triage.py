"""Threat triage API endpoints."""

from __future__ import annotations

import asyncio
import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Response
from fastapi import status as http_status
from pydantic import ValidationError
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_cache, get_session, get_settings, get_task_dispatcher
from app.config import Settings
from app.errors import AppError
from app.models.triage_report import TriageReport
from app.schemas.triage import (
    ScanRequest,
    ScanResponse,
    TaskError,
    TaskState,
    TaskStatusResponse,
    TriageReportResponse,
    TriageResult,
)
from app.services.cache import AsyncCache, TaskRecord
from app.services.dispatcher import TaskDispatcher
from app.utils.helpers import (
    InvalidTargetError,
    compute_cache_key,
    normalize_target,
    utcnow,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/triage", tags=["triage"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=http_status.HTTP_202_ACCEPTED,
    summary="Submit a URL or domain for threat triage",
)
async def scan_target(
    payload: ScanRequest,
    response: Response,
    cache: AsyncCache = Depends(get_cache),
    dispatcher: TaskDispatcher = Depends(get_task_dispatcher),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    try:
        parsed = normalize_target(payload.target)
    except InvalidTargetError as exc:
        raise AppError(
            422,
            "INVALID_TARGET",
            str(exc),
        ) from exc

    try:
        if not payload.force_refresh:
            cached = await cache.get_cached(parsed.target_type, parsed.target)
            if cached is not None:
                response.status_code = http_status.HTTP_200_OK
                return ScanResponse(
                    task_id=cached.task_id,
                    status=TaskState.COMPLETED,
                    cached=True,
                    report_id=cached.report_id,
                    result=cached.normalized,
                    poll_url=_poll_url(cached.task_id, settings.api_v1_prefix),
                )

        cache_key = compute_cache_key(parsed.target_type, parsed.target)
        task_id = uuid4()
        acquired = await cache.acquire_lock(
            cache_key,
            str(task_id),
            ttl_seconds=settings.inflight_lock_ttl_seconds,
        )

        if not acquired:
            existing = await _existing_task(cache, cache_key)
            if existing is not None:
                response.status_code = http_status.HTTP_202_ACCEPTED
                return ScanResponse(
                    task_id=existing.task_id,
                    status=existing.status,
                    cached=False,
                    deduplicated=True,
                    report_id=existing.report_id,
                    poll_url=_poll_url(existing.task_id, settings.api_v1_prefix),
                )
            acquired = await cache.acquire_lock(
                cache_key,
                str(task_id),
                ttl_seconds=settings.inflight_lock_ttl_seconds,
            )
            if not acquired:
                raise AppError(
                    409,
                    "SCAN_IN_PROGRESS",
                    "An identical scan is already in progress.",
                )

        # A scan may have completed between the first cache read and lock
        # acquisition. Re-check to avoid a duplicate VirusTotal request.
        if not payload.force_refresh:
            cached = await cache.get_cached(parsed.target_type, parsed.target)
            if cached is not None:
                await cache.release_lock(cache_key, str(task_id))
                response.status_code = http_status.HTTP_200_OK
                return ScanResponse(
                    task_id=cached.task_id,
                    status=TaskState.COMPLETED,
                    cached=True,
                    report_id=cached.report_id,
                    result=cached.normalized,
                    poll_url=_poll_url(cached.task_id, settings.api_v1_prefix),
                )

        now = utcnow()
        record = TaskRecord(
            task_id=task_id,
            status=TaskState.QUEUED,
            stage="queued",
            target=parsed.target,
            target_type=parsed.target_type,
            created_at=now,
            updated_at=now,
        )
        await cache.set_task_status(
            record,
            ttl_seconds=settings.task_status_ttl_seconds,
        )

        try:
            await asyncio.to_thread(
                dispatcher.send_scan,
                task_id=str(task_id),
                target=parsed.target,
                target_type=parsed.target_type,
                force_refresh=payload.force_refresh,
            )
        except Exception as exc:
            logger.exception("Failed to enqueue task %s", task_id)
            try:
                await cache.release_lock(cache_key, str(task_id))
                await cache.delete_task_status(task_id)
            except RedisError:
                logger.warning("Failed to clean up task %s after enqueue error", task_id)
            raise AppError(
                503,
                "QUEUE_UNAVAILABLE",
                "Unable to queue the scan. Try again shortly.",
            ) from exc

        response.status_code = http_status.HTTP_202_ACCEPTED
        return ScanResponse(
            task_id=task_id,
            status=TaskState.QUEUED,
            cached=False,
            poll_url=_poll_url(task_id, settings.api_v1_prefix),
        )

    except RedisError as exc:
        logger.exception("Redis operation failed during scan submission")
        raise AppError(
            503,
            "CACHE_UNAVAILABLE",
            "The cache service is unavailable. Try again shortly.",
        ) from exc


@router.get(
    "/status/{task_id}",
    response_model=TaskStatusResponse,
    summary="Poll a triage task",
)
async def get_scan_status(
    task_id: UUID,
    cache: AsyncCache = Depends(get_cache),
    settings: Settings = Depends(get_settings),
) -> TaskStatusResponse:
    try:
        record = await cache.get_task_status(task_id)
    except RedisError as exc:
        logger.exception("Redis operation failed while reading task %s", task_id)
        raise AppError(
            503,
            "CACHE_UNAVAILABLE",
            "The cache service is unavailable. Try again shortly.",
        ) from exc

    if record is None:
        raise AppError(404, "TASK_NOT_FOUND", "The requested task was not found.")

    error = None
    if record.status is TaskState.FAILED:
        error = TaskError(
            code=record.error_code or "TASK_FAILED",
            message=record.error_message or "The scan failed.",
            retryable=record.error_retryable,
        )

    return TaskStatusResponse(
        task_id=record.task_id,
        status=record.status,
        stage=record.stage,
        target=record.target,
        target_type=record.target_type,
        attempt=record.attempt,
        report_id=record.report_id,
        report_url=_report_url(record.report_id, settings.api_v1_prefix),
        error=error,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "/report/{report_id}",
    response_model=TriageReportResponse,
    summary="Retrieve a stored triage report",
)
async def get_report(
    report_id: UUID,
    include_raw: bool = Query(
        default=False,
        description="Include the original VirusTotal JSON response.",
    ),
    session: AsyncSession = Depends(get_session),
) -> TriageReportResponse:
    try:
        report = await session.get(TriageReport, report_id)
    except SQLAlchemyError as exc:
        logger.exception("Database error while loading report %s", report_id)
        raise AppError(
            503,
            "DATABASE_UNAVAILABLE",
            "The report database is unavailable. Try again shortly.",
        ) from exc

    if report is None:
        raise AppError(404, "REPORT_NOT_FOUND", "The requested report was not found.")

    try:
        normalized = TriageResult.model_validate(report.normalized_data)
    except ValidationError as exc:
        logger.error("Stored report %s is malformed", report_id, exc_info=True)
        raise AppError(
            500,
            "REPORT_CORRUPTED",
            "The stored report could not be read.",
        ) from exc

    return TriageReportResponse(
        **normalized.model_dump(),
        report_id=report.id,
        created_at=report.created_at,
        raw_vt_response=report.raw_vt_response if include_raw else None,
    )


_ACTIVE_TASK_STATES = {
    TaskState.QUEUED,
    TaskState.PROCESSING,
    TaskState.RETRYING,
}


async def _existing_task(cache: AsyncCache, cache_key: str) -> TaskRecord | None:
    owner = await cache.get_lock_owner(cache_key)
    if owner is None:
        return None
    record = await cache.get_task_status(owner)
    if record is not None:
        if record.status in _ACTIVE_TASK_STATES:
            return record
        # The owner finished but did not release its lock (for example, a
        # worker crash right before cleanup). It is safe to reclaim.
        await cache.release_lock(cache_key, owner)
        return None
    # A lock may exist before its owner has written the status record. Never
    # release another request's lock in that window: the caller will retry
    # acquisition and return SCAN_IN_PROGRESS if the lock is still held.
    return None


def _poll_url(task_id: UUID | str, api_prefix: str) -> str:
    return f"{api_prefix}/triage/status/{task_id}"


def _report_url(report_id: UUID | None, api_prefix: str) -> str | None:
    return f"{api_prefix}/triage/report/{report_id}" if report_id else None
