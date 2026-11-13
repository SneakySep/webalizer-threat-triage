"""Threat triage API endpoints."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request, Response
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
    request: Request,
    response: Response,
    cache: AsyncCache = Depends(get_cache),
    dispatcher: TaskDispatcher = Depends(get_task_dispatcher),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    try:
        await _enforce_scan_rate_limit(request, cache, settings)
    except RedisError as exc:
        logger.exception("Redis operation failed while checking the scan rate limit")
        raise AppError(
            503,
            "CACHE_UNAVAILABLE",
            "The cache service is unavailable. Try again shortly.",
        ) from exc

    try:
        parsed = normalize_target(payload.target)
    except InvalidTargetError as exc:
        raise AppError(
            422,
            "INVALID_TARGET",
            str(exc),
        ) from exc

    cache_key = compute_cache_key(parsed.target_type, parsed.target)
    task_id = uuid4()
    cooldown_key = f"triage:force-refresh:{cache_key}"
    lock_held = False
    cooldown_set = False
    status_created = False

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

        lock_held = True

        if payload.force_refresh and settings.force_refresh_cooldown_seconds > 0:
            allowed = await cache.set_if_absent(
                cooldown_key,
                ttl_seconds=settings.force_refresh_cooldown_seconds,
            )
            if not allowed:
                retry_after = max(1, await cache.get_ttl(cooldown_key))
                raise AppError(
                    429,
                    "FORCE_REFRESH_COOLDOWN",
                    "This target was refreshed recently. Try again shortly.",
                    details={"retry_after_seconds": retry_after},
                    headers={"Retry-After": str(retry_after)},
                )
            cooldown_set = True

        # A scan may have completed between the first cache read and lock
        # acquisition. Re-check to avoid a duplicate VirusTotal request.
        if not payload.force_refresh:
            cached = await cache.get_cached(parsed.target_type, parsed.target)
            if cached is not None:
                await _release_scan_lock(cache, cache_key, task_id)
                lock_held = False
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
        status_created = True

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

    except Exception as exc:
        await _cleanup_scan_submission(
            cache,
            cache_key=cache_key,
            task_id=task_id,
            cooldown_key=cooldown_key,
            lock_held=lock_held,
            cooldown_set=cooldown_set,
            status_created=status_created,
        )
        if isinstance(exc, RedisError):
            logger.exception("Redis operation failed during scan submission")
            raise AppError(
                503,
                "CACHE_UNAVAILABLE",
                "The cache service is unavailable. Try again shortly.",
            ) from exc
        raise


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


async def _enforce_scan_rate_limit(
    request: Request,
    cache: AsyncCache,
    settings: Settings,
) -> None:
    identity = _client_identity(request, settings)
    windows = (
        ("minute", settings.scan_rate_limit_per_minute, 60),
        ("hour", settings.scan_rate_limit_per_hour, 3600),
    )
    for name, limit, window_seconds in windows:
        count, ttl = await cache.increment_window(
            f"triage:rate:scan:{name}:{identity}",
            window_seconds=window_seconds,
        )
        if count > limit:
            retry_after = max(1, ttl)
            raise AppError(
                429,
                "RATE_LIMITED",
                "Too many scan requests. Try again shortly.",
                details={"limit": limit, "window_seconds": window_seconds},
                headers={"Retry-After": str(retry_after)},
            )


def _client_identity(request: Request, settings: Settings) -> str:
    """Key limits by API key when auth is on, otherwise by client address."""

    if settings.triage_api_key_value:
        api_key = request.headers.get("X-API-Key")
        if api_key:
            digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:32]
            return f"key:{digest}"
    host = request.client.host if request.client is not None else "unknown"
    return f"ip:{host}"


async def _release_scan_lock(cache: AsyncCache, cache_key: str, task_id: UUID) -> None:
    try:
        await cache.release_lock(cache_key, str(task_id))
    except RedisError:
        logger.warning("Unable to release scan lock for task %s", task_id, exc_info=True)


async def _cleanup_scan_submission(
    cache: AsyncCache,
    *,
    cache_key: str,
    task_id: UUID,
    cooldown_key: str,
    lock_held: bool,
    cooldown_set: bool,
    status_created: bool,
) -> None:
    if lock_held:
        await _release_scan_lock(cache, cache_key, task_id)
    if cooldown_set:
        try:
            await cache.delete_key(cooldown_key)
        except RedisError:
            logger.warning(
                "Unable to clear force-refresh cooldown for task %s",
                task_id,
                exc_info=True,
            )
    if status_created:
        try:
            await cache.delete_task_status(task_id)
        except RedisError:
            logger.warning(
                "Unable to delete task status for task %s",
                task_id,
                exc_info=True,
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
