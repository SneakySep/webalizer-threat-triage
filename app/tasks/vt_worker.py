"""Celery task that performs the actual VirusTotal triage."""

from __future__ import annotations

import logging
import random
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.celery_app import celery_app
from app.config import get_settings
from app.database import SyncSessionLocal
from app.schemas.triage import TargetType
from app.services.cache import SyncCache
from app.services.rate_limit import RedisTokenBucket
from app.services.triage import TriageService, mark_task_failed, mark_task_retrying
from app.services.virustotal import (
    VirusTotalClient,
    VTAuthError,
    VTError,
    VTRateLimitError,
    VTTransientError,
)
from app.utils.helpers import compute_cache_key

logger = logging.getLogger(__name__)
settings = get_settings()

redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
cache = SyncCache(redis_client)


@celery_app.task(
    bind=True,
    name="triage.scan",
    max_retries=settings.vt_max_retries,
    acks_late=True,
)
def scan_target(
    self: Any,
    task_id: str,
    target: str,
    target_type: str,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Run a URL or domain scan and persist the normalized report."""

    keep_lock = False
    vt_client: VirusTotalClient | None = None
    normalized_type: TargetType | None = None

    try:
        normalized_type = TargetType(target_type)
        limiter = RedisTokenBucket(
            redis_client,
            capacity=settings.vt_rate_limit_per_minute,
        )
        vt_client = VirusTotalClient(
            settings.vt_api_key_value,
            base_url=settings.vt_api_base_url,
            timeout_seconds=settings.vt_http_timeout_seconds,
            limiter=limiter,
            poll_initial_delay_seconds=settings.vt_poll_initial_delay_seconds,
            poll_max_delay_seconds=settings.vt_poll_max_delay_seconds,
            poll_timeout_seconds=settings.vt_poll_timeout_seconds,
        )
        service = TriageService(
            cache=cache,
            session_factory=SyncSessionLocal,
            settings=settings,
        )
        outcome = service.execute(
            task_id=task_id,
            target=target,
            target_type=normalized_type,
            force_refresh=force_refresh,
            attempt=self.request.retries,
            vt_client=vt_client,
        )
        return outcome.as_dict()

    except SoftTimeLimitExceeded:
        logger.exception("Task %s exceeded the soft time limit", task_id)
        _safe_mark_failed(
            task_id,
            code="TASK_TIMEOUT",
            message="The scan exceeded its time limit.",
            retryable=True,
        )
        raise

    except VTRateLimitError as exc:
        if self.request.retries >= self.max_retries:
            _safe_mark_failed(
                task_id,
                code=exc.code,
                message=exc.public_message,
                retryable=True,
            )
            raise
        attempt = self.request.retries + 1
        delay = _retry_delay(exc, attempt)
        keep_lock = True
        _safe_mark_retrying(
            task_id,
            attempt=attempt,
            code=exc.code,
            message=exc.public_message,
            retry_in_seconds=delay,
        )
        raise self.retry(exc=exc, countdown=delay) from exc

    except VTTransientError as exc:
        if self.request.retries >= self.max_retries:
            _safe_mark_failed(
                task_id,
                code=exc.code,
                message=exc.public_message,
                retryable=True,
            )
            raise
        attempt = self.request.retries + 1
        delay = _retry_delay(exc, attempt)
        keep_lock = True
        _safe_mark_retrying(
            task_id,
            attempt=attempt,
            code=exc.code,
            message=exc.public_message,
            retry_in_seconds=delay,
        )
        raise self.retry(exc=exc, countdown=delay) from exc

    except (VTAuthError, VTError) as exc:
        logger.error("Task %s failed with VT error %s: %s", task_id, exc.code, exc)
        _safe_mark_failed(
            task_id,
            code=exc.code,
            message=exc.public_message,
            retryable=exc.retryable,
        )
        raise

    except SQLAlchemyError:
        logger.exception("Task %s failed while persisting a report", task_id)
        _safe_mark_failed(
            task_id,
            code="DATABASE_ERROR",
            message="The report could not be stored.",
            retryable=True,
        )
        raise

    except Exception:
        logger.exception("Task %s failed unexpectedly", task_id)
        _safe_mark_failed(
            task_id,
            code="INTERNAL_ERROR",
            message="The scan failed due to an internal error.",
            retryable=False,
        )
        raise

    finally:
        if vt_client is not None:
            vt_client.close()
        if not keep_lock and normalized_type is not None:
            try:
                cache.release_lock(
                    compute_cache_key(normalized_type, target),
                    task_id,
                )
            except RedisError:
                logger.warning("Unable to release scan lock for task %s", task_id, exc_info=True)


def _retry_delay(exc: VTError, attempt: int) -> float:
    if exc.retry_after is not None:
        return max(1.0, min(float(exc.retry_after), settings.vt_retry_max_seconds))
    exponential = settings.vt_retry_base_seconds * (2 ** max(0, attempt - 1))
    capped = min(exponential, settings.vt_retry_max_seconds)
    return capped * random.uniform(0.8, 1.2)


def _safe_mark_retrying(
    task_id: str,
    *,
    attempt: int,
    code: str,
    message: str,
    retry_in_seconds: float,
) -> None:
    try:
        mark_task_retrying(
            cache,
            settings,
            task_id=task_id,
            attempt=attempt,
            code=code,
            message=message,
            retry_in_seconds=retry_in_seconds,
        )
    except RedisError:
        logger.warning("Could not record retry status for task %s", task_id, exc_info=True)


def _safe_mark_failed(
    task_id: str,
    *,
    code: str,
    message: str,
    retryable: bool,
) -> None:
    try:
        mark_task_failed(
            cache,
            settings,
            task_id=task_id,
            code=code,
            message=message,
            retryable=retryable,
        )
    except RedisError:
        logger.warning("Could not record failure status for task %s", task_id, exc_info=True)
