"""Celery application configuration."""

from __future__ import annotations

import logging

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init, worker_ready

from app.config import get_settings
from app.database import dispose_worker_engine

logger = logging.getLogger(__name__)
settings = get_settings()

celery_app = Celery(
    "webalizer",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.tasks.vt_worker", "app.tasks.maintenance"],
)

celery_app.conf.update(
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": 3600},
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    task_time_limit=settings.celery_task_time_limit_seconds,
    task_soft_time_limit=settings.celery_task_soft_time_limit_seconds,
    result_expires=86_400,
    task_default_queue="vt",
    task_routes={"triage.scan": {"queue": "vt"}},
    task_annotations={
        "triage.scan": {"rate_limit": settings.celery_task_rate_limit},
    },
    beat_schedule={
        "prune-expired-reports": {
            "task": "triage.prune_reports",
            "schedule": crontab(hour=3, minute=15),
        }
    },
)


@worker_ready.connect
def _warn_missing_vt_key(**_kwargs: object) -> None:
    """Log an actionable warning when live scanning is not configured."""

    if not settings.vt_api_key_value:
        logger.warning(
            "VT_API_KEY is not configured; scans will fail with VT_AUTH_FAILED until it is set."
        )


@worker_process_init.connect
def _reset_database_pool(**_kwargs: object) -> None:
    """Ensure forked workers do not share inherited PostgreSQL sockets."""

    dispose_worker_engine()
