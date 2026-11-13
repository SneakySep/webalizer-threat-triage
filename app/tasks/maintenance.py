"""Scheduled maintenance tasks."""

from __future__ import annotations

import logging

from app.celery_app import celery_app
from app.config import get_settings
from app.database import SyncSessionLocal
from app.services.retention import prune_reports

logger = logging.getLogger(__name__)
settings = get_settings()


@celery_app.task(name="triage.prune_reports")
def prune_reports_task() -> int:
    """Delete reports outside the configured retention window."""

    deleted = prune_reports(
        SyncSessionLocal,
        retention_days=settings.report_retention_days,
    )
    logger.info(
        "Retention task removed %s report(s) older than %s day(s)",
        deleted,
        settings.report_retention_days,
    )
    return deleted
