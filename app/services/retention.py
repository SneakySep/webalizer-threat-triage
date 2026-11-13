"""Report retention helpers shared by the cleanup script and tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.triage_report import TriageReport
from app.utils.helpers import utcnow

SessionFactory = Callable[[], Session]


def retention_cutoff(retention_days: int, *, now: datetime | None = None) -> datetime:
    if retention_days < 1:
        raise ValueError("retention_days must be at least 1")
    return (now or utcnow()) - timedelta(days=retention_days)


def count_reports_older_than(
    session_factory: SessionFactory,
    *,
    retention_days: int,
    now: datetime | None = None,
) -> int:
    cutoff = retention_cutoff(retention_days, now=now)
    with session_factory() as session:
        count = session.scalar(
            select(func.count()).select_from(TriageReport).where(TriageReport.created_at < cutoff)
        )
    return int(count or 0)


def prune_reports(
    session_factory: SessionFactory,
    *,
    retention_days: int,
    batch_size: int = 1_000,
    now: datetime | None = None,
) -> int:
    """Delete expired reports in batches to keep transactions short."""

    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    cutoff = retention_cutoff(retention_days, now=now)
    deleted_total = 0

    while True:
        with session_factory() as session:
            report_ids = list(
                session.scalars(
                    select(TriageReport.id)
                    .where(TriageReport.created_at < cutoff)
                    .order_by(TriageReport.created_at)
                    .limit(batch_size)
                )
            )
            if not report_ids:
                break

            result = session.execute(
                delete(TriageReport)
                .where(TriageReport.id.in_(report_ids))
                .execution_options(synchronize_session=False)
            )
            session.commit()
            deleted = int(result.rowcount or 0)
            deleted_total += max(0, deleted)
            if deleted < batch_size:
                break

    return deleted_total
