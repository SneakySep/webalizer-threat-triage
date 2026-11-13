"""PostgreSQL integration tests for report idempotency and retention."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models.triage_report import TriageReport
from app.schemas.triage import TriageResult
from app.services.cache import SyncCache
from app.services.retention import count_reports_older_than, prune_reports
from app.services.triage import TriageService

pytestmark = pytest.mark.integration


def _stored_report(
    result: TriageResult,
    *,
    target: str,
    created_at: datetime,
) -> TriageReport:
    return TriageReport(
        id=uuid.uuid4(),
        task_id=uuid.uuid4(),
        target=target,
        target_type=result.target_type.value,
        risk_score=result.risk_score,
        verdict=result.verdict.value,
        raw_vt_response={},
        normalized_data=result.model_dump(mode="json"),
        created_at=created_at,
    )


def test_report_persistence_is_idempotent_for_a_task(
    integration_session_factory: sessionmaker[Session],
    sample_result: TriageResult,
) -> None:
    settings = get_settings().model_copy(update={"store_raw_vt_response": False})
    service = TriageService(
        cache=cast(SyncCache, None),
        session_factory=integration_session_factory,
        settings=settings,
    )
    task_id = uuid.uuid4()

    first = service._persist_report(
        sample_result,
        {"data": {"id": "integration-task"}},
        task_id=task_id,
    )
    second = service._persist_report(
        sample_result,
        {"data": {"id": "integration-task"}},
        task_id=task_id,
    )

    assert second.id == first.id
    with integration_session_factory() as session:
        reports = list(session.scalars(select(TriageReport)))
    assert len(reports) == 1
    assert reports[0].task_id == task_id
    assert reports[0].raw_vt_response == {}


def test_prune_reports_deletes_only_rows_past_retention(
    integration_session_factory: sessionmaker[Session],
    sample_result: TriageResult,
) -> None:
    now = datetime.now(UTC)
    with integration_session_factory() as session:
        session.add_all(
            [
                _stored_report(
                    sample_result,
                    target="expired-old.example",
                    created_at=now - timedelta(days=400),
                ),
                _stored_report(
                    sample_result,
                    target="expired-recent.example",
                    created_at=now - timedelta(days=200),
                ),
                _stored_report(
                    sample_result,
                    target="kept.example",
                    created_at=now - timedelta(days=10),
                ),
            ]
        )
        session.commit()

    assert (
        count_reports_older_than(
            integration_session_factory,
            retention_days=180,
            now=now,
        )
        == 2
    )

    deleted = prune_reports(
        integration_session_factory,
        retention_days=180,
        batch_size=1,
        now=now,
    )
    assert deleted == 2
    assert (
        count_reports_older_than(
            integration_session_factory,
            retention_days=180,
            now=now,
        )
        == 0
    )

    with integration_session_factory() as session:
        remaining = list(session.scalars(select(TriageReport)))
    assert [report.target for report in remaining] == ["kept.example"]
