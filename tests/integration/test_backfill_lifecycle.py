"""PostgreSQL integration tests for the risk-score backfill."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.triage_report import TriageReport
from app.services.backfill import backfill_risk_scores

pytestmark = pytest.mark.integration


def _stored_blob(
    *,
    malicious: int,
    suspicious: int,
    total: int,
    risk_score: float,
    verdict: str = "suspicious",
) -> dict[str, Any]:
    return {
        "target": "example.com",
        "target_type": "domain",
        "risk_score": risk_score,
        "detection_ratio": f"{malicious}/{total}",
        "verdict": verdict,
        "confidence": None,
        "engine_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": max(0, total - malicious - suspicious),
            "harmless": 0,
            "timeout": 0,
            "total": total,
        },
        "detections": [],
        "categories": [],
        "dns_records": [],
        "scan_date": None,
    }


def _row(blob: dict[str, Any], *, target: str) -> TriageReport:
    return TriageReport(
        id=uuid.uuid4(),
        task_id=uuid.uuid4(),
        target=target,
        target_type="domain",
        risk_score=blob["risk_score"],
        verdict=blob["verdict"],
        raw_vt_response={"data": {"id": "untouched"}},
        normalized_data=blob,
    )


def test_backfill_rewrites_both_the_column_and_the_json_blob(
    integration_session_factory: sessionmaker[Session],
) -> None:
    stale = _stored_blob(malicious=0, suspicious=20, total=90, risk_score=0.0)
    with integration_session_factory() as session:
        session.add(_row(stale, target="stale.example"))
        session.commit()

    report = backfill_risk_scores(integration_session_factory)

    assert report.scanned == 1
    assert report.updated == 1

    with integration_session_factory() as session:
        stored = session.scalars(select(TriageReport)).one()

    # The API reads the blob, so the blob is what actually matters.
    assert float(stored.risk_score) == 11.11
    assert stored.normalized_data["risk_score"] == 11.11
    assert stored.normalized_data["verdict"] == "suspicious"
    # Raw evidence must survive untouched.
    assert stored.raw_vt_response == {"data": {"id": "untouched"}}


def test_backfill_is_idempotent(
    integration_session_factory: sessionmaker[Session],
) -> None:
    stale = _stored_blob(malicious=0, suspicious=20, total=90, risk_score=0.0)
    with integration_session_factory() as session:
        session.add(_row(stale, target="stale.example"))
        session.commit()

    first = backfill_risk_scores(integration_session_factory)
    second = backfill_risk_scores(integration_session_factory)

    assert first.updated == 1
    assert second.updated == 0
    assert second.unchanged == 1


def test_dry_run_changes_nothing_in_the_database(
    integration_session_factory: sessionmaker[Session],
) -> None:
    stale = _stored_blob(malicious=0, suspicious=20, total=90, risk_score=0.0)
    with integration_session_factory() as session:
        session.add(_row(stale, target="stale.example"))
        session.commit()

    report = backfill_risk_scores(integration_session_factory, dry_run=True)

    assert report.updated == 1
    with integration_session_factory() as session:
        stored = session.scalars(select(TriageReport)).one()
    assert float(stored.risk_score) == 0.0
    assert stored.normalized_data["risk_score"] == 0.0


def test_backfill_pages_across_batches(
    integration_session_factory: sessionmaker[Session],
) -> None:
    with integration_session_factory() as session:
        session.add_all(
            [
                _row(
                    _stored_blob(malicious=0, suspicious=20, total=90, risk_score=0.0),
                    target=f"stale-{index}.example",
                )
                for index in range(5)
            ]
        )
        session.commit()

    report = backfill_risk_scores(integration_session_factory, batch_size=2)

    assert report.scanned == 5
    assert report.updated == 5
    with integration_session_factory() as session:
        rows = list(session.scalars(select(TriageReport)))
    assert all(row.normalized_data["risk_score"] == 11.11 for row in rows)
