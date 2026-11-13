"""Fixture setup for tests that require real PostgreSQL and Redis services."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.database import Base
from app.models.triage_report import TriageReport  # noqa: F401
from app.schemas.triage import (
    EngineStats,
    TargetType,
    TriageResult,
    Verdict,
    VerdictConfidence,
)


@pytest.fixture(scope="session")
def integration_engine() -> Iterator[Engine]:
    database_url = os.getenv("INTEGRATION_DATABASE_URL", "").strip()
    if not database_url:
        pytest.skip("Set INTEGRATION_DATABASE_URL to run PostgreSQL integration tests")

    engine = create_engine(database_url, poolclass=NullPool)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def integration_session_factory(
    integration_engine: Engine,
) -> sessionmaker[Session]:
    with integration_engine.begin() as connection:
        connection.execute(text("TRUNCATE TABLE triage_reports"))
    return sessionmaker(
        bind=integration_engine,
        expire_on_commit=False,
        autoflush=False,
    )


@pytest.fixture
def sample_result() -> TriageResult:
    return TriageResult(
        target="integration.example",
        target_type=TargetType.DOMAIN,
        risk_score=2.22,
        detection_ratio="2/90",
        verdict=Verdict.MALICIOUS,
        confidence=VerdictConfidence.MEDIUM,
        engine_stats=EngineStats(
            malicious=2,
            suspicious=1,
            harmless=60,
            undetected=27,
            total=90,
        ),
        detections=[],
        categories=["Phishing"],
        dns_records=[],
        scan_date=None,
    )
