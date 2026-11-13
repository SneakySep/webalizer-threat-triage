"""Persistent historical triage reports."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TriageReport(Base):
    __tablename__ = "triage_reports"
    __table_args__ = (
        CheckConstraint("target_type IN ('url', 'domain')", name="ck_triage_reports_target_type"),
        CheckConstraint(
            "verdict IN ('malicious', 'suspicious', 'harmless', 'unknown')",
            name="ck_triage_reports_verdict",
        ),
        Index("ix_triage_reports_target_created_at", "target", "created_at"),
        Index("ix_triage_reports_verdict", "verdict"),
        Index("ix_triage_reports_target_type", "target_type"),
        Index("ix_triage_reports_created_at", "created_at"),
        UniqueConstraint("task_id", name="uq_triage_reports_task_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    target: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(String(10), nullable=False)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    verdict: Mapped[str] = mapped_column(String(12), nullable=False)
    raw_vt_response: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    normalized_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
    )
