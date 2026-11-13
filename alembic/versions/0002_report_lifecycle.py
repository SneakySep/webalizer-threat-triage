"""Add task idempotency and retention index.

Revision ID: 0002_report_lifecycle
Revises: 0001_create_triage_reports
Create Date: 2026-11-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_report_lifecycle"
down_revision: str | None = "0001_create_triage_reports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "triage_reports",
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_unique_constraint(
        "uq_triage_reports_task_id",
        "triage_reports",
        ["task_id"],
    )
    op.create_index(
        "ix_triage_reports_created_at",
        "triage_reports",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_triage_reports_created_at", table_name="triage_reports")
    op.drop_constraint(
        "uq_triage_reports_task_id",
        "triage_reports",
        type_="unique",
    )
    op.drop_column("triage_reports", "task_id")
