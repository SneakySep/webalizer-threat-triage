"""Create triage_reports table.

Revision ID: 0001_create_triage_reports
Revises:
Create Date: 2026-11-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_create_triage_reports"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "triage_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("target_type", sa.String(length=10), nullable=False),
        sa.Column("risk_score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("verdict", sa.String(length=12), nullable=False),
        sa.Column("raw_vt_response", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("normalized_data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "target_type IN ('url', 'domain')",
            name="ck_triage_reports_target_type",
        ),
        sa.CheckConstraint(
            "verdict IN ('malicious', 'suspicious', 'harmless', 'unknown')",
            name="ck_triage_reports_verdict",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_triage_reports_target_created_at",
        "triage_reports",
        ["target", "created_at"],
    )
    op.create_index("ix_triage_reports_verdict", "triage_reports", ["verdict"])
    op.create_index("ix_triage_reports_target_type", "triage_reports", ["target_type"])


def downgrade() -> None:
    op.drop_index("ix_triage_reports_target_type", table_name="triage_reports")
    op.drop_index("ix_triage_reports_verdict", table_name="triage_reports")
    op.drop_index("ix_triage_reports_target_created_at", table_name="triage_reports")
    op.drop_table("triage_reports")
