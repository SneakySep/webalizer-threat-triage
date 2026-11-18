"""Recompute derived report fields after a scoring-rule change.

``risk_score`` is stored twice: once as a column and once inside the
``normalized_data`` JSON blob. The report endpoints read the blob, so a backfill
that only touched the column would leave the API serving the old value. Both are
updated here.

Only derived fields are recomputed. The raw VirusTotal payload is never touched,
so a backfill is always repeatable from stored evidence.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, cast

from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.triage_report import TriageReport
from app.schemas.triage import TriageResult
from app.services.normalizer import _calculate_risk_score, _calculate_verdict

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]


@dataclass
class BackfillReport:
    """Outcome of a risk-score backfill run."""

    scanned: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped_malformed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "scanned": self.scanned,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "skipped_malformed": self.skipped_malformed,
        }


def _recompute(
    normalized_data: dict[str, Any],
    *,
    malicious_min_engines: int,
    suspicious_min_engines: int,
) -> tuple[float, str] | None:
    """Return the corrected (risk_score, verdict) for a stored report."""

    try:
        result = TriageResult.model_validate(normalized_data)
    except ValidationError:
        return None

    risk_score = _calculate_risk_score(result.engine_stats)
    verdict = _calculate_verdict(
        result.engine_stats,
        malicious_min_engines=malicious_min_engines,
        suspicious_min_engines=suspicious_min_engines,
    )
    return risk_score, verdict.value


def count_reports(session_factory: SessionFactory) -> int:
    with session_factory() as session:
        return int(session.scalar(select(func.count()).select_from(TriageReport)) or 0)


def backfill_risk_scores(
    session_factory: SessionFactory,
    *,
    malicious_min_engines: int = 1,
    suspicious_min_engines: int = 1,
    batch_size: int = 500,
    dry_run: bool = False,
) -> BackfillReport:
    """Recompute risk_score (and optionally verdict) for every stored report.

    ``dry_run`` computes the same numbers and reports what would change without
    writing anything, so the impact can be reviewed before it is applied.
    """

    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    report = BackfillReport()
    last_id: Any = None

    while True:
        with session_factory() as session:
            statement = (
                select(TriageReport.id, TriageReport.normalized_data)
                .order_by(TriageReport.id)
                .limit(batch_size)
            )
            if last_id is not None:
                statement = statement.where(TriageReport.id > last_id)

            rows = list(session.execute(statement).all())
            if not rows:
                break

            for report_id, normalized_data in rows:
                report.scanned += 1
                last_id = report_id

                recomputed = _recompute(
                    cast("dict[str, Any]", normalized_data),
                    malicious_min_engines=malicious_min_engines,
                    suspicious_min_engines=suspicious_min_engines,
                )
                if recomputed is None:
                    report.skipped_malformed += 1
                    logger.warning("Skipping report %s: normalized_data is malformed", report_id)
                    continue

                new_risk, new_verdict = recomputed
                stored = cast("dict[str, Any]", normalized_data)
                stored_risk = float(stored.get("risk_score", 0))
                stored_verdict = str(stored.get("verdict", ""))

                if new_risk == stored_risk and new_verdict == stored_verdict:
                    report.unchanged += 1
                    continue

                report.updated += 1
                if dry_run:
                    continue

                patched = dict(stored)
                patched["risk_score"] = new_risk
                patched["verdict"] = new_verdict
                session.execute(
                    update(TriageReport)
                    .where(TriageReport.id == report_id)
                    .values(
                        risk_score=Decimal(str(new_risk)),
                        verdict=new_verdict,
                        normalized_data=patched,
                    )
                    .execution_options(synchronize_session=False)
                )

            if not dry_run:
                session.commit()

    return report


def backfill_verdicts_only(
    session_factory: SessionFactory,
    *,
    malicious_min_engines: int,
    suspicious_min_engines: int,
    batch_size: int = 500,
) -> int:
    """Count rows whose verdict would change under the given thresholds.

    Verdict thresholds are not recorded per report, so a historical verdict
    cannot be proven to have used the current settings. This returns the count
    without writing, for an operator to review before deciding.
    """

    changed = 0
    last_id: Any = None

    while True:
        with session_factory() as session:
            statement = (
                select(TriageReport.id, TriageReport.normalized_data)
                .order_by(TriageReport.id)
                .limit(batch_size)
            )
            if last_id is not None:
                statement = statement.where(TriageReport.id > last_id)

            rows = list(session.execute(statement).all())
            if not rows:
                break

            for report_id, normalized_data in rows:
                last_id = report_id
                recomputed = _recompute(
                    cast("dict[str, Any]", normalized_data),
                    malicious_min_engines=malicious_min_engines,
                    suspicious_min_engines=suspicious_min_engines,
                )
                if recomputed is None:
                    continue
                if recomputed[1] != str(cast("dict[str, Any]", normalized_data).get("verdict", "")):
                    changed += 1

    return changed


__all__ = [
    "BackfillReport",
    "backfill_risk_scores",
    "backfill_verdicts_only",
    "count_reports",
]
