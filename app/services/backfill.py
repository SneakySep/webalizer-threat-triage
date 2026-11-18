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
    # Rows whose verdict would differ under the current thresholds, whether or
    # not this run was allowed to write them.
    verdicts_changed: int = 0

    @property
    def verdicts_unassessed(self) -> int:
        """Rows whose verdict could not be compared at all.

        ``normalized_data`` did not validate, so there is no engine_stats to
        recompute from and no way to know whether the verdict would have moved.
        ``verdicts_changed`` is therefore a floor, not a total, whenever this is
        non-zero.
        """

        return self.skipped_malformed

    def as_dict(self) -> dict[str, int]:
        return {
            "scanned": self.scanned,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "skipped_malformed": self.skipped_malformed,
            "verdicts_changed": self.verdicts_changed,
            "verdicts_unassessed": self.verdicts_unassessed,
        }


@dataclass
class VerdictSurvey:
    """Result of counting verdict drift without writing anything."""

    scanned: int = 0
    changed: int = 0
    unassessable: int = 0

    @property
    def is_exact(self) -> bool:
        """True when every row could be compared, so ``changed`` is a total."""

        return self.unassessable == 0


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
    write_verdicts: bool = False,
) -> BackfillReport:
    """Recompute risk_score for every stored report.

    ``dry_run`` computes the same numbers and reports what would change without
    writing anything, so the impact can be reviewed before it is applied.

    ``write_verdicts`` controls whether the recomputed verdict is stored. It is
    off by default: the thresholds in force when a report was written are not
    recorded, so a historical verdict cannot be proven to have used the current
    settings. With it off, a verdict is left exactly as stored and only the risk
    score is corrected. Rows whose verdict would differ are still counted in
    ``verdicts_changed`` so the impact is visible before anyone opts in.
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

                verdict_differs = new_verdict != stored_verdict
                if verdict_differs:
                    report.verdicts_changed += 1

                risk_differs = new_risk != stored_risk
                # A verdict-only difference is not a reason to touch the row
                # unless verdicts were explicitly opted into.
                if not risk_differs and not (write_verdicts and verdict_differs):
                    report.unchanged += 1
                    continue

                report.updated += 1
                if dry_run:
                    continue

                patched = dict(stored)
                patched["risk_score"] = new_risk
                values: dict[str, Any] = {
                    "risk_score": Decimal(str(new_risk)),
                    "normalized_data": patched,
                }
                if write_verdicts:
                    patched["verdict"] = new_verdict
                    values["verdict"] = new_verdict

                session.execute(
                    update(TriageReport)
                    .where(TriageReport.id == report_id)
                    .values(**values)
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
) -> VerdictSurvey:
    """Count rows whose verdict would change under the given thresholds.

    Verdict thresholds are not recorded per report, so a historical verdict
    cannot be proven to have used the current settings. This returns the count
    without writing, for an operator to review before deciding.

    Rows whose ``normalized_data`` does not validate cannot be compared and are
    reported as ``unassessable`` rather than folded into ``changed``, so the
    count is never presented as exact when it is not.
    """

    survey = VerdictSurvey()
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
                survey.scanned += 1
                recomputed = _recompute(
                    cast("dict[str, Any]", normalized_data),
                    malicious_min_engines=malicious_min_engines,
                    suspicious_min_engines=suspicious_min_engines,
                )
                if recomputed is None:
                    survey.unassessable += 1
                    continue
                if recomputed[1] != str(cast("dict[str, Any]", normalized_data).get("verdict", "")):
                    survey.changed += 1

    return survey


__all__ = [
    "BackfillReport",
    "VerdictSurvey",
    "backfill_risk_scores",
    "backfill_verdicts_only",
    "count_reports",
]
