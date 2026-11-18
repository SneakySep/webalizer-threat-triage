"""Recompute stored risk scores after a scoring-rule change.

The risk score used to count malicious detections only, so a target flagged
suspicious by many engines could be stored with a 0.0 score next to a
"suspicious" verdict. Reports written before that fix keep the old value until
they are recomputed here.

Run with::

    python -m scripts.backfill_risk_scores --dry-run
    python -m scripts.backfill_risk_scores

The dry run computes the same numbers and reports what would change without
writing anything. Verdicts are left alone unless --with-verdicts is passed: the
verdict thresholds in force when a row was written are not recorded, so
rewriting historical verdicts is a judgement call, not a repair. Because of
that, --with-verdicts only reports the impact; applying it needs
--force-verdicts as well, after the dry run has been reviewed.
"""

from __future__ import annotations

import argparse

from app.config import get_settings
from app.database import SyncSessionLocal
from app.services.backfill import (
    backfill_risk_scores,
    backfill_verdicts_only,
    count_reports,
)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Rows read per transaction.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing anything.",
    )
    parser.add_argument(
        "--with-verdicts",
        action="store_true",
        help=(
            "Also rewrite verdicts using the current thresholds. Only correct if "
            "every stored report was written with these same thresholds."
        ),
    )
    parser.add_argument(
        "--force-verdicts",
        action="store_true",
        help=(
            "Confirm that rewriting historical verdicts is intended. Required "
            "alongside --with-verdicts, and only accepted after a dry run has "
            "shown how many rows would change."
        ),
    )
    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")
    if args.force_verdicts and not args.with_verdicts:
        parser.error("--force-verdicts only applies together with --with-verdicts")

    total = count_reports(SyncSessionLocal)
    print(f"{total} stored report(s) found")
    if total == 0:
        return 0

    if args.with_verdicts:
        survey = backfill_verdicts_only(
            SyncSessionLocal,
            malicious_min_engines=settings.malicious_min_engines,
            suspicious_min_engines=settings.suspicious_min_engines,
            batch_size=args.batch_size,
        )
        print(
            f"{survey.changed} report(s) would change verdict under the current "
            f"thresholds (malicious>={settings.malicious_min_engines}, "
            f"suspicious>={settings.suspicious_min_engines})"
        )
        if not survey.is_exact:
            print(
                f"That count is a floor, not a total: {survey.unassessable} row(s) "
                f"could not be compared because their normalized_data does not "
                f"validate. Repair or accept those separately before treating the "
                f"number as complete."
            )
        if survey.changed and not args.dry_run and not args.force_verdicts:
            print(
                "Refusing to rewrite verdicts without confirmation: thresholds are "
                "not recorded per report, so this cannot be verified as a repair.\n"
                "Review the dry run above, then re-run with --with-verdicts "
                "--force-verdicts to apply it deliberately."
            )
            return 1

    report = backfill_risk_scores(
        SyncSessionLocal,
        malicious_min_engines=settings.malicious_min_engines,
        suspicious_min_engines=settings.suspicious_min_engines,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
        write_verdicts=args.with_verdicts and args.force_verdicts,
    )

    verb = "would be updated" if args.dry_run else "updated"
    print(
        f"Scanned {report.scanned} report(s): {report.updated} {verb}, "
        f"{report.unchanged} already correct, "
        f"{report.skipped_malformed} skipped as malformed"
    )
    if report.verdicts_changed:
        applied = args.with_verdicts and args.force_verdicts
        state = "rewritten" if applied else "left unchanged"
        print(
            f"{report.verdicts_changed} report(s) differ in verdict under the current "
            f"thresholds; verdicts {state}."
        )
    if report.verdicts_unassessed:
        print(
            f"{report.verdicts_unassessed} malformed row(s) could not be assessed for "
            f"verdict drift, so the count above is a floor."
        )
    if args.dry_run and report.updated:
        print("Re-run without --dry-run to apply these changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
