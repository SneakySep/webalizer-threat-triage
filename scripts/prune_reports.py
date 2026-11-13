"""Delete stored triage reports older than the configured retention window."""

from __future__ import annotations

import argparse

from app.config import get_settings
from app.database import SyncSessionLocal
from app.services.retention import count_reports_older_than, prune_reports


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--days",
        type=int,
        default=settings.report_retention_days,
        help="Delete reports older than this many days.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1_000,
        help="Rows deleted per transaction.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report how many rows would be deleted without changing anything.",
    )
    args = parser.parse_args()

    if args.days < 1:
        parser.error("--days must be at least 1")
    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")

    if args.dry_run:
        count = count_reports_older_than(
            SyncSessionLocal,
            retention_days=args.days,
        )
        print(f"{count} report(s) older than {args.days} day(s) would be deleted")
        return

    deleted = prune_reports(
        SyncSessionLocal,
        retention_days=args.days,
        batch_size=args.batch_size,
    )
    print(f"Deleted {deleted} report(s) older than {args.days} day(s)")


if __name__ == "__main__":
    main()
