"""Unit tests for retention helpers that do not need a database."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services.retention import prune_reports, retention_cutoff


def test_retention_cutoff_uses_utc_and_the_requested_window() -> None:
    now = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)

    assert retention_cutoff(180, now=now) == now - timedelta(days=180)


@pytest.mark.parametrize("days", [0, -1])
def test_retention_cutoff_rejects_non_positive_windows(days: int) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        retention_cutoff(days)


def test_prune_rejects_non_positive_batch_sizes() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        prune_reports(lambda: None, retention_days=180, batch_size=0)  # type: ignore[arg-type]


def test_prune_rejects_non_positive_retention_windows() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        prune_reports(lambda: None, retention_days=0)  # type: ignore[arg-type]
