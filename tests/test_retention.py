"""Unit tests for retention helpers that do not need a database."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.celery_app import celery_app
from app.services.retention import prune_reports, retention_cutoff
from app.tasks import maintenance


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


def test_prune_task_uses_the_configured_retention_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, int] = {}

    def fake_prune(_factory: object, *, retention_days: int) -> int:
        captured["retention_days"] = retention_days
        return 4

    monkeypatch.setattr(maintenance, "prune_reports", fake_prune)

    assert maintenance.prune_reports_task.run() == 4
    assert captured["retention_days"] == maintenance.settings.report_retention_days


def test_beat_schedule_runs_report_pruning_daily() -> None:
    schedule = celery_app.conf.beat_schedule["prune-expired-reports"]

    assert schedule["task"] == "triage.prune_reports"
    assert schedule["schedule"].hour == {3}
    assert schedule["schedule"].minute == {15}
