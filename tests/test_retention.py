"""Unit tests for retention helpers that do not need a database."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Delete, Select

from app.celery_app import celery_app
from app.services.retention import prune_reports, retention_cutoff
from app.tasks import maintenance


class _FakeScalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def __iter__(self) -> Iterator[Any]:
        return iter(self._rows)


class _FakeResult:
    def __init__(self, rowcount: int | None) -> None:
        self.rowcount = rowcount


class _FakeSession:
    """Minimal Session stand-in that models a table of expired rows."""

    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def scalars(self, statement: Select[Any]) -> _FakeScalars:
        self._state["select_calls"] += 1
        self._state["select_statements"].append(statement)
        limit = int(statement.compile().params["param_1"])
        return _FakeScalars(self._state["remaining"][:limit])

    def execute(self, statement: Delete) -> _FakeResult:
        self._state["delete_calls"] += 1
        self._state["delete_statements"].append(statement)
        limit = int(self._state["batch_size"])
        batch = self._state["remaining"][:limit]
        del self._state["remaining"][: len(batch)]
        rowcount = self._state["rowcount_override"]
        return _FakeResult(len(batch) if rowcount is None else rowcount)

    def commit(self) -> None:
        self._state["commits"] += 1


def _prune_state(
    expired_rows: int,
    *,
    batch_size: int,
    rowcount_override: int | None = None,
) -> dict[str, Any]:
    return {
        "remaining": [f"id-{index}" for index in range(expired_rows)],
        "batch_size": batch_size,
        "rowcount_override": rowcount_override,
        "select_calls": 0,
        "delete_calls": 0,
        "commits": 0,
        "select_statements": [],
        "delete_statements": [],
    }


def _prune(state: dict[str, Any], *, retention_days: int = 180) -> int:
    return prune_reports(
        lambda: _FakeSession(state),  # type: ignore[arg-type]
        retention_days=retention_days,
        batch_size=state["batch_size"],
    )


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


def test_prune_returns_zero_and_deletes_nothing_when_nothing_is_expired() -> None:
    state = _prune_state(0, batch_size=100)

    assert _prune(state) == 0
    assert state["select_calls"] == 1
    assert state["delete_calls"] == 0
    assert state["commits"] == 0


def test_prune_deletes_everything_in_one_batch_when_it_fits() -> None:
    state = _prune_state(3, batch_size=100)

    assert _prune(state) == 3
    assert state["delete_calls"] == 1
    assert state["commits"] == 1
    assert state["remaining"] == []


def test_prune_loops_until_a_short_batch_ends_the_run() -> None:
    """2500 rows at 1000 per batch needs three passes, not one."""

    state = _prune_state(2_500, batch_size=1_000)

    assert _prune(state) == 2_500
    # 1000, 1000, then a short 500 batch terminates the loop. The short-batch
    # break is an efficiency guard: without it the loop still ends, but only
    # after one extra empty SELECT.
    assert state["delete_calls"] == 3
    assert state["select_calls"] == 3
    assert state["commits"] == 3
    assert state["remaining"] == []


def test_prune_terminates_when_the_total_is_an_exact_multiple() -> None:
    """An exact multiple must not spin forever on a full final batch."""

    state = _prune_state(2_000, batch_size=1_000)

    assert _prune(state) == 2_000
    # 1000, 1000, then an empty select breaks the loop.
    assert state["delete_calls"] == 2
    assert state["select_calls"] == 3
    assert state["remaining"] == []


def test_prune_accumulates_the_total_across_batches() -> None:
    """The return value is the sum of every batch, not the last batch."""

    state = _prune_state(2_500, batch_size=1_000)

    assert _prune(state) == 2_500


def test_prune_never_reports_a_negative_count() -> None:
    """A driver returning -1 for rowcount must not subtract from the total."""

    state = _prune_state(5, batch_size=100, rowcount_override=-1)

    assert _prune(state) == 0


def test_prune_selects_rows_older_than_the_cutoff() -> None:
    """The comparison must be ``<``: inverting it would delete live reports."""

    state = _prune_state(5, batch_size=100)

    _prune(state)

    sql = str(state["select_statements"][0])
    assert "created_at < " in sql
    assert "created_at > " not in sql


def test_prune_reports_the_rowcount_the_database_returned() -> None:
    """The total comes from the driver's rowcount, not the size of the id list."""

    state = _prune_state(5, batch_size=100, rowcount_override=2)

    assert _prune(state) == 2


def test_prune_passes_the_batch_size_into_the_select_limit() -> None:
    state = _prune_state(50, batch_size=7)

    _prune(state)

    limit = int(state["select_statements"][0].compile().params["param_1"])
    assert limit == 7


def test_prune_deletes_by_id_without_loading_orm_objects() -> None:
    state = _prune_state(5, batch_size=100)

    _prune(state)

    statement = state["delete_statements"][0]
    assert statement.get_execution_options()["synchronize_session"] is False
    # The delete must be scoped to the ids just selected. Without the IN filter
    # it would remove every row in the table.
    assert "id IN" in str(statement)


def test_prune_honours_the_retention_window_in_the_cutoff() -> None:
    state = _prune_state(5, batch_size=100)

    _prune(state, retention_days=30)

    cutoff = state["select_statements"][0].compile().params["created_at_1"]
    assert isinstance(cutoff, datetime)
    assert cutoff.tzinfo is not None
    assert abs((datetime.now(UTC) - cutoff) - timedelta(days=30)) < timedelta(minutes=1)
