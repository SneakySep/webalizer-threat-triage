"""Unit tests for the risk-score backfill that do not need a database."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from app.services.backfill import (
    BackfillReport,
    _recompute,
    backfill_risk_scores,
    backfill_verdicts_only,
)


def _stored(
    *,
    malicious: int,
    suspicious: int,
    total: int,
    risk_score: float,
    verdict: str = "suspicious",
) -> dict[str, Any]:
    """A normalized_data blob as the old code would have written it."""

    return {
        "target": "example.com",
        "target_type": "domain",
        "risk_score": risk_score,
        "detection_ratio": f"{malicious}/{total}",
        "verdict": verdict,
        "confidence": None,
        "engine_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": max(0, total - malicious - suspicious),
            "harmless": 0,
            "timeout": 0,
            "total": total,
        },
        "detections": [],
        "categories": [],
        "dns_records": [],
        "scan_date": None,
    }


class _FakeResult:
    def __init__(self, rows: list[tuple[Any, Any]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[Any, Any]]:
        return self._rows


class _FakeSession:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def execute(self, statement: Any) -> _FakeResult:
        self._state["statements"].append(statement)
        if "UPDATE" in str(statement).upper():
            self._state["update_calls"] += 1
            self._state["update_params"].append(statement.compile().params)
            return _FakeResult([])
        start = self._state["cursor"]
        limit = int(statement.compile().params["param_1"])
        batch = self._state["rows"][start : start + limit]
        self._state["cursor"] = start + len(batch)
        return _FakeResult(batch)

    def commit(self) -> None:
        self._state["commits"] += 1


def _state(rows: list[tuple[Any, Any]]) -> dict[str, Any]:
    return {
        "rows": rows,
        "cursor": 0,
        "update_calls": 0,
        "update_params": [],
        "commits": 0,
        "statements": [],
    }


def _run(state: dict[str, Any], **kwargs: Any) -> BackfillReport:
    return backfill_risk_scores(
        lambda: _FakeSession(state),  # type: ignore[arg-type]
        batch_size=kwargs.pop("batch_size", 100),
        **kwargs,
    )


def test_recompute_weights_suspicious_detections() -> None:
    result = _recompute(
        _stored(malicious=0, suspicious=20, total=90, risk_score=0.0),
        malicious_min_engines=1,
        suspicious_min_engines=1,
    )

    assert result is not None
    risk, verdict = result
    assert risk == 11.11
    assert verdict == "suspicious"


def test_recompute_returns_none_for_malformed_blobs() -> None:
    assert (
        _recompute(
            {"risk_score": "not-a-number"},
            malicious_min_engines=1,
            suspicious_min_engines=1,
        )
        is None
    )


def test_backfill_rewrites_a_stale_risk_score() -> None:
    state = _state([(uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0))])

    report = _run(state)

    assert report.scanned == 1
    assert report.updated == 1
    assert report.unchanged == 0
    assert state["update_calls"] == 1


def test_backfill_writes_the_corrected_value_to_both_the_column_and_the_blob() -> None:
    """The API reads the JSON blob, so updating only the column fixes nothing."""

    state = _state([(uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0))])

    _run(state)

    params = state["update_params"][0]
    assert float(params["risk_score"]) == 11.11
    # Verdicts are not written unless explicitly opted into.
    assert "verdict" not in params
    blob = params["normalized_data"]
    assert blob["risk_score"] == 11.11
    assert blob["verdict"] == "suspicious"
    # Everything else in the blob must be preserved, not rebuilt.
    assert blob["detection_ratio"] == "0/90"
    assert blob["engine_stats"]["suspicious"] == 20


def test_backfill_leaves_correct_rows_alone() -> None:
    state = _state(
        [(uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=11.11))]
    )

    report = _run(state)

    assert report.scanned == 1
    assert report.updated == 0
    assert report.unchanged == 1
    assert state["update_calls"] == 0


def test_dry_run_reports_changes_without_writing() -> None:
    state = _state([(uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0))])

    report = _run(state, dry_run=True)

    assert report.updated == 1
    assert state["update_calls"] == 0
    assert state["commits"] == 0


def test_backfill_skips_malformed_rows_and_keeps_going() -> None:
    state = _state(
        [
            (uuid.uuid4(), {"risk_score": "broken"}),
            (uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0)),
        ]
    )

    report = _run(state)

    assert report.scanned == 2
    assert report.skipped_malformed == 1
    assert report.updated == 1


def test_backfill_pages_through_every_row() -> None:
    rows = [
        (uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0))
        for _ in range(7)
    ]
    state = _state(rows)

    report = _run(state, batch_size=3)

    assert report.scanned == 7
    assert report.updated == 7


def test_backfill_advances_the_cursor_between_pages() -> None:
    """A cursor that never advances would re-read the same page forever."""

    rows = [
        (uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0))
        for _ in range(7)
    ]
    state = _state(rows)

    report = _run(state, batch_size=3)

    # 3 + 3 + 1, then a final empty page ends the loop.
    assert report.scanned == 7
    assert state["cursor"] == 7
    selects = [s for s in state["statements"] if "SELECT" in str(s).upper()]
    assert len(selects) == 4
    # Every page after the first must be filtered by the last seen id.
    assert all("id >" in str(s) for s in selects[1:])


def test_backfill_commits_per_batch_when_writing() -> None:
    rows = [
        (uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0))
        for _ in range(5)
    ]
    state = _state(rows)

    _run(state, batch_size=2)

    assert state["commits"] >= 2


def test_backfill_rejects_a_non_positive_batch_size() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        backfill_risk_scores(lambda: None, batch_size=0)  # type: ignore[arg-type]


def test_verdict_only_scan_counts_changes_without_writing() -> None:
    rows: Iterator[tuple[Any, Any]] = iter(
        [
            # Below a raised threshold: old code said harmless, correct is suspicious.
            (
                uuid.uuid4(),
                _stored(malicious=1, suspicious=0, total=90, risk_score=1.11, verdict="harmless"),
            ),
            # Unchanged under the same thresholds.
            (
                uuid.uuid4(),
                _stored(malicious=5, suspicious=0, total=90, risk_score=5.56, verdict="malicious"),
            ),
        ]
    )
    state = _state(list(rows))

    survey = backfill_verdicts_only(
        lambda: _FakeSession(state),  # type: ignore[arg-type]
        malicious_min_engines=2,
        suspicious_min_engines=1,
        batch_size=100,
    )

    assert survey.changed == 1
    assert survey.unassessable == 0
    assert survey.is_exact is True
    assert state["update_calls"] == 0


def test_verdict_survey_reports_unassessable_rows_separately() -> None:
    """A malformed row cannot be compared, so it must not be silently dropped.

    Counting only the rows that validate would present the drift as a total when
    it is really a floor.
    """

    state = _state(
        [
            (uuid.uuid4(), {"risk_score": "broken"}),
            (
                uuid.uuid4(),
                _stored(malicious=1, suspicious=0, total=90, risk_score=1.11, verdict="harmless"),
            ),
        ]
    )

    survey = backfill_verdicts_only(
        lambda: _FakeSession(state),  # type: ignore[arg-type]
        malicious_min_engines=2,
        suspicious_min_engines=1,
        batch_size=100,
    )

    assert survey.scanned == 2
    assert survey.changed == 1
    assert survey.unassessable == 1
    assert survey.is_exact is False


def test_backfill_report_exposes_unassessed_verdicts() -> None:
    state = _state(
        [
            (uuid.uuid4(), {"risk_score": "broken"}),
            (uuid.uuid4(), _stored(malicious=0, suspicious=20, total=90, risk_score=0.0)),
        ]
    )

    report = _run(state)

    assert report.skipped_malformed == 1
    assert report.verdicts_unassessed == 1
    assert report.as_dict()["verdicts_unassessed"] == 1


def test_default_backfill_does_not_rewrite_verdicts() -> None:
    """The risk-score path must not silently rewrite a historical verdict.

    The CLI refuses to rewrite verdicts because the thresholds in force when a
    report was written are not recorded. A risk-score backfill that wrote the
    recomputed verdict anyway would make that refusal meaningless.
    """

    state = _state(
        [
            (
                uuid.uuid4(),
                _stored(malicious=1, suspicious=0, total=90, risk_score=0.0, verdict="harmless"),
            )
        ]
    )

    report = _run(state, malicious_min_engines=2, suspicious_min_engines=1)

    # The risk score is corrected, but the stored verdict is preserved.
    assert report.updated == 1
    assert report.verdicts_changed == 1
    params = state["update_params"][0]
    assert "verdict" not in params
    assert params["normalized_data"]["verdict"] == "harmless"


def test_backfill_writes_verdicts_only_when_explicitly_enabled() -> None:
    state = _state(
        [
            (
                uuid.uuid4(),
                _stored(malicious=1, suspicious=0, total=90, risk_score=0.0, verdict="harmless"),
            )
        ]
    )

    report = _run(
        state,
        malicious_min_engines=2,
        suspicious_min_engines=1,
        write_verdicts=True,
    )

    assert report.updated == 1
    assert report.verdicts_changed == 1
    params = state["update_params"][0]
    assert params["verdict"] == "suspicious"
    assert params["normalized_data"]["verdict"] == "suspicious"


def test_verdict_only_difference_is_unchanged_when_verdicts_are_off() -> None:
    """A row needing no risk-score change must not be rewritten just for a verdict."""

    state = _state(
        [
            (
                uuid.uuid4(),
                _stored(malicious=1, suspicious=0, total=90, risk_score=1.11, verdict="harmless"),
            )
        ]
    )

    report = _run(state, malicious_min_engines=2, suspicious_min_engines=1)

    assert report.unchanged == 1
    assert report.updated == 0
    assert state["update_calls"] == 0


def test_dry_run_counts_verdict_changes_without_writing() -> None:
    state = _state(
        [
            (
                uuid.uuid4(),
                _stored(malicious=1, suspicious=0, total=90, risk_score=1.11, verdict="harmless"),
            )
        ]
    )

    report = _run(
        state,
        malicious_min_engines=2,
        suspicious_min_engines=1,
        dry_run=True,
        write_verdicts=True,
    )

    assert report.verdicts_changed == 1
    assert state["update_calls"] == 0
    assert state["commits"] == 0
