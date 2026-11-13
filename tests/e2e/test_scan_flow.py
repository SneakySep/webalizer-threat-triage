"""Browser flows for confidence-aware verdicts and saved history."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
Page = sync_api.Page
expect = sync_api.expect

pytestmark = pytest.mark.e2e


def _result(**overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target": "flagged.example",
        "target_type": "domain",
        "risk_score": 1.11,
        "detection_ratio": "1/90",
        "verdict": "malicious",
        "confidence": "low",
        "engine_stats": {
            "malicious": 1,
            "suspicious": 0,
            "undetected": 29,
            "harmless": 60,
            "timeout": 0,
            "total": 90,
        },
        "detections": [
            {
                "engine_name": "ExampleGuard",
                "category": "malicious",
                "result": "phishing",
            }
        ],
        "categories": ["Phishing"],
        "dns_records": [],
        "scan_date": "2026-11-12T12:00:00Z",
    }
    result.update(overrides)
    return result


def _mock_scan(page: Page, result: dict[str, Any]) -> None:
    payload = {
        "task_id": str(uuid.uuid4()),
        "status": "completed",
        "cached": True,
        "deduplicated": False,
        "report_id": str(uuid.uuid4()),
        "result": result,
        "poll_url": None,
    }

    def fulfill(route: Any) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(payload),
        )

    page.route("**/api/v1/triage/scan", fulfill)


def _run_scan(page: Page, base_url: str, target: str = "flagged.example") -> None:
    page.goto(base_url)
    page.get_by_label("Link or domain to check").fill(target)
    page.get_by_role("button", name="Check it").click()
    expect(page.locator("#result-card")).to_be_visible()


def test_low_confidence_malicious_result_softens_the_copy(
    page: Page,
    e2e_base_url: str,
) -> None:
    _mock_scan(page, _result())

    _run_scan(page, e2e_base_url)

    expect(page.locator("#verdict-label")).to_have_text("Worth a look")
    expect(page.locator("#verdict-title")).to_have_text("One vendor flagged this link.")
    expect(page.locator("#score-note")).to_have_text("1 malicious report across 90 vendors.")
    expect(page.locator("#tech-confidence")).to_have_text("Low")
    card_text = page.locator("#result-card").inner_text()
    assert "Don’t open this link" not in card_text


def test_low_confidence_label_is_kept_in_saved_history(
    page: Page,
    e2e_base_url: str,
) -> None:
    _mock_scan(page, _result())

    _run_scan(page, e2e_base_url)
    expect(page.locator(".recent-meta").first).to_contain_text("Worth a look")

    page.reload()
    expect(page.locator(".recent-item").first).to_be_visible()
    page.locator(".recent-item").first.click()
    expect(page.locator("#verdict-label")).to_have_text("Worth a look")
    expect(page.locator("#tech-confidence")).to_have_text("Low")


def test_unknown_result_shows_a_no_data_state(
    page: Page,
    e2e_base_url: str,
) -> None:
    _mock_scan(
        page,
        _result(
            target="unseen.example",
            risk_score=0,
            detection_ratio="0/0",
            verdict="unknown",
            confidence=None,
            engine_stats={
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "harmless": 0,
                "timeout": 0,
                "total": 0,
            },
            detections=[],
            categories=[],
            scan_date=None,
        ),
    )

    _run_scan(page, e2e_base_url, target="unseen.example")

    expect(page.locator("#verdict-label")).to_have_text("Unclear")
    expect(page.locator("#score-note")).to_have_text(
        "No vendor statistics were returned for this target."
    )
    expect(page.locator("#tech-risk")).to_have_text("No vendor data")
    expect(page.locator("#tech-ratio")).to_have_text("No vendor data")
    expect(page.locator("#tech-confidence")).to_have_text("Not enough data")
