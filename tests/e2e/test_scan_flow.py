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


def _mock_empty_server_history(page: Page) -> None:
    def fulfill(route: Any) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"items": [], "total": 0, "limit": 6, "offset": 0}),
        )

    page.route("**/api/v1/triage/reports*", fulfill)


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
    _mock_empty_server_history(page)

    _run_scan(page, e2e_base_url)
    expect(page.locator(".recent-meta").first).to_contain_text("Worth a look")

    page.reload()
    expect(page.locator(".recent-item").first).to_be_visible()
    page.locator(".recent-item").first.click()
    expect(page.locator("#verdict-label")).to_have_text("Worth a look")
    expect(page.locator("#tech-confidence")).to_have_text("Low")


def test_report_link_is_copied_with_a_permalink(
    page: Page,
    e2e_base_url: str,
) -> None:
    _mock_scan(page, _result())
    page.add_init_script(
        "navigator.clipboard.writeText = async (value) => { window.__copied = value; };"
    )

    _run_scan(page, e2e_base_url)
    page.locator("#copy-link-button").click()

    expect(page.locator("#copy-status")).to_have_text("Link copied.")
    copied = page.evaluate("window.__copied")
    assert copied.startswith(f"{e2e_base_url}/r/")


def test_server_history_renders_and_opens_a_stored_report(
    page: Page,
    e2e_base_url: str,
) -> None:
    report_id = str(uuid.uuid4())
    summary = {
        "report_id": report_id,
        "target": "flagged.example",
        "target_type": "domain",
        "risk_score": 1.11,
        "detection_ratio": "1/90",
        "verdict": "malicious",
        "confidence": "low",
        "created_at": "2026-11-13T12:00:00Z",
        "permalink": f"/r/{report_id}",
    }
    report = {
        **_result(),
        "report_id": report_id,
        "created_at": "2026-11-13T12:00:00Z",
        "raw_vt_response": None,
    }

    def fulfill_list(route: Any) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"items": [summary], "total": 1, "limit": 6, "offset": 0}),
        )

    def fulfill_report(route: Any) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(report),
        )

    page.route("**/api/v1/triage/reports*", fulfill_list)
    page.route(f"**/api/v1/triage/report/{report_id}", fulfill_report)
    page.goto(e2e_base_url)

    expect(page.locator("#recent-foot")).to_have_text("Saved on this server. Newest first.")
    page.locator(".recent-item").first.click()

    expect(page.locator("#result-card")).to_be_visible()
    expect(page.locator("#verdict-label")).to_have_text("Worth a look")


def test_report_permalink_loads_the_saved_result(
    page: Page,
    e2e_base_url: str,
) -> None:
    report_id = str(uuid.uuid4())
    payload = {
        **_result(),
        "report_id": report_id,
        "created_at": "2026-11-13T12:00:00Z",
        "raw_vt_response": None,
    }

    def fulfill(route: Any) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(payload),
        )

    page.route(f"**/api/v1/triage/report/{report_id}", fulfill)
    page.goto(f"{e2e_base_url}/r/{report_id}")

    expect(page.locator("#result-card")).to_be_visible()
    expect(page.locator("#verdict-label")).to_have_text("Worth a look")
    expect(page.locator("#result-source")).to_have_text("Saved result")


def test_mobile_layout_has_no_horizontal_overflow(
    page: Page,
    e2e_base_url: str,
) -> None:
    page.set_viewport_size({"width": 390, "height": 844})
    _mock_scan(page, _result())

    _run_scan(page, e2e_base_url)

    overflow = page.evaluate(
        "document.documentElement.scrollWidth > document.documentElement.clientWidth"
    )
    assert overflow is False


def test_skip_link_receives_keyboard_focus(
    page: Page,
    e2e_base_url: str,
) -> None:
    page.goto(e2e_base_url)
    page.keyboard.press("Tab")

    skip_link = page.locator(".skip-link")
    expect(skip_link).to_be_focused()
    assert skip_link.evaluate("(element) => getComputedStyle(element).transform") != "none"


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
