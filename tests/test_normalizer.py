"""Tests for VirusTotal response normalization."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.schemas.triage import EngineStats, Verdict, VerdictConfidence
from app.services.normalizer import (
    _calculate_confidence,
    normalize_domain_result,
    normalize_url_result,
)


def test_domain_result_normalization(domain_vt_payload: dict[str, Any]) -> None:
    result = normalize_domain_result("example.com", domain_vt_payload)

    assert result.target == "example.com"
    assert result.target_type == "domain"
    assert result.engine_stats.malicious == 2
    assert result.engine_stats.suspicious == 1
    assert result.engine_stats.timeout == 2
    assert result.engine_stats.total == 90
    assert result.risk_score == 2.22
    assert result.detection_ratio == "2/90"
    assert result.verdict is Verdict.MALICIOUS
    assert result.confidence is VerdictConfidence.MEDIUM
    assert result.scan_date == datetime.fromtimestamp(1_700_000_000, tz=UTC)

    assert len(result.detections) == 2
    assert result.detections[0].category == "malicious"
    assert result.detections[0].engine_name == "EngineMalicious"
    assert result.categories == ["Malware", "Phishing"]

    assert [record.type for record in result.dns_records] == ["A", "AAAA", "MX", "NS"]
    mx_record = result.dns_records[2]
    assert mx_record.value == "mail.example.com"
    assert mx_record.priority == 10
    assert result.dns_records[3].value == "ns1.example.com"
    assert result.dns_records[0].ttl == 300


def test_url_result_normalization(
    url_analysis_payload: dict[str, Any],
    url_object_payload: dict[str, Any],
) -> None:
    result = normalize_url_result(
        "https://example.com/login",
        url_analysis_payload,
        url_object_payload,
    )

    assert result.target_type == "url"
    assert result.engine_stats.total == 90
    assert result.risk_score == 0.0
    assert result.detection_ratio == "0/90"
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.confidence is VerdictConfidence.LOW
    assert result.categories == ["Information Technology"]
    assert result.dns_records == []
    assert len(result.detections) == 1


def test_url_stats_fall_back_to_url_object() -> None:
    analysis = {
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {},
                "results": {},
                "date": 1_700_000_100,
            }
        }
    }
    url_object = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 9,
                    "undetected": 0,
                },
                "last_analysis_results": {"Engine": {"category": "malicious", "result": "malware"}},
                "categories": {"Vendor": "Malware"},
            }
        }
    }

    result = normalize_url_result("https://example.com/", analysis, url_object)
    assert result.engine_stats.total == 10
    assert result.risk_score == 10.0
    assert result.verdict is Verdict.MALICIOUS
    assert result.detections[0].engine_name == "Engine"


def test_missing_domain_report_is_unknown() -> None:
    result = normalize_domain_result("unseen.example", None)
    assert result.verdict is Verdict.UNKNOWN
    assert result.confidence is None
    assert result.engine_stats.total == 0
    assert result.risk_score == 0.0
    assert result.detection_ratio == "0/0"
    assert result.scan_date is None
    assert result.dns_records == []


@pytest.mark.parametrize(
    ("verdict", "stats", "expected"),
    [
        (Verdict.MALICIOUS, EngineStats(malicious=3, total=90), VerdictConfidence.HIGH),
        (Verdict.MALICIOUS, EngineStats(malicious=2, total=90), VerdictConfidence.MEDIUM),
        (Verdict.MALICIOUS, EngineStats(malicious=1, total=8), VerdictConfidence.MEDIUM),
        (Verdict.MALICIOUS, EngineStats(malicious=1, total=90), VerdictConfidence.LOW),
        (Verdict.SUSPICIOUS, EngineStats(suspicious=3, total=90), VerdictConfidence.MEDIUM),
        (Verdict.SUSPICIOUS, EngineStats(suspicious=2, total=90), VerdictConfidence.LOW),
        (Verdict.HARMLESS, EngineStats(harmless=20, total=20), VerdictConfidence.HIGH),
        (Verdict.HARMLESS, EngineStats(harmless=5, total=5), VerdictConfidence.MEDIUM),
        (Verdict.HARMLESS, EngineStats(harmless=4, total=4), VerdictConfidence.LOW),
        (Verdict.UNKNOWN, EngineStats(), None),
    ],
)
def test_confidence_tracks_vendor_evidence(
    verdict: Verdict,
    stats: EngineStats,
    expected: VerdictConfidence | None,
) -> None:
    assert _calculate_confidence(verdict, stats) is expected


def test_verdict_thresholds_are_configurable(domain_vt_payload: dict[str, Any]) -> None:
    result = normalize_domain_result(
        "example.com",
        domain_vt_payload,
        malicious_min_engines=3,
        suspicious_min_engines=2,
    )
    assert result.verdict is Verdict.HARMLESS
