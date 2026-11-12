"""Tests for VirusTotal response normalization."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas.triage import Verdict
from app.services.normalizer import normalize_domain_result, normalize_url_result


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
    assert result.engine_stats.total == 0
    assert result.risk_score == 0.0
    assert result.detection_ratio == "0/0"
    assert result.scan_date is None
    assert result.dns_records == []


def test_verdict_thresholds_are_configurable(domain_vt_payload: dict[str, Any]) -> None:
    result = normalize_domain_result(
        "example.com",
        domain_vt_payload,
        malicious_min_engines=3,
        suspicious_min_engines=2,
    )
    assert result.verdict is Verdict.HARMLESS
