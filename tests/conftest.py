"""Shared test configuration and fixtures."""

from __future__ import annotations

import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("VT_API_KEY", "test-vt-key")
os.environ.setdefault("TRIAGE_API_KEY", "")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/13")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/14")
os.environ.setdefault("VT_POLL_INITIAL_DELAY_SECONDS", "0")
os.environ.setdefault("VT_POLL_MAX_DELAY_SECONDS", "1")
os.environ.setdefault("VT_POLL_TIMEOUT_SECONDS", "2")
os.environ.setdefault("VT_HTTP_TIMEOUT_SECONDS", "2")

from typing import Any  # noqa: E402

import pytest  # noqa: E402

from app.services.normalizer import normalize_domain_result  # noqa: E402


@pytest.fixture
def domain_vt_payload() -> dict[str, Any]:
    return {
        "data": {
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "last_analysis_date": 1_700_000_000,
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 27,
                    "timeout": 2,
                },
                "last_analysis_results": {
                    "EngineMalicious": {
                        "engine_name": "EngineMalicious",
                        "category": "malicious",
                        "result": "phishing",
                        "method": "blacklist",
                    },
                    "EngineSuspicious": {
                        "engine_name": "EngineSuspicious",
                        "category": "suspicious",
                        "result": "suspicious",
                    },
                    "EngineClean": {
                        "engine_name": "EngineClean",
                        "category": "harmless",
                        "result": None,
                    },
                },
                "categories": {
                    "VendorA": "Phishing",
                    "VendorB": "phishing",
                    "VendorC": "Malware",
                },
                "last_dns_records": [
                    {"type": "A", "value": "93.184.216.34", "ttl": 300},
                    {"type": "AAAA", "value": "2606:2800:220:1:248:1893:25c8:1946"},
                    {"type": "MX", "value": "10 mail.example.com.", "priority": 10},
                    {"type": "NS", "value": "ns1.example.com."},
                    {"type": "TXT", "value": "ignored"},
                ],
            },
        }
    }


@pytest.fixture
def normalized_domain_result(domain_vt_payload: dict[str, Any]):
    return normalize_domain_result("example.com", domain_vt_payload)


@pytest.fixture
def url_analysis_payload() -> dict[str, Any]:
    return {
        "data": {
            "id": "u-test",
            "type": "analysis",
            "attributes": {
                "status": "completed",
                "date": 1_700_000_100,
                "stats": {
                    "malicious": 0,
                    "suspicious": 1,
                    "harmless": 70,
                    "undetected": 19,
                    "timeout": 0,
                },
                "results": {
                    "EngineSuspicious": {
                        "engine_name": "EngineSuspicious",
                        "category": "suspicious",
                        "result": "suspicious",
                    },
                    "EngineClean": {
                        "engine_name": "EngineClean",
                        "category": "harmless",
                        "result": None,
                    },
                },
            },
        }
    }


@pytest.fixture
def url_object_payload() -> dict[str, Any]:
    return {
        "data": {
            "id": "u-test",
            "type": "url",
            "attributes": {
                "last_analysis_date": 1_700_000_100,
                "categories": {
                    "VendorA": "Information Technology",
                    "VendorB": "information technology",
                },
            },
        }
    }
