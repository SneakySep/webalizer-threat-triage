"""Normalize VirusTotal API responses into UI-ready triage results."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from app.schemas.triage import (
    DnsRecord,
    EngineStats,
    TargetType,
    TriageResult,
    VendorVerdict,
    Verdict,
    VerdictConfidence,
)

_DNS_TYPES = {"A", "AAAA", "MX", "NS"}
_DNS_ORDER = {"A": 0, "AAAA": 1, "MX": 2, "NS": 3}
_MX_VALUE_RE = re.compile(r"^(\d+)\s+(.+)$")


def normalize_url_result(
    target: str,
    analysis_payload: dict[str, Any],
    url_payload: dict[str, Any] | None = None,
    *,
    malicious_min_engines: int = 1,
    suspicious_min_engines: int = 1,
) -> TriageResult:
    """Normalize a completed URL analysis plus optional URL metadata."""

    analysis_attrs = _attributes(analysis_payload)
    url_attrs = _attributes(url_payload)

    stats = _extract_stats(analysis_attrs)
    if stats.total == 0:
        alternative = _extract_stats(url_attrs)
        if alternative.total:
            stats = alternative

    results = analysis_attrs.get("results") or url_attrs.get("last_analysis_results") or {}
    categories = url_attrs.get("categories") or {}
    scan_timestamp = analysis_attrs.get("date") or url_attrs.get("last_analysis_date")

    return _build_result(
        target=target,
        target_type=TargetType.URL,
        stats=stats,
        results=results,
        categories=categories,
        dns_records=[],
        scan_timestamp=scan_timestamp,
        malicious_min_engines=malicious_min_engines,
        suspicious_min_engines=suspicious_min_engines,
    )


def normalize_domain_result(
    target: str,
    domain_payload: dict[str, Any] | None,
    *,
    malicious_min_engines: int = 1,
    suspicious_min_engines: int = 1,
) -> TriageResult:
    """Normalize a domain object, including its DNS records."""

    attributes = _attributes(domain_payload)
    stats = _extract_stats(attributes)
    results = attributes.get("last_analysis_results") or {}
    categories = attributes.get("categories") or {}
    dns_records = _extract_dns_records(attributes.get("last_dns_records"))

    return _build_result(
        target=target,
        target_type=TargetType.DOMAIN,
        stats=stats,
        results=results,
        categories=categories,
        dns_records=dns_records,
        scan_timestamp=attributes.get("last_analysis_date"),
        malicious_min_engines=malicious_min_engines,
        suspicious_min_engines=suspicious_min_engines,
    )


def _build_result(
    *,
    target: str,
    target_type: TargetType,
    stats: EngineStats,
    results: Any,
    categories: Any,
    dns_records: list[DnsRecord],
    scan_timestamp: Any,
    malicious_min_engines: int,
    suspicious_min_engines: int,
) -> TriageResult:
    risk_score = round((stats.malicious / stats.total) * 100, 2) if stats.total > 0 else 0.0
    detection_ratio = f"{stats.malicious}/{stats.total}"
    verdict = _calculate_verdict(
        stats,
        malicious_min_engines=malicious_min_engines,
        suspicious_min_engines=suspicious_min_engines,
    )
    return TriageResult(
        target=target,
        target_type=target_type,
        risk_score=risk_score,
        detection_ratio=detection_ratio,
        verdict=verdict,
        confidence=_calculate_confidence(verdict, stats),
        engine_stats=stats,
        detections=_extract_detections(results),
        categories=_extract_categories(categories),
        dns_records=dns_records,
        scan_date=_parse_scan_date(scan_timestamp),
    )


def _attributes(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _extract_stats(attributes: dict[str, Any]) -> EngineStats:
    raw_stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    if not isinstance(raw_stats, dict):
        raw_stats = {}

    malicious = _count(raw_stats.get("malicious"))
    suspicious = _count(raw_stats.get("suspicious"))
    undetected = _count(raw_stats.get("undetected"))
    harmless = _count(raw_stats.get("harmless"))
    timeout = _count(raw_stats.get("timeout")) + _count(raw_stats.get("confirmed-timeout"))
    total = malicious + suspicious + undetected + harmless
    return EngineStats(
        malicious=malicious,
        suspicious=suspicious,
        undetected=undetected,
        harmless=harmless,
        timeout=timeout,
        total=total,
    )


def _count(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _calculate_verdict(
    stats: EngineStats,
    *,
    malicious_min_engines: int,
    suspicious_min_engines: int,
) -> Verdict:
    if stats.total == 0:
        return Verdict.UNKNOWN
    if stats.malicious >= max(1, malicious_min_engines):
        return Verdict.MALICIOUS
    if stats.suspicious >= max(1, suspicious_min_engines):
        return Verdict.SUSPICIOUS
    if stats.harmless + stats.undetected > 0:
        return Verdict.HARMLESS
    return Verdict.UNKNOWN


def _calculate_confidence(
    verdict: Verdict,
    stats: EngineStats,
) -> VerdictConfidence | None:
    """Describe how much vendor evidence supports the verdict.

    A single flag is useful but can be a false positive; showing confidence
    separately lets clients keep the same verdict while softening the copy.
    """

    if verdict is Verdict.UNKNOWN:
        return None
    if verdict is Verdict.MALICIOUS:
        if stats.malicious >= 3:
            return VerdictConfidence.HIGH
        if stats.malicious == 2 or stats.total <= 10:
            return VerdictConfidence.MEDIUM
        return VerdictConfidence.LOW
    if verdict is Verdict.SUSPICIOUS:
        if stats.suspicious >= 3:
            return VerdictConfidence.MEDIUM
        return VerdictConfidence.LOW
    if stats.total >= 20:
        return VerdictConfidence.HIGH
    if stats.total >= 5:
        return VerdictConfidence.MEDIUM
    return VerdictConfidence.LOW


def _extract_detections(results: Any) -> list[VendorVerdict]:
    if not isinstance(results, dict):
        return []
    detections: list[VendorVerdict] = []
    for engine, payload in results.items():
        if not isinstance(payload, dict):
            continue
        category = str(payload.get("category") or "").lower()
        if category not in {"malicious", "suspicious"}:
            continue
        detections.append(
            VendorVerdict(
                engine_name=str(payload.get("engine_name") or engine),
                category=category,
                result=_optional_string(payload.get("result")),
                method=_optional_string(payload.get("method")),
                version=_optional_string(payload.get("version")),
            )
        )
    detections.sort(
        key=lambda item: (
            0 if item.category == "malicious" else 1,
            item.engine_name.casefold(),
        )
    )
    return detections


def _extract_categories(categories: Any) -> list[str]:
    if not isinstance(categories, dict):
        return []
    unique: dict[str, str] = {}
    for value in categories.values():
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if cleaned:
            unique.setdefault(cleaned.casefold(), cleaned)
    return sorted(unique.values(), key=str.casefold)


def _extract_dns_records(records: Any) -> list[DnsRecord]:
    if not isinstance(records, list):
        return []
    parsed: list[DnsRecord] = []
    seen: set[tuple[str, str, int | None]] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        record_type = str(record.get("type") or "").upper()
        if record_type not in _DNS_TYPES:
            continue
        raw_value = record.get("value") or record.get("rdata")
        if not isinstance(raw_value, str):
            continue
        value = raw_value.strip()
        if not value:
            continue

        priority = _optional_int(record.get("priority"))
        if record_type == "MX":
            match = _MX_VALUE_RE.match(value)
            if match:
                priority = int(match.group(1))
                value = match.group(2).strip()
        if record_type in {"MX", "NS"}:
            value = value.rstrip(".")

        ttl = _optional_int(record.get("ttl"))
        dedupe_key = (record_type, value.casefold(), priority)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        parsed.append(
            DnsRecord(
                type=record_type,  # type: ignore[arg-type]
                value=value,
                ttl=ttl,
                priority=priority if record_type == "MX" else None,
            )
        )

    parsed.sort(key=lambda item: (_DNS_ORDER[item.type], item.value.casefold()))
    return parsed


def _parse_scan_date(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=UTC)
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                return datetime.fromtimestamp(float(stripped), tz=UTC)
            except ValueError:
                parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return None


def _optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
