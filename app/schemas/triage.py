"""UI-ready schemas for threat triage requests, results, and task status."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TargetType(StrEnum):
    URL = "url"
    DOMAIN = "domain"


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"


class VerdictConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TaskState(StrEnum):
    QUEUED = "queued"
    PROCESSING = "processing"
    RETRYING = "retrying"
    COMPLETED = "completed"
    FAILED = "failed"


class EngineStats(BaseModel):
    """Vendor verdict counts returned by VirusTotal."""

    malicious: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)
    undetected: int = Field(default=0, ge=0)
    harmless: int = Field(default=0, ge=0)
    timeout: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)


class VendorVerdict(BaseModel):
    """A single engine that flagged the target."""

    engine_name: str
    category: str
    result: str | None = None
    method: str | None = None
    version: str | None = None


class DnsRecord(BaseModel):
    """A parsed DNS record suitable for display."""

    type: Literal["A", "AAAA", "MX", "NS"]
    value: str
    ttl: int | None = None
    priority: int | None = None


class TriageResult(BaseModel):
    """Normalized representation of a VirusTotal report."""

    target: str
    target_type: TargetType
    risk_score: float = Field(ge=0, le=100)
    detection_ratio: str
    verdict: Verdict
    confidence: VerdictConfidence | None = None
    engine_stats: EngineStats
    detections: list[VendorVerdict] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    dns_records: list[DnsRecord] = Field(default_factory=list)
    scan_date: datetime | None = None


class ScanRequest(BaseModel):
    """Payload accepted by the scan endpoint."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=4096)
    force_refresh: bool = False

    @field_validator("target")
    @classmethod
    def strip_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("target must not be blank")
        return value


class ScanResponse(BaseModel):
    """Response for a new scan, a deduplicated scan, or a cache hit."""

    task_id: UUID
    status: TaskState
    cached: bool
    deduplicated: bool = False
    report_id: UUID | None = None
    result: TriageResult | None = None
    poll_url: str | None = None


class TaskError(BaseModel):
    """Safe, client-facing task failure details."""

    code: str
    message: str
    retryable: bool = False


class TaskStatusResponse(BaseModel):
    """Progress and outcome of an asynchronous triage task."""

    task_id: UUID
    status: TaskState
    stage: str | None = None
    target: str
    target_type: TargetType
    attempt: int = 0
    report_id: UUID | None = None
    report_url: str | None = None
    error: TaskError | None = None
    created_at: datetime
    updated_at: datetime


class TriageReportResponse(TriageResult):
    """A stored historical report."""

    report_id: UUID
    created_at: datetime
    raw_vt_response: dict[str, Any] | None = None
