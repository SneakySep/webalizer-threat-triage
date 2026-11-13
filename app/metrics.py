"""Prometheus metrics for the HTTP API and scan submissions."""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "webalizer_http_requests_total",
    "HTTP requests handled by the API.",
    ["method", "path", "status"],
)
HTTP_REQUEST_DURATION = Histogram(
    "webalizer_http_request_duration_seconds",
    "HTTP request duration in seconds.",
    ["method", "path"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
SCAN_OUTCOMES = Counter(
    "webalizer_scan_outcomes_total",
    "Scan submission outcomes.",
    ["outcome"],
)

__all__ = [
    "CONTENT_TYPE_LATEST",
    "HTTP_REQUESTS",
    "HTTP_REQUEST_DURATION",
    "SCAN_OUTCOMES",
    "generate_latest",
]
