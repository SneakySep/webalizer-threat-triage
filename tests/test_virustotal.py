"""Tests for the VirusTotal HTTP client and error mapping."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from app.services.virustotal import (
    VirusTotalClient,
    VTAuthError,
    VTBadResponseError,
    VTRateLimitError,
    VTTransientError,
)

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler) -> tuple[VirusTotalClient, httpx.Client]:
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = VirusTotalClient(
        "test-key",
        base_url="https://vt.test/api/v3",
        http_client=http_client,
        poll_initial_delay_seconds=0,
        poll_max_delay_seconds=0,
        poll_timeout_seconds=2,
        sleeper=lambda _seconds: None,
    )
    return client, http_client


def test_url_scan_flow_and_analysis_id_callback() -> None:
    calls: list[tuple[str, str]] = []
    analysis_id = "u-abc123"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            body = request.content.decode()
            assert "url=https%3A%2F%2Fexample.com%2Flogin" in body
            return httpx.Response(
                200,
                json={"data": {"id": analysis_id, "type": "analysis"}},
            )
        if "/analyses/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": analysis_id,
                        "attributes": {
                            "status": "completed",
                            "stats": {"malicious": 0, "harmless": 90},
                        },
                    }
                },
            )
        if "/urls/" in request.url.path:
            return httpx.Response(
                200,
                json={"data": {"attributes": {"categories": {"V": "Technology"}}}},
            )
        raise AssertionError(f"Unexpected request: {request.url}")

    client, http_client = _client(handler)
    seen_ids: list[str] = []
    with http_client:
        analysis, url_report = client.scan_url(
            "https://example.com/login",
            on_analysis_id=seen_ids.append,
        )

    assert analysis["data"]["attributes"]["status"] == "completed"
    assert url_report is not None
    assert seen_ids == [analysis_id]
    assert calls[0] == ("POST", "/api/v3/urls")
    assert any("/analyses/u-abc123" in path for _method, path in calls)


def test_polling_can_resume_an_existing_analysis() -> None:
    analysis_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal analysis_calls
        if request.method == "POST":
            raise AssertionError("The client must not resubmit a valid analysis id")
        if "/analyses/" in request.url.path:
            analysis_calls += 1
            status = "queued" if analysis_calls == 1 else "completed"
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "status": status,
                            "stats": {"malicious": 1, "harmless": 10},
                        }
                    }
                },
            )
        if "/urls/" in request.url.path:
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        raise AssertionError(f"Unexpected request: {request.url}")

    client, http_client = _client(handler)
    with http_client:
        analysis, url_report = client.scan_url(
            "https://example.com/",
            analysis_id="u-existing",
        )

    assert analysis_calls == 2
    assert analysis["data"]["attributes"]["status"] == "completed"
    assert url_report is None


def test_invalid_api_key_maps_to_auth_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}},
        )

    client, http_client = _client(handler)
    with http_client, pytest.raises(VTAuthError):
        client.submit_url("https://example.com/")


def test_rate_limit_maps_to_retryable_error_with_retry_after() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": "12"},
            json={"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}},
        )

    client, http_client = _client(handler)
    with http_client, pytest.raises(VTRateLimitError) as exc_info:
        client.submit_url("https://example.com/")

    assert exc_info.value.retry_after == 12.0
    assert exc_info.value.retryable is True


def test_server_error_is_retryable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    client, http_client = _client(handler)
    with http_client, pytest.raises(VTTransientError):
        client.submit_url("https://example.com/")


def test_missing_domain_returns_none() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    client, http_client = _client(handler)
    with http_client:
        assert client.get_domain_report("unseen.example") is None


def test_client_requires_api_key() -> None:
    with pytest.raises(VTAuthError):
        VirusTotalClient("   ")


def test_malformed_json_is_bad_response() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    client, http_client = _client(handler)
    with http_client, pytest.raises(VTBadResponseError):
        client.submit_url("https://example.com/")


def test_analysis_id_callback_failure_does_not_abort_scan() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "u-1"}})
        if "/analyses/" in request.url.path:
            return httpx.Response(
                200,
                json={"data": {"attributes": {"status": "completed", "stats": {}}}},
            )
        return httpx.Response(404, json={})

    def broken_callback(_analysis_id: str) -> None:
        raise RuntimeError("redis down")

    client, http_client = _client(handler)
    with http_client:
        analysis, _url_report = client.scan_url(
            "https://example.com/",
            on_analysis_id=broken_callback,
        )
    assert analysis["data"]["attributes"]["status"] == "completed"
