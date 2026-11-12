"""Synchronous VirusTotal API v3 client used by Celery workers."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote

import httpx

from app.services.rate_limit import RateLimiter
from app.utils.helpers import url_to_vt_id

logger = logging.getLogger(__name__)


class VTError(Exception):
    """Base class for upstream VirusTotal failures."""

    code = "VT_ERROR"
    public_message = "The VirusTotal request failed."
    retryable = False

    def __init__(
        self,
        detail: str | None = None,
        *,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(detail or self.public_message)
        self.detail = detail
        self.retry_after = retry_after


class VTAuthError(VTError):
    code = "VT_AUTH_FAILED"
    public_message = "VirusTotal authentication failed. Verify the server API key."


class VTInvalidTargetError(VTError):
    code = "VT_INVALID_TARGET"
    public_message = "VirusTotal rejected the submitted target."


class VTNotFoundError(VTError):
    code = "VT_NOT_FOUND"
    public_message = "VirusTotal has no report for this target."


class VTRateLimitError(VTError):
    code = "VT_RATE_LIMITED"
    public_message = "VirusTotal rate limit exceeded."
    retryable = True


class VTTransientError(VTError):
    code = "VT_UPSTREAM_UNAVAILABLE"
    public_message = "VirusTotal is temporarily unavailable."
    retryable = True


class VTTimeoutError(VTTransientError):
    code = "VT_TIMEOUT"
    public_message = "VirusTotal did not finish analyzing the target in time."


class VTBadResponseError(VTError):
    code = "VT_BAD_RESPONSE"
    public_message = "VirusTotal returned an unexpected response."


class VirusTotalClient:
    """Thin, rate-limited wrapper over the VirusTotal v3 HTTP API."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://www.virustotal.com/api/v3",
        timeout_seconds: float = 30.0,
        limiter: RateLimiter | None = None,
        http_client: httpx.Client | None = None,
        poll_initial_delay_seconds: float = 5.0,
        poll_max_delay_seconds: float = 60.0,
        poll_timeout_seconds: float = 300.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key.strip():
            raise VTAuthError("VT_API_KEY is not configured")
        self._base_url = base_url.rstrip("/")
        self._limiter = limiter
        self._poll_initial_delay = poll_initial_delay_seconds
        self._poll_max_delay = poll_max_delay_seconds
        self._poll_timeout = poll_timeout_seconds
        self._sleep = sleeper
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout_seconds)
        self._http.headers["x-apikey"] = api_key
        self._http.headers.setdefault("accept", "application/json")
        self._http.headers.setdefault("user-agent", "webalizer-triage/1.0")

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def submit_url(self, url: str) -> str:
        payload = self._request("POST", "/urls", data={"url": url})
        analysis_id = _nested(payload, "data", "id")
        if not isinstance(analysis_id, str) or not analysis_id:
            raise VTBadResponseError("URL submission did not include an analysis id")
        return analysis_id

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        return self._request("GET", f"/analyses/{quote(analysis_id, safe='')}")

    def get_url_report(self, url: str) -> dict[str, Any] | None:
        url_id = quote(url_to_vt_id(url), safe="")
        try:
            return self._request("GET", f"/urls/{url_id}")
        except VTNotFoundError:
            return None

    def get_domain_report(self, domain: str) -> dict[str, Any] | None:
        try:
            return self._request("GET", f"/domains/{quote(domain, safe='')}")
        except VTNotFoundError:
            return None

    def scan_domain(self, domain: str) -> dict[str, Any] | None:
        return self.get_domain_report(domain)

    def scan_url(
        self,
        url: str,
        *,
        analysis_id: str | None = None,
        on_analysis_id: Callable[[str], None] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Submit a URL, poll the analysis, and return analysis + URL metadata.

        ``analysis_id`` may be supplied when retrying a task so quota is not spent
        re-submitting the same URL. A missing/expired analysis falls back to one
        fresh submission.
        """

        resubmitted = False
        if analysis_id is None:
            analysis_id = self.submit_url(url)
            self._notify_analysis_id(on_analysis_id, analysis_id)

        deadline = time.monotonic() + self._poll_timeout
        delay = max(0.0, self._poll_initial_delay)

        while True:
            try:
                analysis = self.get_analysis(analysis_id)
            except VTNotFoundError:
                if resubmitted:
                    raise
                analysis_id = self.submit_url(url)
                self._notify_analysis_id(on_analysis_id, analysis_id)
                resubmitted = True
                delay = max(0.0, self._poll_initial_delay)
                continue

            status = _analysis_status(analysis)
            if status == "completed":
                break
            if status not in {"queued", "in-progress"}:
                raise VTBadResponseError(f"Unexpected analysis status: {status!r}")
            if time.monotonic() >= deadline:
                raise VTTimeoutError("Timed out waiting for the URL analysis to complete")

            logger.debug(
                "VirusTotal analysis %s status=%s; polling again in %.1fs",
                analysis_id,
                status,
                delay,
            )
            self._sleep(delay)
            delay = min(self._poll_max_delay, max(delay * 2, 1.0))

        url_report: dict[str, Any] | None = None
        try:
            url_report = self.get_url_report(url)
        except (VTRateLimitError, VTTransientError, VTBadResponseError) as exc:
            # Categories are supplementary. Do not discard a completed report if
            # the optional metadata lookup fails.
            logger.warning("URL metadata lookup failed after analysis: %s", exc)

        return analysis, url_report

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        self._acquire_slot()
        url = f"{self._base_url}{path}"
        try:
            response = self._http.request(method, url, **kwargs)
        except httpx.TimeoutException as exc:
            raise VTTransientError(f"VirusTotal request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise VTTransientError(f"VirusTotal connection error: {exc}") from exc

        if 200 <= response.status_code < 300:
            try:
                payload = response.json()
            except ValueError as exc:
                raise VTBadResponseError("VirusTotal returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise VTBadResponseError("VirusTotal returned a non-object response")
            return payload

        message = _upstream_error_message(response)
        if response.status_code in {401, 403}:
            raise VTAuthError(message)
        if response.status_code == 404:
            raise VTNotFoundError(message)
        if response.status_code == 429:
            raise VTRateLimitError(
                message or "VirusTotal rate limit exceeded",
                retry_after=_retry_after_seconds(response),
            )
        if response.status_code == 400:
            raise VTInvalidTargetError(message)
        if response.status_code >= 500:
            raise VTTransientError(message or f"VirusTotal server error ({response.status_code})")
        raise VTError(message or f"Unexpected VirusTotal response ({response.status_code})")

    def _acquire_slot(self) -> None:
        if self._limiter is None:
            return
        try:
            self._limiter.acquire()
        except Exception as exc:
            raise VTTransientError("Rate limiter backend is unavailable") from exc

    @staticmethod
    def _notify_analysis_id(
        callback: Callable[[str], None] | None,
        analysis_id: str,
    ) -> None:
        if callback is None:
            return
        try:
            callback(analysis_id)
        except Exception:
            logger.warning("Failed to persist the VT analysis id", exc_info=True)


def _nested(payload: dict[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _analysis_status(payload: dict[str, Any]) -> str:
    status = _nested(payload, "data", "attributes", "status")
    return str(status) if status is not None else "unknown"


def _upstream_error_message(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("code")
        return str(message) if message else None
    return None


def _retry_after_seconds(response: httpx.Response) -> float | None:
    header = response.headers.get("retry-after")
    if not header:
        return None
    try:
        return max(0.0, float(header))
    except ValueError:
        pass
    try:
        retry_at = parsedate_to_datetime(header)
        return max(0.0, retry_at.timestamp() - time.time())
    except (TypeError, ValueError, OverflowError):
        return None
