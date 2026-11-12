"""Validate the configured VirusTotal API key from inside the worker container.

Run with::

    docker compose exec -T worker python -m scripts.verify_vt_key

The check performs one real domain lookup. It never prints the API key.
"""

from __future__ import annotations

import httpx

from app.config import get_settings

_TIMEOUT_SECONDS = 15.0
_PROBE_DOMAIN = "example.com"


def _error_message(response: httpx.Response) -> str | None:
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


def main() -> int:
    """Return 0 when VirusTotal accepts the key, otherwise 1."""

    settings = get_settings()
    api_key = settings.vt_api_key_value
    if not api_key:
        print("FAIL: VT_API_KEY is not set in this container.")
        print("Set it in .env, recreate the worker, and run this check again.")
        return 1

    url = f"{settings.vt_api_base_url.rstrip('/')}/domains/{_PROBE_DOMAIN}"
    headers = {"x-apikey": api_key, "accept": "application/json"}

    print("Checking VirusTotal with one domain lookup (this uses one API request).")
    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            response = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        print(f"FAIL: could not reach VirusTotal: {exc.__class__.__name__}: {exc}")
        return 1

    if response.status_code == 200:
        print("OK: VirusTotal accepted the API key (HTTP 200).")
        return 0

    if response.status_code in {401, 403}:
        print(f"FAIL: VirusTotal rejected the API key (HTTP {response.status_code}).")
        return 1

    if response.status_code == 429:
        print("WARN: the API key was accepted, but the quota is exhausted (HTTP 429).")
        print("Wait for the quota window to reset, then retry.")
        return 1

    detail = _error_message(response)
    suffix = f" (HTTP {response.status_code})"
    if detail:
        suffix += f": {detail}"
    print(f"FAIL: unexpected VirusTotal response{suffix}.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
