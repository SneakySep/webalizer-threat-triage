"""Start the web app for browser tests unless an external URL is supplied."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

pytest.importorskip("pytest_playwright")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(url: str, process: subprocess.Popen[bytes], timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"The app exited before becoming ready (code {process.returncode})")
        try:
            with urllib.request.urlopen(f"{url}/health/live", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)
    raise RuntimeError(f"The app did not become ready at {url}")


@pytest.fixture(scope="session")
def e2e_base_url() -> Iterator[str]:
    configured_url = os.getenv("E2E_BASE_URL", "").strip()
    if configured_url:
        yield configured_url.rstrip("/")
        return
    if os.getenv("RUN_E2E") != "1":
        pytest.skip("Set RUN_E2E=1 or E2E_BASE_URL to run browser tests")

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_until_ready(url, process)
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
