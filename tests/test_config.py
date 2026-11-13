"""Tests for runtime configuration validation."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from app.config import Settings


def test_scan_rate_windows_must_be_consistent() -> None:
    with pytest.raises(ValidationError, match="SCAN_RATE_LIMIT_PER_HOUR"):
        Settings(
            environment="test",
            vt_api_key=SecretStr("test-vt-key"),
            scan_rate_limit_per_minute=10,
            scan_rate_limit_per_hour=5,
        )
