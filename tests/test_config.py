"""Tests for runtime configuration validation."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from app.config import ApiKeyConfig, Settings


def test_scan_rate_windows_must_be_consistent() -> None:
    with pytest.raises(ValidationError, match="SCAN_RATE_LIMIT_PER_HOUR"):
        Settings(
            environment="test",
            vt_api_key=SecretStr("test-vt-key"),
            scan_rate_limit_per_minute=10,
            scan_rate_limit_per_hour=5,
        )


def test_labelled_api_keys_parse_from_json_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "TRIAGE_API_KEYS",
        '[{"name": "laptop", "key": "laptop-key"}, {"name": "phone", "key": "phone-key"}]',
    )

    settings = Settings(
        _env_file=None,
        environment="test",
        vt_api_key=SecretStr("test-vt-key"),
    )

    assert settings.triage_api_key_values == {
        "laptop": "laptop-key",
        "phone": "phone-key",
    }


def test_labelled_key_cannot_reuse_the_legacy_default_name() -> None:
    with pytest.raises(ValidationError, match="reserved"):
        Settings(
            environment="test",
            vt_api_key=SecretStr("test-vt-key"),
            triage_api_key=SecretStr("legacy-key"),
            triage_api_keys=[
                ApiKeyConfig(name="default", key=SecretStr("labelled-key")),
            ],
        )


def test_duplicate_labelled_api_key_names_are_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate names"):
        Settings(
            environment="test",
            vt_api_key=SecretStr("test-vt-key"),
            triage_api_keys=[
                ApiKeyConfig(name="same", key=SecretStr("one")),
                ApiKeyConfig(name="same", key=SecretStr("two")),
            ],
        )
