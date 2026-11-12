"""Tests for Celery worker startup warnings."""

from __future__ import annotations

import logging

from pydantic import SecretStr

import app.celery_app as celery_module


def test_worker_warns_when_vt_key_is_missing(monkeypatch, caplog) -> None:
    settings = celery_module.settings.model_copy(update={"vt_api_key": SecretStr("")})
    monkeypatch.setattr(celery_module, "settings", settings)

    with caplog.at_level(logging.WARNING, logger=celery_module.__name__):
        celery_module._warn_missing_vt_key()

    assert "VT_API_KEY is not configured" in caplog.text


def test_worker_does_not_warn_when_vt_key_is_configured(
    monkeypatch,
    caplog,
) -> None:
    settings = celery_module.settings.model_copy(update={"vt_api_key": SecretStr("configured-key")})
    monkeypatch.setattr(celery_module, "settings", settings)

    with caplog.at_level(logging.WARNING, logger=celery_module.__name__):
        celery_module._warn_missing_vt_key()

    assert "VT_API_KEY is not configured" not in caplog.text
