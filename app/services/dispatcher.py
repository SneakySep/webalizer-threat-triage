"""Broker-facing task dispatcher used by the API layer."""

from __future__ import annotations

from typing import Protocol

from app.celery_app import celery_app
from app.schemas.triage import TargetType


class TaskDispatcher(Protocol):
    def send_scan(
        self,
        *,
        task_id: str,
        target: str,
        target_type: TargetType,
        force_refresh: bool,
    ) -> None: ...


class CeleryTaskDispatcher:
    def send_scan(
        self,
        *,
        task_id: str,
        target: str,
        target_type: TargetType,
        force_refresh: bool,
    ) -> None:
        celery_app.send_task(
            "triage.scan",
            args=[task_id, target, target_type.value, force_refresh],
            task_id=task_id,
            queue="vt",
        )


def get_task_dispatcher() -> TaskDispatcher:
    return CeleryTaskDispatcher()
