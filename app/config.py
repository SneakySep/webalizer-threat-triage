"""Application configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings.

    Values are read from environment variables (case-insensitive) and an optional
    ``.env`` file. Container deployments should inject secrets at runtime rather
    than baking them into the image.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Webalizer Threat Triage"
    app_version: str = "1.0.0"
    environment: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    docs_enabled: bool = True
    api_v1_prefix: str = "/api/v1"

    # Optional static API-key protection for triage endpoints. Disabled when empty.
    triage_api_key: SecretStr | None = None
    cors_origins: list[str] = Field(default_factory=list)

    # Persistence
    database_url: str = "postgresql+psycopg://triage:triage@localhost:5432/triage"
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=20, ge=0, le=100)

    # Redis logical databases are separated by URL: broker=0, results=1, cache=2.
    redis_url: str = "redis://localhost:6379/2"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # VirusTotal API v3
    vt_api_key: SecretStr = SecretStr("")
    vt_api_base_url: str = "https://www.virustotal.com/api/v3"
    vt_rate_limit_per_minute: int = Field(default=4, ge=1, le=600)
    vt_http_timeout_seconds: float = Field(default=30.0, gt=0)
    vt_poll_initial_delay_seconds: float = Field(default=5.0, ge=0)
    vt_poll_max_delay_seconds: float = Field(default=60.0, ge=1)
    vt_poll_timeout_seconds: float = Field(default=300.0, gt=0)
    vt_max_retries: int = Field(default=5, ge=0, le=20)
    vt_retry_base_seconds: float = Field(default=15.0, ge=1)
    vt_retry_max_seconds: float = Field(default=300.0, ge=1)

    # Caching and job state
    cache_ttl_seconds: int = Field(default=86_400, ge=60)
    task_status_ttl_seconds: int = Field(default=604_800, ge=60)
    inflight_lock_ttl_seconds: int = Field(default=3_600, ge=60)

    # Abuse protection and data lifecycle
    scan_rate_limit_per_minute: int = Field(default=30, ge=1, le=600)
    scan_rate_limit_per_hour: int = Field(default=300, ge=1, le=100_000)
    force_refresh_cooldown_seconds: int = Field(default=300, ge=0)
    report_retention_days: int = Field(default=180, ge=1)
    store_raw_vt_response: bool = True

    # Verdict thresholds
    malicious_min_engines: int = Field(default=1, ge=0)
    suspicious_min_engines: int = Field(default=1, ge=0)

    # Celery
    celery_task_time_limit_seconds: int = Field(default=900, ge=30)
    celery_task_soft_time_limit_seconds: int = Field(default=840, ge=20)

    @model_validator(mode="after")
    def validate_runtime_settings(self) -> Settings:
        if self.vt_retry_max_seconds < self.vt_retry_base_seconds:
            raise ValueError("VT_RETRY_MAX_SECONDS must be >= VT_RETRY_BASE_SECONDS")
        if self.vt_poll_max_delay_seconds < self.vt_poll_initial_delay_seconds:
            raise ValueError("VT_POLL_MAX_DELAY_SECONDS must be >= VT_POLL_INITIAL_DELAY_SECONDS")
        if self.celery_task_soft_time_limit_seconds >= self.celery_task_time_limit_seconds:
            raise ValueError(
                "CELERY_TASK_SOFT_TIME_LIMIT_SECONDS must be less than "
                "CELERY_TASK_TIME_LIMIT_SECONDS"
            )
        if self.scan_rate_limit_per_hour < self.scan_rate_limit_per_minute:
            raise ValueError(
                "SCAN_RATE_LIMIT_PER_HOUR must be greater than or equal to "
                "SCAN_RATE_LIMIT_PER_MINUTE"
            )
        if self.environment == "production" and not self.vt_api_key.get_secret_value():
            raise ValueError("VT_API_KEY is required when ENVIRONMENT=production")
        return self

    @property
    def vt_api_key_value(self) -> str:
        return self.vt_api_key.get_secret_value().strip()

    @property
    def triage_api_key_value(self) -> str:
        return self.triage_api_key.get_secret_value().strip() if self.triage_api_key else ""

    @property
    def celery_task_rate_limit(self) -> str:
        return f"{self.vt_rate_limit_per_minute}/m"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance."""

    return Settings()
