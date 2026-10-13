"""Validated settings for the Avron API and scan worker."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from the environment or a local .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    scanner_api_key: str = Field(
        ...,
        description="API key required by the scan submission and result endpoints",
    )
    database_url: str = Field(
        default="postgresql+asyncpg://localhost:5432/avron",
        description="Async PostgreSQL connection URL",
    )
    database_url_sync: str = Field(
        default="postgresql+psycopg2://localhost:5432/avron",
        description="Synchronous PostgreSQL URL used by Alembic and the worker",
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL used by Celery",
    )
    nvd_api_key: str | None = Field(
        default=None,
        description="Optional NVD API key for higher CVE lookup rate limits",
    )
    scan_timeout_seconds: int = Field(
        default=600,
        ge=1,
        description="Maximum duration of a Nuclei scan in seconds",
    )
    metrics_enabled: bool = Field(
        default=True,
        description="Expose Prometheus metrics at /metrics",
    )
    scan_dir: str = Field(
        default="",
        description="Optional absolute directory for local scan status files",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, or CRITICAL",
    )
    environment: str = Field(
        default="development",
        description="Deployment environment: development, staging, or production",
    )
    testing: bool = Field(
        default=False,
        description="Enable test-specific database behavior",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if value.upper() not in valid:
            raise ValueError(f"log_level must be one of {sorted(valid)}")
        return value.upper()

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        valid = {"development", "staging", "production"}
        if value.lower() not in valid:
            raise ValueError(f"environment must be one of {sorted(valid)}")
        return value.lower()

    @field_validator("scan_dir")
    @classmethod
    def validate_scan_dir(cls, value: str) -> str:
        if value and not Path(value).is_absolute():
            raise ValueError("scan_dir must be an absolute path")
        return value


@lru_cache
def get_settings() -> Settings:
    """Return the cached process-wide settings instance."""
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
