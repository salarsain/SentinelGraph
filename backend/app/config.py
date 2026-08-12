"""
SentinelGraph — Application Configuration

Pydantic Settings with environment variable loading.
All configuration is centralized here for type-safe access.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────
    app_name: str = "SentinelGraph"
    app_env: Literal["development", "staging", "production"] = "development"
    app_debug: bool = True
    app_version: str = "0.1.0"
    app_host: str = "0.0.0.0"
    app_port: int = 8000

    # ── Security / JWT ───────────────────────────────────────
    jwt_secret_key: str = Field(
        ...,
        description="Secret key for JWT signing. Generate with: python -c \"import secrets; print(secrets.token_urlsafe(64))\"",
    )
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    encryption_key: str = Field(
        default="",
        description="AES-GCM key for encrypting secrets at rest (base64-encoded, 32 bytes)",
    )

    # ── Database ─────────────────────────────────────────────
    postgres_user: str = "sentinelgraph"
    postgres_password: str = "sentinelgraph_dev_password"
    postgres_db: str = "sentinelgraph"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    database_url: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_database_url(self) -> str:
        """Build database URL from components if not explicitly set."""
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── Redis ────────────────────────────────────────────────
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_password: str = ""
    redis_url: str = ""
    celery_broker_url: str = ""
    celery_result_backend: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_redis_url(self) -> str:
        if self.redis_url:
            return self.redis_url
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/0"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_celery_broker_url(self) -> str:
        if self.celery_broker_url:
            return self.celery_broker_url
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/1"

    # ── MinIO ────────────────────────────────────────────────
    minio_endpoint: str = "minio:9000"
    minio_root_user: str = "sentinelgraph"
    minio_root_password: str = "sentinelgraph_minio_dev"
    minio_bucket: str = "sentinelgraph-evidence"
    minio_use_ssl: bool = False

    # ── AI / Hugging Face ─────────────────────────────────────
    ai_mode: str = "rule_based"  # "huggingface_api", "local_transformers", "rule_based"
    hf_api_token: str = ""  # Optional: Hugging Face API token (free tier works)
    hf_model_name: str = "mistralai/Mistral-7B-Instruct-v0.3"  # HF model ID
    hf_local_model: str = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"  # Smaller model for local use

    # ── Scanning Defaults ────────────────────────────────────
    max_concurrent_scans: int = 5
    max_crawl_depth: int = 10
    max_requests_per_second: int = 10
    default_request_timeout: int = 30
    max_response_size_mb: int = 10
    user_agent: str = "SentinelGraph/0.1.0 (Security Assessment)"

    # ── Feature Flags ────────────────────────────────────────
    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
