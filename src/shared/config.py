"""
Centralised configuration for Multi Modal Security.

All service configuration comes from environment variables (loaded via
python-dotenv from ``.env`` in the project root).  Every new config value
must also be documented in ``.env.example`` and ``PROJECT_CONTEXT.md``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Pydantic-settings reads env vars automatically and validates types.
    Defaults are set for local Docker Compose development.
    """

    # -- Redis (Event Bus) ------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"

    # -- OpenSearch --------------------------------------------------------
    opensearch_url: str = "http://localhost:9200"
    opensearch_events_index: str = "mms-events"

    # -- PostgreSQL --------------------------------------------------------
    postgres_url: str = "postgresql://mms:mms_dev_password@localhost:5432/mms"

    # -- MinIO (Object Storage) -------------------------------------------
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "mms-evidence"
    minio_secure: bool = False
    forensics_storage_mode: Literal["persistent", "memory"] = "persistent"
    forensics_db_schema: str = Field(default="public", pattern=r"^[a-z][a-z0-9_]{0,62}$")
    storage_timeout_seconds: int = Field(default=5, ge=1, le=30)
    response_storage_mode: Literal["persistent", "memory"] = "persistent"
    incident_storage_mode: Literal["persistent", "memory"] = "persistent"
    incident_db_schema: str = Field(default="public", pattern=r"^[a-z][a-z0-9_]{0,62}$")
    response_db_schema: str = Field(default="public", pattern=r"^[a-z][a-z0-9_]{0,62}$")
    ir_approval_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    ir_execution_mode: Literal["simulation", "firewall_http"] = "simulation"
    ir_firewall_api_url: str = ""
    ir_firewall_api_token: SecretStr = SecretStr("")
    ir_backend_timeout_seconds: float = Field(default=5, ge=1, le=30)

    # -- MQTT (Mosquitto) -------------------------------------------------
    mqtt_broker_host: str = "localhost"
    mqtt_broker_port: int = 1883

    # -- API Gateway ------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    auth_storage_mode: Literal["persistent", "memory"] = "persistent"
    auth_db_schema: str = Field(default="public", pattern=r"^[a-z][a-z0-9_]{0,62}$")
    auth_cookie_secure: bool = False
    auth_session_seconds: int = Field(default=28800, ge=300, le=86400)
    auth_idle_seconds: int = Field(default=1800, ge=60, le=28800)
    auth_login_attempts: int = Field(default=10, ge=3, le=50)
    auth_login_window_seconds: int = Field(default=300, ge=30, le=3600)
    auth_allowed_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000"]

    # Maximum evidence upload bytes (base64 requests add ~33% transport overhead).
    evidence_max_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=100 * 1024 * 1024)
    forensics_max_artifact_rows: int = Field(default=10000, ge=1, le=100000)
    forensics_query_timeout_seconds: int = Field(default=3, ge=1, le=30)

    # -- External API keys (secrets — never have real defaults) -----------
    openai_api_key: str = ""
    copilot_max_requests: int = Field(default=3, ge=1, le=5)
    copilot_audit_mode: Literal["persistent", "memory"] = "persistent"
    copilot_audit_db_schema: str = Field(default="public", pattern=r"^[a-z][a-z0-9_]{0,62}$")
    copilot_max_output_tokens: int = Field(default=700, ge=128, le=2000)
    copilot_context_bytes: int = Field(default=24000, ge=16000, le=64000)
    copilot_request_timeout_seconds: float = Field(default=12, ge=1, le=30)
    copilot_total_timeout_seconds: float = Field(default=30, ge=1, le=90)
    copilot_requests_per_minute: int = Field(default=12, ge=1, le=60)
    copilot_max_concurrent: int = Field(default=2, ge=1, le=4)
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    threat_intel_cache_mode: Literal["persistent", "memory"] = "persistent"
    threat_intel_db_schema: str = Field(default="public", pattern=r"^[a-z][a-z0-9_]{0,62}$")
    threat_intel_cache_capacity: int = Field(default=5000, ge=1, le=100000)
    threat_intel_cache_ttl_seconds: int = Field(default=3600, ge=1, le=86400)
    threat_intel_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10)

    # -- Ingestion --------------------------------------------------------
    raw_logs_dir: str = "data/raw_logs"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton of the application settings."""
    return Settings()


# Convenience alias so modules can just ``from src.shared.config import settings``
settings = get_settings()
