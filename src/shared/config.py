"""
Centralised configuration for Multi Modal Security.

All service configuration comes from environment variables (loaded via
python-dotenv from ``.env`` in the project root).  Every new config value
must also be documented in ``.env.example`` and ``PROJECT_CONTEXT.md``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


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

    # -- MQTT (Mosquitto) -------------------------------------------------
    mqtt_broker_host: str = "localhost"
    mqtt_broker_port: int = 1883

    # -- API Gateway ------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # -- External API keys (secrets — never have real defaults) -----------
    openai_api_key: str = ""
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""

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
