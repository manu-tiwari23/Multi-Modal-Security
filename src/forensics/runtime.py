"""Lazy durable vault construction; imports never contact storage services."""

from threading import RLock

from minio import Minio
import urllib3

from src.shared.config import settings
from .evidence_vault import EvidenceVault, MinIOStorageBackend
from .repository import PostgresMetadataRepository

_vault = None
_lock = RLock()


def get_evidence_vault():
    global _vault
    with _lock:
        if _vault is None:
            if settings.forensics_storage_mode == "memory":
                _vault = EvidenceVault()
            else:
                repository = PostgresMetadataRepository(settings.postgres_url,
                    schema=settings.forensics_db_schema, timeout_seconds=settings.storage_timeout_seconds)
                client = Minio(settings.minio_endpoint, access_key=settings.minio_access_key,
                    secret_key=settings.minio_secret_key, secure=settings.minio_secure,
                    http_client=urllib3.PoolManager(timeout=urllib3.Timeout(
                        connect=settings.storage_timeout_seconds, read=settings.storage_timeout_seconds), retries=False))
                storage = MinIOStorageBackend(client, settings.minio_bucket)
                _vault = EvidenceVault(storage=storage, metadata_repository=repository)
        return _vault
