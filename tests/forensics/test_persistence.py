"""Storage failures must never be mistaken for successful evidence handling."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.forensics import create_forensics_router
from src.forensics.evidence_vault import EvidenceVault, MemoryStorageBackend, MinIOStorageBackend
from src.forensics.integrity_job import IntegrityVerifierJob
from src.forensics.models import ChainOfCustodyEntry, CustodyAction, CustodyStatus
from src.forensics.repository import EvidenceStoreUnavailable, MemoryMetadataRepository, PostgresMetadataRepository


def test_audit_write_failure_prevents_evidence_return(monkeypatch):
    repository = MemoryMetadataRepository()
    vault = EvidenceVault(metadata_repository=repository)
    item = vault.ingest_bytes(b"sample", "sample.txt", "analyst")
    def unavailable(*args, **kwargs):
        raise EvidenceStoreUnavailable("storage unavailable")
    monkeypatch.setattr(repository, "append", unavailable)
    with pytest.raises(EvidenceStoreUnavailable):
        vault.get_evidence_bytes(item.evidence_id, "analyst")


def test_metadata_commit_failure_does_not_acknowledge_or_publish_intake(monkeypatch):
    repository = MemoryMetadataRepository()
    storage = MemoryStorageBackend()
    events = []
    vault = EvidenceVault(storage=storage, metadata_repository=repository, event_publisher=events.append)
    def unavailable(*args):
        raise EvidenceStoreUnavailable("failed commit")
    monkeypatch.setattr(repository, "create", unavailable)
    with pytest.raises(EvidenceStoreUnavailable):
        vault.ingest_bytes(b"sample", "sample.txt", "analyst")
    assert repository.list() == []
    assert events == []
    # Keep the unacknowledged object: an ambiguous DB commit must not cause deletion.
    assert len(storage._storage) == 1


def test_storage_outage_is_not_reported_as_evidence_tampering(monkeypatch):
    vault = EvidenceVault()
    item = vault.ingest_bytes(b"sample", "sample.txt", "analyst")
    def unavailable(*args):
        raise EvidenceStoreUnavailable("storage unavailable")
    monkeypatch.setattr(vault.storage, "exists", unavailable)
    events = []
    with pytest.raises(EvidenceStoreUnavailable):
        IntegrityVerifierJob(vault, event_publisher=events.append).verify_single(item.evidence_id)
    assert events == []
    assert item.is_tampered is False


def test_api_recovers_from_lazy_initialization_failure_without_memory_fallback():
    attempts = []
    vault = EvidenceVault()
    def provider():
        attempts.append(1)
        if len(attempts) == 1:
            raise EvidenceStoreUnavailable("Private connection details must not reach clients")
        return vault
    async def ingest(event):
        return {}
    app = FastAPI()
    app.include_router(create_forensics_router(provider, ingest))
    client = TestClient(app)
    first = client.get("/api/forensics/evidence")
    assert first.status_code == 503
    assert "Private connection" not in first.text
    assert client.get("/api/forensics/evidence").status_code == 200


def test_minio_initialization_outage_propagates():
    class Client:
        def bucket_exists(self, name):
            raise ConnectionError("not connected")
    with pytest.raises(EvidenceStoreUnavailable):
        MinIOStorageBackend(Client())


def test_repository_cannot_attach_custody_to_wrong_evidence():
    vault = EvidenceVault()
    item = vault.ingest_bytes(b"sample", "sample.txt", "analyst")
    entry = ChainOfCustodyEntry(evidence_id="other", actor="analyst", action=CustodyAction.VERIFY,
                               expected_hash=item.sha256, actual_hash=item.sha256, status=CustodyStatus.VERIFIED)
    with pytest.raises(ValueError):
        vault.repository.append(item.evidence_id, entry)


def test_schema_name_is_validated_before_any_connection():
    with pytest.raises(ValueError, match="schema"):
        PostgresMetadataRepository("unused", schema="public;drop table evidence")
