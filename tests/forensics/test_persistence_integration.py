"""Live Postgres/MinIO restart, concurrency and immutability verification."""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import sys
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from minio import Minio
import psycopg2
from psycopg2 import sql
import pytest

from src.api.forensics import create_forensics_router
from src.forensics.evidence_vault import EvidenceVault, MinIOStorageBackend
from src.forensics.integrity_job import IntegrityVerifierJob
from src.forensics.models import EvidenceTamperedError
from src.forensics.repository import EvidenceStoreUnavailable, PostgresMetadataRepository
from src.shared.config import settings

pytestmark = pytest.mark.integration


@pytest.fixture
def durable():
    suffix = uuid4().hex
    schema = "mms_forensic_test_" + suffix
    bucket = "mms-forensic-test-" + suffix
    client = Minio(settings.minio_endpoint, access_key=settings.minio_access_key,
                   secret_key=settings.minio_secret_key, secure=settings.minio_secure)
    try:
        connection = psycopg2.connect(settings.postgres_url, connect_timeout=2)
        connection.close()
        client.list_buckets()
    except Exception:
        pytest.skip("Live Postgres and MinIO are required")
    def make_vault():
        return EvidenceVault(storage=MinIOStorageBackend(client, bucket),
            metadata_repository=PostgresMetadataRepository(settings.postgres_url, schema=schema))
    vault = make_vault()
    try:
        yield vault, make_vault, schema, bucket
    finally:
        # Only the unique schema/bucket created above belongs to this test.
        assert schema.startswith("mms_forensic_test_") and suffix in schema
        with psycopg2.connect(settings.postgres_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        connection.close()
        for item in client.list_objects(bucket, recursive=True):
            client.remove_object(bucket, item.object_name)
        client.remove_bucket(bucket)


def api_client(vault):
    async def ingest(event):
        return {"event_id": event.event_id}
    app = FastAPI()
    from src.api.auth import authorize_request
    from src.auth.models import Principal
    app.dependency_overrides[authorize_request] = lambda: Principal(username="analyst", role="admin")
    app.include_router(create_forensics_router(vault, ingest))
    return TestClient(app)


def test_evidence_and_custody_survive_a_new_python_process_and_api(durable):
    vault, make_vault, schema, bucket = durable
    client = api_client(vault)
    response = client.post("/api/forensics/evidence", json={"filename": "record.log", "case_id": "restart-case",
        "acquired_by": "analyst", "content_base64": base64.b64encode(b"Synthetic record 203.0.113.7").decode()})
    assert response.status_code == 201
    item = response.json()
    env = dict(os.environ, FORENSICS_DB_SCHEMA=schema, MINIO_BUCKET=bucket,
               FORENSICS_STORAGE_MODE="persistent", MMS_TEST_EVIDENCE_ID=item["evidence_id"])
    program = (
        "import os,json; from src.forensics.runtime import get_evidence_vault; "
        "v=get_evidence_vault(); key=os.environ['MMS_TEST_EVIDENCE_ID']; "
        "v.get_evidence_bytes(key,'fresh_process'); "
        "m=v.get_metadata(key); print(json.dumps({'sha256':m.sha256,'actors':[c.actor for c in m.custody_history]}))"
    )
    completed = subprocess.run([sys.executable, "-c", program], env=env, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, "Fresh-process evidence recovery failed"
    result = json.loads(completed.stdout)
    assert result["sha256"] == item["sha256"]
    assert result["actors"] == ["analyst", "fresh_process"]
    fresh = api_client(make_vault())
    assert fresh.get("/api/forensics/evidence?case_id=restart-case").json()["total"] == 1
    report = fresh.get("/api/reports/forensics/restart-case")
    assert report.status_code == 200
    assert item["sha256"] in report.text
    assert "fresh_process" in report.text


def test_concurrent_workers_preserve_every_custody_entry(durable):
    vault, make_vault, _, _ = durable
    item = vault.ingest_bytes(b"concurrent sample", "sample.txt", "intake")
    workers = [vault, make_vault()]
    def access(number):
        return workers[number % 2].get_evidence_bytes(item.evidence_id, f"worker-{number}")
    with ThreadPoolExecutor(max_workers=6) as executor:
        assert all(data == b"concurrent sample" for data in executor.map(access, range(16)))
    history = make_vault().get_chain_of_custody(item.evidence_id)
    assert len(history) == 17
    assert {c.actor for c in history} == {"intake", *[f"worker-{n}" for n in range(16)]}


def test_tamper_history_survives_restart_and_restored_bytes(durable):
    vault, make_vault, _, _ = durable
    item = vault.ingest_bytes(b"original", "sample.txt", "intake")
    key = f"{item.evidence_id}_sample.txt"
    vault.storage.store(key, b"changed synthetic test data")
    with pytest.raises(EvidenceTamperedError):
        make_vault().get_evidence_bytes(item.evidence_id, "analyst")
    vault.storage.store(key, b"original")
    recovered = make_vault()
    assert recovered.get_metadata(item.evidence_id).is_tampered
    assert IntegrityVerifierJob(recovered).verify_single(item.evidence_id).is_tampered
    with pytest.raises(EvidenceTamperedError):
        recovered.get_evidence_bytes(item.evidence_id, "another analyst")


def test_database_rejects_custody_rewrite_and_provenance_changes(durable):
    vault, _, schema, _ = durable
    item = vault.ingest_bytes(b"sample", "sample.txt", "intake")
    repository = vault.repository
    for statement in (
        sql.SQL("UPDATE {} SET entry='{{}}'::jsonb WHERE evidence_id=%s").format(repository.table("mms_evidence_custody")),
        sql.SQL("DELETE FROM {} WHERE evidence_id=%s").format(repository.table("mms_evidence_custody")),
        sql.SQL("UPDATE {} SET case_id='rewritten' WHERE evidence_id=%s").format(repository.table("mms_evidence")),
    ):
        with pytest.raises(EvidenceStoreUnavailable):
            with repository.connection() as connection, connection.cursor() as cursor:
                cursor.execute(statement, (item.evidence_id,))
    assert repository.get(item.evidence_id).filename == "sample.txt"
    assert len(repository.get(item.evidence_id).custody_history) == 1
