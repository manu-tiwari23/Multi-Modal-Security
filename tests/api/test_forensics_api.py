import base64
import hashlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.forensics import create_forensics_router
from src.forensics.evidence_vault import EvidenceVault


@pytest.fixture
def context():
    vault = EvidenceVault()
    events = []

    async def ingest(event):
        events.append(event)
        return {"event_id": event.event_id}

    app = FastAPI()
    app.include_router(create_forensics_router(vault, ingest))
    return TestClient(app), vault, events


def upload(client, **overrides):
    body = {"filename": "sample.log", "case_id": "case-one", "acquired_by": "analyst",
            "content_base64": base64.b64encode(b"Synthetic record 203.0.113.80").decode()}
    body.update(overrides)
    return client.post("/api/forensics/evidence", json=body)


def test_upload_analyze_report_and_case_filter(context):
    client, vault, events = context
    response = upload(client)
    assert response.status_code == 201
    metadata = response.json()
    evidence_id = metadata["evidence_id"]
    assert "storage_path" not in metadata
    assert metadata["sha256"] == hashlib.sha256(b"Synthetic record 203.0.113.80").hexdigest()
    assert metadata["custody_history"][0]["action"] == "intake"
    assert events[0].event_type == "evidence_intake"
    assert events[0].entity.hash == metadata["sha256"]
    analyzed = client.post(f"/api/forensics/evidence/{evidence_id}/analyze")
    assert analyzed.status_code == 200
    assert analyzed.json()["analysis"]["sha256"] == metadata["sha256"]
    upload(client, case_id="case-two", filename="unrelated.txt")
    assert client.get("/api/forensics/evidence?case_id=case-one").json()["total"] == 1
    for format in ("json", "html", "markdown"):
        report = client.get(f"/api/reports/forensics/case-one?format={format}")
        assert report.status_code == 200
        assert metadata["sha256"] in report.text
        assert "unrelated" not in report.text
    assert any(c.notes == "Access verified for purpose: 'forensic_report'." for c in vault.get_chain_of_custody(evidence_id))


@pytest.mark.parametrize("missing", [False, True])
def test_corruption_or_missing_bytes_block_reports_and_publish_alert(context, missing):
    client, vault, events = context
    metadata = upload(client).json()
    key = f"{metadata['evidence_id']}_{metadata['filename']}"
    if missing:
        vault.storage.delete(key)
    else:
        vault.storage.store(key, b"changed synthetic record")
    report = client.get("/api/reports/forensics/case-one")
    assert report.status_code == 409
    assert events[-1].severity == "critical"
    assert events[-1].event_type == ("evidence_missing_detected" if missing else "evidence_tampering_detected")
    record = client.get(f"/api/forensics/evidence/{metadata['evidence_id']}").json()
    assert record["is_tampered"] is True
    assert record["custody_history"][-1]["status"] == "mismatch"


@pytest.mark.parametrize("changes", [
    {"filename": "../escape.txt"}, {"filename": "C:\\private.txt"}, {"filename": "file:stream"},
    {"content_base64": "not/base64!"}, {"case_id": "../case"}, {"acquired_by": " "},
])
def test_invalid_input_is_rejected_without_intake(context, changes):
    client, vault, events = context
    assert upload(client, **changes).status_code == 422
    assert vault.list_evidence() == []
    assert events == []


def test_empty_file_is_valid_and_unknown_case_returns_404(context):
    client, _, _ = context
    assert upload(client, content_base64="").status_code == 201
    assert client.get("/api/reports/forensics/case-one").status_code == 200
    assert client.get("/api/reports/forensics/absent").status_code == 404
    assert client.post("/api/forensics/evidence/absent/analyze").status_code == 404


def test_content_limit_is_enforced_before_storage(context, monkeypatch):
    import src.api.forensics as module
    client, vault, _ = context
    monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES", 1)
    assert upload(client).status_code == 413
    assert vault.list_evidence() == []


def test_metadata_analysis_is_audited_and_invalid_browser_input_rejected(context):
    client, vault, _ = context
    metadata = upload(client).json()
    key = metadata["evidence_id"]
    response = client.post(f"/api/forensics/evidence/{key}/analyze?kind=metadata")
    assert response.status_code == 200
    assert response.json()["analysis_kind"] == "metadata"
    assert response.json()["analysis"]["sha256"] == metadata["sha256"]
    assert vault.get_chain_of_custody(key)[-1].action == "analyze"
    assert client.post(f"/api/forensics/evidence/{key}/analyze?kind=browser").status_code == 422
    assert client.post(f"/api/forensics/evidence/{key}/analyze?kind=execute").status_code == 422


def test_integrity_endpoints_report_current_and_historical_state(context):
    client, vault, _ = context
    metadata = upload(client).json()
    key = metadata["evidence_id"]
    assert client.post(f"/api/forensics/evidence/{key}/verify").json()["status"] == "verified"
    assert client.post("/api/forensics/cases/case-one/verify").json()["verified_count"] == 1
    vault.storage.store(f"{key}_sample.log", b"changed")
    result = client.post("/api/forensics/cases/case-one/verify")
    assert result.status_code == 200
    assert result.json()["all_intact"] is False
    assert result.json()["tampered_count"] == 1
    assert client.post("/api/forensics/cases/absent/verify").status_code == 404


def test_carving_recovers_a_new_hashed_item_with_parent_provenance(context):
    client, vault, _ = context
    data = b"synthetic prefix\x00%PDF-1.4\nSynthetic fixture\n%%EOF\x00tail"
    parent = upload(client, content_base64=base64.b64encode(data).decode()).json()
    response = client.post(f"/api/forensics/evidence/{parent['evidence_id']}/carve/0")
    assert response.status_code == 201
    child = response.json()
    assert child["evidence_id"] != parent["evidence_id"]
    assert child["case_id"] == parent["case_id"]
    assert parent["sha256"] in child["custody_history"][0]["notes"]
    assert vault.get_evidence_bytes(child["evidence_id"], "test") == b"%PDF-1.4\nSynthetic fixture\n%%EOF"
    assert vault.get_evidence_bytes(parent["evidence_id"], "test") == data
    assert client.post(f"/api/forensics/evidence/{parent['evidence_id']}/carve/-1").status_code == 404
