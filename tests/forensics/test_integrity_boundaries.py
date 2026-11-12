import base64

import pytest

from src.forensics.evidence_vault import EvidenceVault
from src.forensics.file_analyzer import FileAnalyzer
from src.forensics.integrity_job import IntegrityVerifierJob
from src.forensics.models import EvidenceTamperedError


def test_verification_cannot_be_disabled():
    vault = EvidenceVault()
    item = vault.ingest_bytes(b"original", "sample.txt", "analyst")
    vault.storage.store(f"{item.evidence_id}_sample.txt", b"changed")
    with pytest.raises(ValueError, match="mandatory"):
        vault.get_evidence_bytes(item.evidence_id, "analyst", verify_hash=False)
    with pytest.raises(EvidenceTamperedError):
        vault.get_evidence_bytes(item.evidence_id, "analyst")


def test_restoring_bytes_does_not_erase_integrity_history_or_reopen_analysis():
    vault = EvidenceVault()
    item = vault.ingest_bytes(b"original", "sample.txt", "analyst")
    key = f"{item.evidence_id}_sample.txt"
    vault.storage.store(key, b"changed")
    assert vault.verify_integrity(item.evidence_id) is False
    vault.storage.store(key, b"original")
    assert vault.verify_integrity(item.evidence_id) is True
    detail = IntegrityVerifierJob(vault).verify_single(item.evidence_id)
    assert detail.status == "verified"  # Current bytes match, but provenance remains flagged.
    assert detail.is_tampered is True
    assert item.is_tampered is True
    with pytest.raises(EvidenceTamperedError, match="recorded integrity failure"):
        vault.get_evidence_bytes(item.evidence_id, "analyst")
    assert any(entry.status == "mismatch" for entry in item.custody_history)


def test_static_base64_command_marker_is_detected_without_execution():
    # Inert text mentioning a shell; no commands, execution or attack payload.
    fixture = base64.b64encode(b"Synthetic forensic fixture mentioning /bin/sh for parser testing")
    analysis = FileAnalyzer().analyze_bytes(fixture, "fixture.txt")
    assert any(i.category == "encoded_payload" for i in analysis.suspicious_indicators)


def test_base64_ordinary_text_is_not_a_command_indicator():
    fixture = base64.b64encode(b"Synthetic forensic fixture mentioning ordinary sample data")
    analysis = FileAnalyzer().analyze_bytes(fixture, "fixture.txt")
    assert not any(i.category == "encoded_payload" for i in analysis.suspicious_indicators)
