"""
Unit tests for Digital Forensics Evidence Vault and Chain of Custody.

Verifies:
1. Immediate SHA-256 and MD5 hashing on intake.
2. Initial chain-of-custody logging.
3. Cryptographic re-verification on every access.
4. Immediate detection, flagging, and halting on tampered evidence.
5. In-place immutability (mutating retrieved bytes does not affect vault).
6. Local storage backend containment.
7. Scheduled batch integrity verification job.
8. Event bus integration with MMS SecurityEvent schema.
9. Chain-of-custody markdown audit report generation.
"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from src.forensics.evidence_vault import (
    EvidenceVault,
    LocalStorageBackend,
    MemoryStorageBackend,
    calculate_hashes,
    infer_evidence_type,
)
from src.forensics.models import (
    CustodyAction,
    CustodyStatus,
    EvidenceTamperedError,
    EvidenceType,
)
from src.shared.event_schema import SecurityEvent


class TestEvidenceVault:
    """Test suite for evidence intake, hashing, custody logging, and tamper detection."""

    def test_calculate_hashes(self):
        """Verify streaming chunked hashing utility matches hashlib."""
        sample = b"Digital Forensics Tamper-Evident Test Data 12345"
        expected_sha = hashlib.sha256(sample).hexdigest()
        expected_md5 = hashlib.md5(sample).hexdigest()

        sha, md5, size = calculate_hashes(sample)
        assert sha == expected_sha
        assert md5 == expected_md5
        assert size == len(sample)

    def test_infer_evidence_type(self):
        """Verify automatic inference of evidence classifications."""
        ev_type, mime = infer_evidence_type("suspicious_auth.log")
        assert ev_type == EvidenceType.LOG

        ev_type, mime = infer_evidence_type("places.sqlite")
        assert ev_type == EvidenceType.BROWSER_ARTIFACT

        ev_type, mime = infer_evidence_type("setupapi.dev.log")
        assert ev_type == EvidenceType.USB_LOG

        ev_type, mime = infer_evidence_type("capture.pcap")
        assert ev_type == EvidenceType.NETWORK_PCAP

        ev_type, mime = infer_evidence_type("phish_sample.eml")
        assert ev_type == EvidenceType.EMAIL

        ev_type, mime = infer_evidence_type("bundle.zip")
        assert ev_type == EvidenceType.ARCHIVE

        ev_type, mime = infer_evidence_type("malware.bin")
        assert ev_type == EvidenceType.FILE

    def test_ingest_bytes_initializes_custody(self):
        """Verify evidence intake immediately hashes and starts chain of custody."""
        vault = EvidenceVault()
        raw_data = b"Suspicious script payload: rm -rf /"
        meta = vault.ingest_bytes(
            data=raw_data,
            filename="payload.sh",
            acquired_by="analyst_alice",
            case_id="CASE-2026-001",
            source_host="prod-web-01",
        )

        assert meta.evidence_id is not None
        assert meta.filename == "payload.sh"
        assert meta.file_size_bytes == len(raw_data)
        assert meta.sha256 == hashlib.sha256(raw_data).hexdigest()
        assert meta.acquired_by == "analyst_alice"
        assert meta.case_id == "CASE-2026-001"
        assert meta.source_host == "prod-web-01"
        assert not meta.is_tampered

        # Verify initial chain of custody
        assert len(meta.custody_history) == 1
        entry = meta.custody_history[0]
        assert entry.action == CustodyAction.INTAKE
        assert entry.actor == "analyst_alice"
        assert entry.status == CustodyStatus.INTAKE
        assert entry.expected_hash == meta.sha256
        assert entry.actual_hash == meta.sha256

    def test_ingest_file_from_disk(self):
        """Verify ingestion from a filesystem path."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"System log content from host")
            tmp_path = Path(tmp.name)

        try:
            vault = EvidenceVault()
            meta = vault.ingest_file(
                file_path=tmp_path,
                acquired_by="incident_responder_bob",
                filename="syslog.txt",
                case_id="CASE-999",
            )
            assert meta.filename == "syslog.txt"
            assert meta.file_size_bytes == len(b"System log content from host")
            assert meta.sha256 == hashlib.sha256(b"System log content from host").hexdigest()
            assert meta.evidence_type == EvidenceType.FILE
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_safe_access_and_re_verification(self):
        """Verify subsequent access recalculates hash and records verified custody action."""
        vault = EvidenceVault()
        data = b"Forensic memory string artifact"
        meta = vault.ingest_bytes(
            data=data,
            filename="strings.txt",
            acquired_by="alice",
        )

        # Access 1: Read by copilot
        content1 = vault.get_evidence_bytes(meta.evidence_id, actor="copilot_service", purpose="nlp_extraction")
        assert content1 == data

        # Access 2: Read by analyst
        content2 = vault.get_evidence_bytes(meta.evidence_id, actor="analyst_carol", purpose="manual_review")
        assert content2 == data

        custody = vault.get_chain_of_custody(meta.evidence_id)
        assert len(custody) == 3  # Intake + 2 Access entries
        assert custody[1].action == CustodyAction.ACCESS
        assert custody[1].actor == "copilot_service"
        assert custody[1].status == CustodyStatus.VERIFIED

        assert custody[2].action == CustodyAction.ACCESS
        assert custody[2].actor == "analyst_carol"
        assert custody[2].status == CustodyStatus.VERIFIED

    def test_tamper_detection_on_access_raises_error(self):
        """Verify corrupted/modified evidence raises EvidenceTamperedError and logs mismatch."""
        storage = MemoryStorageBackend()
        vault = EvidenceVault(storage=storage)
        data = b"Original pristine evidence content"
        meta = vault.ingest_bytes(data=data, filename="evidence.bin", acquired_by="alice")

        # Deliberately tamper with the backend storage
        storage_key = f"{meta.evidence_id}_evidence.bin"
        storage.store(storage_key, b"MODIFIED / CORRUPTED CONTENT BY ATTACKER")

        # Attempting to access evidence must raise EvidenceTamperedError
        with pytest.raises(EvidenceTamperedError) as exc_info:
            vault.get_evidence_bytes(meta.evidence_id, actor="analyst_david", purpose="investigation")

        assert exc_info.value.evidence_id == meta.evidence_id
        assert exc_info.value.expected_hash == meta.sha256
        assert exc_info.value.actual_hash != meta.sha256

        # Check metadata flagged as tampered
        updated_meta = vault.get_metadata(meta.evidence_id)
        assert updated_meta.is_tampered is True

        # Check custody log recorded mismatch
        custody = vault.get_chain_of_custody(meta.evidence_id)
        assert len(custody) == 2
        mismatch_entry = custody[1]
        assert mismatch_entry.status == CustodyStatus.MISMATCH
        assert mismatch_entry.actor == "analyst_david"
        assert "CRITICAL" in mismatch_entry.notes

    def test_immutability_isolated_copy(self):
        """Verify mutating returned bytes or local export copy never alters stored evidence."""
        vault = EvidenceVault()
        orig_data = bytearray(b"Immutable record")
        meta = vault.ingest_bytes(bytes(orig_data), filename="record.dat", acquired_by="alice")

        retrieved = bytearray(vault.get_evidence_bytes(meta.evidence_id, actor="alice"))
        retrieved[0] = ord("X")  # Mutate retrieved array

        # Stored evidence must remain pristine and verified
        re_retrieved = vault.get_evidence_bytes(meta.evidence_id, actor="verifier")
        assert re_retrieved == b"Immutable record"

    def test_export_evidence_copy(self):
        """Verify export_evidence_copy writes out a copy and records EXPORT action."""
        vault = EvidenceVault()
        meta = vault.ingest_bytes(b"Exportable file", filename="export.txt", acquired_by="alice")

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "sub" / "exported_evidence.txt"
            exported_path = vault.export_evidence_copy(
                meta.evidence_id,
                destination_path=out_file,
                actor="analyst_bob",
                purpose="court_exhibit",
            )

            assert exported_path.is_file()
            assert exported_path.read_bytes() == b"Exportable file"

            custody = vault.get_chain_of_custody(meta.evidence_id)
            assert any(entry.action == CustodyAction.EXPORT and entry.actor == "analyst_bob" for entry in custody)

    def test_local_storage_backend(self):
        """Verify LocalStorageBackend properly persists and reads files within directory bounds."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            storage = LocalStorageBackend(base_dir=tmp_dir)
            vault = EvidenceVault(storage=storage)

            meta = vault.ingest_bytes(
                data=b"Disk persisted evidence",
                filename="disk.dat",
                acquired_by="alice",
            )
            assert storage.exists(f"{meta.evidence_id}_disk.dat")

            content = vault.get_evidence_bytes(meta.evidence_id, actor="alice")
            assert content == b"Disk persisted evidence"

    def test_scheduled_integrity_verification_job(self):
        """Verify batch verification of all evidence items."""
        storage = MemoryStorageBackend()
        vault = EvidenceVault(storage=storage)

        m1 = vault.ingest_bytes(b"File 1 intact", filename="f1.txt", acquired_by="alice")
        m2 = vault.ingest_bytes(b"File 2 intact", filename="f2.txt", acquired_by="alice")

        # Initial sweep: all intact
        result = vault.verify_all_evidence(actor="nightly_cron")
        assert result["total_items"] == 2
        assert result["verified_count"] == 2
        assert result["tampered_count"] == 0
        assert result["all_intact"] is True

        # Deliberately tamper with File 2
        storage.store(f"{m2.evidence_id}_f2.txt", b"TAMPERED FILE 2")

        # Second sweep: detects File 2 tampered
        result2 = vault.verify_all_evidence(actor="nightly_cron")
        assert result2["verified_count"] == 1
        assert result2["tampered_count"] == 1
        assert m2.evidence_id in result2["tampered_ids"]
        assert result2["all_intact"] is False

    def test_event_bus_publishing_on_intake(self):
        """Verify SecurityEvent is published upon evidence intake with correct schema."""
        published_events: list[SecurityEvent] = []

        vault = EvidenceVault(event_publisher=lambda ev: published_events.append(ev))
        vault.ingest_bytes(
            data=b"Payload for event bus test",
            filename="artifact.bin",
            acquired_by="collector_agent",
            source_host="workstation-42",
            case_id="CASE-55",
        )

        assert len(published_events) == 1
        event = published_events[0]
        assert event.source == "forensics"
        assert event.event_type == "evidence_intake"
        assert event.severity == "low"
        assert event.entity.host == "workstation-42"
        assert event.entity.hash is not None
        assert event.raw["filename"] == "artifact.bin"
        assert event.raw["case_id"] == "CASE-55"

    def test_export_custody_report_markdown(self):
        """Verify format of generated chain of custody markdown report."""
        vault = EvidenceVault()
        meta = vault.ingest_bytes(
            data=b"Custody report test evidence",
            filename="forensic_report.log",
            acquired_by="lead_investigator",
            case_id="CASE-ALPHA",
        )
        vault.get_evidence_bytes(meta.evidence_id, actor="senior_analyst", purpose="correlation")

        report = vault.export_custody_report(meta.evidence_id)
        assert "# FORENSIC EVIDENCE CHAIN OF CUSTODY REPORT" in report
        assert meta.evidence_id in report
        assert "CASE-ALPHA" in report
        assert "lead_investigator" in report
        assert "senior_analyst" in report
        assert "VERIFIED INTACT" in report
        assert "| Timestamp (UTC) | Actor | Action | Expected SHA-256 |" in report
