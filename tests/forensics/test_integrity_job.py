"""
Unit tests for Digital Forensics Evidence Integrity Re-Verification Job Subsystem.

Verifies:
1. Empty vault sweep behavior.
2. Complete sweep across intact evidence artifacts (100% verified).
3. Immediate detection and flagging of deliberately corrupted/tampered bytes.
4. Chain of custody log updates with VERIFY and MISMATCH records.
5. Critical SecurityEvent generation and dispatch to MMS event pipeline.
6. Custom alert callback invocation on integrity violation.
7. Detection and alerting on missing backend storage files.
8. Scoped verification sweeps filtered by case_id.
9. On-demand single evidence verification.
10. Defensible forensic audit certificate generation in Markdown and dictionary export.
11. Background daemon thread execution and graceful termination.
12. Historical audit reports retention and retrieval.
"""

import time
from pathlib import Path
from typing import List

import pytest

from src.forensics.evidence_vault import EvidenceVault, MemoryStorageBackend
from src.forensics.integrity_job import IntegrityVerifierJob
from src.forensics.models import (
    CustodyAction,
    CustodyStatus,
    EvidenceIntegrityDetail,
    EvidenceIntegrityStatus,
)
from src.shared.event_schema import SecurityEvent


class TestIntegrityVerifierJob:
    """Test suite for forensic evidence integrity re-verification engine."""

    def test_empty_vault_sweep(self):
        """Verify sweep on an empty vault completes safely with zero count."""
        vault = EvidenceVault()
        job = IntegrityVerifierJob(vault=vault)

        report = job.run_sweep(actor="test_verifier")

        assert report.total_checked == 0
        assert report.verified_count == 0
        assert report.tampered_count == 0
        assert report.missing_count == 0
        assert report.error_count == 0
        assert report.all_intact is True
        assert "No evidence artifacts" in report.summary
        assert report.completed_at is not None
        assert report.duration_seconds >= 0.0

    def test_all_evidence_intact_sweep(self):
        """Verify sweep where all artifacts are cryptographically pristine."""
        vault = EvidenceVault()
        job = IntegrityVerifierJob(vault=vault)

        m1 = vault.ingest_bytes(b"Clean log evidence data 1", filename="syslog_1.log", acquired_by="alice", case_id="CASE-A")
        m2 = vault.ingest_bytes(b"Clean binary artifact data 2", filename="payload.bin", acquired_by="bob", case_id="CASE-A")
        m3 = vault.ingest_bytes(b"Clean browser history data 3", filename="History", acquired_by="carol", case_id="CASE-B")

        report = job.run_sweep(actor="nightly_audit")

        assert report.total_checked == 3
        assert report.verified_count == 3
        assert report.tampered_count == 0
        assert report.all_intact is True
        assert len(report.tampered_evidence_ids) == 0
        assert "cryptographically verified intact" in report.summary

        # Confirm custody histories received VERIFIED entries
        for meta in [m1, m2, m3]:
            assert not meta.is_tampered
            last_entry = meta.custody_history[-1]
            assert last_entry.action == CustodyAction.VERIFY
            assert last_entry.actor == "nightly_audit"
            assert last_entry.status == CustodyStatus.VERIFIED
            assert last_entry.actual_hash == meta.sha256

    def test_detect_deliberate_tampering_hash_mismatch(self):
        """Verify sweep catches deliberately corrupted storage bytes and flags metadata."""
        storage = MemoryStorageBackend()
        vault = EvidenceVault(storage=storage)
        job = IntegrityVerifierJob(vault=vault)

        m1 = vault.ingest_bytes(b"Pristine authentic file 1", filename="intact.txt", acquired_by="alice")
        m2 = vault.ingest_bytes(b"Target for tampering file 2", filename="tamper_me.dat", acquired_by="bob")

        # Deliberately mutate bytes directly in storage backend (simulating disk bit rot or malicious modification)
        storage_key = f"{m2.evidence_id}_{Path(m2.filename).name}"
        storage.store(storage_key, b"CORRUPTED OR MALICIOUSLY ALTERED BYTES!")

        report = job.run_sweep(actor="security_sentinel")

        assert report.total_checked == 2
        assert report.verified_count == 1
        assert report.tampered_count == 1
        assert report.all_intact is False
        assert m2.evidence_id in report.tampered_evidence_ids
        assert "CRITICAL WARNING: Integrity violations discovered" in report.summary

        # Check file 2 metadata was flagged
        assert m2.is_tampered is True
        tamper_custody = m2.custody_history[-1]
        assert tamper_custody.action == CustodyAction.VERIFY
        assert tamper_custody.status == CustodyStatus.MISMATCH
        assert tamper_custody.actual_hash != m2.sha256
        assert "CRITICAL" in tamper_custody.notes

        # File 1 remains intact
        assert m1.is_tampered is False

    def test_tamper_security_event_publishing(self):
        """Verify critical SecurityEvent is dispatched to MMS pipeline on tamper detection."""
        published_events: List[SecurityEvent] = []

        def mock_publisher(event: SecurityEvent) -> None:
            published_events.append(event)

        storage = MemoryStorageBackend()
        vault = EvidenceVault(storage=storage)
        job = IntegrityVerifierJob(vault=vault, event_publisher=mock_publisher)

        m = vault.ingest_bytes(b"Critical evidence record", filename="evidence.raw", acquired_by="alice", case_id="CASE-999")

        # Clear intake event
        published_events.clear()

        # Tamper backend storage
        storage_key = f"{m.evidence_id}_{Path(m.filename).name}"
        storage.store(storage_key, b"HACKED EVIDENCE")

        report = job.run_sweep(actor="mms_cron")

        assert report.tampered_count == 1
        assert len(published_events) == 1

        sec_event = published_events[0]
        assert sec_event.source == "forensics"
        assert sec_event.event_type == "evidence_tampering_detected"
        assert sec_event.severity == "critical"
        assert sec_event.raw["evidence_id"] == m.evidence_id
        assert sec_event.raw["filename"] == "evidence.raw"
        assert sec_event.raw["status"] == "mismatch"
        assert sec_event.enrichment["tamper_detected"] is True
        assert sec_event.enrichment["mitre_technique"] == "T1565"

    def test_alert_callback_invocation(self):
        """Verify custom alert callback receives detail on tampering."""
        alerts: List[EvidenceIntegrityDetail] = []

        def mock_alert_cb(detail: EvidenceIntegrityDetail) -> None:
            alerts.append(detail)

        storage = MemoryStorageBackend()
        vault = EvidenceVault(storage=storage)
        job = IntegrityVerifierJob(vault=vault, alert_callback=mock_alert_cb)

        m = vault.ingest_bytes(b"Legal exhibit file", filename="exhibit_a.pdf", acquired_by="detective_smith")

        # Tamper
        storage_key = f"{m.evidence_id}_{Path(m.filename).name}"
        storage.store(storage_key, b"TAMPERED PDF STREAM")

        job.run_sweep()

        assert len(alerts) == 1
        assert alerts[0].evidence_id == m.evidence_id
        assert alerts[0].status == EvidenceIntegrityStatus.MISMATCH
        assert alerts[0].is_tampered is True

    def test_detect_missing_storage_file(self):
        """Verify sweep flags missing storage backend files and dispatches missing event."""
        published_events: List[SecurityEvent] = []
        storage = MemoryStorageBackend()
        vault = EvidenceVault(storage=storage)
        job = IntegrityVerifierJob(vault=vault, event_publisher=lambda e: published_events.append(e))

        m = vault.ingest_bytes(b"Target file for deletion", filename="deleted_from_disk.bin", acquired_by="alice")
        published_events.clear()

        # Delete backend file
        storage_key = f"{m.evidence_id}_{Path(m.filename).name}"
        storage.delete(storage_key)

        report = job.run_sweep()

        assert report.missing_count == 1
        assert report.all_intact is False
        assert m.is_tampered is True

        detail = report.details[0]
        assert detail.status == EvidenceIntegrityStatus.MISSING
        assert detail.actual_sha256 is None

        # Check custody entry
        last_custody = m.custody_history[-1]
        assert last_custody.status == CustodyStatus.MISMATCH
        assert last_custody.actual_hash == "MISSING"

        # Check published event
        assert len(published_events) == 1
        assert published_events[0].event_type == "evidence_missing_detected"
        assert published_events[0].severity == "critical"

    def test_case_filtered_sweep(self):
        """Verify sweeping a specific case only inspects evidence belonging to that case."""
        vault = EvidenceVault()
        job = IntegrityVerifierJob(vault=vault)

        vault.ingest_bytes(b"Data 1", filename="file1.txt", acquired_by="alice", case_id="CASE-ALPHA")
        vault.ingest_bytes(b"Data 2", filename="file2.txt", acquired_by="bob", case_id="CASE-ALPHA")
        vault.ingest_bytes(b"Data 3", filename="file3.txt", acquired_by="carol", case_id="CASE-BETA")

        report = job.run_sweep(case_id="CASE-ALPHA", actor="case_auditor")

        assert report.sweep_type == "case"
        assert report.case_id == "CASE-ALPHA"
        assert report.total_checked == 2
        assert report.verified_count == 2
        assert all(d.case_id == "CASE-ALPHA" for d in report.details)

    def test_verify_single_evidence(self):
        """Verify on-demand verification of a single evidence artifact."""
        vault = EvidenceVault()
        job = IntegrityVerifierJob(vault=vault)

        m = vault.ingest_bytes(b"Single test artifact", filename="single.dat", acquired_by="analyst")

        detail = job.verify_single(m.evidence_id, actor="single_verifier")

        assert detail.evidence_id == m.evidence_id
        assert detail.status == EvidenceIntegrityStatus.VERIFIED
        assert detail.actual_sha256 == m.sha256
        assert detail.actual_md5 == m.md5

        last_report = job.get_last_report()
        assert last_report is not None
        assert last_report.sweep_type == "single"
        assert last_report.total_checked == 1

    def test_report_serialization_and_markdown(self):
        """Verify serialization to dictionary and Markdown certificate formatting."""
        storage = MemoryStorageBackend()
        vault = EvidenceVault(storage=storage)
        job = IntegrityVerifierJob(vault=vault)

        m1 = vault.ingest_bytes(b"Valid evidence", filename="valid.doc", acquired_by="alice", case_id="CASE-101")
        m2 = vault.ingest_bytes(b"Tampered evidence", filename="corrupted.log", acquired_by="bob", case_id="CASE-101")

        # Corrupt file 2
        storage.store(f"{m2.evidence_id}_{Path(m2.filename).name}", b"BIT_FLIPPED")

        report = job.run_sweep(case_id="CASE-101", actor="lead_investigator")

        # Dict export
        data = report.to_dict()
        assert data["job_id"] == report.job_id
        assert data["total_checked"] == 2
        assert data["verified_count"] == 1
        assert data["tampered_count"] == 1
        assert len(data["details"]) == 2
        assert isinstance(data["started_at"], str)

        # Markdown Certificate
        md = report.to_markdown()
        assert "# FORENSIC INTEGRITY RE-VERIFICATION AUDIT CERTIFICATE" in md
        assert "⚠️ CRITICAL: EVIDENCE INTEGRITY FAILURE / TAMPERING DETECTED" in md
        assert "lead_investigator" in md
        assert "(Case: `CASE-101`)" in md
        assert "valid.doc" in md
        assert "corrupted.log" in md
        assert "❌ **MISMATCH**" in md
        assert f"⚠️ `{m2.evidence_id}`" in md

    def test_background_daemon_lifecycle(self):
        """Verify background daemon starts, runs periodic sweeps, and stops cleanly."""
        vault = EvidenceVault()
        job = IntegrityVerifierJob(vault=vault)

        vault.ingest_bytes(b"Daemon test file", filename="daemon.txt", acquired_by="alice")

        # Start with very short interval (0.05 seconds) for quick test
        thread = job.start_background_job(interval_seconds=0.05, actor="daemon_test")
        assert thread.is_alive()

        # Let daemon run a couple iterations
        time.sleep(0.18)

        # Stop daemon
        job.stop_background_job(timeout=2.0)
        assert not thread.is_alive()

        history = job.get_job_history()
        assert len(history) >= 1
        assert all(r.verified_count == 1 for r in history)

    def test_job_history_and_clear(self):
        """Verify bounded history retention and clearing."""
        vault = EvidenceVault()
        job = IntegrityVerifierJob(vault=vault, max_history=3)

        vault.ingest_bytes(b"History item", filename="history.txt", acquired_by="alice")

        for _ in range(5):
            job.run_sweep()

        history = job.get_job_history()
        assert len(history) == 3  # Capped at max_history

        job.clear_history()
        assert len(job.get_job_history()) == 0
        assert job.get_last_report() is None
