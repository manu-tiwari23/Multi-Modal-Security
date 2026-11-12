"""
Forensic Evidence Integrity Re-Verification Job Subsystem.

Complies with ARCHITECTURE.md §4.5, §8 and REQUIREMENTS.md §1.5:
- Continuous and on-demand re-validation of evidence hashes.
- Tamper detection across all vault artifacts with immediate custody updates.
- Immediate dispatch of critical SecurityEvents to the MMS pipeline upon mismatch.
- Support for on-demand batch sweeps, case-filtered audits, and periodic background daemon execution.
- Production-grade defensible audit reporting in structured dict and Markdown certificate formats.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional, Union

from src.forensics.evidence_vault import EvidenceVault, calculate_hashes
from src.forensics.models import (
    ChainOfCustodyEntry,
    CustodyAction,
    CustodyStatus,
    EvidenceIntegrityDetail,
    EvidenceIntegrityStatus,
    EvidenceMetadata,
    IntegrityJobReport,
)
from src.shared.event_schema import Entity, SecurityEvent

logger = logging.getLogger("mms.forensics.integrity_job")


class IntegrityVerifierJob:
    """Automated forensic evidence integrity re-verification engine.
    
    Inspects all evidence stored in an EvidenceVault, recalculates SHA-256 and MD5
    cryptographic hashes directly from storage backends, verifies provenance,
    updates chain-of-custody ledgers, flags tampered records, and broadcasts
    critical SecurityEvents across the MMS event bus.
    """

    def __init__(
        self,
        vault: EvidenceVault,
        event_publisher: Optional[Callable[[SecurityEvent], None]] = None,
        alert_callback: Optional[Callable[[EvidenceIntegrityDetail], None]] = None,
        max_history: int = 100,
    ) -> None:
        """Initialize the IntegrityVerifierJob.
        
        Args:
            vault: The EvidenceVault instance to monitor.
            event_publisher: Optional callback/publisher to dispatch SecurityEvent models.
            alert_callback: Optional callback invoked immediately when tampering or missing evidence is detected.
            max_history: Maximum number of audit job reports to retain in memory.
        """
        self.vault = vault
        self.event_publisher = event_publisher or vault.event_publisher
        self.alert_callback = alert_callback
        self.max_history = max_history

        self._history: List[IntegrityJobReport] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None

    def verify_item(
        self,
        metadata: EvidenceMetadata,
        actor: str = "integrity_verifier",
    ) -> EvidenceIntegrityDetail:
        """Verify the cryptographic integrity of a single evidence metadata entry.
        
        Recalculates dual hashes directly from storage backend bytes without
        raising exceptions, updates the chain-of-custody log, and triggers alerts
        if discrepancies are identified.
        """
        evidence_id = metadata.evidence_id
        storage_key = f"{evidence_id}_{Path(metadata.filename).name}"
        now = datetime.now(timezone.utc)

        # 1. Retrieve raw storage bytes
        try:
            if not self.vault.storage.exists(storage_key):
                raise FileNotFoundError(f"Evidence key '{storage_key}' not found in storage backend.")
            data = self.vault.storage.retrieve(storage_key)
        except Exception as exc:
            # File missing or storage unreachable
            detail = EvidenceIntegrityDetail(
                evidence_id=evidence_id,
                filename=metadata.filename,
                case_id=metadata.case_id,
                status=EvidenceIntegrityStatus.MISSING,
                expected_sha256=metadata.sha256,
                actual_sha256=None,
                expected_md5=metadata.md5,
                actual_md5=None,
                is_tampered=True,
                checked_at=now,
                notes=f"CRITICAL: Evidence storage file missing or unreadable: {exc}",
            )
            # Log custody mismatch
            custody_entry = ChainOfCustodyEntry(
                evidence_id=evidence_id,
                actor=actor,
                action=CustodyAction.VERIFY,
                expected_hash=metadata.sha256,
                actual_hash="MISSING",
                status=CustodyStatus.MISMATCH,
                notes=f"CRITICAL: Missing evidence artifact during integrity sweep ({exc}).",
            )
            metadata.custody_history.append(custody_entry)
            metadata.is_tampered = True

            self._publish_tamper_event(
                detail=detail,
                event_type="evidence_missing_detected",
                description=f"Evidence artifact '{metadata.filename}' ({evidence_id}) missing from storage backend.",
            )
            if self.alert_callback:
                try:
                    self.alert_callback(detail)
                except Exception as cb_err:
                    logger.error(f"Error in integrity alert callback: {cb_err}")

            return detail

        # 2. Recalculate dual cryptographic hashes
        try:
            actual_sha256, actual_md5, actual_size = calculate_hashes(data)
        except Exception as hash_err:
            detail = EvidenceIntegrityDetail(
                evidence_id=evidence_id,
                filename=metadata.filename,
                case_id=metadata.case_id,
                status=EvidenceIntegrityStatus.ERROR,
                expected_sha256=metadata.sha256,
                actual_sha256=None,
                expected_md5=metadata.md5,
                actual_md5=None,
                is_tampered=True,
                checked_at=now,
                notes=f"Error computing hash: {hash_err}",
            )
            return detail

        # 3. Compare with registered baseline hashes
        if actual_sha256 == metadata.sha256:
            # Verified intact
            detail = EvidenceIntegrityDetail(
                evidence_id=evidence_id,
                filename=metadata.filename,
                case_id=metadata.case_id,
                status=EvidenceIntegrityStatus.VERIFIED,
                expected_sha256=metadata.sha256,
                actual_sha256=actual_sha256,
                expected_md5=metadata.md5,
                actual_md5=actual_md5,
                is_tampered=False,
                checked_at=now,
                notes="Cryptographic hash matches intake baseline.",
            )
            custody_entry = ChainOfCustodyEntry(
                evidence_id=evidence_id,
                actor=actor,
                action=CustodyAction.VERIFY,
                expected_hash=metadata.sha256,
                actual_hash=actual_sha256,
                status=CustodyStatus.VERIFIED,
                notes="Integrity re-verification passed successfully.",
            )
            metadata.custody_history.append(custody_entry)
            metadata.is_tampered = False
            return detail
        else:
            # Hash mismatch — evidence tampered or corrupted!
            detail = EvidenceIntegrityDetail(
                evidence_id=evidence_id,
                filename=metadata.filename,
                case_id=metadata.case_id,
                status=EvidenceIntegrityStatus.MISMATCH,
                expected_sha256=metadata.sha256,
                actual_sha256=actual_sha256,
                expected_md5=metadata.md5,
                actual_md5=actual_md5,
                is_tampered=True,
                checked_at=now,
                notes=f"CRITICAL: Hash mismatch! Expected {metadata.sha256}, got {actual_sha256}.",
            )
            custody_entry = ChainOfCustodyEntry(
                evidence_id=evidence_id,
                actor=actor,
                action=CustodyAction.VERIFY,
                expected_hash=metadata.sha256,
                actual_hash=actual_sha256,
                status=CustodyStatus.MISMATCH,
                notes=f"CRITICAL: Cryptographic hash mismatch during integrity verification! (Expected: {metadata.sha256[:12]}..., Got: {actual_sha256[:12]}...)",
            )
            metadata.custody_history.append(custody_entry)
            metadata.is_tampered = True

            self._publish_tamper_event(
                detail=detail,
                event_type="evidence_tampering_detected",
                description=f"Evidence tampering detected for file '{metadata.filename}' ({evidence_id}). Hash mismatch!",
            )
            if self.alert_callback:
                try:
                    self.alert_callback(detail)
                except Exception as cb_err:
                    logger.error(f"Error in integrity alert callback: {cb_err}")

            return detail

    def run_sweep(
        self,
        case_id: Optional[str] = None,
        actor: str = "integrity_verifier",
    ) -> IntegrityJobReport:
        """Execute a synchronous integrity re-verification sweep.
        
        Args:
            case_id: If specified, only checks evidence associated with this case.
            actor: Audit identity recording the verification action.
            
        Returns:
            IntegrityJobReport containing complete metrics and per-item details.
        """
        start_time = datetime.now(timezone.utc)
        items = self.vault.list_evidence(case_id=case_id)
        sweep_type = "case" if case_id else "full"

        report = IntegrityJobReport(
            actor=actor,
            sweep_type=sweep_type,
            case_id=case_id,
            started_at=start_time,
            total_checked=len(items),
        )

        for item in items:
            detail = self.verify_item(item, actor=actor)
            report.details.append(detail)

            if detail.status == EvidenceIntegrityStatus.VERIFIED:
                report.verified_count += 1
            elif detail.status == EvidenceIntegrityStatus.MISMATCH:
                report.tampered_count += 1
                report.tampered_evidence_ids.append(detail.evidence_id)
            elif detail.status == EvidenceIntegrityStatus.MISSING:
                report.missing_count += 1
                report.tampered_evidence_ids.append(detail.evidence_id)
            else:
                report.error_count += 1

        end_time = datetime.now(timezone.utc)
        report.completed_at = end_time
        report.duration_seconds = max(0.0, (end_time - start_time).total_seconds())
        report.all_intact = (report.tampered_count == 0 and report.missing_count == 0 and report.error_count == 0)

        # Build human-readable summary
        if report.total_checked == 0:
            report.summary = "Vault sweep completed: No evidence artifacts registered to inspect."
        elif report.all_intact:
            report.summary = (
                f"Vault sweep completed successfully: {report.verified_count}/{report.total_checked} "
                f"artifacts cryptographically verified intact in {report.duration_seconds:.3f}s."
            )
        else:
            report.summary = (
                f"CRITICAL WARNING: Integrity violations discovered! Total: {report.total_checked}, "
                f"Verified: {report.verified_count}, Tampered: {report.tampered_count}, "
                f"Missing: {report.missing_count}, Errors: {report.error_count}."
            )

        with self._lock:
            self._history.append(report)
            if len(self._history) > self.max_history:
                self._history.pop(0)

        return report

    def verify_single(
        self,
        evidence_id: str,
        actor: str = "integrity_verifier",
    ) -> EvidenceIntegrityDetail:
        """Verify a single evidence artifact on demand."""
        metadata = self.vault.get_metadata(evidence_id)
        start_time = datetime.now(timezone.utc)
        detail = self.verify_item(metadata, actor=actor)

        # Record as single sweep in history
        report = IntegrityJobReport(
            actor=actor,
            sweep_type="single",
            case_id=metadata.case_id,
            started_at=start_time,
            completed_at=datetime.now(timezone.utc),
            duration_seconds=max(0.0, (datetime.now(timezone.utc) - start_time).total_seconds()),
            total_checked=1,
            verified_count=1 if detail.status == EvidenceIntegrityStatus.VERIFIED else 0,
            tampered_count=1 if detail.status == EvidenceIntegrityStatus.MISMATCH else 0,
            missing_count=1 if detail.status == EvidenceIntegrityStatus.MISSING else 0,
            error_count=1 if detail.status == EvidenceIntegrityStatus.ERROR else 0,
            all_intact=detail.status == EvidenceIntegrityStatus.VERIFIED,
            tampered_evidence_ids=[evidence_id] if detail.is_tampered else [],
            details=[detail],
            summary=f"Single check on '{metadata.filename}': status {detail.status.value.upper()}.",
        )

        with self._lock:
            self._history.append(report)
            if len(self._history) > self.max_history:
                self._history.pop(0)

        return detail

    def start_background_job(
        self,
        interval_seconds: float = 3600.0,
        actor: str = "scheduled_verifier",
    ) -> threading.Thread:
        """Start a background daemon thread that runs periodic integrity sweeps.
        
        Args:
            interval_seconds: Sleep interval between verification runs (default: 1 hour).
            actor: Audit actor recorded in custody entries.
            
        Returns:
            The spawned threading.Thread instance.
        """
        with self._lock:
            if self._bg_thread is not None and self._bg_thread.is_alive():
                logger.warning("Background integrity verifier thread is already running.")
                return self._bg_thread

            self._stop_event.clear()

            def _worker_loop() -> None:
                logger.info(f"Integrity verifier daemon started with interval {interval_seconds}s.")
                while not self._stop_event.is_set():
                    try:
                        self.run_sweep(actor=actor)
                    except Exception as err:
                        logger.error(f"Error during background integrity sweep: {err}")

                    # Sleep in small increments or wait on stop event
                    if self._stop_event.wait(timeout=interval_seconds):
                        break
                logger.info("Integrity verifier daemon terminated gracefully.")

            self._bg_thread = threading.Thread(
                target=_worker_loop,
                name="MMS-IntegrityVerifierDaemon",
                daemon=True,
            )
            self._bg_thread.start()
            return self._bg_thread

    def stop_background_job(self, timeout: float = 5.0) -> None:
        """Signal and join the background verifier daemon thread."""
        with self._lock:
            if self._bg_thread is None or not self._bg_thread.is_alive():
                return
            self._stop_event.set()
            thread = self._bg_thread

        thread.join(timeout=timeout)
        with self._lock:
            self._bg_thread = None

    def get_last_report(self) -> Optional[IntegrityJobReport]:
        """Return the most recently generated audit report, if any."""
        with self._lock:
            if self._history:
                return self._history[-1]
            return None

    def get_job_history(self) -> List[IntegrityJobReport]:
        """Return a copy of all audit job reports currently in memory."""
        with self._lock:
            return list(self._history)

    def clear_history(self) -> None:
        """Clear all historical audit reports in memory."""
        with self._lock:
            self._history.clear()

    def _publish_tamper_event(
        self,
        detail: EvidenceIntegrityDetail,
        event_type: str,
        description: str,
    ) -> None:
        """Broadcast a critical SecurityEvent over the event bus."""
        if not self.event_publisher:
            return

        event = SecurityEvent(
            source="forensics",
            event_type=event_type,
            severity="critical",
            entity=Entity(
                hash=detail.expected_sha256,
                host=detail.case_id or "evidence_vault",
            ),
            raw={
                "evidence_id": detail.evidence_id,
                "filename": detail.filename,
                "case_id": detail.case_id,
                "status": detail.status.value,
                "expected_sha256": detail.expected_sha256,
                "actual_sha256": detail.actual_sha256,
                "expected_md5": detail.expected_md5,
                "actual_md5": detail.actual_md5,
                "checked_at": detail.checked_at.isoformat(),
                "notes": detail.notes,
            },
            enrichment={
                "mitre_technique": "T1565",  # Data Manipulation
                "mitre_tactic": "TA0040",     # Impact / Defense Evasion (T1070)
                "incident_candidate": True,
                "tamper_detected": True,
                "description": description,
            },
        )

        try:
            self.event_publisher(event)
        except Exception as exc:
            logger.error(f"Failed to publish tamper SecurityEvent: {exc}")
