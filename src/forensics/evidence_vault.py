"""
Evidence Vault and Chain-of-Custody Management Subsystem.

Implements ARCHITECTURE.md §4.5, §8 and .agents/skills/forensics/SKILL.md:
- Immediate SHA-256 and MD5 hashing on intake.
- Tamper-evident verification on every subsequent access.
- Pluggable storage backend (MinIO / Local filesystem / In-Memory).
- Chain-of-custody logging with actor provenance.
- Immutable copy dispatch to prevent in-place evidence modification.
- Event bus publishing for SOC / Copilot cross-modal integration.
"""

from __future__ import annotations

import hashlib
import io
import mimetypes
import os
import shutil
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from src.forensics.models import (
    ChainOfCustodyEntry,
    CustodyAction,
    CustodyStatus,
    EvidenceMetadata,
    EvidenceTamperedError,
    EvidenceType,
)
from src.shared.event_schema import Entity, SecurityEvent


# ---------------------------------------------------------------------------
# Storage Backend Interface & Implementations
# ---------------------------------------------------------------------------

class StorageBackend(ABC):
    """Abstract storage backend for immutable forensic evidence storage."""

    @abstractmethod
    def store(self, key: str, data: bytes) -> str:
        """Store bytes under a key, returning the storage path/URI."""
        ...

    @abstractmethod
    def retrieve(self, key: str) -> bytes:
        """Retrieve stored bytes for a key."""
        ...

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if a key exists in storage."""
        ...

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete evidence (restricted administrative operation)."""
        ...


class MemoryStorageBackend(StorageBackend):
    """In-memory storage backend for fast, isolated testing and ephemeral vaults."""

    def __init__(self) -> None:
        self._storage: Dict[str, bytes] = {}

    def store(self, key: str, data: bytes) -> str:
        self._storage[key] = bytes(data)  # Store an immutable copy
        return f"memory://{key}"

    def retrieve(self, key: str) -> bytes:
        if key not in self._storage:
            raise KeyError(f"Evidence key '{key}' not found in memory store.")
        return bytes(self._storage[key])  # Return an immutable copy

    def exists(self, key: str) -> bool:
        return key in self._storage

    def delete(self, key: str) -> bool:
        if key in self._storage:
            del self._storage[key]
            return True
        return False


class LocalStorageBackend(StorageBackend):
    """Filesystem-based evidence vault storage with isolated directory containment."""

    def __init__(self, base_dir: Union[str, Path]) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_path(self, key: str) -> Path:
        # Sanitize key to prevent path traversal
        clean_key = Path(key).name
        return self.base_dir / clean_key

    def store(self, key: str, data: bytes) -> str:
        target = self._resolve_path(key)
        target.write_bytes(data)
        return str(target)

    def retrieve(self, key: str) -> bytes:
        target = self._resolve_path(key)
        if not target.exists():
            raise FileNotFoundError(f"Evidence file '{target}' not found.")
        return target.read_bytes()

    def exists(self, key: str) -> bool:
        return self._resolve_path(key).exists()

    def delete(self, key: str) -> bool:
        target = self._resolve_path(key)
        if target.exists():
            target.unlink()
            return True
        return False


class MinIOStorageBackend(StorageBackend):
    """MinIO / S3 object storage backend for production forensic evidence."""

    def __init__(self, client: Any, bucket_name: str = "mms-evidence") -> None:
        self.client = client
        self.bucket_name = bucket_name
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
        except Exception:
            pass

    def store(self, key: str, data: bytes) -> str:
        data_stream = io.BytesIO(data)
        self.client.put_object(
            bucket_name=self.bucket_name,
            object_name=key,
            data=data_stream,
            length=len(data),
        )
        return f"minio://{self.bucket_name}/{key}"

    def retrieve(self, key: str) -> bytes:
        response = self.client.get_object(self.bucket_name, key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def exists(self, key: str) -> bool:
        try:
            self.client.stat_object(self.bucket_name, key)
            return True
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        try:
            self.client.remove_object(self.bucket_name, key)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Hashing & File Type Inference Utilities
# ---------------------------------------------------------------------------

def calculate_hashes(data: Union[bytes, io.IOBase, Path, str]) -> Tuple[str, str, int]:
    """Calculate SHA-256 and MD5 hashes in streaming chunks.
    
    Returns:
        Tuple of (sha256_hex, md5_hex, total_bytes)
    """
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    total_bytes = 0
    chunk_size = 65536  # 64 KB

    if isinstance(data, bytes):
        sha256_hash.update(data)
        md5_hash.update(data)
        total_bytes = len(data)
    elif isinstance(data, (Path, str)):
        path = Path(data)
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
                total_bytes += len(chunk)
    elif hasattr(data, "read"):
        while chunk := data.read(chunk_size):
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            sha256_hash.update(chunk)
            md5_hash.update(chunk)
            total_bytes += len(chunk)
    else:
        raise TypeError(f"Unsupported data type for hashing: {type(data)}")

    return sha256_hash.hexdigest(), md5_hash.hexdigest(), total_bytes


def infer_evidence_type(filename: str, sample_bytes: Optional[bytes] = None) -> Tuple[EvidenceType, str]:
    """Infer evidence type and MIME type from filename extension and magic bytes."""
    lower_name = filename.lower()
    guessed_mime, _ = mimetypes.guess_type(filename)
    mime = guessed_mime or "application/octet-stream"

    # Browser Artifacts (SQLite databases, session data, JSON history)
    if any(lower_name.endswith(ext) for ext in [".sqlite", ".sqlite3", ".db"]) or any(
        term in lower_name for term in ["history", "cookies", "places.sqlite", "web data", "login data"]
    ):
        return EvidenceType.BROWSER_ARTIFACT, mime

    # USB / Peripheral Activity
    if any(term in lower_name for term in ["setupapi.dev.log", "setupapi", "usbstor", "usb_activity"]):
        return EvidenceType.USB_LOG, "text/plain"

    # Logs
    if any(lower_name.endswith(ext) for ext in [".log", ".evtx", ".syslog"]) or "auth.log" in lower_name:
        return EvidenceType.LOG, mime or "text/plain"

    # Network PCAPs
    if any(lower_name.endswith(ext) for ext in [".pcap", ".pcapng", ".cap"]):
        return EvidenceType.NETWORK_PCAP, "application/vnd.tcpdump.pcap"

    # Email artifacts
    if any(lower_name.endswith(ext) for ext in [".eml", ".msg", ".mbox"]):
        return EvidenceType.EMAIL, "message/rfc822"

    # Compressed Archives
    if any(lower_name.endswith(ext) for ext in [".zip", ".tar", ".gz", ".bz2", ".7z", ".xz"]):
        return EvidenceType.ARCHIVE, mime

    return EvidenceType.FILE, mime


# ---------------------------------------------------------------------------
# Evidence Vault Implementation
# ---------------------------------------------------------------------------

class EvidenceVault:
    """Secure forensic evidence vault with automated integrity tracking.
    
    Guarantees:
    1. Cryptographic hashing (SHA-256, MD5) immediately upon intake.
    2. Automated chain-of-custody logging for all actions.
    3. Mandatory re-verification on every read access — halts on mismatch.
    4. Safe copy export: original evidence is never mutated or returned directly.
    5. Event bus integration with MMS pipeline.
    """

    def __init__(
        self,
        storage: Optional[StorageBackend] = None,
        event_publisher: Optional[Callable[[SecurityEvent], None]] = None,
    ) -> None:
        self.storage: StorageBackend = storage or MemoryStorageBackend()
        self.event_publisher = event_publisher
        self._metadata_registry: Dict[str, EvidenceMetadata] = {}

    def ingest_bytes(
        self,
        data: bytes,
        filename: str,
        acquired_by: str,
        case_id: Optional[str] = None,
        source_host: Optional[str] = None,
        source_device: Optional[str] = None,
        evidence_type: Optional[EvidenceType] = None,
        notes: Optional[str] = None,
    ) -> EvidenceMetadata:
        """Ingest raw evidence bytes into the vault.
        
        Calculates SHA-256 immediately before any analysis, stores immutable copy,
        and initializes the chain-of-custody record.
        """
        evidence_id = str(uuid.uuid4())
        sha256, md5, size = calculate_hashes(data)

        inferred_type, mime = infer_evidence_type(filename, data[:1024])
        final_type = evidence_type or inferred_type

        storage_key = f"{evidence_id}_{Path(filename).name}"
        storage_path = self.storage.store(storage_key, data)

        intake_entry = ChainOfCustodyEntry(
            evidence_id=evidence_id,
            actor=acquired_by,
            action=CustodyAction.INTAKE,
            expected_hash=sha256,
            actual_hash=sha256,
            status=CustodyStatus.INTAKE,
            notes=notes or f"Evidence intake of '{filename}' ({size} bytes).",
        )

        metadata = EvidenceMetadata(
            evidence_id=evidence_id,
            case_id=case_id,
            filename=filename,
            file_size_bytes=size,
            sha256=sha256,
            md5=md5,
            mime_type=mime,
            evidence_type=final_type,
            acquired_by=acquired_by,
            source_host=source_host,
            source_device=source_device,
            storage_path=storage_path,
            custody_history=[intake_entry],
        )

        self._metadata_registry[evidence_id] = metadata

        # Publish evidence intake event to MMS pipeline
        self._publish_intake_event(metadata)

        return metadata

    def ingest_file(
        self,
        file_path: Union[str, Path],
        acquired_by: str,
        filename: Optional[str] = None,
        case_id: Optional[str] = None,
        source_host: Optional[str] = None,
        source_device: Optional[str] = None,
        evidence_type: Optional[EvidenceType] = None,
        notes: Optional[str] = None,
    ) -> EvidenceMetadata:
        """Ingest a physical file from the local filesystem into the vault."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Source evidence file '{path}' does not exist.")

        data = path.read_bytes()
        actual_name = filename or path.name

        return self.ingest_bytes(
            data=data,
            filename=actual_name,
            acquired_by=acquired_by,
            case_id=case_id,
            source_host=source_host,
            source_device=source_device,
            evidence_type=evidence_type,
            notes=notes or f"Ingested from filesystem path: {path}",
        )

    def get_metadata(self, evidence_id: str) -> EvidenceMetadata:
        """Retrieve evidence metadata record."""
        if evidence_id not in self._metadata_registry:
            raise KeyError(f"Evidence ID '{evidence_id}' not found in registry.")
        return self._metadata_registry[evidence_id]

    def list_evidence(self, case_id: Optional[str] = None) -> List[EvidenceMetadata]:
        """List all evidence in vault, optionally filtered by case_id."""
        if case_id:
            return [m for m in self._metadata_registry.values() if m.case_id == case_id]
        return list(self._metadata_registry.values())

    def get_evidence_bytes(
        self,
        evidence_id: str,
        actor: str,
        purpose: str = "analysis",
        verify_hash: bool = True,
    ) -> bytes:
        """Safely retrieve evidence bytes.
        
        Mandatory re-verification: recalculates SHA-256 against intake hash.
        If hash mismatch occurs: logs mismatch, flags metadata as tampered,
        and halts execution by raising EvidenceTamperedError.
        """
        metadata = self.get_metadata(evidence_id)
        storage_key = f"{evidence_id}_{Path(metadata.filename).name}"
        data = self.storage.retrieve(storage_key)

        if verify_hash:
            actual_sha256, _, _ = calculate_hashes(data)
            if actual_sha256 != metadata.sha256:
                # Log mismatch and flag as tampered
                mismatch_entry = ChainOfCustodyEntry(
                    evidence_id=evidence_id,
                    actor=actor,
                    action=CustodyAction.ACCESS,
                    expected_hash=metadata.sha256,
                    actual_hash=actual_sha256,
                    status=CustodyStatus.MISMATCH,
                    notes=f"CRITICAL: Hash mismatch during access for '{purpose}'! Evidence integrity compromised.",
                )
                metadata.custody_history.append(mismatch_entry)
                metadata.is_tampered = True
                raise EvidenceTamperedError(evidence_id, metadata.sha256, actual_sha256)

            # Verification passed
            access_entry = ChainOfCustodyEntry(
                evidence_id=evidence_id,
                actor=actor,
                action=CustodyAction.ACCESS,
                expected_hash=metadata.sha256,
                actual_hash=actual_sha256,
                status=CustodyStatus.VERIFIED,
                notes=f"Access verified for purpose: '{purpose}'.",
            )
            metadata.custody_history.append(access_entry)

        return bytes(data)  # Return an isolated copy

    def export_evidence_copy(
        self,
        evidence_id: str,
        destination_path: Union[str, Path],
        actor: str,
        purpose: str = "export",
    ) -> Path:
        """Export a verified copy of evidence to a local path without touching original."""
        data = self.get_evidence_bytes(evidence_id=evidence_id, actor=actor, purpose=purpose)
        dest = Path(destination_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)

        metadata = self.get_metadata(evidence_id)
        export_entry = ChainOfCustodyEntry(
            evidence_id=evidence_id,
            actor=actor,
            action=CustodyAction.EXPORT,
            expected_hash=metadata.sha256,
            actual_hash=metadata.sha256,
            status=CustodyStatus.VERIFIED,
            notes=f"Exported copy to destination: {dest} for purpose '{purpose}'.",
        )
        metadata.custody_history.append(export_entry)
        return dest

    def verify_integrity(self, evidence_id: str, actor: str = "integrity_monitor") -> bool:
        """Perform explicit integrity verification on an evidence item."""
        metadata = self.get_metadata(evidence_id)
        storage_key = f"{evidence_id}_{Path(metadata.filename).name}"
        data = self.storage.retrieve(storage_key)
        actual_sha256, _, _ = calculate_hashes(data)

        if actual_sha256 == metadata.sha256:
            entry = ChainOfCustodyEntry(
                evidence_id=evidence_id,
                actor=actor,
                action=CustodyAction.VERIFY,
                expected_hash=metadata.sha256,
                actual_hash=actual_sha256,
                status=CustodyStatus.VERIFIED,
                notes="Integrity verified successfully.",
            )
            metadata.custody_history.append(entry)
            metadata.is_tampered = False
            return True
        else:
            entry = ChainOfCustodyEntry(
                evidence_id=evidence_id,
                actor=actor,
                action=CustodyAction.VERIFY,
                expected_hash=metadata.sha256,
                actual_hash=actual_sha256,
                status=CustodyStatus.MISMATCH,
                notes="CRITICAL: Hash mismatch detected during scheduled integrity verification.",
            )
            metadata.custody_history.append(entry)
            metadata.is_tampered = True
            return False

    def verify_all_evidence(self, actor: str = "scheduled_verifier") -> Dict[str, Any]:
        """Verify integrity of all evidence in the vault."""
        total = len(self._metadata_registry)
        verified = 0
        tampered: List[str] = []

        for evidence_id in list(self._metadata_registry.keys()):
            if self.verify_integrity(evidence_id, actor=actor):
                verified += 1
            else:
                tampered.append(evidence_id)

        return {
            "total_items": total,
            "verified_count": verified,
            "tampered_count": len(tampered),
            "tampered_ids": tampered,
            "all_intact": len(tampered) == 0,
        }

    def get_chain_of_custody(self, evidence_id: str) -> List[ChainOfCustodyEntry]:
        """Return chronological chain of custody for an evidence item."""
        metadata = self.get_metadata(evidence_id)
        return list(metadata.custody_history)

    def export_custody_report(self, evidence_id: str) -> str:
        """Generate a defensible forensic Chain of Custody Markdown report."""
        metadata = self.get_metadata(evidence_id)
        status_banner = "⚠️ TAMPERED / INTEGRITY FAILURE" if metadata.is_tampered else "✅ VERIFIED INTACT"

        lines = [
            "# FORENSIC EVIDENCE CHAIN OF CUSTODY REPORT",
            f"**Evidence ID:** `{metadata.evidence_id}`",
            f"**Case ID:** `{metadata.case_id or 'Unassigned'}`",
            f"**File Name:** `{metadata.filename}`",
            f"**File Size:** {metadata.file_size_bytes} bytes",
            f"**Evidence Type:** {metadata.evidence_type.value.upper()}",
            f"**MIME Type:** `{metadata.mime_type}`",
            f"**Acquired By:** `{metadata.acquired_by}`",
            f"**Intake Timestamp:** `{metadata.intake_timestamp.isoformat()}`",
            f"**Initial SHA-256:** `{metadata.sha256}`",
            f"**Initial MD5:** `{metadata.md5}`",
            f"**Current Status:** {status_banner}",
            "",
            "## Chronological Custody Audit Log",
            "",
            "| Timestamp (UTC) | Actor | Action | Expected SHA-256 | Actual SHA-256 | Status | Notes |",
            "|---|---|---|---|---|---|---|",
        ]

        for entry in metadata.custody_history:
            exp_short = entry.expected_hash[:10] + "..." if len(entry.expected_hash) > 10 else entry.expected_hash
            act_short = entry.actual_hash[:10] + "..." if len(entry.actual_hash) > 10 else entry.actual_hash
            lines.append(
                f"| {entry.timestamp.isoformat()} | {entry.actor} | {entry.action.value} | "
                f"`{exp_short}` | `{act_short}` | {entry.status.value.upper()} | {entry.notes or ''} |"
            )

        return "\n".join(lines)

    def _publish_intake_event(self, metadata: EvidenceMetadata) -> None:
        """Publish canonical SecurityEvent to MMS pipeline."""
        if not self.event_publisher:
            return

        event = SecurityEvent(
            source="forensics",
            event_type="evidence_intake",
            severity="low",
            entity=Entity(
                host=metadata.source_host,
                hash=metadata.sha256,
            ),
            raw={
                "evidence_id": metadata.evidence_id,
                "case_id": metadata.case_id,
                "filename": metadata.filename,
                "file_size_bytes": metadata.file_size_bytes,
                "sha256": metadata.sha256,
                "md5": metadata.md5,
                "evidence_type": metadata.evidence_type.value,
                "acquired_by": metadata.acquired_by,
                "source_host": metadata.source_host,
                "source_device": metadata.source_device,
            },
            enrichment={
                "chain_of_custody_initialized": True,
                "custody_action": "intake",
            },
        )

        try:
            self.event_publisher(event)
        except Exception:
            # Event publishing failure shouldn't crash evidence ingestion
            pass
