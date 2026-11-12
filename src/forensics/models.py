"""
Digital Forensics Data Models & Chain-of-Custody Schemas.

Complies with ARCHITECTURE.md §4.5, §8 and .agents/skills/forensics/SKILL.md:
- Immediate SHA-256 (and MD5) calculation on intake.
- Tamper-evident verification on access.
- Immutable chain-of-custody logging.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    """Classification of forensic evidence."""
    FILE = "file"
    LOG = "log"
    BROWSER_ARTIFACT = "browser_artifact"
    USB_LOG = "usb_log"
    EMAIL = "email"
    NETWORK_PCAP = "network_pcap"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


class CustodyAction(str, Enum):
    """Actions performed on digital evidence across its lifecycle."""
    INTAKE = "intake"
    ACCESS = "access"
    VERIFY = "verify"
    TRANSFER = "transfer"
    ANALYZE = "analyze"
    EXPORT = "export"


class CustodyStatus(str, Enum):
    """Integrity status during custody operations."""
    INTAKE = "intake"
    VERIFIED = "verified"
    MISMATCH = "mismatch"


class ChainOfCustodyEntry(BaseModel):
    """Tamper-evident record of an action performed on digital evidence.
    
    Every time an evidence file is ingested, accessed, verified, or analyzed,
    a record is appended logging the actor, action, timestamp, and verification hash.
    """
    custody_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str
    action: CustodyAction
    expected_hash: str
    actual_hash: str
    status: CustodyStatus = CustodyStatus.VERIFIED
    notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert entry to a dictionary with ISO-formatted timestamp."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        return data


class EvidenceMetadata(BaseModel):
    """Forensic metadata and provenance record for collected evidence.
    
    Stores all cryptographic hashes, file attributes, intake timestamps,
    and the chronological chain-of-custody log.
    """
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: Optional[str] = None
    filename: str
    file_size_bytes: int
    sha256: str
    md5: str
    mime_type: str = "application/octet-stream"
    evidence_type: EvidenceType = EvidenceType.FILE
    intake_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acquired_by: str
    source_host: Optional[str] = None
    source_device: Optional[str] = None
    storage_path: str
    is_tampered: bool = False
    custody_history: list[ChainOfCustodyEntry] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary with serialized datetimes."""
        data = self.model_dump()
        data["intake_timestamp"] = self.intake_timestamp.isoformat()
        data["custody_history"] = [entry.to_dict() for entry in self.custody_history]
        return data


class EvidenceTamperedError(Exception):
    """Raised when an evidence file fails cryptographic integrity verification."""
    def __init__(self, evidence_id: str, expected_hash: str, actual_hash: str, message: str = ""):
        self.evidence_id = evidence_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        err_msg = message or (
            f"Evidence integrity check failed for evidence ID '{evidence_id}'! "
            f"Expected SHA-256: {expected_hash}, Actual SHA-256: {actual_hash}"
        )
        super().__init__(err_msg)


# ---------------------------------------------------------------------------
# Integrity Re-Verification Job Models
# ---------------------------------------------------------------------------

class EvidenceIntegrityStatus(str, Enum):
    """Integrity status result for an individual evidence item."""
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    MISSING = "missing"
    ERROR = "error"


class EvidenceIntegrityDetail(BaseModel):
    """Detailed audit result for a single evidence item checked during a job."""
    evidence_id: str
    filename: str
    case_id: Optional[str] = None
    status: EvidenceIntegrityStatus
    expected_sha256: str
    actual_sha256: Optional[str] = None
    expected_md5: str
    actual_md5: Optional[str] = None
    is_tampered: bool = False
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize integrity detail with ISO timestamp."""
        data = self.model_dump()
        data["checked_at"] = self.checked_at.isoformat()
        return data


class IntegrityJobReport(BaseModel):
    """Comprehensive report produced by an integrity re-verification sweep."""
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    actor: str = "scheduled_verifier"
    sweep_type: str = "full"  # "full", "case", "single"
    case_id: Optional[str] = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    total_checked: int = 0
    verified_count: int = 0
    tampered_count: int = 0
    missing_count: int = 0
    error_count: int = 0
    all_intact: bool = True
    tampered_evidence_ids: list[str] = Field(default_factory=list)
    details: list[EvidenceIntegrityDetail] = Field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize report with nested detail records."""
        data = self.model_dump()
        data["started_at"] = self.started_at.isoformat()
        data["completed_at"] = self.completed_at.isoformat() if self.completed_at else None
        data["details"] = [d.to_dict() for d in self.details]
        return data

    def to_markdown(self) -> str:
        """Generate a defensible forensic Integrity Verification Certificate in Markdown."""
        banner = "✅ ALL EVIDENCE INTACT & CRYPTOGRAPHICALLY VERIFIED" if self.all_intact else "⚠️ CRITICAL: EVIDENCE INTEGRITY FAILURE / TAMPERING DETECTED"
        lines = [
            "# FORENSIC INTEGRITY RE-VERIFICATION AUDIT CERTIFICATE",
            f"**Job ID:** `{self.job_id}`",
            f"**Status:** **{banner}**",
            f"**Actor / Trigger:** `{self.actor}`",
            f"**Sweep Type:** {self.sweep_type.upper()}" + (f" (Case: `{self.case_id}`)" if self.case_id else ""),
            f"**Started At (UTC):** `{self.started_at.isoformat()}`",
            f"**Completed At (UTC):** `{self.completed_at.isoformat() if self.completed_at else 'In Progress'}`",
            f"**Duration:** {self.duration_seconds:.3f} seconds",
            "",
            "## Summary Metrics",
            f"- **Total Items Checked:** {self.total_checked}",
            f"- **Verified Intact:** {self.verified_count}",
            f"- **Tampered (Hash Mismatch):** {self.tampered_count}",
            f"- **Missing Storage Files:** {self.missing_count}",
            f"- **Processing Errors:** {self.error_count}",
            "",
            "## Evidence Inspection Table",
            "",
            "| Evidence ID | Filename | Case ID | Expected SHA-256 | Actual SHA-256 | Status | Notes |",
            "|---|---|---|---|---|---|---|",
        ]

        for d in self.details:
            exp_short = d.expected_sha256[:10] + "..." if len(d.expected_sha256) > 10 else d.expected_sha256
            act_short = (d.actual_sha256[:10] + "...") if d.actual_sha256 and len(d.actual_sha256) > 10 else (d.actual_sha256 or "N/A")
            status_badge = d.status.value.upper()
            if d.status == EvidenceIntegrityStatus.VERIFIED:
                status_str = f"✅ {status_badge}"
            elif d.status == EvidenceIntegrityStatus.MISMATCH:
                status_str = f"❌ **{status_badge}**"
            elif d.status == EvidenceIntegrityStatus.MISSING:
                status_str = f"🚨 **{status_badge}**"
            else:
                status_str = f"⚠️ {status_badge}"

            lines.append(
                f"| `{d.evidence_id[:8]}...` | `{d.filename}` | `{d.case_id or '-'}` | "
                f"`{exp_short}` | `{act_short}` | {status_str} | {d.notes or ''} |"
            )

        if self.tampered_evidence_ids:
            lines.append("")
            lines.append("## Flagged Compromised Evidence IDs")
            for tid in self.tampered_evidence_ids:
                lines.append(f"- ⚠️ `{tid}`")

        return "\n".join(lines)



# ---------------------------------------------------------------------------
# File Analysis & Deleted File Recovery Models
# ---------------------------------------------------------------------------

class SuspiciousIndicator(BaseModel):
    """Suspicious artifact or heuristic detected during file analysis."""
    category: str  # e.g., "high_entropy", "extension_spoofing", "embedded_ioc", "malicious_string"
    description: str
    severity: str = "medium"  # "low", "medium", "high", "critical"
    evidence_match: str


class CarvedFile(BaseModel):
    """A file carved from raw unallocated space, binary dumps, or corrupted containers."""
    recovered_name: str
    file_type: str
    offset_start: int
    offset_end: int
    size_bytes: int
    sha256: str
    md5: str


class RecycleBinRecord(BaseModel):
    """Metadata extracted from deleted file artifacts (e.g. Windows Recycle Bin $I/$R or Trash)."""
    original_path: str
    recovered_filename: str
    deletion_time: Optional[datetime] = None
    file_size_bytes: int
    source_index_file: Optional[str] = None
    recovered_data_file: Optional[str] = None


class FileAnalysisResult(BaseModel):
    """Comprehensive result of forensic file-level analysis and deleted file recovery."""
    filename: str
    file_size_bytes: int
    sha256: str
    md5: str
    shannon_entropy: float
    is_high_entropy: bool
    detected_type: str
    declared_extension: str
    is_extension_spoofed: bool
    extracted_iocs: dict[str, list[str]] = Field(default_factory=dict)
    suspicious_indicators: list[SuspiciousIndicator] = Field(default_factory=list)
    carved_files: list[CarvedFile] = Field(default_factory=list)
    recovered_deleted_files: list[RecycleBinRecord] = Field(default_factory=list)
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """Convert analysis result to dictionary with serialized nested models."""
        return self.model_dump()


# ---------------------------------------------------------------------------
# Metadata Extraction Models
# ---------------------------------------------------------------------------

class DocumentMetadata(BaseModel):
    """Metadata extracted from Office (OOXML/OLE) or PDF documents."""
    title: Optional[str] = None
    author: Optional[str] = None
    last_modified_by: Optional[str] = None
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    application: Optional[str] = None
    app_version: Optional[str] = None
    revision: Optional[str] = None
    language: Optional[str] = None
    page_count: Optional[int] = None
    word_count: Optional[int] = None
    total_edit_time_minutes: Optional[int] = None
    producer: Optional[str] = None
    creator: Optional[str] = None
    has_javascript: bool = False
    has_launch_action: bool = False
    embedded_scripts: list[str] = Field(default_factory=list)


class ImageMetadata(BaseModel):
    """EXIF / IPTC metadata extracted from raster or vector images."""
    make: Optional[str] = None
    model: Optional[str] = None
    software: Optional[str] = None
    date_time_original: Optional[datetime] = None
    date_time_digitized: Optional[datetime] = None
    artist: Optional[str] = None
    copyright: Optional[str] = None
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    gps_altitude: Optional[float] = None
    width_pixels: Optional[int] = None
    height_pixels: Optional[int] = None
    color_space: Optional[str] = None
    user_comment: Optional[str] = None


class ExecutableMetadata(BaseModel):
    """PE / ELF header compilation and version metadata."""
    compile_time: Optional[datetime] = None
    target_machine: Optional[str] = None
    subsystem: Optional[str] = None
    imphash: Optional[str] = None
    company_name: Optional[str] = None
    file_description: Optional[str] = None
    file_version: Optional[str] = None
    product_name: Optional[str] = None
    product_version: Optional[str] = None
    original_filename: Optional[str] = None
    sections: list[dict[str, Any]] = Field(default_factory=list)


class ExtractedMetadata(BaseModel):
    """Forensic metadata envelope for any inspected evidence file."""
    filename: str
    file_format: str
    file_size_bytes: int
    sha256: str
    parser_used: str  # "internal_ooxml", "internal_pdf", "internal_exif", "internal_pe", "exiftool"
    document: Optional[DocumentMetadata] = None
    image: Optional[ImageMetadata] = None
    executable: Optional[ExecutableMetadata] = None
    filesystem_timestamps: dict[str, Optional[datetime]] = Field(default_factory=dict)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    suspicious_artifacts: list[str] = Field(default_factory=list)
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize metadata with ISO formatted datetimes."""
        data = self.model_dump()
        return data


# ---------------------------------------------------------------------------
# Browser Artifacts Models
# ---------------------------------------------------------------------------

class BrowserType(str, Enum):
    """Supported web browsers for forensic artifact parsing."""
    CHROME = "chrome"
    EDGE = "edge"
    FIREFOX = "firefox"
    BRAVE = "brave"
    OPERA = "opera"
    UNKNOWN = "unknown"


class BrowserHistoryEntry(BaseModel):
    """Forensic navigation history record."""
    url: str
    title: Optional[str] = None
    visit_time: datetime
    visit_count: int = 1
    typed_count: int = 0
    browser_type: BrowserType = BrowserType.UNKNOWN


class BrowserDownloadEntry(BaseModel):
    """Forensic browser file download artifact."""
    target_path: str
    source_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_bytes: int = 0
    state: str = "complete"  # "complete", "cancelled", "interrupted"
    danger_type: int = 0
    browser_type: BrowserType = BrowserType.UNKNOWN
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None


class BrowserCookieEntry(BaseModel):
    """Forensic browser cookie artifact."""
    host: str
    name: str
    path: str = "/"
    creation_time: datetime
    expires_time: Optional[datetime] = None
    is_secure: bool = False
    is_httponly: bool = False


class BrowserSearchEntry(BaseModel):
    """Keyword search query entered into browser omnibox or search engine."""
    term: str
    search_time: Optional[datetime] = None
    browser_type: BrowserType = BrowserType.UNKNOWN
    is_suspicious: bool = False
    category: Optional[str] = None


class BrowserAnalysisResult(BaseModel):
    """Consolidated forensic report for a browser profile directory."""
    browser_type: BrowserType
    profile_dir: str
    history_count: int
    downloads_count: int
    cookies_count: int
    search_terms_count: int
    history_entries: list[BrowserHistoryEntry] = Field(default_factory=list)
    downloads: list[BrowserDownloadEntry] = Field(default_factory=list)
    cookies: list[BrowserCookieEntry] = Field(default_factory=list)
    search_terms: list[BrowserSearchEntry] = Field(default_factory=list)
    suspicious_searches: list[str] = Field(default_factory=list)
    suspicious_downloads: list[BrowserDownloadEntry] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary with serialized datetimes."""
        return self.model_dump()


# ---------------------------------------------------------------------------
# USB Activity Analysis Models
# ---------------------------------------------------------------------------

class USBDeviceArtifact(BaseModel):
    """Forensic USB device artifact extracted from registry, setupapi, or event logs."""
    device_id: str
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    vendor_name: Optional[str] = None
    product_name: Optional[str] = None
    serial_number: Optional[str] = None
    device_class: str = "Unknown"  # e.g., "Mass Storage", "HID Keyboard", "Composite"
    device_description: Optional[str] = None
    first_install_time: Optional[datetime] = None
    last_connected_time: Optional[datetime] = None
    last_disconnected_time: Optional[datetime] = None
    drive_letters: list[str] = Field(default_factory=list)
    volume_name: Optional[str] = None
    source_artifacts: list[str] = Field(default_factory=list)
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert artifact to dictionary with ISO timestamps."""
        data = self.model_dump()
        if self.first_install_time:
            data["first_install_time"] = self.first_install_time.isoformat()
        if self.last_connected_time:
            data["last_connected_time"] = self.last_connected_time.isoformat()
        if self.last_disconnected_time:
            data["last_disconnected_time"] = self.last_disconnected_time.isoformat()
        return data


class USBTimelineEntry(BaseModel):
    """Timestamped event in the USB connection timeline."""
    timestamp: datetime
    event_type: str  # "first_install", "connection", "disconnection", "drive_mounted"
    device_id: str
    description: str
    source_artifact: str
    is_suspicious: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert timeline entry to dictionary with ISO timestamp."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        return data


class USBAnalysisResult(BaseModel):
    """Consolidated forensic analysis report for USB device activity."""
    devices_detected: list[USBDeviceArtifact] = Field(default_factory=list)
    device_count: int = 0
    suspicious_device_count: int = 0
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    suspicious_devices: list[USBDeviceArtifact] = Field(default_factory=list)
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary with serialized nested models."""
        return self.model_dump()




