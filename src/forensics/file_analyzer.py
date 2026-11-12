"""
Forensic File Analysis and Deleted File Recovery Subsystem.

Implements ARCHITECTURE.md §4.5, §8 and .agents/skills/forensics/SKILL.md:
- File-level deep inspection and magic byte verification.
- Shannon entropy analysis for packed, obfuscated, or encrypted payloads.
- Extension spoofing detection (e.g. executable masquerading as PDF/image).
- Printable string & embedded IOC extraction (IPs, URLs, domains, emails, base64).
- Malicious command signature & webshell indicator scanning.
- Signature-based file carving from unallocated streams and binary dumps.
- Deleted file recovery via Windows Recycle Bin ($I/$R) and Linux/macOS Trash.
"""

from __future__ import annotations

import base64
import collections
import ipaddress
import math
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.forensics.evidence_vault import calculate_hashes
from src.forensics.models import (
    CarvedFile,
    FileAnalysisResult,
    RecycleBinRecord,
    SuspiciousIndicator,
)


# ---------------------------------------------------------------------------
# Magic Byte Signatures & Definitions
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES: List[Dict[str, Any]] = [
    {
        "type": "Windows Executable (PE/EXE)",
        "extensions": [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"],
        "header": b"MZ",
        "offset": 0,
        "is_executable": True,
    },
    {
        "type": "Linux ELF Executable",
        "extensions": [".elf", ".bin", ".so"],
        "header": b"\x7fELF",
        "offset": 0,
        "is_executable": True,
    },
    {
        "type": "Mach-O Executable",
        "extensions": [".dylib", ".macho", ".bin"],
        "header": b"\xfe\xed\xfa\xce",  # 32-bit
        "offset": 0,
        "is_executable": True,
    },
    {
        "type": "Mach-O 64-bit Executable",
        "extensions": [".dylib", ".macho", ".bin"],
        "header": b"\xfe\xed\xfa\xcf",  # 64-bit
        "offset": 0,
        "is_executable": True,
    },
    {
        "type": "PDF Document",
        "extensions": [".pdf"],
        "header": b"%PDF-",
        "offset": 0,
        "footer": b"%%EOF",
        "is_executable": False,
    },
    {
        "type": "JPEG Image",
        "extensions": [".jpg", ".jpeg", ".jpe"],
        "header": b"\xff\xd8\xff",
        "offset": 0,
        "footer": b"\xff\xd9",
        "is_executable": False,
    },
    {
        "type": "PNG Image",
        "extensions": [".png"],
        "header": b"\x89PNG\r\n\x1a\n",
        "offset": 0,
        "footer": b"IEND\xaeB`\x82",
        "is_executable": False,
    },
    {
        "type": "GIF Image",
        "extensions": [".gif"],
        "header": b"GIF89a",
        "offset": 0,
        "footer": b"\x00\x3b",
        "is_executable": False,
    },
    {
        "type": "ZIP Archive / OpenXML Document",
        "extensions": [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"],
        "header": b"PK\x03\x04",
        "offset": 0,
        "footer": b"PK\x05\x06",
        "is_executable": False,
    },
    {
        "type": "7-Zip Archive",
        "extensions": [".7z"],
        "header": b"7z\xbc\xaf\x27\x1c",
        "offset": 0,
        "is_executable": False,
    },
    {
        "type": "GZIP Archive",
        "extensions": [".gz", ".tgz"],
        "header": b"\x1f\x8b",
        "offset": 0,
        "is_executable": False,
    },
    {
        "type": "SQLite Database",
        "extensions": [".sqlite", ".sqlite3", ".db"],
        "header": b"SQLite format 3\x00",
        "offset": 0,
        "is_executable": False,
    },
]

# Suspicious strings / command tokens across scripts and binaries
SUSPICIOUS_STRING_PATTERNS = [
    (r"(?i)powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", "critical", "Encoded PowerShell Execution"),
    (r"(?i)powershell(?:\.exe)?\s+.*-(?:w|windowstyle)\s+hidden", "high", "Hidden Window PowerShell Launch"),
    (r"(?i)downloadstring|downloadfile|invoke-webrequest|iwr|curl|wget", "high", "Remote Resource Download Token"),
    (r"(?i)\biex\b|invoke-expression", "high", "Dynamic Code Execution (IEX)"),
    (r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows", "critical", "Volume Shadow Copy Deletion (Ransomware Tactic)"),
    (r"(?i)mimikatz|sekurlsa|lsadump|logonpasswords", "critical", "Credential Dumping / Mimikatz Artifact"),
    (r"(?i)certutil(?:\.exe)?\s+.*-urlcache", "high", "Certutil Remote File Ingress"),
    (r"(?i)cmd(?:\.exe)?\s+/c\s+.*", "medium", "Shell Command Execution"),
    (r"(?i)eval\s*\(\s*base64_decode\s*\(", "critical", "Obfuscated PHP Webshell Payload"),
    (r"(?i)passthru|shell_exec|system\s*\(|assert\s*\(", "high", "Dynamic Server-Side Command Execution"),
    (r"(?i)/bin/(?:sh|bash)\s+-i", "critical", "Interactive Reverse Shell Pattern"),
    (r"(?i)nc\s+-[el]|socat\s+tcp-listen", "critical", "Netcat/Socat Listener/Relay"),
]


# ---------------------------------------------------------------------------
# Shannon Entropy & String Extraction Helpers
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence (0.0 - 8.0).
    
    Higher values (typically > 7.2) indicate compression, encryption,
    or packed binary payloads (ransomware / obfuscation).
    """
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_printable_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract printable ASCII and UTF-16LE strings from binary data."""
    strings: List[str] = []

    # ASCII printable strings
    ascii_matches = re.findall(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}", data)
    for m in ascii_matches:
        try:
            strings.append(m.decode("ascii"))
        except UnicodeDecodeError:
            pass

    # UTF-16LE printable strings
    utf16_matches = re.findall(rb"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + rb",}", data)
    for m in utf16_matches:
        try:
            strings.append(m.decode("utf-16le"))
        except UnicodeDecodeError:
            pass

    return strings


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract IPs, URLs, domains, and email addresses from text."""
    iocs: Dict[str, Set[str]] = {
        "ips": set(),
        "urls": set(),
        "domains": set(),
        "emails": set(),
    }

    # URLs
    url_pattern = re.compile(r"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
    for match in url_pattern.finditer(text):
        url = match.group(0).rstrip(".,;)'\"")
        iocs["urls"].add(url)

    # IPv4 addresses
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    for match in ip_pattern.finditer(text):
        ip = match.group(0)
        try:
            parsed = ipaddress.ip_address(ip)
            # Exclude loopback/link-local/multicast if desired, but keep valid IPs
            if not parsed.is_multicast and not parsed.is_unspecified:
                iocs["ips"].add(ip)
        except ValueError:
            pass

    # Email addresses
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    for match in email_pattern.finditer(text):
        iocs["emails"].add(match.group(0))

    # Convert sets to sorted lists
    return {k: sorted(list(v)) for k, v in iocs.items()}


# ---------------------------------------------------------------------------
# Windows Recycle Bin ($I / $R) and Trash Parsers
# ---------------------------------------------------------------------------

def parse_windows_recycle_i_file(data: bytes, source_name: str = "") -> Optional[RecycleBinRecord]:
    """Parse Windows Vista / 7 / 8 / 10 / 11 Recycle Bin $I index file.
    
    Structure:
    - Offset 0x00: Format version (uint64): 1 (Vista-8) or 2 (Win 10+)
    - Offset 0x08: Original file size (uint64)
    - Offset 0x10: Deletion timestamp (Windows FILETIME, uint64)
    - Offset 0x18: Path length (uint32, only in format version 2)
    - Offset 0x18 (v1) or 0x1C (v2): Original path as null-terminated UTF-16LE string.
    """
    if len(data) < 28:
        return None

    try:
        version = struct.unpack_from("<Q", data, 0)[0]
        if version not in (1, 2):
            return None

        file_size = struct.unpack_from("<Q", data, 8)[0]
        filetime = struct.unpack_from("<Q", data, 16)[0]

        # Convert Windows FILETIME (100-nanosecond intervals since Jan 1 1601 UTC)
        deletion_dt: Optional[datetime] = None
        if filetime > 0:
            # 11644473600 is seconds between 1601 and 1970
            epoch_seconds = (filetime / 10_000_000) - 11644473600
            if 0 < epoch_seconds < 4102444800:  # Valid date up to 2100
                deletion_dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)

        # Path extraction
        path_offset = 28 if version == 2 else 24
        raw_path = data[path_offset:]
        # Cut at null terminator
        null_idx = raw_path.find(b"\x00\x00")
        if null_idx != -1:
            raw_path = raw_path[: null_idx + (null_idx % 2)]  # ensure even length
        original_path = raw_path.decode("utf-16le", errors="ignore").rstrip("\x00")
        filename = Path(original_path).name or original_path

        # Matching $R file name
        recovered_data_file = None
        if source_name.startswith("$I"):
            recovered_data_file = "$R" + source_name[2:]

        return RecycleBinRecord(
            original_path=original_path,
            recovered_filename=filename,
            deletion_time=deletion_dt,
            file_size_bytes=file_size,
            source_index_file=source_name,
            recovered_data_file=recovered_data_file,
        )
    except Exception:
        return None


def parse_linux_trashinfo(content: str, source_name: str = "") -> Optional[RecycleBinRecord]:
    """Parse Linux / FreeDesktop.org .trashinfo metadata file."""
    path_match = re.search(r"^Path=(.+)$", content, re.MULTILINE)
    date_match = re.search(r"^DeletionDate=(.+)$", content, re.MULTILINE)

    if not path_match:
        return None

    original_path = path_match.group(1).strip()
    filename = Path(original_path).name

    deletion_dt = None
    if date_match:
        date_str = date_match.group(1).strip()
        try:
            deletion_dt = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return RecycleBinRecord(
        original_path=original_path,
        recovered_filename=filename,
        deletion_time=deletion_dt,
        file_size_bytes=0,
        source_index_file=source_name,
    )


# ---------------------------------------------------------------------------
# File Analyzer & Deleted File Carving Engine
# ---------------------------------------------------------------------------

class FileAnalyzer:
    """Forensic file-level analysis and deleted file recovery engine."""

    def __init__(self, entropy_threshold: float = 7.2) -> None:
        self.entropy_threshold = entropy_threshold

    def identify_magic(self, data: bytes) -> Tuple[str, bool, List[str]]:
        """Identify file format from magic bytes and check if executable."""
        if not data:
            return "Empty File", False, []

        for sig in MAGIC_SIGNATURES:
            offset = sig["offset"]
            header = sig["header"]
            if len(data) >= offset + len(header) and data[offset : offset + len(header)] == header:
                # Additional PE check: offset 0x3C points to PE header
                if sig["header"] == b"MZ" and len(data) >= 0x40:
                    pe_offset_bytes = data[0x3C:0x40]
                    pe_offset = struct.unpack("<I", pe_offset_bytes)[0]
                    if len(data) >= pe_offset + 4 and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                        return sig["type"], sig["is_executable"], sig["extensions"]
                else:
                    return sig["type"], sig["is_executable"], sig["extensions"]

        # Script magic
        if data.startswith(b"#!"):
            first_line = data[:128].split(b"\n")[0].decode("ascii", errors="ignore")
            return f"Script ({first_line})", True, [".sh", ".py", ".pl", ".bash"]

        # Plain text
        try:
            data[:512].decode("utf-8")
            return "Plain Text / Script", False, [".txt", ".log", ".json", ".csv", ".xml", ".html", ".py", ".sh", ".ps1"]
        except UnicodeDecodeError:
            pass

        return "Unknown Binary", False, []

    def analyze_bytes(self, data: bytes, filename: str) -> FileAnalysisResult:
        """Perform comprehensive forensic analysis on a raw file's byte content."""
        sha256, md5, size = calculate_hashes(data)
        entropy = calculate_entropy(data)
        is_high_entropy = entropy >= self.entropy_threshold

        detected_type, is_executable, valid_extensions = self.identify_magic(data)
        ext = Path(filename).suffix.lower()

        indicators: List[SuspiciousIndicator] = []

        # Check for High Entropy (Encryption / Packing / Obfuscation)
        if is_high_entropy and size > 256:
            indicators.append(
                SuspiciousIndicator(
                    category="high_entropy",
                    description=f"High Shannon entropy ({entropy}/8.0) suggests compressed, packed, or encrypted payload.",
                    severity="high" if entropy >= 7.6 else "medium",
                    evidence_match=f"Entropy: {entropy}",
                )
            )

        # Check for Extension Spoofing
        is_spoofed = False
        if valid_extensions and ext and ext not in valid_extensions:
            # Dangerous: executable disguised as benign document or media
            if is_executable and ext in [".pdf", ".jpg", ".png", ".txt", ".docx", ".xlsx", ".mp3", ".csv"]:
                is_spoofed = True
                indicators.append(
                    SuspiciousIndicator(
                        category="extension_spoofing",
                        description=f"CRITICAL: Executable binary ({detected_type}) disguised with '{ext}' extension!",
                        severity="critical",
                        evidence_match=f"Detected: {detected_type}, Declared Extension: {ext}",
                    )
                )
            elif detected_type not in ["Plain Text / Script", "Unknown Binary"]:
                is_spoofed = True
                indicators.append(
                    SuspiciousIndicator(
                        category="extension_spoofing",
                        description=f"File extension '{ext}' does not match header signature ({detected_type}).",
                        severity="medium",
                        evidence_match=f"Detected: {detected_type}, Extension: {ext}",
                    )
                )

        # String extraction and IOC analysis
        all_strings = extract_printable_strings(data)
        combined_text = " ".join(all_strings)
        extracted_iocs = extract_iocs_from_text(combined_text)

        # Pattern scan for malicious command strings
        for pattern, severity, desc in SUSPICIOUS_STRING_PATTERNS:
            matches = re.findall(pattern, combined_text)
            if matches:
                sample_match = matches[0] if isinstance(matches[0], str) else str(matches[0])
                indicators.append(
                    SuspiciousIndicator(
                        category="malicious_string",
                        description=desc,
                        severity=severity,
                        evidence_match=sample_match[:120],
                    )
                )

        # Base64 Decoded Payload Analysis
        base64_candidates = re.findall(r"[A-Za-z0-9+/]{32,}={0,2}", combined_text)
        for b64 in base64_candidates[:5]:  # inspect first 5 long base64 strings
            try:
                decoded = base64.b64decode(b64)
                if len(decoded) > 16:
                    dec_type, dec_exec, _ = self.identify_magic(decoded)
                    if dec_exec:
                        indicators.append(
                            SuspiciousIndicator(
                                category="encoded_payload",
                                description=f"Embedded Base64 blob contains hidden executable ({dec_type})!",
                                severity="critical",
                                evidence_match=b64[:60] + "...",
                            )
                        )
                    elif any(token.encode() in decoded.lower() for token in [b"powershell", b"cmd.exe", b"/bin/sh", b"wget", b"curl"]):
                        indicators.append(
                            SuspiciousIndicator(
                                category="encoded_payload",
                                description="Embedded Base64 blob contains hidden shell commands.",
                                severity="high",
                                evidence_match=b64[:60] + "...",
                            )
                        )
            except Exception:
                pass

        # Perform Carving if binary contains nested files
        carved = self.carve_files(data)

        # Recycle Bin Artifact check
        recovered_deleted: List[RecycleBinRecord] = []
        if Path(filename).name.startswith("$I"):
            rec = parse_windows_recycle_i_file(data, source_name=filename)
            if rec:
                recovered_deleted.append(rec)
        elif Path(filename).suffix == ".trashinfo":
            rec = parse_linux_trashinfo(combined_text, source_name=filename)
            if rec:
                recovered_deleted.append(rec)

        # Summary generation
        summary_parts = [
            f"Analyzed '{filename}' ({size} bytes).",
            f"Detected format: {detected_type} (Entropy: {entropy}).",
        ]
        if is_spoofed:
            summary_parts.append("WARNING: Extension spoofing detected.")
        if indicators:
            summary_parts.append(f"Found {len(indicators)} suspicious indicator(s).")
        if carved:
            summary_parts.append(f"Carved {len(carved)} embedded/deleted file(s).")
        if recovered_deleted:
            summary_parts.append(f"Parsed {len(recovered_deleted)} deleted Recycle Bin record(s).")

        return FileAnalysisResult(
            filename=filename,
            file_size_bytes=size,
            sha256=sha256,
            md5=md5,
            shannon_entropy=entropy,
            is_high_entropy=is_high_entropy,
            detected_type=detected_type,
            declared_extension=ext,
            is_extension_spoofed=is_spoofed,
            extracted_iocs=extracted_iocs,
            suspicious_indicators=indicators,
            carved_files=carved,
            recovered_deleted_files=recovered_deleted,
            summary=" ".join(summary_parts),
        )

    def analyze_file(self, file_path: Union[str, Path]) -> FileAnalysisResult:
        """Analyze a file from a local filesystem path."""
        path = Path(file_path).resolve()
        data = path.read_bytes()
        return self.analyze_bytes(data, filename=path.name)

    def carve_files(
        self,
        data: bytes,
        output_dir: Optional[Union[str, Path]] = None,
        max_carve_per_type: int = 10,
    ) -> List[CarvedFile]:
        """Carve embedded or deleted files from raw binary data using header/footer signatures."""
        carved_files: List[CarvedFile] = []
        out_path = Path(output_dir).resolve() if output_dir else None
        if out_path:
            out_path.mkdir(parents=True, exist_ok=True)

        for sig in MAGIC_SIGNATURES:
            header = sig["header"]
            footer = sig.get("footer")
            sig_type = sig["type"]

            if not footer and header != b"MZ":
                continue

            current_pos = 0
            carved_count = 0

            while carved_count < max_carve_per_type:
                start_idx = data.find(header, current_pos)
                if start_idx == -1:
                    break

                # If the header is at offset 0 of the entire file, skip carving the file itself
                # unless it's an unallocated block
                if start_idx == 0 and len(data) < 2_000_000:
                    current_pos = len(header)
                    continue

                end_idx = -1
                if footer:
                    footer_idx = data.find(footer, start_idx + len(header))
                    if footer_idx != -1:
                        end_idx = footer_idx + len(footer)
                elif header == b"MZ":
                    # Estimate PE size or carve minimum 1024 bytes up to 1MB
                    end_idx = min(len(data), start_idx + 1024 * 1024)

                if end_idx != -1 and end_idx > start_idx:
                    carved_bytes = data[start_idx:end_idx]
                    c_sha256, c_md5, c_size = calculate_hashes(carved_bytes)
                    rec_name = f"carved_{start_idx:08x}_{sig['extensions'][0][1:]}.{sig['extensions'][0][1:]}"

                    carved_file = CarvedFile(
                        recovered_name=rec_name,
                        file_type=sig_type,
                        offset_start=start_idx,
                        offset_end=end_idx,
                        size_bytes=c_size,
                        sha256=c_sha256,
                        md5=c_md5,
                    )
                    carved_files.append(carved_file)
                    carved_count += 1

                    if out_path:
                        (out_path / rec_name).write_bytes(carved_bytes)

                    current_pos = end_idx
                else:
                    current_pos = start_idx + len(header)

        return carved_files

    def recover_deleted_from_directory(
        self,
        directory: Union[str, Path],
        recovery_dir: Optional[Union[str, Path]] = None,
    ) -> List[RecycleBinRecord]:
        """Scan a directory for deleted file metadata ($I files or .trashinfo) and recover matching data files."""
        dir_path = Path(directory).resolve()
        recovered: List[RecycleBinRecord] = []
        out_path = Path(recovery_dir).resolve() if recovery_dir else None
        if out_path:
            out_path.mkdir(parents=True, exist_ok=True)

        if not dir_path.is_dir():
            return recovered

        # 1. Scan for Windows Recycle Bin $I files
        for i_path in dir_path.glob("$I*"):
            if i_path.is_file():
                record = parse_windows_recycle_i_file(i_path.read_bytes(), source_name=i_path.name)
                if record:
                    # Look for corresponding $R file
                    if record.recovered_data_file:
                        r_path = dir_path / record.recovered_data_file
                        if r_path.is_file() and out_path:
                            dest_file = out_path / record.recovered_filename
                            dest_file.write_bytes(r_path.read_bytes())
                    recovered.append(record)

        # 2. Scan for Linux/Unix .trashinfo files
        for trash_path in dir_path.glob("*.trashinfo"):
            if trash_path.is_file():
                record = parse_linux_trashinfo(trash_path.read_text(errors="ignore"), source_name=trash_path.name)
                if record:
                    # Look for file in ../files or same dir
                    candidate = dir_path / record.recovered_filename
                    if candidate.is_file() and out_path:
                        dest_file = out_path / record.recovered_filename
                        dest_file.write_bytes(candidate.read_bytes())
                    recovered.append(record)

        return recovered
