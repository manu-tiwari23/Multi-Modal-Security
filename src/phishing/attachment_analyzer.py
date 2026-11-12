"""
Static Attachment Analyzer for Phishing Detection.

Phase 5, Feature 3 — Stateless scoring service that performs static and
metadata-only inspection of email attachments without ever executing,
detonating, or writing untrusted payloads to disk.

Complies with:
- ARCHITECTURE.md §4.4 — Attachment Scanner (static analysis + hash intel)
- .agents/skills/phishing-detection/SKILL.md — stateless scoring service,
  static/metadata analysis ONLY (no execution/detonation in main env),
  mandatory signal explanations, cached threat-intel hash lookups with
  bounded timeout and graceful degradation.
- AGENTS.md — module isolation (no imports from src/forensics/), synthetic
  test data only, ASCII-safe evidence formatting.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import math
import re
import threading
import time
import urllib.error
import urllib.request
import zipfile
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any, Optional

from src.phishing.models import (
    AttachmentFeatures,
    AttachmentScanResult,
    EmailAttachmentInfo,
    PhishingSeverity,
    PhishingSignal,
    PhishingVerdict,
    SignalCategory,
    ThreatIntelResult,
)
from src.shared.config import settings
from src.shared.event_schema import Entity, SecurityEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — Extensions, Magic Signatures, Static Threat Patterns
# ---------------------------------------------------------------------------

EXECUTABLE_EXTENSIONS: set[str] = {
    ".exe", ".dll", ".scr", ".pif", ".com", ".cpl", ".msi", ".msp",
    ".hta", ".jar", ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".drv",
    ".sys", ".ocx", ".app", ".dmg", ".pkg", ".deb", ".rpm", ".elf",
}

SCRIPT_EXTENSIONS: set[str] = {
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".bat", ".cmd", ".reg", ".vba", ".py", ".sh",
}

MACRO_EXTENSIONS: set[str] = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".ppam",
    ".doc", ".xls", ".ppt",
}

OOXML_DOCUMENT_EXTENSIONS: set[str] = {
    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".dotx", ".dotm",
    ".xltx", ".xltm", ".potx", ".potm",
}

ARCHIVE_EXTENSIONS: set[str] = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".ace",
}

HTML_SVG_EXTENSIONS: set[str] = {
    ".html", ".htm", ".xhtml", ".svg", ".mht", ".mhtml",
}

BENIGN_DOCUMENT_EXTENSIONS: set[str] = {
    ".pdf", ".txt", ".csv", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".docx", ".xlsx", ".pptx", ".rtf", ".ics", ".eml",
}

# Magic byte signatures: (prefix, offset, type_label)
MAGIC_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"MZ", 0, "pe_executable"),
    (b"\x7fELF", 0, "elf_executable"),
    (b"\xfe\xed\xfa\xce", 0, "macho_executable"),
    (b"\xfe\xed\xfa\xcf", 0, "macho_executable"),
    (b"\xcf\xfa\xed\xfe", 0, "macho_executable"),
    (b"\xca\xfe\xba\xbe", 0, "macho_or_java"),
    (b"%PDF-", 0, "pdf"),
    (b"PK\x03\x04", 0, "zip_container"),
    (b"PK\x05\x06", 0, "zip_container"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole2_compound"),
    (b"{\\rtf", 0, "rtf"),
    (b"Rar!\x1a\x07", 0, "rar_archive"),
    (b"7z\xbc\xaf'\x1c", 0, "7z_archive"),
    (b"\x1f\x8b\x08", 0, "gzip_archive"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "windows_lnk"),
    (b"\x89PNG\r\n\x1a\n", 0, "png_image"),
    (b"\xff\xd8\xff", 0, "jpeg_image"),
    (b"GIF87a", 0, "gif_image"),
    (b"GIF89a", 0, "gif_image"),
]

# Expected magic type families per declared extension
EXPECTED_MAGIC_BY_EXT: dict[str, set[str]] = {
    ".exe": {"pe_executable"},
    ".dll": {"pe_executable"},
    ".scr": {"pe_executable"},
    ".sys": {"pe_executable"},
    ".cpl": {"pe_executable"},
    ".pdf": {"pdf"},
    ".png": {"png_image"},
    ".jpg": {"jpeg_image"},
    ".jpeg": {"jpeg_image"},
    ".gif": {"gif_image"},
    ".zip": {"zip_container", "ooxml_document"},
    ".jar": {"zip_container"},
    ".docx": {"ooxml_document", "zip_container"},
    ".xlsx": {"ooxml_document", "zip_container"},
    ".pptx": {"ooxml_document", "zip_container"},
    ".docm": {"ooxml_document", "zip_container"},
    ".xlsm": {"ooxml_document", "zip_container"},
    ".pptm": {"ooxml_document", "zip_container"},
    ".doc": {"ole2_compound", "rtf", "ooxml_document"},
    ".xls": {"ole2_compound", "ooxml_document"},
    ".ppt": {"ole2_compound", "ooxml_document"},
    ".msi": {"ole2_compound"},
    ".rtf": {"rtf"},
    ".rar": {"rar_archive"},
    ".7z": {"7z_archive"},
    ".gz": {"gzip_archive"},
    ".lnk": {"windows_lnk"},
}

PDF_ACTIVE_KEYWORDS: list[tuple[bytes, str]] = [
    (b"/JavaScript", "Embedded JavaScript action (/JavaScript)"),
    (b"/JS", "Embedded JavaScript tag (/JS)"),
    (b"/Launch", "External application launch action (/Launch)"),
    (b"/OpenAction", "Automatic trigger on document open (/OpenAction)"),
    (b"/AA", "Additional automatic trigger action (/AA)"),
    (b"/EmbeddedFile", "Embedded file payload (/EmbeddedFile)"),
    (b"/RichMedia", "Embedded Flash/RichMedia object (/RichMedia)"),
]

HTML_SMUGGLING_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"<script\b", re.IGNORECASE), "Inline <script> tag inside attachment"),
    (re.compile(r"\batob\s*\(", re.IGNORECASE), "Base64 atob() payload decoding"),
    (re.compile(r"\bnew\s+Blob\s*\(", re.IGNORECASE), "JavaScript Blob smuggling assembly"),
    (re.compile(r"createObjectURL\s*\(", re.IGNORECASE), "URL.createObjectURL client-side file drop"),
    (re.compile(r"msSaveOrOpenBlob", re.IGNORECASE), "msSaveOrOpenBlob automatic download trigger"),
    (re.compile(r"<form\b[^>]*>", re.IGNORECASE), "Embedded HTML <form> for credential capture"),
    (re.compile(r"type\s*=\s*[\"']password[\"']", re.IGNORECASE), "Password input field in HTML attachment"),
    (re.compile(r"http-equiv\s*=\s*[\"']refresh[\"']", re.IGNORECASE), "HTML meta-refresh redirect"),
]

SUSPICIOUS_STATIC_STRINGS: list[tuple[re.Pattern[bytes], str]] = [
    (re.compile(rb"powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden|bypass)", re.IGNORECASE),
     "Obfuscated/hidden PowerShell execution command"),
    (re.compile(rb"invoke-expression|\biex\s*\(", re.IGNORECASE),
     "PowerShell dynamic Invoke-Expression execution"),
    (re.compile(rb"cmd(?:\.exe)?\s+/c\b", re.IGNORECASE),
     "Windows command shell (/c) execution string"),
    (re.compile(rb"wscript\.shell|shell\.application|scripting\.filesystemobject", re.IGNORECASE),
     "Windows Script Host / COM automation object"),
    (re.compile(rb"autoopen|auto_open|autoexec|document_open|workbook_open", re.IGNORECASE),
     "Office VBA auto-execution macro trigger"),
    (re.compile(rb"urldownloadtofile|winhttprequest|xmlhttp|msxml2\.xmlhttp", re.IGNORECASE),
     "Downloader API / HTTP payload staging string"),
    (re.compile(rb"certutil\s+-urlcache|bitsadmin\s+/transfer|mshta(?:\.exe)?\s+http", re.IGNORECASE),
     "Living-off-the-land binary (LOLBin) download command"),
]

OLE2_MACRO_MARKERS: tuple[bytes, ...] = (
    b"_VBA_PROJECT",
    b"VBA\x00",
    b"Macros",
    b"AutoOpen",
    b"Document_Open",
    b"Workbook_Open",
)

_URL_BYTES_PATTERN = re.compile(rb"https?://[^\s<>\"'\)\]\}>\x00-\x1f]{4,200}", re.IGNORECASE)
_RTLO_CHAR = "\u202e"
_BIDI_OVERRIDE_CHARS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

# Zip inspection safety bounds (prevent memory exhaustion on crafted archives)
MAX_ZIP_MEMBERS_INSPECT = 250
MAX_OOXML_XML_READ_BYTES = 512 * 1024  # 512 KB per XML entry


def safe_ascii(text: str) -> str:
    """Escape non-ASCII characters (including RTLO U+202E) cleanly for Windows/log safety."""
    if not text:
        return ""
    out: list[str] = []
    for ch in text:
        if ord(ch) < 128 and ch.isprintable():
            out.append(ch)
        elif ch in ("\n", "\r", "\t"):
            out.append(" ")
        else:
            out.append(f"[U+{ord(ch):04X}]")
    return "".join(out)


# ---------------------------------------------------------------------------
# Thread-Safe Hash Reputation Cache
# ---------------------------------------------------------------------------

class HashReputationCache:
    """Thread-safe in-memory TTL cache for attachment SHA-256 lookups."""

    def __init__(self, default_ttl_seconds: float = 3600.0, max_entries: int = 5000) -> None:
        self.default_ttl = default_ttl_seconds
        self.max_entries = max_entries
        self._cache: dict[str, tuple[ThreatIntelResult, float]] = {}
        self._lock = threading.Lock()

    def _normalize_hash(self, sha256: str) -> str:
        return sha256.strip().lower()

    def get(self, sha256: str) -> Optional[ThreatIntelResult]:
        """Return cached ThreatIntelResult if present and unexpired."""
        key = self._normalize_hash(sha256)
        if not key:
            return None
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            result, expires_at = entry
            if time.monotonic() > expires_at:
                del self._cache[key]
                return None
            cached_copy = result.model_copy()
            cached_copy.cached = True
            return cached_copy

    def set(self, sha256: str, result: ThreatIntelResult, ttl_seconds: Optional[float] = None) -> None:
        """Cache a ThreatIntelResult with TTL and bounded capacity."""
        key = self._normalize_hash(sha256)
        if not key:
            return
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = time.monotonic() + ttl
        with self._lock:
            if len(self._cache) >= self.max_entries and key not in self._cache:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[key] = (result.model_copy(), expires_at)

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            now = time.monotonic()
            expired = [k for k, (_, exp) in self._cache.items() if now > exp]
            for k in expired:
                del self._cache[k]
            return len(self._cache)


# ---------------------------------------------------------------------------
# Pluggable Hash Threat Intelligence Providers
# ---------------------------------------------------------------------------

class AttachmentHashProvider(ABC):
    """Abstract base class for attachment file hash reputation lookups."""

    @abstractmethod
    def lookup_hash(self, sha256: str, timeout: float = 1.5) -> ThreatIntelResult:
        """Query threat intelligence for a file SHA-256 hash."""
        ...


class SyntheticHashBlocklistProvider(AttachmentHashProvider):
    """Offline synthetic malicious hash feed for safe testing and demos.

    Uses SHA-256 hashes of known harmless synthetic test fixtures (including the
    standard EICAR anti-malware test string hash) — never real malware.
    """

    # Well-known standard EICAR test string SHA-256 (benign AV test string)
    EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    DEFAULT_SYNTHETIC_HASHES: dict[str, dict[str, Any]] = {
        EICAR_SHA256: {
            "categories": ["test_signature", "malware_dropper"],
            "positives": 58,
            "total": 70,
            "score": 95.0,
        },
        # SHA-256 of synthetic test payload b"MMS-SYNTHETIC-MALICIOUS-ATTACHMENT-TEST"
        hashlib.sha256(b"MMS-SYNTHETIC-MALICIOUS-ATTACHMENT-TEST").hexdigest(): {
            "categories": ["phishing_payload", "synthetic_ioc"],
            "positives": 42,
            "total": 70,
            "score": 90.0,
        },
    }

    def __init__(self, extra_hashes: Optional[dict[str, dict[str, Any]]] = None) -> None:
        self.blocklist = dict(self.DEFAULT_SYNTHETIC_HASHES)
        if extra_hashes:
            for k, v in extra_hashes.items():
                self.blocklist[k.strip().lower()] = v

    def lookup_hash(self, sha256: str, timeout: float = 1.5) -> ThreatIntelResult:
        norm = sha256.strip().lower()
        match = self.blocklist.get(norm)
        if match:
            return ThreatIntelResult(
                ioc=norm,
                is_malicious=True,
                threat_score=float(match.get("score", 90.0)),
                source="synthetic_hash_blocklist",
                positives=int(match.get("positives", 30)),
                total_engines=int(match.get("total", 70)),
                categories=list(match.get("categories", ["malicious_attachment"])),
                tags=["synthetic_match"],
            )
        return ThreatIntelResult(
            ioc=norm,
            is_malicious=False,
            threat_score=0.0,
            source="synthetic_hash_blocklist",
            positives=0,
            total_engines=70,
        )


class MockHashIntelProvider(AttachmentHashProvider):
    """Configurable mock hash provider for unit testing timeouts, hits, and errors."""

    def __init__(
        self,
        malicious_hashes: Optional[dict[str, ThreatIntelResult]] = None,
        delay_seconds: float = 0.0,
        raise_exception: Optional[Exception] = None,
    ) -> None:
        self.malicious_hashes = {k.lower(): v for k, v in (malicious_hashes or {}).items()}
        self.delay_seconds = delay_seconds
        self.raise_exception = raise_exception
        self.call_count = 0

    def lookup_hash(self, sha256: str, timeout: float = 1.5) -> ThreatIntelResult:
        self.call_count += 1
        if self.delay_seconds > 0:
            if self.delay_seconds > timeout:
                time.sleep(timeout)
                raise TimeoutError(f"Mock hash lookup exceeded timeout ({timeout}s)")
            time.sleep(self.delay_seconds)
        if self.raise_exception:
            raise self.raise_exception
        norm = sha256.strip().lower()
        if norm in self.malicious_hashes:
            return self.malicious_hashes[norm].model_copy()
        return ThreatIntelResult(
            ioc=norm,
            is_malicious=False,
            threat_score=0.0,
            source="mock_hash_provider",
            positives=0,
            total_engines=70,
        )


class VirusTotalHashProvider(AttachmentHashProvider):
    """VirusTotal API v3 file hash lookup with strict timeout and graceful fallback."""

    VT_FILE_API = "https://www.virustotal.com/api/v3/files/{sha256}"

    def __init__(
        self,
        api_key: Optional[str] = None,
        fallback_provider: Optional[AttachmentHashProvider] = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.vt_api_key
        self.fallback = fallback_provider or SyntheticHashBlocklistProvider()

    def lookup_hash(self, sha256: str, timeout: float = 1.5) -> ThreatIntelResult:
        norm = sha256.strip().lower()
        if not self.api_key:
            return self.fallback.lookup_hash(norm, timeout=timeout)

        req = urllib.request.Request(
            self.VT_FILE_API.format(sha256=norm),
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(v) for v in stats.values() if isinstance(v, (int, float))) or 70
            positives = malicious + suspicious
            score = min(100.0, (positives / max(1, total)) * 150.0) if positives > 0 else 0.0
            return ThreatIntelResult(
                ioc=norm,
                is_malicious=malicious >= 2 or positives >= 3,
                threat_score=round(score, 1),
                source="virustotal",
                positives=positives,
                total_engines=total,
                categories=["virustotal_file_scan"] if positives > 0 else [],
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return ThreatIntelResult(ioc=norm, is_malicious=False, source="virustotal")
            logger.debug("VirusTotal hash lookup HTTP error (%s), degrading gracefully", exc.code)
            return self.fallback.lookup_hash(norm, timeout=timeout)
        except Exception as exc:
            logger.debug("VirusTotal hash lookup error (%s), degrading gracefully", exc)
            return self.fallback.lookup_hash(norm, timeout=timeout)


# ---------------------------------------------------------------------------
# Static Attachment Feature Extractor
# ---------------------------------------------------------------------------

class AttachmentFeatureExtractor:
    """Extracts static binary, structural, and metadata features from bytes.

    Strictly static: never executes code, never writes payloads to disk,
    and bounds all in-memory archive reads.
    """

    @classmethod
    def extract(
        cls,
        data: bytes,
        filename: str,
        content_type: str = "application/octet-stream",
    ) -> AttachmentFeatures:
        """Inspect raw attachment bytes and filename statically."""
        clean_name = filename.strip() if filename else "unnamed_attachment"
        declared_ext = cls._extract_extension(clean_name)
        has_double_ext = cls._has_double_extension(clean_name)
        has_rtlo = any(ch in clean_name for ch in _BIDI_OVERRIDE_CHARS)

        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        entropy = cls._shannon_entropy(data)

        detected_type = cls._detect_magic_type(data)

        # In-memory inspection of ZIP / OOXML containers
        archive_members: list[str] = []
        archive_suspicious: list[str] = []
        is_encrypted_archive = False
        is_zip_bomb_suspect = False
        has_embedded_macros = False
        has_external_template = False
        ooxml_urls: list[str] = []

        if detected_type == "zip_container":
            zip_info = cls._inspect_zip_in_memory(data)
            if zip_info["is_ooxml"]:
                detected_type = "ooxml_document"
            archive_members = zip_info["members"]
            archive_suspicious = zip_info["suspicious_members"]
            is_encrypted_archive = zip_info["is_encrypted"]
            is_zip_bomb_suspect = zip_info["is_zip_bomb"]
            has_embedded_macros = zip_info["has_vba_macros"]
            has_external_template = zip_info["has_external_template"]
            ooxml_urls = zip_info["urls"]

        # Legacy OLE2 / RTF macro detection
        if detected_type == "ole2_compound":
            if any(marker in data for marker in OLE2_MACRO_MARKERS):
                has_embedded_macros = True
        elif detected_type == "rtf":
            if b"\\objdata" in data or b"\\objemb" in data or b"\\objlink" in data:
                has_embedded_macros = True

        # PDF active content detection
        has_pdf_active = False
        if detected_type == "pdf" or declared_ext == ".pdf":
            for kw, _ in PDF_ACTIVE_KEYWORDS:
                if kw in data:
                    has_pdf_active = True
                    break

        # HTML / SVG smuggling detection
        has_html_smuggling = False
        if detected_type in ("html_document", "svg_image") or declared_ext in HTML_SVG_EXTENSIONS:
            text_sample = data[:256 * 1024].decode("utf-8", errors="ignore")
            for pattern, _ in HTML_SMUGGLING_PATTERNS:
                if pattern.search(text_sample):
                    has_html_smuggling = True
                    break

        # Extension spoofing check
        is_spoofed = cls._is_extension_spoofed(declared_ext, detected_type)

        # Static URL extraction
        extracted_urls = cls._extract_urls(data, extra_urls=ooxml_urls)

        # Static suspicious string patterns (for scripts, executables, docs, HTML)
        suspicious_strings: list[str] = []
        scan_slice = data[:1024 * 1024]  # Bound regex scanning at 1 MB
        for pattern, label in SUSPICIOUS_STATIC_STRINGS:
            if pattern.search(scan_slice) and label not in suspicious_strings:
                suspicious_strings.append(label)

        is_executable = declared_ext in EXECUTABLE_EXTENSIONS or detected_type in (
            "pe_executable", "elf_executable", "macho_executable", "windows_lnk"
        )
        is_script = declared_ext in SCRIPT_EXTENSIONS
        is_archive = declared_ext in ARCHIVE_EXTENSIONS or detected_type in (
            "zip_container", "rar_archive", "7z_archive", "gzip_archive"
        )
        is_macro_enabled = declared_ext in MACRO_EXTENSIONS or has_embedded_macros

        return AttachmentFeatures(
            filename=clean_name,
            declared_extension=declared_ext,
            claimed_content_type=content_type or "application/octet-stream",
            detected_file_type=detected_type,
            size_bytes=len(data),
            sha256=sha256,
            md5=md5,
            shannon_entropy=round(entropy, 3),
            has_double_extension=has_double_ext,
            has_rtlo_override=has_rtlo,
            is_extension_spoofed=is_spoofed,
            is_executable=is_executable,
            is_script=is_script,
            is_archive=is_archive,
            is_macro_enabled=is_macro_enabled,
            has_embedded_macros=has_embedded_macros,
            has_external_template=has_external_template,
            has_pdf_active_content=has_pdf_active,
            has_html_smuggling=has_html_smuggling,
            is_encrypted_archive=is_encrypted_archive,
            is_zip_bomb_suspect=is_zip_bomb_suspect,
            archive_members=archive_members,
            archive_suspicious_members=archive_suspicious,
            extracted_urls=extracted_urls,
            suspicious_strings=suspicious_strings,
        )

    @staticmethod
    def _extract_extension(filename: str) -> str:
        # Strip trailing spaces/dots used in spoofing tricks
        cleaned = filename.strip().rstrip(".")
        if "." not in cleaned:
            return ""
        return "." + cleaned.rsplit(".", 1)[-1].lower()

    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        """Detect double extensions like invoice.pdf.exe or report.docx .js."""
        cleaned = re.sub(r"\s+", "", filename.strip().lower())
        parts = cleaned.split(".")
        if len(parts) < 3:
            return False
        final_ext = "." + parts[-1]
        prev_ext = "." + parts[-2]
        risky_final = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | HTML_SVG_EXTENSIONS
        lure_prev = BENIGN_DOCUMENT_EXTENSIONS | {".doc", ".xls", ".ppt", ".zip"}
        return final_ext in risky_final and prev_ext in lure_prev

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _detect_magic_type(data: bytes) -> str:
        if not data:
            return "empty"
        for sig, offset, label in MAGIC_SIGNATURES:
            if len(data) >= offset + len(sig) and data[offset:offset + len(sig)] == sig:
                return label

        # Check text-based markup formats (HTML / SVG / Script)
        head = data[:512].lstrip().lower()
        if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
            return "html_document"
        if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
            return "svg_image"

        # Heuristic printable text check
        sample = data[:4096]
        printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        if sample and (printable / len(sample)) >= 0.90:
            return "plain_text"
        return "unknown"

    @classmethod
    def _is_extension_spoofed(cls, declared_ext: str, detected_type: str) -> bool:
        if not declared_ext or detected_type in ("unknown", "empty"):
            return False
        # Executable binaries masquerading as documents, images, or archives
        if detected_type in ("pe_executable", "elf_executable", "macho_executable", "windows_lnk"):
            if declared_ext not in EXECUTABLE_EXTENSIONS:
                return True
        # HTML/SVG smuggling disguised as document/image
        if detected_type in ("html_document", "svg_image"):
            if declared_ext in (BENIGN_DOCUMENT_EXTENSIONS | MACRO_EXTENSIONS) - {".xml"}:
                return True
        # Known expected magic mismatch (excluding plain_text/unknown)
        expected = EXPECTED_MAGIC_BY_EXT.get(declared_ext)
        if expected and detected_type not in expected:
            # Allow plain_text only for text-like extensions, not binary PDF/PNG/ZIP/EXE
            return True
        return False

    @classmethod
    def _inspect_zip_in_memory(cls, data: bytes) -> dict[str, Any]:
        """Safely inspect ZIP/OOXML directory and select XML metadata in memory."""
        result: dict[str, Any] = {
            "is_ooxml": False,
            "members": [],
            "suspicious_members": [],
            "is_encrypted": False,
            "is_zip_bomb": False,
            "has_vba_macros": False,
            "has_external_template": False,
            "urls": [],
        }
        try:
            with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
                infos = zf.infolist()[:MAX_ZIP_MEMBERS_INSPECT]
                total_uncompressed = 0
                total_compressed = max(1, len(data))

                for info in infos:
                    name = info.filename
                    lower_name = name.lower()
                    result["members"].append(name)
                    total_uncompressed += max(0, info.file_size)

                    # Bit 0 indicates encrypted zip member
                    if info.flag_bits & 0x1:
                        result["is_encrypted"] = True

                    # OOXML structure markers
                    if lower_name == "[content_types].xml" or lower_name.startswith(("word/", "xl/", "ppt/")):
                        result["is_ooxml"] = True

                    # Embedded VBA macro binary inside OOXML
                    if lower_name.endswith("vbaproject.bin"):
                        result["has_vba_macros"] = True

                    # Inspect .rels files for remote template injection (T1221)
                    if lower_name.endswith(".rels") and not (info.flag_bits & 0x1):
                        if info.file_size <= MAX_OOXML_XML_READ_BYTES:
                            try:
                                rel_bytes = zf.read(info)[:MAX_OOXML_XML_READ_BYTES]
                                rel_text = rel_bytes.decode("utf-8", errors="ignore")
                                if 'targetmode="external"' in rel_text.lower():
                                    # Extract external targets
                                    targets = re.findall(r'Target\s*=\s*["\']([^"\']+)["\']', rel_text, re.IGNORECASE)
                                    for t in targets:
                                        if t.lower().startswith(("http://", "https://", "file://", "\\\\")):
                                            result["has_external_template"] = True
                                            if t.lower().startswith(("http://", "https://")):
                                                result["urls"].append(t)
                            except Exception:
                                pass

                    # Flag suspicious archive members
                    if not info.is_dir():
                        member_ext = cls._extract_extension(name)
                        if (
                            member_ext in (EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | HTML_SVG_EXTENSIONS)
                            or cls._has_double_extension(name)
                            or member_ext in ARCHIVE_EXTENSIONS
                        ):
                            result["suspicious_members"].append(name)

                # Zip-bomb compression ratio heuristic (>100x ratio and >10MB uncompressed)
                if total_uncompressed > 10 * 1024 * 1024 and (total_uncompressed / total_compressed) >= 100:
                    result["is_zip_bomb"] = True

        except (zipfile.BadZipFile, Exception):
            # Malformed or truncated zip — do not crash
            pass

        return result

    @staticmethod
    def _extract_urls(data: bytes, extra_urls: Optional[list[str]] = None) -> list[str]:
        urls: list[str] = list(extra_urls or [])
        scan_slice = data[:1024 * 1024]
        for match in _URL_BYTES_PATTERN.findall(scan_slice):
            try:
                u = match.decode("utf-8", errors="ignore").rstrip(".,;)")
                if u not in urls:
                    urls.append(u)
            except Exception:
                pass
        return urls[:50]


# ---------------------------------------------------------------------------
# AttachmentAnalyzer — Stateless Scoring Service
# ---------------------------------------------------------------------------

class AttachmentAnalyzer:
    """Stateless static attachment phishing & malware delivery detector.

    Produces a PhishingVerdict with normalized risk score (0–100), individual
    PhishingSignal indicators, MITRE ATT&CK tags, and a mandatory human-readable
    explanation. Never executes or detonates attachment bytes.
    """

    SCORE_THRESHOLDS: dict[str, float] = {
        "critical": 80.0,
        "high": 60.0,
        "medium": 35.0,
        "low": 15.0,
    }

    def __init__(
        self,
        hash_provider: Optional[AttachmentHashProvider] = None,
        cache: Optional[HashReputationCache] = None,
        intel_timeout_seconds: float = 1.5,
    ) -> None:
        self.hash_provider = hash_provider or SyntheticHashBlocklistProvider()
        self.cache = cache or HashReputationCache()
        self.intel_timeout_seconds = intel_timeout_seconds

    def scan_bytes(
        self,
        data: bytes,
        filename: str,
        content_type: str = "application/octet-stream",
        email_id: Optional[str] = None,
    ) -> PhishingVerdict:
        """Statically scan attachment bytes and return a PhishingVerdict."""
        return self.scan_bytes_detailed(
            data=data,
            filename=filename,
            content_type=content_type,
            email_id=email_id,
        ).verdict

    def scan_bytes_detailed(
        self,
        data: bytes,
        filename: str,
        content_type: str = "application/octet-stream",
        email_id: Optional[str] = None,
    ) -> AttachmentScanResult:
        """Statically scan attachment bytes and return features, intel, and verdict."""
        features = AttachmentFeatureExtractor.extract(
            data=data,
            filename=filename,
            content_type=content_type,
        )
        signals = self._evaluate_features(features)
        ti_result, ti_signals = self._evaluate_hash_intel(features.sha256)
        signals.extend(ti_signals)

        verdict = self._synthesize_verdict(
            features=features,
            signals=signals,
            ti_result=ti_result,
            email_id=email_id,
        )
        return AttachmentScanResult(
            filename=features.filename,
            verdict=verdict,
            features=features,
            threat_intel=ti_result,
        )

    def scan_metadata(
        self,
        attachment: EmailAttachmentInfo,
        email_id: Optional[str] = None,
    ) -> PhishingVerdict:
        """Analyze attachment metadata (when raw bytes are unavailable)."""
        declared_ext = (
            attachment.extension.lower()
            if attachment.extension
            else AttachmentFeatureExtractor._extract_extension(attachment.filename)
        )
        features = AttachmentFeatures(
            filename=attachment.filename,
            declared_extension=declared_ext,
            claimed_content_type=attachment.content_type,
            detected_file_type="metadata_only",
            size_bytes=attachment.size_bytes,
            sha256=attachment.sha256 or "",
            md5=attachment.md5 or "",
            has_double_extension=AttachmentFeatureExtractor._has_double_extension(attachment.filename),
            has_rtlo_override=any(ch in attachment.filename for ch in _BIDI_OVERRIDE_CHARS),
            is_executable=attachment.is_executable or declared_ext in EXECUTABLE_EXTENSIONS,
            is_script=declared_ext in SCRIPT_EXTENSIONS,
            is_archive=attachment.is_archive or declared_ext in ARCHIVE_EXTENSIONS,
            is_macro_enabled=attachment.is_macro_enabled or declared_ext in MACRO_EXTENSIONS,
        )
        signals = self._evaluate_features(features)
        ti_result: Optional[ThreatIntelResult] = None
        if features.sha256:
            ti_result, ti_signals = self._evaluate_hash_intel(features.sha256)
            signals.extend(ti_signals)

        return self._synthesize_verdict(
            features=features,
            signals=signals,
            ti_result=ti_result,
            email_id=email_id,
        )

    # ------------------------------------------------------------------
    # Heuristic Signal Evaluation
    # ------------------------------------------------------------------

    def _evaluate_features(self, f: AttachmentFeatures) -> list[PhishingSignal]:
        signals: list[PhishingSignal] = []
        safe_name = safe_ascii(f.filename)

        # 1. Right-to-Left Override (RTLO) filename spoofing
        if f.has_rtlo_override:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="rtlo_filename_spoofing",
                description="Attachment filename contains Unicode bidirectional override characters (RTLO) used to visually disguise executable extensions",
                severity=PhishingSeverity.CRITICAL,
                score_contribution=50.0,
                evidence=f"Filename: {safe_name}",
                mitre_technique="T1036.007",
            ))

        # 2. Double extension masquerading
        if f.has_double_extension:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="double_extension_masquerading",
                description=f"Attachment '{safe_name}' uses a deceptive double extension to hide an executable or script payload behind a document/image lure",
                severity=PhishingSeverity.CRITICAL,
                score_contribution=45.0,
                evidence=f"Filename: {safe_name}, Declared ext: {f.declared_extension}",
                mitre_technique="T1036.007",
            ))

        # 3. Magic byte vs extension spoofing
        if f.is_extension_spoofed:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="magic_byte_extension_mismatch",
                description=f"Attachment binary header ({f.detected_file_type}) does not match declared extension '{f.declared_extension}' — strong file masquerading indicator",
                severity=PhishingSeverity.CRITICAL,
                score_contribution=50.0,
                evidence=f"File: {safe_name}, Declared: {f.declared_extension}, Detected: {f.detected_file_type}",
                mitre_technique="T1036.008",
            ))

        # 4. Executable / LNK / Disk image payload
        if f.is_executable:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="executable_attachment",
                description=f"Attachment '{safe_name}' is an executable binary, disk image, or shortcut payload",
                severity=PhishingSeverity.CRITICAL,
                score_contribution=45.0,
                evidence=f"File: {safe_name}, Type: {f.detected_file_type}, Ext: {f.declared_extension}",
                mitre_technique="T1566.001",
            ))

        # 5. Script payload (.ps1, .vbs, .js, .bat, .hta)
        if f.is_script:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="script_attachment",
                description=f"Attachment '{safe_name}' is a script file ({f.declared_extension}) capable of executing host commands",
                severity=PhishingSeverity.HIGH,
                score_contribution=40.0,
                evidence=f"File: {safe_name}, Ext: {f.declared_extension}",
                mitre_technique="T1059",
            ))

        # 6. Embedded VBA macros or macro-enabled document
        if f.has_embedded_macros:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="embedded_vba_macros",
                description=f"Document '{safe_name}' contains embedded VBA macro structures or OLE objects commonly used for initial malware execution",
                severity=PhishingSeverity.HIGH,
                score_contribution=40.0,
                evidence=f"File: {safe_name}, Type: {f.detected_file_type}",
                mitre_technique="T1566.001",
            ))
        elif f.is_macro_enabled:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="macro_capable_document_extension",
                description=f"Attachment '{safe_name}' uses a macro-capable Office format ({f.declared_extension})",
                severity=PhishingSeverity.MEDIUM,
                score_contribution=22.0,
                evidence=f"File: {safe_name}, Ext: {f.declared_extension}",
                mitre_technique="T1566.001",
            ))

        # 7. OOXML Remote Template Injection (T1221)
        if f.has_external_template:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="external_template_injection",
                description="Office OpenXML document references an external remote template or relationship target",
                severity=PhishingSeverity.CRITICAL,
                score_contribution=45.0,
                evidence=f"File: {safe_name}, Extracted external URLs: {', '.join(f.extracted_urls[:3])}",
                mitre_technique="T1221",
            ))

        # 8. Weaponized PDF active tags
        if f.has_pdf_active_content:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="weaponized_pdf_active_content",
                description="PDF attachment contains active scripting or automatic launch tags (/JavaScript, /Launch, /OpenAction, /EmbeddedFile)",
                severity=PhishingSeverity.HIGH,
                score_contribution=40.0,
                evidence=f"PDF file: {safe_name}",
                mitre_technique="T1204.002",
            ))

        # 9. HTML / SVG smuggling
        if f.has_html_smuggling:
            signals.append(PhishingSignal(
                category=SignalCategory.CONTENT_ANOMALY,
                name="html_svg_smuggling_indicators",
                description="HTML/SVG attachment contains client-side scripting, Blob assembly, or embedded credential form patterns",
                severity=PhishingSeverity.HIGH,
                score_contribution=38.0,
                evidence=f"File: {safe_name}, Type: {f.detected_file_type}",
                mitre_technique="T1027.006",
            ))

        # 10. Archive risks (encrypted bypass, suspicious nested payloads, zip bomb)
        if f.is_encrypted_archive:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="encrypted_archive_bypass",
                description="Archive contains password-protected/encrypted entries — a common technique to evade perimeter AV and email scanners",
                severity=PhishingSeverity.HIGH,
                score_contribution=35.0,
                evidence=f"Archive: {safe_name}",
                mitre_technique="T1566.001",
            ))

        if f.archive_suspicious_members:
            safe_members = [safe_ascii(m) for m in f.archive_suspicious_members[:5]]
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="archive_contains_dangerous_payload",
                description=f"Archive '{safe_name}' bundles {len(f.archive_suspicious_members)} executable, script, or nested archive member(s)",
                severity=PhishingSeverity.CRITICAL,
                score_contribution=45.0,
                evidence=f"Members: {', '.join(safe_members)}",
                mitre_technique="T1566.001",
            ))
        elif f.is_archive and not f.is_encrypted_archive:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="archive_attachment",
                description=f"Attachment '{safe_name}' is an archive container that can obscure payloads",
                severity=PhishingSeverity.LOW,
                score_contribution=15.0,
                evidence=f"Archive: {safe_name}, Members: {len(f.archive_members)}",
                mitre_technique="T1566.001",
            ))

        if f.is_zip_bomb_suspect:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="abnormal_archive_compression_ratio",
                description="Archive exhibits extreme compression ratio indicative of a zip-bomb / decompression exhaustion payload",
                severity=PhishingSeverity.HIGH,
                score_contribution=35.0,
                evidence=f"Archive: {safe_name}",
                mitre_technique="T1499",
            ))

        # 11. Suspicious static execution/staging strings
        if f.suspicious_strings:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="suspicious_static_execution_strings",
                description=f"Static inspection identified {len(f.suspicious_strings)} offensive execution or staging pattern(s)",
                severity=PhishingSeverity.HIGH,
                score_contribution=min(35.0, 20.0 + (len(f.suspicious_strings) - 1) * 8.0),
                evidence="; ".join(f.suspicious_strings[:4]),
                mitre_technique="T1059",
            ))

        # 12. High Shannon entropy on non-compressed formats
        naturally_compressed = {
            "zip_container", "ooxml_document", "rar_archive", "7z_archive",
            "gzip_archive", "png_image", "jpeg_image", "gif_image", "pdf",
            "metadata_only",
        }
        if f.size_bytes >= 256 and f.shannon_entropy >= 7.2 and f.detected_file_type not in naturally_compressed:
            signals.append(PhishingSignal(
                category=SignalCategory.ATTACHMENT_RISK,
                name="high_entropy_packed_payload",
                description=f"Attachment exhibits high Shannon entropy ({f.shannon_entropy:.2f}/8.0) suggesting packed, encrypted, or obfuscated content",
                severity=PhishingSeverity.MEDIUM,
                score_contribution=20.0,
                evidence=f"Entropy: {f.shannon_entropy:.2f}, Size: {f.size_bytes}B",
                mitre_technique="T1027.002",
            ))

        return signals

    def _evaluate_hash_intel(self, sha256: str) -> tuple[Optional[ThreatIntelResult], list[PhishingSignal]]:
        """Query cached hash reputation with bounded timeout & graceful degradation."""
        if not sha256:
            return None, []

        signals: list[PhishingSignal] = []
        cached = self.cache.get(sha256)
        if cached:
            ti_res = cached
        else:
            try:
                ti_res = self.hash_provider.lookup_hash(sha256, timeout=self.intel_timeout_seconds)
                self.cache.set(sha256, ti_res)
            except Exception as exc:
                logger.debug("Hash threat intel lookup degraded gracefully on '%s': %s", sha256[:12], exc)
                ti_res = ThreatIntelResult(
                    ioc=sha256,
                    is_malicious=False,
                    threat_score=0.0,
                    source="fallback_degraded",
                    details={"error": str(exc)},
                )

        if ti_res and ti_res.is_malicious:
            contrib = max(50.0, ti_res.threat_score)
            signals.append(PhishingSignal(
                category=SignalCategory.THREAT_INTEL_MATCH,
                name="attachment_hash_threat_intel_match",
                description=f"Attachment SHA-256 matched known malicious payload in threat intelligence ({ti_res.source})",
                severity=PhishingSeverity.CRITICAL,
                score_contribution=contrib,
                evidence=f"SHA256: {sha256[:16]}..., Positives: {ti_res.positives}/{ti_res.total_engines}",
                mitre_technique="T1204.002",
            ))

        return ti_res, signals

    # ------------------------------------------------------------------
    # Verdict Synthesis & Pipeline Mapping
    # ------------------------------------------------------------------

    def _synthesize_verdict(
        self,
        features: AttachmentFeatures,
        signals: list[PhishingSignal],
        ti_result: Optional[ThreatIntelResult],
        email_id: Optional[str] = None,
    ) -> PhishingVerdict:
        safe_name = safe_ascii(features.filename)

        if not signals:
            return PhishingVerdict(
                email_id=email_id,
                target_filename=features.filename,
                attachment_sha256=features.sha256 or None,
                analysis_type="attachment",
                score=0.0,
                severity=PhishingSeverity.SAFE,
                is_phishing=False,
                confidence=0.92,
                signals=[],
                explanation=(
                    f"Attachment '{safe_name}' ({features.detected_file_type}, {features.size_bytes} bytes) "
                    f"is clean — no dangerous extensions, spoofing, macros, active content, or hash matches detected."
                ),
                mitre_techniques=[],
            )

        raw_score = sum(s.score_contribution for s in signals)
        score = min(100.0, max(0.0, round(raw_score, 1)))

        if score >= self.SCORE_THRESHOLDS["critical"]:
            severity = PhishingSeverity.CRITICAL
        elif score >= self.SCORE_THRESHOLDS["high"]:
            severity = PhishingSeverity.HIGH
        elif score >= self.SCORE_THRESHOLDS["medium"]:
            severity = PhishingSeverity.MEDIUM
        elif score >= self.SCORE_THRESHOLDS["low"]:
            severity = PhishingSeverity.LOW
        else:
            severity = PhishingSeverity.SAFE

        is_phishing = score >= self.SCORE_THRESHOLDS["medium"]

        conf = 0.55 + min(0.30, len(signals) * 0.1)
        if ti_result and ti_result.is_malicious:
            conf = max(conf, 0.96)
        if any(s.severity == PhishingSeverity.CRITICAL for s in signals):
            conf = max(conf, 0.88)
        confidence = round(min(0.99, conf), 2)

        mitre_techniques = sorted({s.mitre_technique for s in signals if s.mitre_technique})

        lines = [
            f"Verdict: {severity.value.upper()} (Attachment Risk Score: {score:.1f}/100, Confidence: {int(confidence * 100)}%).",
            f"Analyzed Attachment: '{safe_name}' (Declared: '{features.declared_extension or 'none'}', Detected: '{features.detected_file_type}', Size: {features.size_bytes}B).",
            f"Identified {len(signals)} suspicious indicator(s):",
        ]
        for idx, sig in enumerate(signals, 1):
            lines.append(f"  [{idx}] {sig.name} ({sig.severity.value.upper()}): {sig.description}")
            if sig.evidence:
                lines.append(f"      Evidence: {sig.evidence}")

        if is_phishing:
            lines.append(
                "Recommendation: Quarantine attachment immediately; do NOT open or execute outside an isolated malware sandbox."
            )
        else:
            lines.append("Recommendation: Exercise caution and verify sender intent before opening.")

        return PhishingVerdict(
            email_id=email_id,
            target_filename=features.filename,
            attachment_sha256=features.sha256 or None,
            analysis_type="attachment",
            score=score,
            severity=severity,
            is_phishing=is_phishing,
            confidence=confidence,
            signals=signals,
            explanation="\n".join(lines),
            mitre_techniques=mitre_techniques,
        )

    def to_security_event(
        self,
        verdict: PhishingVerdict,
        features: Optional[AttachmentFeatures] = None,
        source_user: Optional[str] = None,
        host: Optional[str] = None,
    ) -> SecurityEvent:
        """Convert an attachment PhishingVerdict into a canonical SecurityEvent."""
        severity_map = {
            PhishingSeverity.SAFE: "low",
            PhishingSeverity.LOW: "low",
            PhishingSeverity.MEDIUM: "medium",
            PhishingSeverity.HIGH: "high",
            PhishingSeverity.CRITICAL: "critical",
        }
        return SecurityEvent(
            source="phishing",
            event_type="phishing_attachment_detected" if verdict.is_phishing else "phishing_attachment_scanned",
            severity=severity_map.get(verdict.severity, "low"),
            entity=Entity(
                ip=None,
                user=source_user,
                host=host or "mail-gateway",
                hash=verdict.attachment_sha256,
            ),
            raw=verdict.to_security_event_raw(),
            enrichment={
                "target_filename": safe_ascii(verdict.target_filename or ""),
                "attachment_sha256": verdict.attachment_sha256,
                "detected_file_type": features.detected_file_type if features else "unknown",
                "phishing_score": verdict.score,
                "signal_count": len(verdict.signals),
                "mitre_techniques": verdict.mitre_techniques,
            },
        )

