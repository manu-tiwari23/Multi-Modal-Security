"""
Forensic Metadata Extraction Engine.

Implements ARCHITECTURE.md §4.5, §8 and .agents/skills/forensics/SKILL.md:
- Extraction of document metadata (OOXML: Word/Excel/PowerPoint, and PDF).
- Extraction of raster/vector image metadata (EXIF, GPS, camera, software).
- PE binary compilation timestamps, machine architectures, and section metrics.
- PDF weaponization indicator detection (/Launch, /JS, /OpenAction).
- Filesystem MACB timestamp extraction.
- Optional integration with ExifTool CLI when present, with 100% pure-Python fallback.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.forensics.evidence_vault import calculate_hashes
from src.forensics.file_analyzer import calculate_entropy
from src.forensics.models import (
    DocumentMetadata,
    ExecutableMetadata,
    ExtractedMetadata,
    ImageMetadata,
)


# ---------------------------------------------------------------------------
# Date Parsing Helpers
# ---------------------------------------------------------------------------

def parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    """Parse ISO-8601 datetime strings into timezone-aware UTC datetime."""
    if not dt_str:
        return None
    try:
        # Normalize trailing Z to +00:00
        clean_str = dt_str.strip()
        if clean_str.endswith("Z"):
            clean_str = clean_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def parse_pdf_datetime(pdf_dt_str: str) -> Optional[datetime]:
    """Parse PDF date strings like 'D:20260822143000Z' or 'D:20260822143000+00'00''.
    
    Standard PDF format: D:YYYYMMDDHHmmSSOHH'mm'
    """
    if not pdf_dt_str:
        return None
    clean = pdf_dt_str.strip()
    if clean.startswith("D:"):
        clean = clean[2:]

    # Extract digits: YYYYMMDDHHmmSS
    match = re.match(r"^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", clean)
    if not match:
        return None

    groups = match.groups()
    year = int(groups[0])
    month = int(groups[1]) if groups[1] else 1
    day = int(groups[2]) if groups[2] else 1
    hour = int(groups[3]) if groups[3] else 0
    minute = int(groups[4]) if groups[4] else 0
    second = int(groups[5]) if groups[5] else 0

    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_exif_datetime(dt_str: str) -> Optional[datetime]:
    """Parse EXIF format dates like '2026:08:22 14:30:00' into UTC datetime."""
    if not dt_str or not isinstance(dt_str, str):
        return None
    try:
        # Format: 'YYYY:MM:DD HH:MM:SS'
        match = re.match(r"^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})", dt_str.strip())
        if match:
            y, m, d, H, M, S = [int(v) for v in match.groups()]
            return datetime(y, m, d, H, M, S, tzinfo=timezone.utc)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Format-Specific Pure-Python Parsers
# ---------------------------------------------------------------------------

class OOXMLMetadataParser:
    """Extract metadata from Office OpenXML archives (.docx, .xlsx, .pptx)."""

    NAMESPACES = {
        "dc": "http://purl.org/dc/elements/1.1/",
        "dcterms": "http://purl.org/dc/terms/",
        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
        "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    }

    @classmethod
    def parse(cls, data: bytes) -> Tuple[DocumentMetadata, List[str], Dict[str, Any]]:
        doc = DocumentMetadata()
        suspicious: List[str] = []
        raw: Dict[str, Any] = {}

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()

                # Check for VBA Macros
                macro_files = [n for n in names if "vbaProject.bin" in n or n.endswith(".vba")]
                if macro_files:
                    doc.has_javascript = False  # Not JS, but macro script
                    doc.embedded_scripts.extend(macro_files)
                    suspicious.append(f"VBA Macro project detected: {', '.join(macro_files)}")

                # Parse docProps/core.xml
                if "docProps/core.xml" in names:
                    core_xml = z.read("docProps/core.xml")
                    root = ET.fromstring(core_xml)

                    def get_text(ns: str, tag: str) -> Optional[str]:
                        elem = root.find(f"{ns}:{tag}", cls.NAMESPACES)
                        return elem.text if elem is not None and elem.text else None

                    doc.title = get_text("dc", "title")
                    doc.author = get_text("dc", "creator")
                    doc.last_modified_by = get_text("cp", "lastModifiedBy")
                    doc.revision = get_text("cp", "revision")
                    doc.language = get_text("dc", "language")

                    created_str = get_text("dcterms", "created")
                    if created_str:
                        doc.created_time = parse_iso_datetime(created_str)
                    mod_str = get_text("dcterms", "modified")
                    if mod_str:
                        doc.modified_time = parse_iso_datetime(mod_str)

                    raw["core_properties"] = {
                        "title": doc.title,
                        "author": doc.author,
                        "last_modified_by": doc.last_modified_by,
                        "revision": doc.revision,
                        "created": created_str,
                        "modified": mod_str,
                    }

                # Parse docProps/app.xml
                if "docProps/app.xml" in names:
                    app_xml = z.read("docProps/app.xml")
                    root = ET.fromstring(app_xml)
                    for child in root:
                        tag_name = child.tag.split("}")[-1]
                        raw[tag_name] = child.text
                        if tag_name == "Application":
                            doc.application = child.text
                        elif tag_name == "AppVersion":
                            doc.app_version = child.text
                        elif tag_name == "TotalTime" and child.text and child.text.isdigit():
                            doc.total_edit_time_minutes = int(child.text)
                        elif tag_name == "Pages" and child.text and child.text.isdigit():
                            doc.page_count = int(child.text)
                        elif tag_name == "Words" and child.text and child.text.isdigit():
                            doc.word_count = int(child.text)

        except Exception as e:
            raw["error"] = str(e)

        return doc, suspicious, raw


class PDFMetadataParser:
    """Extract metadata and weaponization signals from PDF documents."""

    @classmethod
    def parse(cls, data: bytes) -> Tuple[DocumentMetadata, List[str], Dict[str, Any]]:
        doc = DocumentMetadata()
        suspicious: List[str] = []
        raw: Dict[str, Any] = {}

        # 1. Weaponization detection
        if re.search(rb"/JavaScript|/JS\b", data):
            doc.has_javascript = True
            doc.embedded_scripts.append("Embedded PDF JavaScript (/JS or /JavaScript)")
            suspicious.append("CRITICAL: Embedded JavaScript detected inside PDF document!")

        if re.search(rb"/Launch\b", data):
            doc.has_launch_action = True
            suspicious.append("CRITICAL: Arbitrary Process Launch action (/Launch) detected inside PDF!")

        if re.search(rb"/OpenAction\b|/AA\b", data):
            suspicious.append("Automated OpenAction/AdditionalAction detected (triggers code on open).")

        if re.search(rb"/EmbeddedFiles\b", data):
            suspicious.append("Embedded binary payload stream (/EmbeddedFiles) detected.")

        # 2. Extract Info Dictionary
        info_match = re.search(rb"/Info\s+(\d+)\s+(\d+)\s+R", data)
        raw_info: Optional[bytes] = None
        if info_match:
            obj_id = info_match.group(1)
            # Find the object definition: obj_id 0 obj << ... >> endobj
            obj_pattern = re.compile(rb"\b" + obj_id + rb"\s+0\s+obj\s*<<(.*?)>>", re.DOTALL)
            found_obj = obj_pattern.search(data)
            if found_obj:
                raw_info = found_obj.group(1)

        # Fallback to direct << ... >> scan if /Info object not resolved
        if not raw_info:
            direct_info = re.search(rb"/Title\s*\(|/Author\s*\(|/Producer\s*\(", data)
            if direct_info:
                # Grab a 2048-byte window
                start = max(0, direct_info.start() - 50)
                raw_info = data[start : start + 2048]

        if raw_info:
            def extract_field(field_name: bytes) -> Optional[str]:
                pattern = re.compile(field_name + rb"\s*\((.*?)\)", re.DOTALL)
                m = pattern.search(raw_info)
                if m:
                    try:
                        return m.group(1).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                return None

            doc.title = extract_field(b"/Title")
            doc.author = extract_field(b"/Author")
            doc.creator = extract_field(b"/Creator")
            doc.producer = extract_field(b"/Producer")

            created_str = extract_field(b"/CreationDate")
            if created_str:
                doc.created_time = parse_pdf_datetime(created_str)
                raw["CreationDate"] = created_str

            mod_str = extract_field(b"/ModDate")
            if mod_str:
                doc.modified_time = parse_pdf_datetime(mod_str)
                raw["ModDate"] = mod_str

            raw["title"] = doc.title
            raw["author"] = doc.author
            raw["creator"] = doc.creator
            raw["producer"] = doc.producer

        return doc, suspicious, raw


class ImageEXIFParser:
    """Extract EXIF and camera/GPS metadata from JPEG and PNG images."""

    @classmethod
    def parse_jpeg(cls, data: bytes) -> Tuple[ImageMetadata, List[str], Dict[str, Any]]:
        img = ImageMetadata()
        suspicious: List[str] = []
        raw: Dict[str, Any] = {}

        # Scan for APP1 EXIF segment (\xFF\xE1)
        app1_idx = data.find(b"\xff\xe1")
        if app1_idx == -1 or len(data) < app1_idx + 14:
            return img, suspicious, raw

        length = struct.unpack(">H", data[app1_idx + 2 : app1_idx + 4])[0]
        exif_block = data[app1_idx + 4 : app1_idx + 2 + length]

        if not exif_block.startswith(b"Exif\x00\x00"):
            return img, suspicious, raw

        tiff_data = exif_block[6:]
        if len(tiff_data) < 8:
            return img, suspicious, raw

        byte_order = tiff_data[:2]
        endian = "<" if byte_order == b"II" else (">" if byte_order == b"MM" else None)
        if not endian:
            return img, suspicious, raw

        try:
            first_ifd_offset = struct.unpack_from(f"{endian}I", tiff_data, 4)[0]
            if first_ifd_offset + 2 > len(tiff_data):
                return img, suspicious, raw

            num_entries = struct.unpack_from(f"{endian}H", tiff_data, first_ifd_offset)[0]
            entry_offset = first_ifd_offset + 2

            gps_ifd_offset: Optional[int] = None

            for _ in range(num_entries):
                if entry_offset + 12 > len(tiff_data):
                    break
                tag, field_type, count, val_offset = struct.unpack_from(f"{endian}HHI I", tiff_data, entry_offset)
                entry_offset += 12

                # Helper to read ASCII values
                def read_ascii() -> str:
                    if count <= 4:
                        raw_bytes = struct.pack(f"{endian}I", val_offset)[:count]
                    else:
                        raw_bytes = tiff_data[val_offset : val_offset + count]
                    return raw_bytes.decode("ascii", errors="ignore").rstrip("\x00").strip()

                if tag == 0x010F:  # Make
                    img.make = read_ascii()
                elif tag == 0x0110:  # Model
                    img.model = read_ascii()
                elif tag == 0x0131:  # Software
                    img.software = read_ascii()
                elif tag == 0x013B:  # Artist
                    img.artist = read_ascii()
                elif tag == 0x8298:  # Copyright
                    img.copyright = read_ascii()
                elif tag == 0x0132 or tag == 0x9003:  # DateTime / DateTimeOriginal
                    dt_str = read_ascii()
                    img.date_time_original = parse_exif_datetime(dt_str)
                    raw["DateTimeOriginal"] = dt_str
                elif tag == 0x8825:  # GPS IFD offset
                    gps_ifd_offset = val_offset

            # Parse GPS IFD if present
            if gps_ifd_offset and gps_ifd_offset + 2 <= len(tiff_data):
                gps_entries = struct.unpack_from(f"{endian}H", tiff_data, gps_ifd_offset)[0]
                g_offset = gps_ifd_offset + 2
                lat_ref = "N"
                lon_ref = "E"
                lat_vals = None
                lon_vals = None

                for _ in range(gps_entries):
                    if g_offset + 12 > len(tiff_data):
                        break
                    gtag, gtype, gcount, gval = struct.unpack_from(f"{endian}HHI I", tiff_data, g_offset)
                    g_offset += 12

                    if gtag == 0x0001:  # Lat Ref
                        lat_ref = chr(gval & 0xFF)
                    elif gtag == 0x0003:  # Lon Ref
                        lon_ref = chr(gval & 0xFF)
                    elif gtag == 0x0002 and gval + 24 <= len(tiff_data):  # Latitude
                        d_num, d_den, m_num, m_den, s_num, s_den = struct.unpack_from(f"{endian}IIIIII", tiff_data, gval)
                        lat_vals = (d_num / (d_den or 1), m_num / (m_den or 1), s_num / (s_den or 1))
                    elif gtag == 0x0004 and gval + 24 <= len(tiff_data):  # Longitude
                        d_num, d_den, m_num, m_den, s_num, s_den = struct.unpack_from(f"{endian}IIIIII", tiff_data, gval)
                        lon_vals = (d_num / (d_den or 1), m_num / (m_den or 1), s_num / (s_den or 1))

                if lat_vals:
                    lat = lat_vals[0] + (lat_vals[1] / 60.0) + (lat_vals[2] / 3600.0)
                    img.gps_latitude = round(-lat if lat_ref.upper() == "S" else lat, 6)
                if lon_vals:
                    lon = lon_vals[0] + (lon_vals[1] / 60.0) + (lon_vals[2] / 3600.0)
                    img.gps_longitude = round(-lon if lon_ref.upper() == "W" else lon, 6)

        except Exception as e:
            raw["exif_parse_error"] = str(e)

        return img, suspicious, raw

    @classmethod
    def parse_png(cls, data: bytes) -> Tuple[ImageMetadata, List[str], Dict[str, Any]]:
        img = ImageMetadata()
        suspicious: List[str] = []
        raw: Dict[str, Any] = {}

        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return img, suspicious, raw

        offset = 8
        while offset + 8 <= len(data):
            chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
            chunk_type = data[offset + 4 : offset + 8]
            chunk_data = data[offset + 8 : offset + 8 + chunk_len]
            offset += 12 + chunk_len

            if chunk_type == b"IHDR" and len(chunk_data) >= 8:
                img.width_pixels, img.height_pixels = struct.unpack(">II", chunk_data[:8])
            elif chunk_type == b"tEXt":
                parts = chunk_data.split(b"\x00", 1)
                if len(parts) == 2:
                    k = parts[0].decode("ascii", errors="ignore").strip()
                    v = parts[1].decode("latin1", errors="ignore").strip()
                    raw[k] = v
                    if k.lower() == "software":
                        img.software = v
                    elif k.lower() in ("author", "artist"):
                        img.artist = v
                    elif k.lower() in ("creation time", "date"):
                        img.date_time_original = parse_iso_datetime(v) or parse_exif_datetime(v)
            elif chunk_type == b"IEND":
                break

        return img, suspicious, raw


class PEMetadataParser:
    """Extract compilation timestamps, target architecture, and section metrics from PE files."""

    MACHINE_TYPES = {
        0x014C: "Intel 386 (x86)",
        0x8664: "AMD64 (x64)",
        0xAA64: "ARM64",
        0x01C0: "ARM",
    }

    SUBSYSTEMS = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows CUI (Console)",
        7: "POSIX CUI",
        9: "Windows CE GUI",
        10: "EFI Application",
    }

    @classmethod
    def parse(cls, data: bytes) -> Tuple[ExecutableMetadata, List[str], Dict[str, Any]]:
        pe = ExecutableMetadata()
        suspicious: List[str] = []
        raw: Dict[str, Any] = {}

        if len(data) < 0x40 or not data.startswith(b"MZ"):
            return pe, suspicious, raw

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return pe, suspicious, raw

        # FileHeader starts right after 'PE\x00\x00' (4 bytes)
        file_header_offset = pe_offset + 4
        machine, num_sections, timedatestamp = struct.unpack_from("<HH I", data, file_header_offset)
        size_opt_header, characteristics = struct.unpack_from("<HH", data, file_header_offset + 16)

        pe.target_machine = cls.MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})")
        if timedatestamp > 0:
            try:
                pe.compile_time = datetime.fromtimestamp(timedatestamp, tz=timezone.utc)
            except (ValueError, OSError):
                pass

        raw["timedatestamp_raw"] = timedatestamp
        raw["number_of_sections"] = num_sections

        # Optional Header
        opt_header_offset = file_header_offset + 20
        if size_opt_header >= 68 and opt_header_offset + size_opt_header <= len(data):
            subsystem = struct.unpack_from("<H", data, opt_header_offset + 68)[0]
            pe.subsystem = cls.SUBSYSTEMS.get(subsystem, f"Unknown ({subsystem})")

        # Section Headers
        sections_offset = opt_header_offset + size_opt_header
        sections: List[Dict[str, Any]] = []

        for i in range(num_sections):
            sec_start = sections_offset + (i * 40)
            if sec_start + 40 > len(data):
                break
            sec_name_raw = data[sec_start : sec_start + 8].rstrip(b"\x00")
            sec_name = sec_name_raw.decode("ascii", errors="ignore")
            vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", data, sec_start + 8)

            # Compute section entropy to detect packed sections
            sec_bytes = data[raw_offset : raw_offset + raw_size] if raw_offset + raw_size <= len(data) else b""
            sec_entropy = calculate_entropy(sec_bytes) if sec_bytes else 0.0

            sec_info = {
                "name": sec_name,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "entropy": sec_entropy,
            }
            sections.append(sec_info)

            # Flag packed executable sections
            if sec_name.lower() in [".text", "code"] and sec_entropy > 7.1:
                suspicious.append(f"High entropy in executable section '{sec_name}' ({sec_entropy}/8.0) indicates packing/obfuscation.")

        pe.sections = sections

        # Version Info Strings scan (VS_VERSION_INFO / StringFileInfo)
        version_strings = [
            "CompanyName", "FileDescription", "FileVersion", "InternalName",
            "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion"
        ]
        for field in version_strings:
            pattern = re.compile(field.encode("utf-16le") + rb"\x00\x00([^\x00]{2,128})", re.IGNORECASE)
            match = pattern.search(data)
            if match:
                val = match.group(1).decode("utf-16le", errors="ignore").rstrip("\x00").strip()
                if field == "CompanyName":
                    pe.company_name = val
                elif field == "FileDescription":
                    pe.file_description = val
                elif field == "FileVersion":
                    pe.file_version = val
                elif field == "ProductName":
                    pe.product_name = val
                elif field == "ProductVersion":
                    pe.product_version = val
                elif field == "OriginalFilename":
                    pe.original_filename = val
                raw[field] = val

        return pe, suspicious, raw


# ---------------------------------------------------------------------------
# Metadata Extractor Orchestrator
# ---------------------------------------------------------------------------

class MetadataExtractor:
    """Forensic metadata extractor with multi-format support and ExifTool integration."""

    def __init__(self, prefer_exiftool: bool = False) -> None:
        self.exiftool_path = shutil.which("exiftool")
        self.prefer_exiftool = prefer_exiftool and bool(self.exiftool_path)

    def extract_from_bytes(self, data: bytes, filename: str) -> ExtractedMetadata:
        """Extract forensic metadata from raw byte buffer."""
        sha256, _, size = calculate_hashes(data)
        lower_name = filename.lower()

        doc_meta: Optional[DocumentMetadata] = None
        img_meta: Optional[ImageMetadata] = None
        exe_meta: Optional[ExecutableMetadata] = None
        suspicious: List[str] = []
        raw_meta: Dict[str, Any] = {}
        parser_used = "generic"
        file_format = "Unknown"

        # 1. Office OOXML Documents
        office_exts = [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".dotx", ".dotm", ".xltx", ".xltm", ".potx", ".potm", ".zip"]
        if any(lower_name.endswith(ext) for ext in office_exts) or (data.startswith(b"PK\x03\x04") and not lower_name.endswith((".jar", ".apk"))):
            if data.startswith(b"PK\x03\x04"):
                doc_meta, suspicious, raw_meta = OOXMLMetadataParser.parse(data)
                if doc_meta.title or doc_meta.author or doc_meta.application or suspicious:
                    parser_used = "internal_ooxml"
                    file_format = "Office OpenXML Document"
                else:
                    # Generic ZIP archive if no office XMLs detected
                    parser_used = "internal_zip"
                    file_format = "ZIP Archive"

        # 2. PDF Documents
        elif lower_name.endswith(".pdf") or data.startswith(b"%PDF-"):
            doc_meta, suspicious, raw_meta = PDFMetadataParser.parse(data)
            parser_used = "internal_pdf"
            file_format = "PDF Document"

        # 3. JPEG Images
        elif any(lower_name.endswith(ext) for ext in [".jpg", ".jpeg"]) or data.startswith(b"\xff\xd8\xff"):
            img_meta, suspicious, raw_meta = ImageEXIFParser.parse_jpeg(data)
            parser_used = "internal_exif"
            file_format = "JPEG Image"

        # 4. PNG Images
        elif lower_name.endswith(".png") or data.startswith(b"\x89PNG\r\n\x1a\n"):
            img_meta, suspicious, raw_meta = ImageEXIFParser.parse_png(data)
            parser_used = "internal_png"
            file_format = "PNG Image"

        # 5. PE Executables
        elif any(lower_name.endswith(ext) for ext in [".exe", ".dll", ".sys", ".scr"]) or data.startswith(b"MZ"):
            exe_meta, suspicious, raw_meta = PEMetadataParser.parse(data)
            parser_used = "internal_pe"
            file_format = "Windows PE Executable"

        # Summary Generation
        summary_tokens = [f"Metadata extracted from '{filename}' ({size} bytes, format: {file_format})."]
        if doc_meta:
            if doc_meta.author:
                summary_tokens.append(f"Author: '{doc_meta.author}'.")
            if doc_meta.created_time:
                summary_tokens.append(f"Created: {doc_meta.created_time.isoformat()}.")
        if img_meta:
            if img_meta.make and img_meta.model:
                summary_tokens.append(f"Camera: {img_meta.make} {img_meta.model}.")
            if img_meta.gps_latitude is not None and img_meta.gps_longitude is not None:
                summary_tokens.append(f"GPS Coordinates: ({img_meta.gps_latitude}, {img_meta.gps_longitude}).")
        if exe_meta:
            if exe_meta.compile_time:
                summary_tokens.append(f"Compile Timestamp: {exe_meta.compile_time.isoformat()}.")
            if exe_meta.target_machine:
                summary_tokens.append(f"Architecture: {exe_meta.target_machine}.")
        if suspicious:
            summary_tokens.append(f"Alert: {len(suspicious)} suspicious forensic artifact(s) identified.")

        return ExtractedMetadata(
            filename=filename,
            file_format=file_format,
            file_size_bytes=size,
            sha256=sha256,
            parser_used=parser_used,
            document=doc_meta,
            image=img_meta,
            executable=exe_meta,
            filesystem_timestamps={},
            raw_metadata=raw_meta,
            suspicious_artifacts=suspicious,
            summary=" ".join(summary_tokens),
        )

    def extract_from_file(self, file_path: Union[str, Path]) -> ExtractedMetadata:
        """Extract metadata from physical disk file including filesystem MACB timestamps."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: '{path}'")

        # ExifTool CLI integration if requested and available
        if self.prefer_exiftool and self.exiftool_path:
            try:
                res = subprocess.run(
                    [self.exiftool_path, "-json", "-fast2", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                if res.returncode == 0:
                    records = json.loads(res.stdout)
                    if records:
                        return self._map_exiftool_record(records[0], path)
            except Exception:
                pass  # Fallback to internal pure-Python parser

        data = path.read_bytes()
        extracted = self.extract_from_bytes(data, filename=path.name)

        # Append filesystem MACB timestamps
        try:
            stat = path.stat()
            fs_times: Dict[str, Optional[datetime]] = {
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                "accessed": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc),
                "changed_or_created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc),
            }
            if hasattr(stat, "st_birthtime"):
                fs_times["birth"] = datetime.fromtimestamp(stat.st_birthtime, tz=timezone.utc)
            extracted.filesystem_timestamps = fs_times
        except Exception:
            pass

        return extracted

    def _map_exiftool_record(self, record: Dict[str, Any], path: Path) -> ExtractedMetadata:
        """Map raw JSON output from ExifTool CLI into canonical ExtractedMetadata model."""
        filename = path.name
        sha256, _, size = calculate_hashes(path)
        file_format = record.get("FileType", "Unknown")

        doc = DocumentMetadata(
            title=record.get("Title"),
            author=record.get("Author") or record.get("Creator"),
            created_time=parse_iso_datetime(record.get("CreateDate")),
            modified_time=parse_iso_datetime(record.get("ModifyDate")),
            application=record.get("Software") or record.get("Application"),
            producer=record.get("Producer"),
        )

        img = ImageMetadata(
            make=record.get("Make"),
            model=record.get("Model"),
            software=record.get("Software"),
            date_time_original=parse_iso_datetime(record.get("DateTimeOriginal")),
            gps_latitude=record.get("GPSLatitude"),
            gps_longitude=record.get("GPSLongitude"),
        )

        return ExtractedMetadata(
            filename=filename,
            file_format=file_format,
            file_size_bytes=size,
            sha256=sha256,
            parser_used="exiftool",
            document=doc,
            image=img,
            raw_metadata=record,
            summary=f"ExifTool extracted metadata for '{filename}' ({file_format}).",
        )
