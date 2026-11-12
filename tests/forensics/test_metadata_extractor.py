"""
Unit tests for Forensic Metadata Extraction.

Verifies:
1. Office OOXML (.docx/.xlsx/.pptx) author, modification date, app, and revision parsing.
2. Office document VBA macro detection.
3. PDF metadata (Title, Author, CreationDate) parsing.
4. PDF weaponization indicators (/JavaScript, /Launch, /OpenAction).
5. Image EXIF metadata (Camera Make/Model, Software, DateTimeOriginal, GPS coordinates).
6. PNG image dimensions and tEXt chunks (Software, Author).
7. Windows PE compilation timestamps, target architecture, and section metrics.
8. Physical file MACB timestamp extraction.
9. ExifTool JSON mapping fallback.
"""

import io
import struct
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.forensics.metadata_extractor import (
    ImageEXIFParser,
    MetadataExtractor,
    OOXMLMetadataParser,
    PDFMetadataParser,
    PEMetadataParser,
    parse_exif_datetime,
    parse_iso_datetime,
    parse_pdf_datetime,
)
from src.forensics.models import ExtractedMetadata


class TestMetadataExtractor:
    """Test suite for forensic metadata extraction across document, image, and binary formats."""

    def test_date_parsers(self):
        """Verify datetime parsing across ISO, PDF, and EXIF formats."""
        # ISO
        iso_dt = parse_iso_datetime("2026-08-20T10:15:30Z")
        assert iso_dt is not None
        assert iso_dt.year == 2026
        assert iso_dt.tzinfo == timezone.utc

        # PDF format: D:YYYYMMDDHHmmSSZ
        pdf_dt = parse_pdf_datetime("D:20260822143000Z")
        assert pdf_dt is not None
        assert pdf_dt.year == 2026
        assert pdf_dt.month == 8
        assert pdf_dt.day == 22
        assert pdf_dt.hour == 14
        assert pdf_dt.minute == 30

        # EXIF format: YYYY:MM:DD HH:MM:SS
        exif_dt = parse_exif_datetime("2026:08:22 15:45:00")
        assert exif_dt is not None
        assert exif_dt.year == 2026
        assert exif_dt.hour == 15
        assert exif_dt.minute == 45

    def test_ooxml_document_metadata_extraction(self):
        """Verify extraction of core and extended properties from an Office document (.docx)."""
        extractor = MetadataExtractor()

        # Build in-memory synthetic docx ZIP
        core_xml = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            b'<dc:title>Q3 Threat Assessment</dc:title>'
            b'<dc:creator>Alice Investigator</dc:creator>'
            b'<cp:lastModifiedBy>Bob Analyst</cp:lastModifiedBy>'
            b'<cp:revision>5</cp:revision>'
            b'<dcterms:created>2026-08-20T09:30:00Z</dcterms:created>'
            b'<dcterms:modified>2026-08-21T11:00:00Z</dcterms:modified>'
            b'</cp:coreProperties>'
        )

        app_xml = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            b'<Application>Microsoft Office Word</Application>'
            b'<AppVersion>16.0000</AppVersion>'
            b'<Pages>12</Pages>'
            b'<Words>4500</Words>'
            b'<TotalTime>65</TotalTime>'
            b'</Properties>'
        )

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            z.writestr("docProps/core.xml", core_xml)
            z.writestr("docProps/app.xml", app_xml)
            z.writestr("word/document.xml", b"<document>Sample Content</document>")

        data = zip_buf.getvalue()
        meta = extractor.extract_from_bytes(data, filename="report.docx")

        assert meta.parser_used == "internal_ooxml"
        assert meta.document is not None
        assert meta.document.title == "Q3 Threat Assessment"
        assert meta.document.author == "Alice Investigator"
        assert meta.document.last_modified_by == "Bob Analyst"
        assert meta.document.revision == "5"
        assert meta.document.application == "Microsoft Office Word"
        assert meta.document.page_count == 12
        assert meta.document.word_count == 4500
        assert meta.document.total_edit_time_minutes == 65
        assert meta.document.created_time.year == 2026
        assert len(meta.suspicious_artifacts) == 0

    def test_ooxml_vba_macro_detection(self):
        """Verify detection of embedded VBA macro project in Word/Excel documents."""
        extractor = MetadataExtractor()

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            z.writestr("docProps/core.xml", b"<cp:coreProperties></cp:coreProperties>")
            z.writestr("word/vbaProject.bin", b"VBA_BINARY_BLOB_CODE")

        meta = extractor.extract_from_bytes(zip_buf.getvalue(), filename="invoice.docm")
        assert any("VBA Macro" in s for s in meta.suspicious_artifacts)
        assert "word/vbaProject.bin" in meta.document.embedded_scripts

    def test_pdf_metadata_extraction(self):
        """Verify extraction of standard PDF /Info dictionary attributes."""
        extractor = MetadataExtractor()

        pdf_content = (
            b"%PDF-1.7\n"
            b"1 0 obj\n"
            b"<< /Title (Executive Confidential Report) /Author (Eve Attacker) "
            b"/Creator (Acrobat PDF Maker) /Producer (Skia/PDF m120) "
            b"/CreationDate (D:20260822100000Z) >>\n"
            b"endobj\n"
            b"trailer << /Info 1 0 R >>\n"
            b"%%EOF"
        )

        meta = extractor.extract_from_bytes(pdf_content, filename="executive.pdf")
        assert meta.parser_used == "internal_pdf"
        assert meta.document is not None
        assert meta.document.title == "Executive Confidential Report"
        assert meta.document.author == "Eve Attacker"
        assert meta.document.creator == "Acrobat PDF Maker"
        assert meta.document.producer == "Skia/PDF m120"
        assert meta.document.created_time.year == 2026

    def test_pdf_weaponization_indicators(self):
        """Verify critical detection of /JavaScript and /Launch actions in weaponized PDFs."""
        extractor = MetadataExtractor()

        malicious_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
            b"2 0 obj << /S /JavaScript /JS (app.alert('Compromised');) >> endobj\n"
            b"3 0 obj << /S /Launch /F (cmd.exe) >> endobj\n"
            b"%%EOF"
        )

        meta = extractor.extract_from_bytes(malicious_pdf, filename="payload.pdf")
        assert meta.document.has_javascript is True
        assert meta.document.has_launch_action is True
        assert any("JavaScript" in s for s in meta.suspicious_artifacts)
        assert any("Launch" in s for s in meta.suspicious_artifacts)
        assert any("OpenAction" in s for s in meta.suspicious_artifacts)

    def test_jpeg_exif_and_gps_parsing(self):
        """Verify JPEG EXIF parsing including Camera Make/Model and GPS coordinates."""
        extractor = MetadataExtractor()

        # Construct synthetic TIFF EXIF payload
        endian = "<"
        tiff_header = b"II\x2a\x00\x08\x00\x00\x00"  # Little-endian, offset to IFD 0 is 8

        # IFD 0: Make (0x010F), Model (0x0110), Software (0x0131), DateTimeOriginal (0x9003), GPS IFD (0x8825)
        # Entry format: Tag (2B), Type (2B: 2=ASCII, 4=LONG), Count (4B), Value/Offset (4B)
        num_entries = 5
        ifd0_entries = struct.pack(f"{endian}H", num_entries)

        # Offsets for string values after IFD block
        # IFD0 starts at 8, length = 2 + (5 * 12) + 4 = 66 -> offset 74
        make_str = b"Sony\x00"
        model_str = b"Alpha 7 IV\x00"
        software_str = b"v2.01\x00"
        dt_str = b"2026:08:22 12:30:00\x00"

        val_offset = 74
        off_make = val_offset
        val_offset += len(make_str)
        off_model = val_offset
        val_offset += len(model_str)
        off_software = val_offset
        val_offset += len(software_str)
        off_dt = val_offset
        val_offset += len(dt_str)

        # GPS IFD offset
        gps_ifd_offset = val_offset
        # GPS entries: LatRef (N), Lat (3 rational numbers = 24B), LonRef (W), Lon (24B)
        # GPS IFD size: 2 + (4 * 12) + 4 = 54B
        gps_data_offset = gps_ifd_offset + 54

        ifd0_entries += struct.pack(f"{endian}HHI I", 0x010F, 2, len(make_str), off_make)
        ifd0_entries += struct.pack(f"{endian}HHI I", 0x0110, 2, len(model_str), off_model)
        ifd0_entries += struct.pack(f"{endian}HHI I", 0x0131, 2, len(software_str), off_software)
        ifd0_entries += struct.pack(f"{endian}HHI I", 0x9003, 2, len(dt_str), off_dt)
        ifd0_entries += struct.pack(f"{endian}HHI I", 0x8825, 4, 1, gps_ifd_offset)
        ifd0_entries += struct.pack(f"{endian}I", 0)  # Next IFD = 0

        # Construct strings block
        strings_block = make_str + model_str + software_str + dt_str

        # GPS IFD
        gps_num_entries = 4
        gps_ifd = struct.pack(f"{endian}H", gps_num_entries)
        # LatRef = 'N'
        gps_ifd += struct.pack(f"{endian}HHI I", 0x0001, 2, 2, ord("N"))
        # Lat data offset
        off_lat = gps_data_offset
        gps_ifd += struct.pack(f"{endian}HHI I", 0x0002, 5, 3, off_lat)
        # LonRef = 'W'
        gps_ifd += struct.pack(f"{endian}HHI I", 0x0003, 2, 2, ord("W"))
        # Lon data offset
        off_lon = off_lat + 24
        gps_ifd += struct.pack(f"{endian}HHI I", 0x0004, 5, 3, off_lon)
        gps_ifd += struct.pack(f"{endian}I", 0)

        # 37 deg 46 min 30 sec = 37.775
        lat_rationals = struct.pack(f"{endian}IIIIII", 37, 1, 46, 1, 30, 1)
        # 122 deg 25 min 0 sec = 122.416667
        lon_rationals = struct.pack(f"{endian}IIIIII", 122, 1, 25, 1, 0, 1)

        gps_data = lat_rationals + lon_rationals

        tiff_payload = tiff_header + ifd0_entries + strings_block + gps_ifd + gps_data
        exif_marker = b"\xff\xe1" + struct.pack(">H", len(tiff_payload) + 8) + b"Exif\x00\x00" + tiff_payload
        jpeg_data = b"\xff\xd8" + exif_marker + b"\xff\xd9"

        meta = extractor.extract_from_bytes(jpeg_data, filename="scene.jpg")
        assert meta.parser_used == "internal_exif"
        assert meta.image is not None
        assert meta.image.make == "Sony"
        assert meta.image.model == "Alpha 7 IV"
        assert meta.image.software == "v2.01"
        assert meta.image.date_time_original.year == 2026
        assert meta.image.gps_latitude is not None
        assert 37.77 < meta.image.gps_latitude < 37.78
        assert meta.image.gps_longitude is not None
        assert -122.42 < meta.image.gps_longitude < -122.41  # West is negative

    def test_png_metadata_and_dimensions(self):
        """Verify PNG image dimension and text metadata chunk extraction."""
        extractor = MetadataExtractor()

        # Build minimal PNG
        header = b"\x89PNG\r\n\x1a\n"
        # IHDR: width=1920, height=1080
        ihdr_data = struct.pack(">IIBBBBB", 1920, 1080, 8, 2, 0, 0, 0)
        ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"

        # tEXt: Software=ForensicsSuite
        text_data = b"Software\x00ForensicsSuite v3.2"
        text_chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data + b"\x00\x00\x00\x00"

        # IEND
        iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"

        png_data = header + ihdr_chunk + text_chunk + iend_chunk
        meta = extractor.extract_from_bytes(png_data, filename="screenshot.png")

        assert meta.parser_used == "internal_png"
        assert meta.image is not None
        assert meta.image.width_pixels == 1920
        assert meta.image.height_pixels == 1080
        assert meta.image.software == "ForensicsSuite v3.2"

    def test_pe_executable_metadata(self):
        """Verify extraction of PE compilation timestamp, machine type, and section entropy."""
        extractor = MetadataExtractor()

        # Synthetic PE binary
        pe_offset = 0x80
        data = bytearray(b"MZ" + b"\x00" * (pe_offset - 2))

        # PE signature
        data[0x3C:0x40] = struct.pack("<I", pe_offset)
        data += b"PE\x00\x00"

        # FileHeader: Machine=0x8664 (AMD64), num_sections=1, TimeDateStamp=1787227200 (Aug 2026)
        # SizeOfOptionalHeader = 224 (0xE0)
        timedatestamp = 1787227200
        file_header = struct.pack("<HH I II HH", 0x8664, 1, timedatestamp, 0, 0, 224, 0x0002)
        data += file_header

        # OptionalHeader: Subsystem at offset 68 (2 = Windows GUI)
        opt_header = bytearray(b"\x00" * 224)
        opt_header[68:70] = struct.pack("<H", 2)
        data += opt_header

        # SectionHeader for .text (40 bytes)
        # Name (8B), VirtualSize(4B), VirtualAddr(4B), RawSize(4B), RawOffset(4B)
        raw_sec_offset = len(data) + 40
        sec_bytes = b"\x90" * 512  # NOP sled
        sec_header = struct.pack("<8sIIII12sI", b".text\x00\x00\x00", 512, 0x1000, 512, raw_sec_offset, b"\x00" * 12, 0x60000020)
        data += sec_header
        data += sec_bytes

        meta = extractor.extract_from_bytes(bytes(data), filename="agent.exe")
        assert meta.parser_used == "internal_pe"
        assert meta.executable is not None
        assert meta.executable.target_machine == "AMD64 (x64)"
        assert meta.executable.subsystem == "Windows GUI"
        assert meta.executable.compile_time.year == 2026
        assert len(meta.executable.sections) == 1
        assert meta.executable.sections[0]["name"] == ".text"

    def test_extract_from_file_with_macb_timestamps(self):
        """Verify extraction from physical disk file attaches filesystem MACB timestamps."""
        extractor = MetadataExtractor()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(b"Evidence file on local drive for MACB verification.")
            tmp_path = Path(tmp.name)

        try:
            meta = extractor.extract_from_file(tmp_path)
            assert isinstance(meta, ExtractedMetadata)
            assert "modified" in meta.filesystem_timestamps
            assert meta.filesystem_timestamps["modified"] is not None
            assert meta.filesystem_timestamps["modified"].tzinfo == timezone.utc
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_exiftool_record_mapping(self):
        """Verify mapping of ExifTool CLI JSON records into ExtractedMetadata."""
        extractor = MetadataExtractor()

        fake_record = {
            "FileType": "PDF",
            "Title": "Investigative Findings",
            "Author": "Special Agent Smith",
            "CreateDate": "2026-08-20T10:00:00Z",
            "Software": "LibreOffice 24.2",
            "Make": "Canon",
            "Model": "EOS R5",
            "GPSLatitude": 40.7128,
            "GPSLongitude": -74.0060,
        }

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(b"%PDF-1.4\n%%EOF")
            tmp_path = Path(tmp.name)

        try:
            mapped = extractor._map_exiftool_record(fake_record, tmp_path)
            assert mapped.parser_used == "exiftool"
            assert mapped.document.title == "Investigative Findings"
            assert mapped.document.author == "Special Agent Smith"
            assert mapped.image.make == "Canon"
            assert mapped.image.gps_latitude == 40.7128
        finally:
            tmp_path.unlink(missing_ok=True)
