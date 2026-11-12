"""
Unit tests for Forensic File Analysis and Deleted File Recovery.

Verifies:
1. Shannon entropy calculation across plain, structured, and random bytes.
2. File format magic byte identification.
3. Extension spoofing detection (e.g., PE disguised as PDF/PNG).
4. Printable string (ASCII & UTF-16LE) and IOC extraction (IP, URL, Email).
5. Malicious command patterns and embedded Base64 payload decoding.
6. Signature-based file carving from composite binary dumps.
7. Windows Recycle Bin ($I/$R) metadata parsing and deleted file recovery.
8. Linux / FreeDesktop .trashinfo deleted file recovery.
"""

import os
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.forensics.file_analyzer import (
    FileAnalyzer,
    calculate_entropy,
    extract_iocs_from_text,
    extract_printable_strings,
    parse_linux_trashinfo,
    parse_windows_recycle_i_file,
)
from src.forensics.models import (
    FileAnalysisResult,
    RecycleBinRecord,
)


class TestFileAnalyzer:
    """Test suite for forensic file analysis and deleted file recovery."""

    def test_calculate_entropy(self):
        """Verify Shannon entropy accurately distinguishes plain text from random data."""
        # Empty
        assert calculate_entropy(b"") == 0.0

        # Uniform low entropy
        low_entropy = calculate_entropy(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        assert low_entropy == 0.0

        # Typical text (entropy around 3.5 - 4.5)
        text_entropy = calculate_entropy(b"The quick brown fox jumps over the lazy dog repeatedly for entropy testing.")
        assert 3.0 < text_entropy < 5.0

        # Pseudo-random / compressed bytes (entropy close to 8.0)
        random_bytes = os.urandom(2048)
        high_entropy = calculate_entropy(random_bytes)
        assert high_entropy > 7.5

    def test_identify_magic_pe_executable(self):
        """Verify Windows PE header detection including e_lfanew offset."""
        analyzer = FileAnalyzer()

        # Build minimal synthetic PE header
        pe_header = bytearray(b"MZ" + b"\x00" * 58)  # up to 0x3C
        pe_header += struct.pack("<I", 0x40)  # PE offset at 0x40
        pe_header += b"PE\x00\x00" + b"\x00" * 100

        sig_type, is_exec, valid_exts = analyzer.identify_magic(bytes(pe_header))
        assert "Windows Executable" in sig_type
        assert is_exec is True
        assert ".exe" in valid_exts

    def test_identify_magic_elf_and_pdf(self):
        """Verify ELF binary and PDF document header identification."""
        analyzer = FileAnalyzer()

        elf_data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64
        sig_type, is_exec, _ = analyzer.identify_magic(elf_data)
        assert "Linux ELF" in sig_type
        assert is_exec is True

        pdf_data = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"\x00" * 64
        sig_type, is_exec, exts = analyzer.identify_magic(pdf_data)
        assert "PDF Document" in sig_type
        assert is_exec is False
        assert ".pdf" in exts

    def test_extension_spoofing_detection(self):
        """Verify critical detection when an executable is disguised as an invoice PDF."""
        analyzer = FileAnalyzer()

        # Synthetic PE binary named invoice.pdf
        pe_header = bytearray(b"MZ" + b"\x00" * 58)
        pe_header += struct.pack("<I", 0x40)
        pe_header += b"PE\x00\x00" + b"\x00" * 200

        result = analyzer.analyze_bytes(bytes(pe_header), filename="invoice_2026.pdf")
        assert result.is_extension_spoofed is True
        assert any(ind.category == "extension_spoofing" and ind.severity == "critical" for ind in result.suspicious_indicators)

    def test_extract_printable_strings_ascii_and_utf16(self):
        """Verify extraction of both ASCII and UTF-16LE strings."""
        data = b"ASCII_STRING_ONE\x00\x00" + "UTF16_STRING_TWO".encode("utf-16le") + b"\x00\x00"
        extracted = extract_printable_strings(data)
        assert "ASCII_STRING_ONE" in extracted
        assert "UTF16_STRING_TWO" in extracted

    def test_extract_iocs_from_text(self):
        """Verify regex extraction of IPs, URLs, and emails."""
        text = (
            "Attacker dropped stage 2 from http://c2.malicious-domain.com/payload.bin "
            "communicating with 198.51.100.25 and backup 203.0.113.10. "
            "Exfiltration recipient is drop@exfil-service.org."
        )
        iocs = extract_iocs_from_text(text)
        assert "198.51.100.25" in iocs["ips"]
        assert "203.0.113.10" in iocs["ips"]
        assert "http://c2.malicious-domain.com/payload.bin" in iocs["urls"]
        assert "drop@exfil-service.org" in iocs["emails"]

    def test_malicious_command_detection(self):
        """Verify suspicious command token detection like volume shadow deletion and mimikatz."""
        analyzer = FileAnalyzer()
        script_data = (
            b"#!/bin/bash\n"
            b"# Ransomware deployment script\n"
            b"vssadmin.exe delete shadows /all /quiet\n"
            b"powershell.exe -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n"
            b"sekurlsa::logonpasswords\n"
        )
        result = analyzer.analyze_bytes(script_data, filename="deploy.sh")

        cats = [ind.category for ind in result.suspicious_indicators]
        assert "malicious_string" in cats

        descriptions = " ".join([ind.description for ind in result.suspicious_indicators])
        assert "Volume Shadow Copy Deletion" in descriptions
        assert "Credential Dumping" in descriptions
        assert "Hidden Window PowerShell Launch" in descriptions

    def test_signature_based_file_carving(self):
        """Verify file carving finds and extracts embedded JPEG and PDF from binary padding."""
        analyzer = FileAnalyzer()

        # Build raw binary stream containing junk, then a JPEG, then junk, then a PDF
        junk1 = b"\x00\x11\x22\x33" * 50
        jpeg_content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"\xaa" * 100) + b"\xff\xd9"
        junk2 = b"\x44\x55\x66\x77" * 30
        pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF"

        stream = junk1 + jpeg_content + junk2 + pdf_content

        with tempfile.TemporaryDirectory() as tmp_dir:
            carved = analyzer.carve_files(stream, output_dir=tmp_dir)

            assert len(carved) >= 2
            carved_types = [c.file_type for c in carved]
            assert any("JPEG" in t for t in carved_types)
            assert any("PDF" in t for t in carved_types)

            # Check that files were written to disk
            files = list(Path(tmp_dir).iterdir())
            assert len(files) >= 2
            assert any(".jpg" in f.name for f in files)
            assert any(".pdf" in f.name for f in files)

    def test_parse_windows_recycle_bin_i_file(self):
        """Verify parsing Windows Recycle Bin $I index metadata."""
        # Version 2 (Windows 10/11)
        version = 2
        file_size = 1048576  # 1 MB

        # 2026-08-20 12:00:00 UTC in Windows FILETIME:
        # 11644473600 + unix_time(1787227200) = 13431700800 * 10_000_000
        unix_ts = int(datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc).timestamp())
        filetime = (unix_ts + 11644473600) * 10_000_000

        orig_path = r"C:\Users\Victim\Documents\SecretBudget.xlsx"
        path_bytes = orig_path.encode("utf-16le") + b"\x00\x00"

        raw_i_data = (
            struct.pack("<Q", version)
            + struct.pack("<Q", file_size)
            + struct.pack("<Q", filetime)
            + struct.pack("<I", len(orig_path))
            + path_bytes
        )

        record = parse_windows_recycle_i_file(raw_i_data, source_name="$ISOMERANDOM.xlsx")
        assert record is not None
        assert record.original_path == orig_path
        assert record.recovered_filename == "SecretBudget.xlsx"
        assert record.file_size_bytes == 1048576
        assert record.recovered_data_file == "$RSOMERANDOM.xlsx"
        assert record.deletion_time is not None
        assert record.deletion_time.year == 2026
        assert record.deletion_time.month == 8

    def test_recover_deleted_from_directory(self):
        """Verify end-to-end deleted file recovery from simulated $Recycle.Bin folder."""
        analyzer = FileAnalyzer()

        with tempfile.TemporaryDirectory() as recycle_dir, tempfile.TemporaryDirectory() as recover_dir:
            rec_path = Path(recycle_dir)
            out_path = Path(recover_dir)

            # Create matching $I and $R pair
            version = 2
            file_size = 35
            filetime = (1787227200 + 11644473600) * 10_000_000
            orig_path = r"C:\Accounting\Q3_Report.docx"
            path_bytes = orig_path.encode("utf-16le") + b"\x00\x00"

            i_data = (
                struct.pack("<Q", version)
                + struct.pack("<Q", file_size)
                + struct.pack("<Q", filetime)
                + struct.pack("<I", len(orig_path))
                + path_bytes
            )

            (rec_path / "$IAB12CD.docx").write_bytes(i_data)
            (rec_path / "$RAB12CD.docx").write_bytes(b"Restored deleted document content!!")

            recovered_records = analyzer.recover_deleted_from_directory(rec_path, recovery_dir=out_path)

            assert len(recovered_records) == 1
            assert recovered_records[0].recovered_filename == "Q3_Report.docx"

            # Check restored file exists with original name
            restored_file = out_path / "Q3_Report.docx"
            assert restored_file.is_file()
            assert restored_file.read_bytes() == b"Restored deleted document content!!"

    def test_parse_linux_trashinfo(self):
        """Verify Linux/FreeDesktop .trashinfo parser."""
        trashinfo_content = (
            "[Trash Info]\n"
            "Path=/home/analyst/evidence_dump.csv\n"
            "DeletionDate=2026-08-22T14:30:00\n"
        )
        record = parse_linux_trashinfo(trashinfo_content, source_name="evidence_dump.csv.trashinfo")
        assert record is not None
        assert record.original_path == "/home/analyst/evidence_dump.csv"
        assert record.recovered_filename == "evidence_dump.csv"
        assert record.deletion_time.year == 2026

    def test_analyze_file_from_disk(self):
        """Verify full file analysis from physical disk path."""
        analyzer = FileAnalyzer()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(
                b"Forensic sample report text.\n"
                b"IOC IP: 192.0.2.1\n"
                b"Command: powershell -enc dGVzdA==\n"
            )
            tmp_path = Path(tmp.name)

        try:
            result = analyzer.analyze_file(tmp_path)
            assert isinstance(result, FileAnalysisResult)
            assert result.filename == tmp_path.name
            assert "192.0.2.1" in result.extracted_iocs["ips"]
            assert result.shannon_entropy > 0.0
            assert "Analyzed" in result.summary
        finally:
            tmp_path.unlink(missing_ok=True)
