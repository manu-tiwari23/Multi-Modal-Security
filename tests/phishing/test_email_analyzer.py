"""
Unit tests for Phishing Detection — Email Header & Content Analyzer.

Uses only synthetic/mock phishing and legitimate email samples as required
by AGENTS.md security guardrails (no real victim data).
"""

import pytest

from src.phishing.email_analyzer import (
    ARCHIVE_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    FREE_EMAIL_PROVIDERS,
    MACRO_EXTENSIONS,
    URL_SHORTENERS,
    EmailAnalyzer,
    EmailParser,
)
from src.phishing.models import (
    EmailAttachmentInfo,
    EmailBody,
    EmailHeader,
    ParsedEmail,
    PhishingSeverity,
    PhishingSignal,
    PhishingVerdict,
    SignalCategory,
)


# ---------------------------------------------------------------------------
# Helpers — synthetic email builders
# ---------------------------------------------------------------------------

def _build_email(
    from_addr: str = "sender@example.com",
    from_display: str | None = None,
    to: str = "victim@company.com",
    subject: str = "Test Email",
    body_text: str | None = "Hello, this is a test.",
    body_html: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
    spf: str | None = None,
    dkim: str | None = None,
    dmarc: str | None = None,
    urls: list[str] | None = None,
    attachments: list[EmailAttachmentInfo] | None = None,
    received_chain: list[str] | None = None,
) -> ParsedEmail:
    """Build a synthetic ParsedEmail for testing."""
    header = EmailHeader(
        from_address=from_addr,
        from_display_name=from_display,
        to_addresses=[to],
        subject=subject,
        reply_to=reply_to,
        return_path=return_path,
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
        received_chain=received_chain if received_chain is not None else ["from mail.example.com"],
    )
    body = EmailBody(
        plain_text=body_text,
        html_content=body_html,
        extracted_urls=urls or [],
        extracted_domains=[],
    )
    return ParsedEmail(
        header=header,
        body=body,
        attachments=attachments or [],
    )


# ---------------------------------------------------------------------------
# Test: PhishingSignal and PhishingVerdict data models
# ---------------------------------------------------------------------------

class TestModels:
    """Pydantic model creation, serialization, and constraint tests."""

    def test_signal_creation(self):
        signal = PhishingSignal(
            category=SignalCategory.HEADER_ANOMALY,
            name="Test Signal",
            description="A test signal",
            severity=PhishingSeverity.HIGH,
            score_contribution=15.0,
            evidence="test evidence",
            mitre_technique="T1566.001",
        )
        assert signal.category == SignalCategory.HEADER_ANOMALY
        assert signal.score_contribution == 15.0
        d = signal.to_dict()
        assert d["name"] == "Test Signal"

    def test_verdict_creation(self):
        verdict = PhishingVerdict(
            score=75.0,
            severity=PhishingSeverity.HIGH,
            is_phishing=True,
            confidence=0.85,
            explanation="Test explanation",
        )
        assert verdict.score == 75.0
        assert verdict.is_phishing is True
        d = verdict.to_dict()
        assert "analyzed_at" in d

    def test_verdict_security_event_raw(self):
        verdict = PhishingVerdict(
            score=50.0,
            severity=PhishingSeverity.MEDIUM,
            is_phishing=True,
            signals=[PhishingSignal(
                category=SignalCategory.URGENCY_LANGUAGE,
                name="Test",
                description="Test",
            )],
        )
        raw = verdict.to_security_event_raw()
        assert raw["score"] == 50.0
        assert raw["signal_count"] == 1
        assert raw["is_phishing"] is True

    def test_parsed_email_creation(self):
        email = _build_email(subject="Hello World")
        assert email.header.subject == "Hello World"
        assert len(email.header.to_addresses) == 1


# ---------------------------------------------------------------------------
# Test: EmailParser — raw email string parsing
# ---------------------------------------------------------------------------

class TestEmailParser:
    """Tests for the EmailParser that converts raw RFC 5322 messages."""

    SAMPLE_LEGITIMATE = (
        "From: Alice Smith <alice@trustedcorp.com>\r\n"
        "To: bob@company.com\r\n"
        "Subject: Quarterly Report\r\n"
        "Date: Mon, 01 Jan 2026 10:00:00 +0000\r\n"
        "Message-ID: <msg001@trustedcorp.com>\r\n"
        "Received: from mail.trustedcorp.com (192.0.2.1) by mx.company.com\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Hi Bob,\r\n\r\n"
        "Please find the quarterly report attached.\r\n\r\n"
        "Best regards,\r\nAlice\r\n"
    )

    SAMPLE_PHISHING = (
        'From: "Microsoft Security" <security-alert@free-mail.tk>\r\n'
        "To: victim@company.com\r\n"
        "Reply-To: phisher@evil.xyz\r\n"
        "Subject: URGENT!! Your Account Has Been Suspended!!!\r\n"
        "Authentication-Results: mx.company.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Dear Customer,\r\n\r\n"
        "Your account has been suspended due to unusual activity.\r\n"
        "Click here immediately to verify your account:\r\n"
        "http://192.168.1.100/login/verify.php?user=victim&token=abc\r\n\r\n"
        "Failure to respond within 24 hours will result in permanent suspension.\r\n\r\n"
        "Microsoft Security Team\r\n"
    )

    def test_parse_legitimate_email(self):
        parsed = EmailParser.parse_raw_string(self.SAMPLE_LEGITIMATE)
        assert parsed.header.from_address == "alice@trustedcorp.com"
        assert parsed.header.from_display_name == "Alice Smith"
        assert parsed.header.subject == "Quarterly Report"
        assert parsed.body.plain_text is not None
        assert "quarterly report" in parsed.body.plain_text.lower()

    def test_parse_phishing_email(self):
        parsed = EmailParser.parse_raw_string(self.SAMPLE_PHISHING)
        assert parsed.header.from_address == "security-alert@free-mail.tk"
        assert parsed.header.reply_to == "phisher@evil.xyz"
        assert parsed.header.spf_result == "fail"
        assert parsed.header.dkim_result == "fail"
        assert parsed.header.dmarc_result == "fail"
        assert len(parsed.body.extracted_urls) >= 1

    def test_parse_raw_bytes(self):
        raw_bytes = self.SAMPLE_LEGITIMATE.encode("utf-8")
        parsed = EmailParser.parse_raw_bytes(raw_bytes)
        assert parsed.header.from_address == "alice@trustedcorp.com"
        assert parsed.raw_size_bytes > 0


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — authentication failure detection
# ---------------------------------------------------------------------------

class TestAuthenticationDetection:
    """Tests for SPF, DKIM, and DMARC failure detection."""

    def test_spf_fail_detected(self):
        email = _build_email(spf="fail")
        verdict = EmailAnalyzer().analyze(email)
        spf_signals = [s for s in verdict.signals if "SPF" in s.name]
        assert len(spf_signals) == 1
        assert spf_signals[0].score_contribution == 20.0

    def test_spf_softfail_detected(self):
        email = _build_email(spf="softfail")
        verdict = EmailAnalyzer().analyze(email)
        spf_signals = [s for s in verdict.signals if "SPF" in s.name]
        assert len(spf_signals) == 1
        assert spf_signals[0].score_contribution == 12.0  # Lower than hard fail

    def test_dkim_fail_detected(self):
        email = _build_email(dkim="fail")
        verdict = EmailAnalyzer().analyze(email)
        dkim_signals = [s for s in verdict.signals if "DKIM" in s.name]
        assert len(dkim_signals) == 1

    def test_dmarc_fail_detected(self):
        email = _build_email(dmarc="fail")
        verdict = EmailAnalyzer().analyze(email)
        dmarc_signals = [s for s in verdict.signals if "DMARC" in s.name]
        assert len(dmarc_signals) == 1
        assert dmarc_signals[0].score_contribution == 22.0

    def test_all_auth_pass_no_signals(self):
        email = _build_email(spf="pass", dkim="pass", dmarc="pass")
        verdict = EmailAnalyzer().analyze(email)
        auth_signals = [s for s in verdict.signals if s.category == SignalCategory.AUTHENTICATION_FAILURE]
        assert len(auth_signals) == 0


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — header anomaly detection
# ---------------------------------------------------------------------------

class TestHeaderAnomalyDetection:
    """Tests for Reply-To/Return-Path mismatches and missing headers."""

    def test_reply_to_domain_mismatch(self):
        email = _build_email(
            from_addr="admin@trustedbank.com",
            reply_to="phisher@evil-domain.xyz",
        )
        verdict = EmailAnalyzer().analyze(email)
        mismatch_signals = [s for s in verdict.signals if "Reply-To" in s.name]
        assert len(mismatch_signals) == 1
        assert "evil-domain.xyz" in mismatch_signals[0].evidence

    def test_return_path_mismatch(self):
        email = _build_email(
            from_addr="info@company.com",
            return_path="<bounce@different-company.net>",
        )
        verdict = EmailAnalyzer().analyze(email)
        rp_signals = [s for s in verdict.signals if "Return-Path" in s.name]
        assert len(rp_signals) == 1

    def test_missing_received_chain(self):
        email = _build_email(received_chain=[])
        verdict = EmailAnalyzer().analyze(email)
        missing_signals = [s for s in verdict.signals if "Received" in s.name]
        assert len(missing_signals) == 1

    def test_no_anomaly_on_matching_domains(self):
        email = _build_email(
            from_addr="user@example.com",
            reply_to="support@example.com",
        )
        verdict = EmailAnalyzer().analyze(email)
        mismatch_signals = [s for s in verdict.signals if "Mismatch" in s.name]
        assert len(mismatch_signals) == 0


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — impersonation detection
# ---------------------------------------------------------------------------

class TestImpersonationDetection:
    """Tests for display name spoofing and brand impersonation."""

    def test_brand_impersonation_in_display_name(self):
        email = _build_email(
            from_addr="phisher@random-domain.xyz",
            from_display="Microsoft Support",
        )
        verdict = EmailAnalyzer().analyze(email)
        imp_signals = [s for s in verdict.signals if s.category == SignalCategory.IMPERSONATION]
        assert len(imp_signals) >= 1
        assert any("microsoft" in s.evidence.lower() for s in imp_signals)

    def test_email_in_display_name(self):
        email = _build_email(
            from_addr="phisher@evil.com",
            from_display="admin@trustedbank.com",
        )
        verdict = EmailAnalyzer().analyze(email)
        imp_signals = [s for s in verdict.signals if "Display Name" in s.name]
        assert len(imp_signals) >= 1

    def test_no_impersonation_on_legitimate_display(self):
        email = _build_email(
            from_addr="alice@company.com",
            from_display="Alice Smith",
        )
        verdict = EmailAnalyzer().analyze(email)
        imp_signals = [s for s in verdict.signals if s.category == SignalCategory.IMPERSONATION]
        assert len(imp_signals) == 0


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — urgency language / social engineering detection
# ---------------------------------------------------------------------------

class TestUrgencyLanguageDetection:
    """Tests for social engineering language pattern matching."""

    def test_account_suspension_threat(self):
        email = _build_email(
            body_text="Your account has been suspended. Verify your account immediately.",
        )
        verdict = EmailAnalyzer().analyze(email)
        urgency = [s for s in verdict.signals if s.category == SignalCategory.URGENCY_LANGUAGE]
        assert len(urgency) >= 1

    def test_time_deadline_pressure(self):
        email = _build_email(
            body_text="You must respond within 24 hours or your access will be revoked.",
        )
        verdict = EmailAnalyzer().analyze(email)
        urgency = [s for s in verdict.signals if s.category == SignalCategory.URGENCY_LANGUAGE]
        assert len(urgency) >= 1

    def test_excessive_exclamation_marks(self):
        email = _build_email(subject="URGENT!! Act NOW!!")
        verdict = EmailAnalyzer().analyze(email)
        punct_signals = [s for s in verdict.signals if "Punctuation" in s.name]
        assert len(punct_signals) == 1

    def test_no_urgency_in_normal_email(self):
        email = _build_email(
            body_text="Hi, please find the monthly report attached. Let me know if you have questions.",
        )
        verdict = EmailAnalyzer().analyze(email)
        urgency = [s for s in verdict.signals if s.category == SignalCategory.URGENCY_LANGUAGE]
        assert len(urgency) == 0


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — URL analysis
# ---------------------------------------------------------------------------

class TestURLAnalysis:
    """Tests for suspicious URL pattern detection."""

    def test_ip_address_url(self):
        email = _build_email(urls=["http://192.168.1.100/login.php"])
        verdict = EmailAnalyzer().analyze(email)
        ip_signals = [s for s in verdict.signals if "IP Address" in s.name]
        assert len(ip_signals) == 1

    def test_url_shortener_detected(self):
        email = _build_email(urls=["https://bit.ly/3xAbCdE"])
        verdict = EmailAnalyzer().analyze(email)
        short_signals = [s for s in verdict.signals if "Shortener" in s.name]
        assert len(short_signals) == 1

    def test_credential_harvesting_url(self):
        email = _build_email(urls=["https://evil.com/login/verify.php?user=victim&password=test"])
        verdict = EmailAnalyzer().analyze(email)
        cred_signals = [s for s in verdict.signals if s.category == SignalCategory.CREDENTIAL_HARVESTING]
        assert len(cred_signals) >= 1

    def test_deceptive_at_symbol_url(self):
        email = _build_email(urls=["http://trusted.com@evil.com/login"])
        verdict = EmailAnalyzer().analyze(email)
        at_signals = [s for s in verdict.signals if "@ Symbol" in s.name]
        assert len(at_signals) == 1

    def test_clean_url_no_signals(self):
        email = _build_email(urls=["https://www.company.com/report/2026-q3"])
        verdict = EmailAnalyzer().analyze(email)
        url_signals = [s for s in verdict.signals if "URL" in s.name or "Shortener" in s.name or "IP" in s.name]
        assert len(url_signals) == 0


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — attachment risk assessment
# ---------------------------------------------------------------------------

class TestAttachmentRisk:
    """Tests for attachment metadata risk scoring."""

    def test_executable_attachment_flagged(self):
        att = EmailAttachmentInfo(
            filename="invoice.exe", extension=".exe", is_executable=True, size_bytes=50000,
        )
        email = _build_email(attachments=[att])
        verdict = EmailAnalyzer().analyze(email)
        exec_signals = [s for s in verdict.signals if "Executable" in s.name]
        assert len(exec_signals) == 1
        assert exec_signals[0].score_contribution == 25.0

    def test_macro_document_flagged(self):
        att = EmailAttachmentInfo(
            filename="report.docm", extension=".docm", is_macro_enabled=True, size_bytes=30000,
        )
        email = _build_email(attachments=[att])
        verdict = EmailAnalyzer().analyze(email)
        macro_signals = [s for s in verdict.signals if "Macro" in s.name]
        assert len(macro_signals) == 1

    def test_archive_attachment_flagged(self):
        att = EmailAttachmentInfo(
            filename="files.zip", extension=".zip", is_archive=True, size_bytes=100000,
        )
        email = _build_email(attachments=[att])
        verdict = EmailAnalyzer().analyze(email)
        archive_signals = [s for s in verdict.signals if "Archive" in s.name]
        assert len(archive_signals) == 1


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — content anomaly detection
# ---------------------------------------------------------------------------

class TestContentAnomalyDetection:
    """Tests for HTML content anomalies and embedded forms."""

    def test_hidden_html_content_detected(self):
        email = _build_email(
            body_html='<div style="display:none">tracking pixel</div><p>Click here</p>',
            body_text=None,
        )
        verdict = EmailAnalyzer().analyze(email)
        hidden_signals = [s for s in verdict.signals if "Hidden" in s.name]
        assert len(hidden_signals) == 1

    def test_embedded_form_detected(self):
        email = _build_email(
            body_html='<form action="http://evil.com/steal"><input name="password"></form>',
            body_text=None,
        )
        verdict = EmailAnalyzer().analyze(email)
        form_signals = [s for s in verdict.signals if "Form" in s.name]
        assert len(form_signals) == 1

    def test_mismatched_link_text_and_href(self):
        email = _build_email(
            body_html='<a href="http://evil-phishing.com/steal">https://trusted-bank.com/login</a>',
        )
        verdict = EmailAnalyzer().analyze(email)
        mismatch_signals = [s for s in verdict.signals if "Mismatched" in s.name]
        assert len(mismatch_signals) == 1
        assert mismatch_signals[0].score_contribution == 22.0


# ---------------------------------------------------------------------------
# Test: EmailAnalyzer — full pipeline integration (end-to-end)
# ---------------------------------------------------------------------------

class TestFullPipelineIntegration:
    """End-to-end tests combining multiple detection modules."""

    def test_obvious_phishing_scores_high(self):
        """A clearly phishing email should score >= 60 (HIGH)."""
        email = _build_email(
            from_addr="alert@security-update.tk",
            from_display="Microsoft Security",
            reply_to="phisher@evil.xyz",
            subject="URGENT!! Your Account Will Be Suspended!!!",
            body_text=(
                "Your account has been suspended due to unusual activity. "
                "Click here immediately to verify your account. "
                "Failure to respond within 24 hours will result in permanent closure."
            ),
            urls=["http://192.168.1.100/login.php?user=victim&pass=test"],
            spf="fail",
            dkim="fail",
            dmarc="fail",
            attachments=[EmailAttachmentInfo(
                filename="security_patch.exe",
                extension=".exe",
                is_executable=True,
                size_bytes=45000,
            )],
        )
        verdict = EmailAnalyzer().analyze(email)

        assert verdict.score >= 60.0
        assert verdict.severity in (PhishingSeverity.HIGH, PhishingSeverity.CRITICAL)
        assert verdict.is_phishing is True
        assert len(verdict.signals) >= 5
        assert len(verdict.explanation) > 0
        assert "T1566" in str(verdict.mitre_techniques)

    def test_legitimate_email_scores_low(self):
        """A clearly legitimate email should score < 20 (SAFE/LOW)."""
        email = _build_email(
            from_addr="alice@trustedcorp.com",
            from_display="Alice Smith",
            subject="Quarterly Report Q3 2026",
            body_text=(
                "Hi Bob,\n\n"
                "Please find the quarterly performance report attached. "
                "Let me know if you have any questions.\n\n"
                "Best regards,\nAlice"
            ),
            spf="pass",
            dkim="pass",
            dmarc="pass",
            urls=["https://www.trustedcorp.com/reports/2026-q3"],
        )
        verdict = EmailAnalyzer().analyze(email)

        assert verdict.score < 20.0
        assert verdict.severity in (PhishingSeverity.SAFE, PhishingSeverity.LOW)
        assert verdict.is_phishing is False

    def test_explanation_always_present(self):
        """Per SKILL.md, explanations must always accompany scores."""
        # Even a clean email should have an explanation
        clean = _build_email(body_text="All good here.")
        verdict = EmailAnalyzer().analyze(clean)
        assert len(verdict.explanation) > 0
        assert "Phishing Score" in verdict.explanation

    def test_security_event_conversion(self):
        """Verify the phishing verdict converts to a canonical SecurityEvent."""
        email = _build_email(
            from_addr="phisher@evil.com",
            subject="Phishing test",
            body_text="Verify your account immediately.",
        )
        analyzer = EmailAnalyzer()
        verdict = analyzer.analyze(email)
        event = analyzer.to_security_event(verdict, email)

        assert event.source == "phishing"
        assert event.entity.user == "phisher@evil.com"
        assert event.entity.host == "evil.com"
        assert "phishing_score" in event.enrichment

    def test_raw_email_end_to_end(self):
        """Full pipeline: raw RFC 5322 string → parse → analyze → verdict."""
        raw = (
            'From: "PayPal Support" <security@paypa1-verify.tk>\r\n'
            "To: victim@company.com\r\n"
            "Reply-To: attacker@evil.xyz\r\n"
            "Subject: Unusual Activity on Your Account\r\n"
            "Authentication-Results: mx.company.com; spf=fail; dkim=fail\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Dear Customer,\r\n\r\n"
            "Unusual activity was detected on your account. "
            "Verify your account within 24 hours to avoid suspension.\r\n"
            "http://192.168.1.50/paypal-login.php?id=victim\r\n"
        )
        parsed = EmailParser.parse_raw_string(raw)
        verdict = EmailAnalyzer().analyze(parsed)

        assert verdict.is_phishing is True
        assert verdict.score >= 40.0
        assert len(verdict.signals) >= 3
        assert len(verdict.explanation) > 50  # Substantial explanation


# ---------------------------------------------------------------------------
# Test: Sender reputation
# ---------------------------------------------------------------------------

class TestSenderReputation:
    """Tests for sender reputation heuristics."""

    def test_brand_from_free_email(self):
        email = _build_email(
            from_addr="support@gmail.com",
            from_display="PayPal Security",
            subject="PayPal Account Alert",
        )
        verdict = EmailAnalyzer().analyze(email)
        rep_signals = [s for s in verdict.signals if s.category == SignalCategory.SENDER_REPUTATION]
        assert len(rep_signals) >= 1

    def test_suspicious_tld(self):
        email = _build_email(from_addr="admin@company.tk")
        verdict = EmailAnalyzer().analyze(email)
        tld_signals = [s for s in verdict.signals if "TLD" in s.name]
        assert len(tld_signals) == 1
