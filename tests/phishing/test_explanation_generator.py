"""
Unit & Labeled-Dataset Integration Tests for Phishing Explanation Generator.

Tests ExplanationGenerator across email, URL, attachment, and composite
verdicts, verifies ASCII-safe rendering and score-cap attribution, and
evaluates full-pipeline precision/recall on a labeled synthetic dataset
per .agents/skills/phishing-detection/SKILL.md.
"""

from __future__ import annotations

import pytest

from src.phishing.attachment_analyzer import AttachmentAnalyzer
from src.phishing.email_analyzer import EmailAnalyzer, EmailParser
from src.phishing.explanation_generator import ExplanationGenerator
from src.phishing.models import (
    PhishingSeverity,
    PhishingSignal,
    PhishingVerdict,
    SignalCategory,
)
from src.phishing.url_scanner import URLScanner


# ---------------------------------------------------------------------------
# 1. Clean Verdict Explainability (Never a Bare Number)
# ---------------------------------------------------------------------------

class TestCleanExplanations:

    def setup_method(self) -> None:
        self.gen = ExplanationGenerator()

    def test_clean_url_verdict_still_gets_rich_explanation(self) -> None:
        scanner = URLScanner()
        verdict = scanner.scan_url("https://google.com")
        exp = self.gen.explain(verdict)

        assert exp.score == 0.0
        assert exp.severity == PhishingSeverity.SAFE
        assert exp.is_phishing is False
        assert exp.score_capped is False
        assert "0.0/100" in exp.headline
        assert "no phishing or malicious indicators fired" in exp.headline.lower()
        assert exp.category_breakdown == []
        assert exp.top_factors == []
        assert len(exp.recommended_actions) >= 1
        assert "Score" in exp.formatted_markdown or "0.0/100" in exp.formatted_markdown
        assert exp.formatted_text != ""

    def test_clean_attachment_verdict_explanation(self) -> None:
        analyzer = AttachmentAnalyzer()
        verdict = analyzer.scan_bytes(b"Quarterly budget notes.", "budget.txt", "text/plain")
        exp = self.gen.explain(verdict)

        assert "budget.txt" in exp.target_summary
        assert exp.is_phishing is False
        assert "SAFE" in exp.headline


# ---------------------------------------------------------------------------
# 2. Single-Vector Signal Attribution & Category Breakdown
# ---------------------------------------------------------------------------

class TestSingleVectorExplanations:

    def setup_method(self) -> None:
        self.gen = ExplanationGenerator()

    def test_email_explanation_breakdown_and_mitre(self) -> None:
        raw_email = (
            "From: Microsoft Support <support@microsoft-security-verify.xyz>\r\n"
            "Reply-To: collector@evil-harvest.top\r\n"
            "Authentication-Results: mx.target.corp; spf=fail; dkim=fail; dmarc=fail\r\n"
            "To: user@target.corp\r\n"
            "Subject: URGENT: Your account will be suspended within 24 hours!!\r\n\r\n"
            "Verify your account immediately or failure to respond will lock access:\r\n"
            "http://198.51.100.44/login/verify\r\n"
        )
        parsed = EmailParser.parse_raw_string(raw_email)
        analyzer = EmailAnalyzer(url_scanner=URLScanner())
        verdict = analyzer.analyze(parsed)
        exp = self.gen.explain(verdict)

        assert exp.is_phishing is True
        assert exp.score >= 80.0
        assert len(exp.category_breakdown) >= 3
        # Category breakdown must be sorted descending by raw_points
        pts = [c.raw_points for c in exp.category_breakdown]
        assert pts == sorted(pts, reverse=True)
        # Top factors sorted descending by score_contribution
        fac_pts = [f.score_contribution for f in exp.top_factors]
        assert fac_pts == sorted(fac_pts, reverse=True)
        # Share percents should approximately sum to 100%
        assert 98.0 <= sum(c.share_percent for c in exp.category_breakdown) <= 102.0
        # MITRE details enriched with names & tactics
        assert len(exp.mitre_details) >= 1
        assert all(m.technique_name and m.tactic for m in exp.mitre_details)
        # Recommendations mention analyst approval / quarantine / verification
        assert len(exp.recommended_actions) >= 2
        assert "Category Breakdown" in exp.formatted_markdown
        assert "Score Breakdown by Category:" in exp.formatted_text

    def test_url_explanation_score_cap_and_unicode_ascii_safety(self) -> None:
        scanner = URLScanner()
        # Cyrillic 'a' homoglyph + credential path + dangerous exe payload -> raw > 100
        verdict = scanner.scan_url("http://p\u0430ypal.com/login/verify-password.exe")
        exp = self.gen.explain(verdict)

        assert exp.score == 100.0
        assert exp.raw_score > 100.0
        assert exp.score_capped is True
        assert "capped from" in exp.headline.lower()
        assert "capped at the 100.0 maximum" in exp.narrative.lower()
        # Must remain 100% ASCII-safe for Windows console output
        exp.headline.encode("ascii")
        exp.narrative.encode("ascii")
        exp.formatted_text.encode("ascii")
        exp.formatted_markdown.encode("ascii")

    def test_attachment_explanation_with_rtlo_spoofing(self) -> None:
        analyzer = AttachmentAnalyzer()
        verdict = analyzer.scan_bytes(b"MZ\x90\x00SYNTHETIC", "report_\u202efdp.exe")
        exp = self.gen.explain(verdict)

        assert exp.is_phishing is True
        assert exp.severity == PhishingSeverity.CRITICAL
        assert "[U+202E]" in exp.target_summary
        exp.formatted_text.encode("ascii")
        exp.formatted_markdown.encode("ascii")
        assert any("sandbox" in act.lower() or "quarantine" in act.lower() for act in exp.recommended_actions)


# ---------------------------------------------------------------------------
# 3. Cross-Vector Composite Explanations & Edge Cases
# ---------------------------------------------------------------------------

class TestCompositeAndEdgeCases:

    def setup_method(self) -> None:
        self.gen = ExplanationGenerator()

    def test_composite_explanation_merges_email_url_and_attachment(self) -> None:
        raw_email = (
            "From: Security <alerts@paypal-verify.xyz>\r\n"
            "To: employee@target.corp\r\n"
            "Subject: Urgent invoice verification\r\n\r\n"
            "See http://xn--pypal-4ve.com/login and attached invoice.\r\n"
        )
        parsed = EmailParser.parse_raw_string(raw_email)
        email_verdict = EmailAnalyzer().analyze(parsed)
        url_verdict = URLScanner().scan_url("http://xn--pypal-4ve.com/login")
        att_verdict = AttachmentAnalyzer().scan_bytes(b"MZ\x90\x00SYNTHETIC", "invoice.pdf")

        exp = self.gen.explain_composite(
            email_verdict=email_verdict,
            url_verdicts=[url_verdict],
            attachment_verdicts=[att_verdict],
        )

        assert exp.analysis_type == "composite"
        assert exp.is_phishing is True
        assert exp.score >= 85.0
        assert "Email" in exp.target_summary
        assert "1 URL(s)" in exp.target_summary
        assert "1 Attachment(s)" in exp.target_summary
        assert any(c.category == SignalCategory.ATTACHMENT_RISK for c in exp.category_breakdown)
        assert any(c.category == SignalCategory.HOMOGRAPH_ATTACK for c in exp.category_breakdown)
        assert "T1036.008" in [m.technique_id for m in exp.mitre_details]

    def test_empty_composite_and_zero_weight_signal_edge_cases(self) -> None:
        empty_exp = self.gen.explain_composite()
        assert empty_exp.analysis_type == "composite"
        assert empty_exp.score == 0.0
        assert empty_exp.is_phishing is False

        zero_sig = PhishingSignal(
            category=SignalCategory.CONTENT_ANOMALY,
            name="informational_note",
            description="Minor formatting note",
            severity=PhishingSeverity.LOW,
            score_contribution=0.0,
            evidence="none",
        )
        verdict = PhishingVerdict(
            analysis_type="email",
            score=0.0,
            severity=PhishingSeverity.LOW,
            is_phishing=False,
            confidence=0.6,
            signals=[zero_sig],
        )
        exp = self.gen.explain(verdict, target="custom-target")
        assert exp.target_summary == "custom-target"
        assert len(exp.top_factors) == 1
        assert exp.top_factors[0].share_percent == 100.0


# ---------------------------------------------------------------------------
# 4. Integration Test: Labeled Dataset Pipeline Precision / Recall
# ---------------------------------------------------------------------------

class TestLabeledDatasetPipelineEvaluation:
    """Measures detection precision, recall, and explanation completeness
    across a labeled synthetic corpus of benign and phishing emails.
    """

    def test_labeled_email_pipeline_precision_recall_and_explainability(self) -> None:
        url_scanner = URLScanner()
        att_analyzer = AttachmentAnalyzer()
        email_analyzer = EmailAnalyzer(url_scanner=url_scanner, attachment_analyzer=att_analyzer)
        explainer = ExplanationGenerator()

        # Labeled synthetic corpus: (raw_email, optional_attachment, expected_is_phishing)
        dataset: list[tuple[str, tuple[str, bytes] | None, bool]] = [
            # --- 6 Benign Emails ---
            (
                "From: Alice Smith <alice@acme.corp>\r\n"
                "Authentication-Results: mx.acme.corp; spf=pass; dkim=pass; dmarc=pass\r\n"
                "To: bob@acme.corp\r\n"
                "Subject: Weekly Engineering Sync Notes\r\n\r\n"
                "Hi Bob,\r\nAttached are the sprint planning notes.\r\n",
                ("sprint_notes.txt", b"Sprint 14 backlog items and owners."),
                False,
            ),
            (
                "From: Google Workspace <no-reply@google.com>\r\n"
                "Authentication-Results: mx.acme.corp; spf=pass; dkim=pass; dmarc=pass\r\n"
                "To: staff@acme.corp\r\n"
                "Subject: Calendar invite accepted\r\n\r\n"
                "Your meeting link: https://google.com/calendar\r\n",
                None,
                False,
            ),
            (
                "From: HR Benefits <benefits@acme.corp>\r\n"
                "Authentication-Results: mx.acme.corp; spf=pass; dkim=pass; dmarc=pass\r\n"
                "To: employee@acme.corp\r\n"
                "Subject: Updated 2026 Holiday Schedule\r\n\r\n"
                "Please review the attached PDF holiday calendar.\r\n",
                ("holidays_2026.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"),
                False,
            ),
            (
                "From: GitHub Notifications <notifications@github.com>\r\n"
                "Authentication-Results: mx.acme.corp; spf=pass; dkim=pass; dmarc=pass\r\n"
                "To: dev@acme.corp\r\n"
                "Subject: [mms] PR #42 merged\r\n\r\n"
                "Pull request #42 was merged cleanly.\r\n",
                None,
                False,
            ),
            (
                "From: Finance Team <finance@partner-org.com>\r\n"
                "Authentication-Results: mx.acme.corp; spf=pass; dkim=pass\r\n"
                "To: ap@acme.corp\r\n"
                "Subject: Q3 Statement Summary\r\n\r\n"
                "Hello team, let us know if you have questions on Q3 figures.\r\n",
                None,
                False,
            ),
            (
                "From: IT Helpdesk <helpdesk@acme.corp>\r\n"
                "Authentication-Results: mx.acme.corp; spf=pass; dkim=pass; dmarc=pass\r\n"
                "To: all@acme.corp\r\n"
                "Subject: Planned Maintenance Saturday\r\n\r\n"
                "Routine patching will occur Saturday 02:00 UTC.\r\n",
                None,
                False,
            ),
            # --- 6 Phishing Emails ---
            (
                "From: PayPal Security <security@paypal.com.verify-login.xyz>\r\n"
                "Reply-To: harvest@evil-collect.tk\r\n"
                "Authentication-Results: mx.acme.corp; spf=fail; dkim=fail; dmarc=fail\r\n"
                "To: victim@acme.corp\r\n"
                "Subject: URGENT: Your account has been suspended within 24 hours!\r\n\r\n"
                "Verify your account immediately:\r\n"
                "http://xn--pypal-4ve.com/login/verify\r\n",
                None,
                True,
            ),
            (
                "From: Microsoft 365 <admin@m1crosoft-support.top>\r\n"
                "Authentication-Results: mx.acme.corp; spf=fail; dmarc=fail\r\n"
                "To: user@acme.corp\r\n"
                "Subject: Unusual sign-in activity detected\r\n\r\n"
                "Confirm your password now at http://198.51.100.77/signin/auth.php?user=test\r\n",
                None,
                True,
            ),
            (
                "From: CEO Office <ceo@gmail.com>\r\n"
                "To: payroll@acme.corp\r\n"
                "Subject: URGENT Wire Transfer Required Immediately!!\r\n\r\n"
                "Failure to respond within 2 hours will delay vendor settlement. Click here to confirm:\r\n"
                "http://bit.ly/3xFakeLink\r\n",
                None,
                True,
            ),
            (
                "From: Billing Dept <billing@vendor-portal.club>\r\n"
                "Authentication-Results: mx.acme.corp; spf=softfail\r\n"
                "To: finance@acme.corp\r\n"
                "Subject: Overdue Invoice Attached\r\n\r\n"
                "Please open the attached invoice document immediately.\r\n",
                ("invoice_2026.pdf.exe", b"MZ\x90\x00SYNTHETIC_PE"),
                True,
            ),
            (
                "From: DHL Express <tracking@dhl-delivery-notice.xyz>\r\n"
                "Authentication-Results: mx.acme.corp; spf=fail; dkim=fail\r\n"
                "To: ops@acme.corp\r\n"
                "Subject: Package Delivery Failed - Action Required\r\n\r\n"
                "Review shipping receipt attached.\r\n",
                ("receipt.pdf", b"%PDF-1.7\n<< /OpenAction 1 0 R /JavaScript (x) >>"),
                True,
            ),
            (
                "From: DocuSign Alerts <docs@docusign-secure.icu>\r\n"
                "Authentication-Results: mx.acme.corp; spf=fail\r\n"
                "To: legal@acme.corp\r\n"
                "Subject: Urgent Contract Signature Needed\r\n\r\n"
                "Open attached secure document to sign.\r\n",
                ("contract.html", b"<html><form action='https://evil.test/login'><input type='password'/></form><script>new Blob([atob('QQ==')])</script></html>"),
                True,
            ),
        ]

        tp = fp = tn = fn = 0
        for raw_email, att_tuple, expected in dataset:
            parsed = EmailParser.parse_raw_string(raw_email)
            email_verdict = email_analyzer.analyze(parsed)
            url_verdicts = [url_scanner.scan_url(u) for u in parsed.body.extracted_urls]
            att_verdicts = (
                [att_analyzer.scan_bytes(att_tuple[1], att_tuple[0], email_id=parsed.email_id)]
                if att_tuple
                else []
            )

            explained = explainer.explain_composite(
                email_verdict=email_verdict,
                url_verdicts=url_verdicts,
                attachment_verdicts=att_verdicts,
            )

            # Mandatory explainability invariants on every sample
            assert explained.headline != ""
            assert explained.narrative != ""
            assert explained.formatted_text != ""
            assert explained.formatted_markdown != ""
            if explained.is_phishing:
                assert len(explained.top_factors) >= 1
                assert len(explained.recommended_actions) >= 1

            pred = explained.is_phishing
            if pred and expected:
                tp += 1
            elif pred and not expected:
                fp += 1
            elif not pred and not expected:
                tn += 1
            else:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        assert precision >= 0.85, f"Precision too low: {precision:.2f} (TP={tp}, FP={fp})"
        assert recall >= 0.85, f"Recall too low: {recall:.2f} (TP={tp}, FN={fn})"
        assert f1 >= 0.85, f"F1 too low: {f1:.2f}"

