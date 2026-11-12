"""
Email Header & Content Analyzer for Phishing Detection.

Phase 5, Feature 1 — Stateless scoring service that examines email headers
and body content for phishing indicators. Produces a PhishingVerdict with
individual signals and a combined human-readable explanation.

Complies with:
- ARCHITECTURE.md §4.4 — stateless scoring microservice
- .agents/skills/phishing-detection/SKILL.md — mandatory signal explanations
- AGENTS.md — uses synthetic/mock data, never real victim data

Scoring components:
  1. Header anomaly detection (authentication failures, spoofing indicators)
  2. Sender reputation heuristics (domain age proxy, free email providers)
  3. Content NLP analysis (urgency language, social engineering patterns)
  4. URL/link analysis (obfuscation, credential harvesting patterns)
  5. Impersonation detection (display name spoofing, brand name abuse)
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser, Parser
from typing import Any, Optional
from urllib.parse import urlparse

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
from src.shared.event_schema import Entity, SecurityEvent


# ---------------------------------------------------------------------------
# Constants — Detection Rules and Patterns
# ---------------------------------------------------------------------------

# Urgency / social engineering language patterns (case-insensitive)
URGENCY_PATTERNS: list[tuple[str, str]] = [
    (r"\b(?:act\s+now|immediate(?:ly)?|urgent(?:ly)?)\b", "Urgency pressure language detected"),
    (r"\b(?:your\s+account\s+(?:has\s+been|will\s+be|is)\s+(?:suspended|locked|disabled|closed|compromised))\b",
     "Account suspension/compromise threat"),
    (r"\b(?:verify\s+your\s+(?:account|identity|information|payment))\b",
     "Verification request — common phishing lure"),
    (r"\b(?:click\s+(?:here|below|this\s+link)\s+(?:to|immediately|now))\b",
     "Directive click instruction"),
    (r"\b(?:within\s+\d+\s+(?:hour|minute|day)s?)\b",
     "Artificial time deadline imposed"),
    (r"\b(?:unusual\s+(?:activity|sign[\s-]?in|login|access))\b",
     "Unusual activity notification — common phishing pretext"),
    (r"\b(?:confirm\s+your\s+(?:password|credentials|login|billing))\b",
     "Credential confirmation request"),
    (r"\b(?:failure\s+to\s+(?:respond|verify|confirm|update))\b",
     "Consequence threat for inaction"),
    (r"\b(?:unauthorized\s+(?:access|transaction|activity|charge))\b",
     "Unauthorized activity claim"),
    (r"\b(?:won\s+a?\s*(?:prize|lottery|gift|reward|sweepstakes))\b",
     "Prize/reward lure — advance fee scam indicator"),
]

# Credential harvesting URL patterns
CREDENTIAL_HARVEST_PATTERNS: list[tuple[str, str]] = [
    (r"(?:login|signin|sign-in|log-in|secure|verify|account|password|auth|credential)",
     "URL path contains authentication/credential keywords"),
    (r"(?:\.php\?|\.asp\?|\.cgi\?).+(?:user|pass|email|login|id|token)",
     "Dynamic URL with credential-related query parameters"),
]

# Known brand names commonly impersonated in phishing
IMPERSONATED_BRANDS: list[str] = [
    "microsoft", "apple", "google", "amazon", "paypal", "netflix",
    "facebook", "instagram", "linkedin", "twitter", "bank of america",
    "wells fargo", "chase", "citibank", "dhl", "fedex", "ups",
    "usps", "irs", "dropbox", "adobe", "salesforce", "zoom",
    "slack", "docusign", "office365", "onedrive", "outlook",
    "icloud", "whatsapp", "telegram",
]

# Free email providers (phishing often uses these as sender domains)
FREE_EMAIL_PROVIDERS: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "zoho.com", "yandex.com", "gmx.com",
    "icloud.com", "live.com", "msn.com", "tutanota.com", "fastmail.com",
}

# Dangerous executable attachment extensions
DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".pif", ".cmd", ".bat", ".ps1", ".vbs", ".js",
    ".wsf", ".msi", ".dll", ".com", ".hta", ".cpl", ".reg",
}

# Macro-enabled document extensions
MACRO_EXTENSIONS: set[str] = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".doc", ".xls", ".ppt",  # Legacy formats can contain macros
}

# Archive extensions that can hide malicious payloads
ARCHIVE_EXTENSIONS: set[str] = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".img",
}

# URL shortener domains
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "tiny.cc", "shorte.st", "adf.ly",
    "v.gd", "shorturl.at", "cutt.ly",
}


# ---------------------------------------------------------------------------
# EmailParser — converts raw email bytes/string into ParsedEmail
# ---------------------------------------------------------------------------

class EmailParser:
    """Parses raw email content (RFC 5322 / MIME) into a structured ParsedEmail.

    Extracts headers, body text/HTML, URLs, and attachment metadata without
    opening or executing any attachments.
    """

    # Regex to extract URLs from text and HTML
    _URL_PATTERN = re.compile(
        r'https?://[^\s<>"\')\]}>]+',
        re.IGNORECASE,
    )

    # Regex to extract href from HTML
    _HREF_PATTERN = re.compile(
        r'href\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    @classmethod
    def parse_raw_bytes(cls, raw_bytes: bytes) -> ParsedEmail:
        """Parse raw email bytes into a ParsedEmail model."""
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return cls._build_parsed_email(msg, raw_size=len(raw_bytes))

    @classmethod
    def parse_raw_string(cls, raw_string: str) -> ParsedEmail:
        """Parse raw email string into a ParsedEmail model."""
        msg = Parser(policy=policy.default).parsestr(raw_string)
        return cls._build_parsed_email(msg, raw_size=len(raw_string.encode("utf-8", errors="replace")))

    @classmethod
    def _build_parsed_email(cls, msg: Any, raw_size: int) -> ParsedEmail:
        """Internal: convert a parsed email.message.Message into a ParsedEmail."""
        header = cls._extract_headers(msg)
        body = cls._extract_body(msg)
        attachments = cls._extract_attachments(msg)

        return ParsedEmail(
            header=header,
            body=body,
            attachments=attachments,
            raw_size_bytes=raw_size,
        )

    @classmethod
    def _extract_headers(cls, msg: Any) -> EmailHeader:
        """Extract phishing-relevant headers from the email message."""
        from_addr = msg.get("From", "")
        # Parse display name and email address
        display_name = ""
        email_addr = from_addr
        if "<" in from_addr and ">" in from_addr:
            parts = from_addr.split("<")
            display_name = parts[0].strip().strip('"').strip("'")
            email_addr = parts[1].rstrip(">").strip()

        # Parse To addresses
        to_raw = msg.get("To", "")
        to_addresses = [addr.strip() for addr in to_raw.split(",") if addr.strip()] if to_raw else []

        # Parse CC
        cc_raw = msg.get("Cc", "")
        cc_addresses = [addr.strip() for addr in cc_raw.split(",") if addr.strip()] if cc_raw else []

        # Parse Received chain
        received_chain = []
        for val in msg.get_all("Received", []):
            if val:
                received_chain.append(str(val).strip())

        # Parse authentication results
        auth_results = str(msg.get("Authentication-Results", "")).lower()
        spf_result = cls._parse_auth_result(auth_results, "spf")
        dkim_result = cls._parse_auth_result(auth_results, "dkim")
        dmarc_result = cls._parse_auth_result(auth_results, "dmarc")

        # Raw headers
        raw_headers = {}
        for key in msg.keys():
            raw_headers[key] = str(msg.get(key, ""))

        return EmailHeader(
            message_id=msg.get("Message-ID"),
            from_address=email_addr,
            from_display_name=display_name if display_name else None,
            reply_to=msg.get("Reply-To"),
            return_path=msg.get("Return-Path"),
            to_addresses=to_addresses,
            cc_addresses=cc_addresses,
            subject=msg.get("Subject"),
            x_mailer=msg.get("X-Mailer"),
            content_type=msg.get_content_type(),
            received_chain=received_chain,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            raw_headers=raw_headers,
        )

    @classmethod
    def _parse_auth_result(cls, auth_string: str, mechanism: str) -> Optional[str]:
        """Extract SPF/DKIM/DMARC result from Authentication-Results header."""
        if not auth_string:
            return None
        # Look for patterns like "spf=pass", "dkim=fail", "dmarc=none"
        match = re.search(rf"{mechanism}\s*=\s*(\w+)", auth_string)
        return match.group(1) if match else None

    @classmethod
    def _extract_body(cls, msg: Any) -> EmailBody:
        """Extract plain text and HTML body, plus embedded URLs."""
        plain_text = None
        html_content = None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                if content_type == "text/plain" and plain_text is None:
                    payload = part.get_content()
                    plain_text = str(payload) if payload else None
                elif content_type == "text/html" and html_content is None:
                    payload = part.get_content()
                    html_content = str(payload) if payload else None
        else:
            content_type = msg.get_content_type()
            payload = msg.get_content()
            if content_type == "text/plain":
                plain_text = str(payload) if payload else None
            elif content_type == "text/html":
                html_content = str(payload) if payload else None

        # Extract URLs from both text and HTML
        urls: list[str] = []
        if plain_text:
            urls.extend(cls._URL_PATTERN.findall(plain_text))
        if html_content:
            urls.extend(cls._URL_PATTERN.findall(html_content))
            urls.extend(cls._HREF_PATTERN.findall(html_content))

        # Deduplicate preserving order
        seen: set[str] = set()
        unique_urls: list[str] = []
        for u in urls:
            if u.startswith("http") and u not in seen:
                seen.add(u)
                unique_urls.append(u)

        # Extract unique domains from URLs
        domains: set[str] = set()
        for url in unique_urls:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    domains.add(parsed.hostname.lower())
            except Exception:
                pass

        return EmailBody(
            plain_text=plain_text,
            html_content=html_content,
            extracted_urls=unique_urls,
            extracted_domains=sorted(domains),
        )

    @classmethod
    def _extract_attachments(cls, msg: Any) -> list[EmailAttachmentInfo]:
        """Extract attachment metadata without detonating the files."""
        attachments: list[EmailAttachmentInfo] = []
        if not msg.is_multipart():
            return attachments

        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            if "attachment" not in content_disposition:
                continue

            filename = part.get_filename() or "unnamed_attachment"
            content_type = part.get_content_type() or "application/octet-stream"

            # Get raw bytes for hashing (but never execute)
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            size_bytes = len(payload) if payload else 0
            sha256 = hashlib.sha256(payload).hexdigest() if payload else None
            md5 = hashlib.md5(payload).hexdigest() if payload else None

            ext = ""
            if "." in filename:
                ext = "." + filename.rsplit(".", 1)[-1].lower()

            attachments.append(EmailAttachmentInfo(
                filename=filename,
                content_type=content_type,
                size_bytes=size_bytes,
                sha256=sha256,
                md5=md5,
                is_executable=ext in DANGEROUS_EXTENSIONS,
                is_archive=ext in ARCHIVE_EXTENSIONS,
                is_macro_enabled=ext in MACRO_EXTENSIONS,
                extension=ext,
            ))

        return attachments


# ---------------------------------------------------------------------------
# EmailAnalyzer — the core phishing detection engine for emails
# ---------------------------------------------------------------------------

class EmailAnalyzer:
    """Stateless email phishing detection engine.

    Analyzes a ParsedEmail and produces a PhishingVerdict containing:
    - A composite risk score (0–100)
    - Individual PhishingSignals explaining what fired and why
    - A human-readable explanation summarizing all signals
    - MITRE ATT&CK technique tags

    This is the Phase 5, Feature 1 implementation covering:
    - Email header anomaly detection
    - Authentication failure analysis (SPF, DKIM, DMARC)
    - Sender reputation heuristics
    - Content-based social engineering language detection
    - Link/URL suspicious pattern detection
    - Display name impersonation detection
    - Attachment risk assessment (metadata only, no detonation)
    """

    # Score thresholds for severity classification
    SCORE_THRESHOLDS: dict[str, float] = {
        "critical": 80.0,
        "high": 60.0,
        "medium": 40.0,
        "low": 20.0,
    }

    def __init__(
        self,
        url_scanner: Optional[Any] = None,
        attachment_analyzer: Optional[Any] = None,
    ) -> None:
        """Initialize EmailAnalyzer with optional URLScanner and AttachmentAnalyzer."""
        self.url_scanner = url_scanner
        self.attachment_analyzer = attachment_analyzer

    def analyze(self, email: ParsedEmail) -> PhishingVerdict:
        """Analyze a parsed email for phishing indicators.

        Args:
            email: A fully parsed email structure.

        Returns:
            PhishingVerdict with score, signals, and explanation.
        """
        signals: list[PhishingSignal] = []

        # Run all detection modules
        signals.extend(self._check_authentication(email.header))
        signals.extend(self._check_header_anomalies(email.header))
        signals.extend(self._check_sender_reputation(email.header))
        signals.extend(self._check_impersonation(email.header))
        signals.extend(self._check_urgency_language(email.body, email.header.subject))
        signals.extend(self._check_urls(email.body))
        signals.extend(self._check_attachments(email.attachments))
        signals.extend(self._check_content_anomalies(email))

        # Calculate composite score
        raw_score = sum(s.score_contribution for s in signals)
        final_score = min(100.0, max(0.0, raw_score))

        # Determine severity
        severity = self._score_to_severity(final_score)

        # Determine if phishing
        is_phishing = final_score >= self.SCORE_THRESHOLDS["medium"]

        # Calculate confidence (based on signal count and consistency)
        confidence = self._calculate_confidence(signals, final_score)

        # Collect MITRE techniques
        mitre_techniques = sorted(set(
            s.mitre_technique for s in signals if s.mitre_technique
        ))

        # Build human-readable explanation
        explanation = self._build_explanation(signals, final_score, severity)

        return PhishingVerdict(
            email_id=email.email_id,
            analysis_type="email",
            score=round(final_score, 1),
            severity=severity,
            is_phishing=is_phishing,
            confidence=round(confidence, 3),
            signals=signals,
            explanation=explanation,
            mitre_techniques=mitre_techniques,
        )

    # ------------------------------------------------------------------
    # Detection Modules
    # ------------------------------------------------------------------

    def _check_authentication(self, header: EmailHeader) -> list[PhishingSignal]:
        """Check SPF, DKIM, and DMARC authentication results."""
        signals: list[PhishingSignal] = []

        if header.spf_result and header.spf_result in ("fail", "softfail"):
            signals.append(PhishingSignal(
                category=SignalCategory.AUTHENTICATION_FAILURE,
                name="SPF Authentication Failure",
                description=f"SPF check returned '{header.spf_result}' — the sending server "
                            f"is not authorized to send email for this domain",
                severity=PhishingSeverity.HIGH,
                score_contribution=20.0 if header.spf_result == "fail" else 12.0,
                evidence=f"SPF={header.spf_result}",
                mitre_technique="T1566.001",
            ))

        if header.dkim_result and header.dkim_result == "fail":
            signals.append(PhishingSignal(
                category=SignalCategory.AUTHENTICATION_FAILURE,
                name="DKIM Signature Failure",
                description="DKIM signature verification failed — the email content may have "
                            "been modified in transit or the signature is forged",
                severity=PhishingSeverity.HIGH,
                score_contribution=18.0,
                evidence=f"DKIM={header.dkim_result}",
                mitre_technique="T1566.001",
            ))

        if header.dmarc_result and header.dmarc_result == "fail":
            signals.append(PhishingSignal(
                category=SignalCategory.AUTHENTICATION_FAILURE,
                name="DMARC Policy Failure",
                description="DMARC alignment failed — the sender domain's anti-spoofing "
                            "policy flagged this email as potentially fraudulent",
                severity=PhishingSeverity.HIGH,
                score_contribution=22.0,
                evidence=f"DMARC={header.dmarc_result}",
                mitre_technique="T1566.001",
            ))

        return signals

    def _check_header_anomalies(self, header: EmailHeader) -> list[PhishingSignal]:
        """Detect suspicious header patterns."""
        signals: list[PhishingSignal] = []

        # Reply-To mismatch with From
        if header.reply_to and header.from_address:
            from_domain = self._extract_domain(header.from_address)
            reply_domain = self._extract_domain(header.reply_to)
            if from_domain and reply_domain and from_domain != reply_domain:
                signals.append(PhishingSignal(
                    category=SignalCategory.HEADER_ANOMALY,
                    name="Reply-To Domain Mismatch",
                    description=f"Reply-To domain ({reply_domain}) differs from sender domain "
                                f"({from_domain}) — replies would go to a different organization",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=15.0,
                    evidence=f"From: {from_domain}, Reply-To: {reply_domain}",
                    mitre_technique="T1566.001",
                ))

        # Return-Path mismatch with From
        if header.return_path and header.from_address:
            from_domain = self._extract_domain(header.from_address)
            return_domain = self._extract_domain(header.return_path)
            if from_domain and return_domain and from_domain != return_domain:
                signals.append(PhishingSignal(
                    category=SignalCategory.HEADER_ANOMALY,
                    name="Return-Path Domain Mismatch",
                    description=f"Return-Path domain ({return_domain}) differs from sender domain "
                                f"({from_domain}) — bounce messages would go elsewhere",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=10.0,
                    evidence=f"From: {from_domain}, Return-Path: {return_domain}",
                    mitre_technique="T1566.001",
                ))

        # Empty or missing Received chain (likely crafted/spoofed)
        if len(header.received_chain) == 0:
            signals.append(PhishingSignal(
                category=SignalCategory.HEADER_ANOMALY,
                name="Missing Received Headers",
                description="No Received headers found — legitimate email always has at least "
                            "one hop recorded; this may indicate a locally crafted message",
                severity=PhishingSeverity.MEDIUM,
                score_contribution=8.0,
                evidence="Received chain: empty",
            ))

        return signals

    def _check_sender_reputation(self, header: EmailHeader) -> list[PhishingSignal]:
        """Heuristic sender reputation checks."""
        signals: list[PhishingSignal] = []
        sender_domain = self._extract_domain(header.from_address)

        if not sender_domain:
            return signals

        # Free email provider sending as organization
        if sender_domain in FREE_EMAIL_PROVIDERS:
            # Check if subject or display name impersonates a brand
            subject_lower = (header.subject or "").lower()
            display_lower = (header.from_display_name or "").lower()
            for brand in IMPERSONATED_BRANDS:
                if brand in display_lower or brand in subject_lower:
                    signals.append(PhishingSignal(
                        category=SignalCategory.SENDER_REPUTATION,
                        name="Brand Impersonation from Free Email",
                        description=f"Email claims to be from '{brand}' but uses a free email "
                                    f"provider ({sender_domain}) — legitimate organizations use "
                                    f"their own domain",
                        severity=PhishingSeverity.HIGH,
                        score_contribution=18.0,
                        evidence=f"Sender: {header.from_address}, Brand: {brand}",
                        mitre_technique="T1566.001",
                    ))
                    break  # Only flag once

        # Suspicious TLD patterns (often used in phishing)
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".club", ".icu"}
        for tld in suspicious_tlds:
            if sender_domain.endswith(tld):
                signals.append(PhishingSignal(
                    category=SignalCategory.SENDER_REPUTATION,
                    name="Suspicious Sender TLD",
                    description=f"Sender domain uses TLD '{tld}' which is frequently associated "
                                f"with disposable phishing domains",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=10.0,
                    evidence=f"Domain: {sender_domain}",
                    mitre_technique="T1566.001",
                ))
                break

        return signals

    def _check_impersonation(self, header: EmailHeader) -> list[PhishingSignal]:
        """Detect display name spoofing and brand impersonation."""
        signals: list[PhishingSignal] = []

        if not header.from_display_name:
            return signals

        display_lower = header.from_display_name.lower()
        sender_domain = self._extract_domain(header.from_address) or ""

        # Display name contains an email address (common social engineering trick)
        if "@" in header.from_display_name and "." in header.from_display_name:
            # The display name looks like an email — misleads the user
            signals.append(PhishingSignal(
                category=SignalCategory.IMPERSONATION,
                name="Email Address in Display Name",
                description="The display name contains what appears to be an email address — "
                            "this is a common social engineering technique to make the "
                            "email appear to come from a different sender",
                severity=PhishingSeverity.HIGH,
                score_contribution=15.0,
                evidence=f"Display: '{header.from_display_name}', Actual: {header.from_address}",
                mitre_technique="T1566.001",
            ))

        # Brand name in display name but domain doesn't match
        for brand in IMPERSONATED_BRANDS:
            if brand in display_lower and brand not in sender_domain:
                signals.append(PhishingSignal(
                    category=SignalCategory.IMPERSONATION,
                    name="Brand Name Impersonation",
                    description=f"Display name references '{brand}' but the actual sender domain "
                                f"({sender_domain}) is not associated with that brand",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=16.0,
                    evidence=f"Display: '{header.from_display_name}', Domain: {sender_domain}",
                    mitre_technique="T1566.001",
                ))
                break

        return signals

    def _check_urgency_language(
        self, body: EmailBody, subject: Optional[str]
    ) -> list[PhishingSignal]:
        """Detect social engineering urgency/pressure language."""
        signals: list[PhishingSignal] = []

        # Combine subject and body text for analysis
        text_to_scan = ""
        if subject:
            text_to_scan += subject + " "
        if body.plain_text:
            text_to_scan += body.plain_text + " "
        if body.html_content:
            # Strip HTML tags for content analysis
            text_to_scan += re.sub(r"<[^>]+>", " ", body.html_content)

        if not text_to_scan.strip():
            return signals

        text_lower = text_to_scan.lower()

        matched_patterns: set[str] = set()
        for pattern, description in URGENCY_PATTERNS:
            if re.search(pattern, text_lower):
                if description not in matched_patterns:
                    matched_patterns.add(description)
                    # Find the actual matching text for evidence
                    match = re.search(pattern, text_lower)
                    evidence_text = match.group(0) if match else description
                    signals.append(PhishingSignal(
                        category=SignalCategory.URGENCY_LANGUAGE,
                        name="Social Engineering Language",
                        description=description,
                        severity=PhishingSeverity.MEDIUM,
                        score_contribution=8.0,
                        evidence=f"Matched: '{evidence_text}'",
                        mitre_technique="T1566.001",
                    ))

        # Excessive exclamation marks or all-caps in subject
        if subject:
            exclamation_count = subject.count("!")
            if exclamation_count >= 2:
                signals.append(PhishingSignal(
                    category=SignalCategory.URGENCY_LANGUAGE,
                    name="Excessive Punctuation in Subject",
                    description=f"Subject line contains {exclamation_count} exclamation marks — "
                                f"legitimate organizational emails rarely use multiple exclamation marks",
                    severity=PhishingSeverity.LOW,
                    score_contribution=5.0,
                    evidence=f"Subject: '{subject}'",
                ))

            # All-caps words (more than 3 consecutive caps words)
            caps_words = re.findall(r"\b[A-Z]{3,}\b", subject)
            if len(caps_words) >= 2:
                signals.append(PhishingSignal(
                    category=SignalCategory.URGENCY_LANGUAGE,
                    name="Excessive Capitalization",
                    description="Subject contains multiple ALL-CAPS words — commonly used in "
                                "phishing to create a sense of urgency or importance",
                    severity=PhishingSeverity.LOW,
                    score_contribution=4.0,
                    evidence=f"Caps words: {', '.join(caps_words[:5])}",
                ))

        return signals

    def _check_urls(self, body: EmailBody) -> list[PhishingSignal]:
        """Analyze URLs in the email body for suspicious patterns."""
        signals: list[PhishingSignal] = []

        for url in body.extracted_urls:
            try:
                parsed = urlparse(url)
            except Exception:
                continue

            hostname = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            full_url = url.lower()

            # URL shortener detected
            if hostname in URL_SHORTENERS:
                signals.append(PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="URL Shortener Detected",
                    description=f"Email contains a shortened URL ({hostname}) — shorteners "
                                f"hide the true destination and are commonly used in phishing",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=10.0,
                    evidence=f"URL: {url[:100]}",
                    mitre_technique="T1566.002",
                ))

            # IP address instead of domain
            if hostname and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                signals.append(PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="IP Address URL",
                    description=f"Link points to a raw IP address ({hostname}) instead of a "
                                f"domain name — legitimate organizations use registered domains",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=15.0,
                    evidence=f"URL: {url[:100]}",
                    mitre_technique="T1566.002",
                ))

            # Credential harvesting URL patterns
            for pattern, description in CREDENTIAL_HARVEST_PATTERNS:
                if re.search(pattern, path) or re.search(pattern, full_url):
                    signals.append(PhishingSignal(
                        category=SignalCategory.CREDENTIAL_HARVESTING,
                        name="Credential Harvesting URL",
                        description=description,
                        severity=PhishingSeverity.HIGH,
                        score_contribution=12.0,
                        evidence=f"URL: {url[:100]}",
                        mitre_technique="T1566.002",
                    ))
                    break  # One match per URL is enough

            # Mismatched domain in anchor text (HTML-only, basic heuristic)
            # Check for "@" in URL (deceptive URL scheme like http://legit.com@evil.com)
            if "@" in hostname or (parsed.netloc and "@" in parsed.netloc):
                signals.append(PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="Deceptive URL with @ Symbol",
                    description="URL contains an '@' symbol in the authority component — "
                                "this can trick users into thinking the link goes to a different site",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=18.0,
                    evidence=f"URL: {url[:100]}",
                    mitre_technique="T1566.002",
                ))

            # Excessive subdomains (typosquatting/confusion technique)
            if hostname:
                subdomain_count = hostname.count(".")
                if subdomain_count >= 4:
                    signals.append(PhishingSignal(
                        category=SignalCategory.URL_OBFUSCATION,
                        name="Excessive Subdomain Depth",
                        description=f"URL has {subdomain_count} subdomain levels — excessive "
                                    f"subdomain depth is used to disguise the actual domain",
                        severity=PhishingSeverity.MEDIUM,
                        score_contribution=8.0,
                        evidence=f"Host: {hostname}",
                        mitre_technique="T1566.002",
                    ))
            # Optional URLScanner deep inspection (homographs, typosquatting, threat intel)
            if self.url_scanner:
                try:
                    url_verdict = self.url_scanner.scan_url(url)
                    for usig in url_verdict.signals:
                        if not any(s.name == usig.name for s in signals):
                            signals.append(usig)
                except Exception:
                    pass

        return signals

    def _check_attachments(self, attachments: list[EmailAttachmentInfo]) -> list[PhishingSignal]:
        """Assess attachment risk based on metadata (no detonation)."""
        signals: list[PhishingSignal] = []

        for att in attachments:
            if att.is_executable:
                signals.append(PhishingSignal(
                    category=SignalCategory.ATTACHMENT_RISK,
                    name="Executable Attachment",
                    description=f"Email contains an executable attachment ({att.filename}) — "
                                f"legitimate emails rarely include executable files as attachments",
                    severity=PhishingSeverity.CRITICAL,
                    score_contribution=25.0,
                    evidence=f"File: {att.filename} ({att.extension}), Size: {att.size_bytes}B",
                    mitre_technique="T1566.001",
                ))

            if att.is_macro_enabled:
                signals.append(PhishingSignal(
                    category=SignalCategory.ATTACHMENT_RISK,
                    name="Macro-Enabled Document",
                    description=f"Attachment '{att.filename}' is a macro-enabled document — "
                                f"VBA macros are a common malware delivery mechanism",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=20.0,
                    evidence=f"File: {att.filename} ({att.extension})",
                    mitre_technique="T1566.001",
                ))

            if att.is_archive:
                signals.append(PhishingSignal(
                    category=SignalCategory.ATTACHMENT_RISK,
                    name="Archive Attachment",
                    description=f"Email contains an archive attachment ({att.filename}) — "
                                f"archives can hide malicious payloads and bypass email filters",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=8.0,
                    evidence=f"File: {att.filename} ({att.extension}), Size: {att.size_bytes}B",
                    mitre_technique="T1566.001",
                ))

            # Optional AttachmentAnalyzer deep inspection (hash intel, double ext, RTLO)
            if self.attachment_analyzer:
                try:
                    att_verdict = self.attachment_analyzer.scan_metadata(att)
                    for asig in att_verdict.signals:
                        if asig.name in (
                            "rtlo_filename_spoofing",
                            "double_extension_masquerading",
                            "attachment_hash_threat_intel_match",
                            "script_attachment",
                        ) and not any(s.name == asig.name for s in signals):
                            signals.append(asig)
                except Exception:
                    pass

        return signals

    def _check_content_anomalies(self, email: ParsedEmail) -> list[PhishingSignal]:
        """Detect content-level anomalies in the email."""
        signals: list[PhishingSignal] = []

        # HTML-only email with no plain text (can hide malicious content)
        if email.body.html_content and not email.body.plain_text:
            # Check if HTML contains hidden elements (display:none, visibility:hidden)
            html_lower = email.body.html_content.lower()
            if "display:none" in html_lower or "visibility:hidden" in html_lower:
                signals.append(PhishingSignal(
                    category=SignalCategory.CONTENT_ANOMALY,
                    name="Hidden HTML Content",
                    description="Email HTML contains hidden elements (display:none / visibility:hidden) "
                                "— this technique is used to embed tracking or confuse text-based "
                                "phishing filters",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=10.0,
                    evidence="Hidden CSS properties detected in HTML body",
                    mitre_technique="T1566.001",
                ))

            # Check for form elements (data exfiltration)
            if "<form" in html_lower:
                signals.append(PhishingSignal(
                    category=SignalCategory.CREDENTIAL_HARVESTING,
                    name="Embedded Form in Email",
                    description="Email HTML contains a <form> element — legitimate emails "
                                "link to forms on websites rather than embedding them directly",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=18.0,
                    evidence="<form> element detected in HTML body",
                    mitre_technique="T1566.001",
                ))

        # Mismatched link text and URL (basic check on HTML)
        if email.body.html_content:
            # Find <a> tags where the visible text looks like a URL different from href
            link_pattern = re.compile(
                r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(https?://[^<]+)</a>',
                re.IGNORECASE,
            )
            for match in link_pattern.finditer(email.body.html_content):
                href_url = match.group(1)
                display_url = match.group(2)
                try:
                    href_domain = urlparse(href_url).hostname or ""
                    display_domain = urlparse(display_url).hostname or ""
                    if href_domain and display_domain and href_domain != display_domain:
                        signals.append(PhishingSignal(
                            category=SignalCategory.URL_OBFUSCATION,
                            name="Mismatched Link Text and Destination",
                            description=f"Link text shows '{display_domain}' but actually "
                                        f"points to '{href_domain}' — this is a classic "
                                        f"phishing deception technique",
                            severity=PhishingSeverity.CRITICAL,
                            score_contribution=22.0,
                            evidence=f"Display: {display_url[:80]}, Actual: {href_url[:80]}",
                            mitre_technique="T1566.002",
                        ))
                except Exception:
                    pass

        return signals

    # ------------------------------------------------------------------
    # Scoring & Explanation Helpers
    # ------------------------------------------------------------------

    def _score_to_severity(self, score: float) -> PhishingSeverity:
        """Map a numeric score to a severity level."""
        if score >= self.SCORE_THRESHOLDS["critical"]:
            return PhishingSeverity.CRITICAL
        elif score >= self.SCORE_THRESHOLDS["high"]:
            return PhishingSeverity.HIGH
        elif score >= self.SCORE_THRESHOLDS["medium"]:
            return PhishingSeverity.MEDIUM
        elif score >= self.SCORE_THRESHOLDS["low"]:
            return PhishingSeverity.LOW
        else:
            return PhishingSeverity.SAFE

    def _calculate_confidence(
        self, signals: list[PhishingSignal], score: float
    ) -> float:
        """Calculate analysis confidence based on signal consistency.

        Higher confidence when:
        - Multiple independent signal categories fire
        - High-severity signals are present
        - Score is extreme (very high or very low)
        """
        if not signals:
            return 0.5  # No signals means we're unsure, not confident it's safe

        categories = set(s.category for s in signals)
        high_sev_count = sum(1 for s in signals if s.severity in (PhishingSeverity.HIGH, PhishingSeverity.CRITICAL))

        # Base confidence from category diversity (more categories = more confident)
        category_factor = min(1.0, len(categories) / 4.0)

        # High-severity signal factor
        severity_factor = min(1.0, high_sev_count / 3.0)

        # Score extremity factor (very high or very low scores are more certain)
        if score >= 80.0 or score <= 10.0:
            extremity_factor = 0.9
        elif score >= 60.0 or score <= 20.0:
            extremity_factor = 0.7
        else:
            extremity_factor = 0.5

        confidence = (category_factor * 0.35) + (severity_factor * 0.35) + (extremity_factor * 0.3)
        return min(1.0, max(0.0, confidence))

    def _build_explanation(
        self,
        signals: list[PhishingSignal],
        score: float,
        severity: PhishingSeverity,
    ) -> str:
        """Build a human-readable explanation of the phishing analysis.

        Per SKILL.md, explanations MUST always accompany scores with the
        specific signals that fired — never a bare number.
        """
        if not signals:
            return (
                f"Phishing Score: {score:.1f}/100 ({severity.value.upper()}) — "
                f"No phishing indicators detected. The email appears to be legitimate "
                f"based on header analysis, content inspection, and URL examination."
            )

        lines = [
            f"Phishing Score: {score:.1f}/100 ({severity.value.upper()})",
            f"Detected {len(signals)} phishing indicator(s):",
            "",
        ]

        # Group signals by category
        by_category: dict[SignalCategory, list[PhishingSignal]] = {}
        for s in signals:
            by_category.setdefault(s.category, []).append(s)

        for category, cat_signals in by_category.items():
            lines.append(f"  [{category.value.upper()}]")
            for s in cat_signals:
                lines.append(f"    • {s.name}: {s.description}")
                if s.evidence:
                    lines.append(f"      Evidence: {s.evidence}")
            lines.append("")

        return "\n".join(lines).strip()

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(address: str) -> Optional[str]:
        """Extract domain part from an email address or header value."""
        if not address:
            return None
        # Handle "Name <email@domain>" format
        if "<" in address:
            match = re.search(r"<([^>]+)>", address)
            if match:
                address = match.group(1)
        if "@" in address:
            return address.split("@")[-1].lower().strip()
        return None

    def to_security_event(self, verdict: PhishingVerdict, email: ParsedEmail) -> SecurityEvent:
        """Convert a phishing verdict into a canonical SecurityEvent for the pipeline.

        Publishes the verdict to the MMS event bus so the SOC correlation engine
        and AI Copilot can reason over phishing detections alongside other signals.
        """
        severity_map = {
            PhishingSeverity.SAFE: "low",
            PhishingSeverity.LOW: "low",
            PhishingSeverity.MEDIUM: "medium",
            PhishingSeverity.HIGH: "high",
            PhishingSeverity.CRITICAL: "critical",
        }

        return SecurityEvent(
            source="phishing",
            entity=Entity(
                ip=None,
                user=email.header.from_address or None,
                host=self._extract_domain(email.header.from_address),
            ),
            event_type="phishing_email_detected" if verdict.is_phishing else "phishing_email_scanned",
            severity=severity_map.get(verdict.severity, "low"),
            raw=verdict.to_security_event_raw(),
            enrichment={
                "phishing_score": verdict.score,
                "signal_count": len(verdict.signals),
                "mitre_techniques": verdict.mitre_techniques,
                "subject": email.header.subject or "",
            },
        )
