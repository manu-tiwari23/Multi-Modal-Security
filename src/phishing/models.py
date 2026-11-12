"""
Phishing Detection Data Models & Scoring Schemas.

Complies with ARCHITECTURE.md §4.4 and .agents/skills/phishing-detection/SKILL.md:
- Each detector is a stateless scoring service: input → {score, explanation} out.
- The Explanation Generator must always accompany a score with specific signals
  that fired — never return a bare number.
- Attachment analysis is static/metadata only unless an isolated sandbox is set up.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Signal Categories
# ---------------------------------------------------------------------------

class SignalCategory(str, Enum):
    """Categories of phishing indicators detected during analysis."""
    HEADER_ANOMALY = "header_anomaly"
    SENDER_REPUTATION = "sender_reputation"
    AUTHENTICATION_FAILURE = "authentication_failure"
    URGENCY_LANGUAGE = "urgency_language"
    SUSPICIOUS_LINK = "suspicious_link"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    IMPERSONATION = "impersonation"
    ATTACHMENT_RISK = "attachment_risk"
    CONTENT_ANOMALY = "content_anomaly"
    DOMAIN_AGE = "domain_age"
    URL_OBFUSCATION = "url_obfuscation"
    SOCIAL_ENGINEERING = "social_engineering"
    HOMOGRAPH_ATTACK = "homograph_attack"
    THREAT_INTEL_MATCH = "threat_intel_match"
    IP_HOST = "ip_host"


class PhishingSeverity(str, Enum):
    """Risk severity levels for phishing verdicts."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Signal — an individual phishing indicator that fired
# ---------------------------------------------------------------------------

class PhishingSignal(BaseModel):
    """A single phishing indicator detected during analysis.

    Every signal records what was found, which category it belongs to,
    its contribution to the overall risk score, and a human-readable
    explanation of why it matters.
    """
    signal_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: SignalCategory
    name: str
    description: str
    severity: PhishingSeverity = PhishingSeverity.MEDIUM
    score_contribution: float = 0.0
    evidence: str = ""
    mitre_technique: Optional[str] = None  # e.g., "T1566.001" (Phishing: Spearphishing Attachment)

    def to_dict(self) -> dict[str, Any]:
        """Serialize signal to dictionary."""
        return self.model_dump()


# ---------------------------------------------------------------------------
# Email Analysis Models
# ---------------------------------------------------------------------------

class EmailHeader(BaseModel):
    """Parsed email header fields relevant to phishing detection."""
    message_id: Optional[str] = None
    from_address: str = ""
    from_display_name: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    to_addresses: list[str] = Field(default_factory=list)
    cc_addresses: list[str] = Field(default_factory=list)
    subject: Optional[str] = None
    date: Optional[datetime] = None
    received_chain: list[str] = Field(default_factory=list)
    x_mailer: Optional[str] = None
    content_type: Optional[str] = None

    # Authentication results
    spf_result: Optional[str] = None  # "pass", "fail", "softfail", "neutral", "none"
    dkim_result: Optional[str] = None  # "pass", "fail", "none"
    dmarc_result: Optional[str] = None  # "pass", "fail", "none"

    # Raw headers dict for anything we didn't parse explicitly
    raw_headers: dict[str, str] = Field(default_factory=dict)


class EmailBody(BaseModel):
    """Parsed email body content."""
    plain_text: Optional[str] = None
    html_content: Optional[str] = None
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_domains: list[str] = Field(default_factory=list)


class EmailAttachmentInfo(BaseModel):
    """Metadata about an email attachment (no detonation — static analysis only)."""
    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: Optional[str] = None
    md5: Optional[str] = None
    is_executable: bool = False
    is_archive: bool = False
    is_macro_enabled: bool = False
    extension: str = ""


class ParsedEmail(BaseModel):
    """Fully parsed email structure ready for phishing analysis."""
    email_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    header: EmailHeader = Field(default_factory=EmailHeader)
    body: EmailBody = Field(default_factory=EmailBody)
    attachments: list[EmailAttachmentInfo] = Field(default_factory=list)
    raw_size_bytes: int = 0
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Phishing Verdict — the output of any detector
# ---------------------------------------------------------------------------

class PhishingVerdict(BaseModel):
    """Result of phishing analysis on an email, URL, or attachment.

    Per SKILL.md, a verdict MUST always include the specific signals that
    fired — never a bare score. The explanation field provides a
    human-readable summary combining all signal descriptions.
    """
    verdict_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email_id: Optional[str] = None
    target_url: Optional[str] = None
    target_filename: Optional[str] = None
    attachment_sha256: Optional[str] = None
    analysis_type: str = "email"  # "email", "url", "attachment"
    score: float = 0.0  # 0.0 (safe) to 100.0 (confirmed phishing)
    severity: PhishingSeverity = PhishingSeverity.SAFE
    is_phishing: bool = False
    confidence: float = 0.0  # 0.0 to 1.0
    signals: list[PhishingSignal] = Field(default_factory=list)
    explanation: str = ""  # Human-readable summary of all signals
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mitre_techniques: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize verdict to dictionary with ISO timestamps."""
        data = self.model_dump()
        data["analyzed_at"] = self.analyzed_at.isoformat()
        data["signals"] = [s.to_dict() for s in self.signals]
        return data

    def to_security_event_raw(self) -> dict[str, Any]:
        """Return a raw dict suitable for SecurityEvent.raw field."""
        return {
            "verdict_id": self.verdict_id,
            "analysis_type": self.analysis_type,
            "email_id": self.email_id,
            "target_url": self.target_url,
            "target_filename": self.target_filename,
            "attachment_sha256": self.attachment_sha256,
            "score": self.score,
            "severity": self.severity.value,
            "is_phishing": self.is_phishing,
            "confidence": self.confidence,
            "signal_count": len(self.signals),
            "explanation": self.explanation,
            "mitre_techniques": self.mitre_techniques,
        }


# ---------------------------------------------------------------------------
# URL Scanner Specific Models
# ---------------------------------------------------------------------------

class URLFeatures(BaseModel):
    """Extracted lexical, structural, and semantic features of a URL."""
    raw_url: str
    scheme: str = ""
    netloc: str = ""
    hostname: str = ""
    registered_domain: str = ""
    subdomain: str = ""
    subdomain_count: int = 0
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    userinfo: Optional[str] = None
    url_length: int = 0
    hostname_length: int = 0
    path_length: int = 0
    query_length: int = 0
    is_ip_address: bool = False
    ip_obfuscation_type: Optional[str] = None  # e.g., "dotted_decimal", "dword", "octal", "hex", "ipv6"
    is_shortener: bool = False
    is_punycode: bool = False
    has_homoglyphs: bool = False
    has_deceptive_userinfo: bool = False
    shannon_entropy: float = 0.0
    tld: str = ""
    is_suspicious_tld: bool = False
    has_credential_tokens: bool = False
    has_dangerous_extension: bool = False


class ThreatIntelResult(BaseModel):
    """External or cached threat intelligence lookup result for an IOC/URL."""
    ioc: str
    is_malicious: bool = False
    threat_score: float = 0.0  # 0.0 to 100.0
    source: str = "threat_intel"  # "virustotal", "abuseipdb", "openphish", "local_cache", "synthetic"
    positives: int = 0
    total_engines: int = 0
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    cached: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class URLScanResult(BaseModel):
    """Composite container holding URL features, threat intel, and final verdict."""
    url: str
    verdict: PhishingVerdict
    features: Optional[URLFeatures] = None
    threat_intel: Optional[ThreatIntelResult] = None


# ---------------------------------------------------------------------------
# Attachment Analyzer Specific Models
# ---------------------------------------------------------------------------

class AttachmentFeatures(BaseModel):
    """Extracted static and metadata features of an email attachment."""
    filename: str
    declared_extension: str = ""
    claimed_content_type: str = "application/octet-stream"
    detected_file_type: str = "unknown"
    size_bytes: int = 0
    sha256: str = ""
    md5: str = ""
    shannon_entropy: float = 0.0
    has_double_extension: bool = False
    has_rtlo_override: bool = False
    is_extension_spoofed: bool = False
    is_executable: bool = False
    is_script: bool = False
    is_archive: bool = False
    is_macro_enabled: bool = False
    has_embedded_macros: bool = False
    has_external_template: bool = False
    has_pdf_active_content: bool = False
    has_html_smuggling: bool = False
    is_encrypted_archive: bool = False
    is_zip_bomb_suspect: bool = False
    archive_members: list[str] = Field(default_factory=list)
    archive_suspicious_members: list[str] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)


class AttachmentScanResult(BaseModel):
    """Composite container holding attachment features, hash intel, and verdict."""
    filename: str
    verdict: PhishingVerdict
    features: AttachmentFeatures
    threat_intel: Optional[ThreatIntelResult] = None


# ---------------------------------------------------------------------------
# Explanation Generator Models
# ---------------------------------------------------------------------------

class CategoryContribution(BaseModel):
    """Aggregated score contribution for a single phishing signal category."""
    category: SignalCategory
    category_label: str
    signal_count: int
    raw_points: float
    share_percent: float
    highest_severity: PhishingSeverity
    top_signals: list[str] = Field(default_factory=list)


class SignalAttribution(BaseModel):
    """Individual signal contribution explaining why a verdict scored as it did."""
    signal_name: str
    category: str
    severity: PhishingSeverity
    score_contribution: float
    share_percent: float
    reason: str
    evidence: str = ""
    mitre_technique: Optional[str] = None


class MitreMappingDetail(BaseModel):
    """Human-readable MITRE ATT&CK technique reference."""
    technique_id: str
    technique_name: str
    tactic: str


class StructuredExplanation(BaseModel):
    """Auditable, layered explanation of why a phishing verdict scored as it did."""
    verdict_id: str
    analysis_type: str
    target_summary: str
    score: float
    raw_score: float = 0.0
    score_capped: bool = False
    severity: PhishingSeverity
    is_phishing: bool
    confidence: float
    headline: str
    narrative: str
    category_breakdown: list[CategoryContribution] = Field(default_factory=list)
    top_factors: list[SignalAttribution] = Field(default_factory=list)
    mitre_details: list[MitreMappingDetail] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    formatted_text: str = ""
    formatted_markdown: str = ""
