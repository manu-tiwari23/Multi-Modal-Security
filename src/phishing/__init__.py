"""
Multi Modal Security (MMS) - Phishing Detection Module.

Provides stateless email, URL, and attachment phishing analysis services.
Each detector produces a PhishingVerdict with a score, individual signals,
and a mandatory human-readable explanation (per ARCHITECTURE.md §4.4).
"""

from src.phishing.attachment_analyzer import (
    AttachmentAnalyzer,
    AttachmentFeatureExtractor,
    AttachmentHashProvider,
    HashReputationCache,
    MockHashIntelProvider,
    SyntheticHashBlocklistProvider,
    VirusTotalHashProvider,
)
from src.phishing.email_analyzer import (
    EmailAnalyzer,
    EmailParser,
)
from src.phishing.explanation_generator import ExplanationGenerator
from src.phishing.models import (
    AttachmentFeatures,
    AttachmentScanResult,
    CategoryContribution,
    EmailAttachmentInfo,
    EmailBody,
    EmailHeader,
    MitreMappingDetail,
    ParsedEmail,
    PhishingSeverity,
    PhishingSignal,
    PhishingVerdict,
    SignalAttribution,
    SignalCategory,
    StructuredExplanation,
    ThreatIntelResult,
    URLFeatures,
    URLScanResult,
)
from src.phishing.url_scanner import (
    LookalikeAnalyzer,
    MockThreatIntelProvider,
    SyntheticBlocklistProvider,
    ThreatIntelProvider,
    URLFeatureExtractor,
    URLReputationCache,
    URLScanner,
    VirusTotalLookupProvider,
)

__all__ = [
    "AttachmentAnalyzer",
    "AttachmentFeatureExtractor",
    "AttachmentFeatures",
    "AttachmentHashProvider",
    "AttachmentScanResult",
    "CategoryContribution",
    "EmailAnalyzer",
    "EmailParser",
    "EmailAttachmentInfo",
    "EmailBody",
    "EmailHeader",
    "ExplanationGenerator",
    "HashReputationCache",
    "MitreMappingDetail",
    "MockHashIntelProvider",
    "ParsedEmail",
    "PhishingSeverity",
    "PhishingSignal",
    "PhishingVerdict",
    "SignalAttribution",
    "SignalCategory",
    "StructuredExplanation",
    "SyntheticHashBlocklistProvider",
    "ThreatIntelResult",
    "URLFeatures",
    "URLScanResult",
    "LookalikeAnalyzer",
    "MockThreatIntelProvider",
    "SyntheticBlocklistProvider",
    "ThreatIntelProvider",
    "URLFeatureExtractor",
    "URLReputationCache",
    "URLScanner",
    "VirusTotalHashProvider",
    "VirusTotalLookupProvider",
]
