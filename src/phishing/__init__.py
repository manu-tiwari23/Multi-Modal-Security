"""
Multi Modal Security (MMS) - Phishing Detection Module.

Provides stateless email, URL, and attachment phishing analysis services.
Each detector produces a PhishingVerdict with a score, individual signals,
and a mandatory human-readable explanation (per ARCHITECTURE.md §4.4).
"""

from src.phishing.email_analyzer import (
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
    "EmailAnalyzer",
    "EmailParser",
    "EmailAttachmentInfo",
    "EmailBody",
    "EmailHeader",
    "ParsedEmail",
    "PhishingSeverity",
    "PhishingSignal",
    "PhishingVerdict",
    "SignalCategory",
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
    "VirusTotalLookupProvider",
]
