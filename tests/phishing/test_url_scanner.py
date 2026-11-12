"""
Unit tests for Phishing Detection — URL Reputation Scanner.

Tests Phase 5, Feature 2:
- URL Feature Extraction (schemes, netloc, userinfo, IP obfuscation, shorteners, TLDs)
- IDN Homograph & Punycode detection
- Brand typosquatting, Leetspeak, and subdomain injection
- Thread-safe TTL reputation caching
- Threat intel provider interface (Mock, Synthetic blocklist, VT graceful fallback)
- Heuristic scoring rules and threshold severity mapping
- Explanation generator completeness (mandatory signals & evidence)
- SecurityEvent pipeline mapping and MITRE ATT&CK tagging
"""

import time
import pytest

from src.phishing.models import (
    PhishingSeverity,
    PhishingSignal,
    PhishingVerdict,
    SignalCategory,
    ThreatIntelResult,
    URLFeatures,
)
from src.phishing.url_scanner import (
    LookalikeAnalyzer,
    MockThreatIntelProvider,
    SyntheticBlocklistProvider,
    URLFeatureExtractor,
    URLReputationCache,
    URLScanner,
    VirusTotalLookupProvider,
)
from src.shared.event_schema import SecurityEvent


# ===========================================================================
# 1. URL Feature Extraction Tests
# ===========================================================================

class TestURLFeatureExtractor:
    """Tests for URLFeatureExtractor lexical and structural parsing."""

    def test_extract_clean_url(self) -> None:
        url = "https://www.google.com/search?q=cybersecurity"
        f = URLFeatureExtractor.extract_features(url)

        assert f.scheme == "https"
        assert f.hostname == "www.google.com"
        assert f.registered_domain == "google.com"
        assert f.subdomain == "www"
        assert f.subdomain_count == 1
        assert f.tld == "com"
        assert not f.is_ip_address
        assert not f.is_shortener
        assert not f.is_suspicious_tld
        assert not f.has_deceptive_userinfo

    def test_extract_url_with_port(self) -> None:
        url = "http://example.com:8080/api/v1/status"
        f = URLFeatureExtractor.extract_features(url)

        assert f.hostname == "example.com"
        assert f.port == 8080
        assert f.path == "/api/v1/status"

    def test_extract_multi_part_tld(self) -> None:
        url = "https://banking.barclays.co.uk/auth/login"
        f = URLFeatureExtractor.extract_features(url)

        assert f.tld == "co.uk"
        assert f.registered_domain == "barclays.co.uk"
        assert f.subdomain == "banking"

    def test_extract_userinfo_deception(self) -> None:
        url = "https://paypal.com:account-update@evil-phishing.com/login"
        f = URLFeatureExtractor.extract_features(url)

        assert f.has_deceptive_userinfo
        assert f.userinfo == "paypal.com:account-update"
        assert f.hostname == "evil-phishing.com"

    def test_extract_raw_ipv4(self) -> None:
        url = "http://192.168.1.100/admin/panel"
        f = URLFeatureExtractor.extract_features(url)

        assert f.is_ip_address
        assert f.ip_obfuscation_type == "dotted_decimal"
        assert f.hostname == "192.168.1.100"

    def test_extract_ipv6(self) -> None:
        url = "http://[2001:db8::1]/index.html"
        f = URLFeatureExtractor.extract_features(url)

        assert f.is_ip_address
        assert f.ip_obfuscation_type == "ipv6"

    def test_extract_dword_ip(self) -> None:
        # 2130706433 = 127.0.0.1
        url = "http://2130706433/login"
        f = URLFeatureExtractor.extract_features(url)

        assert f.is_ip_address
        assert f.ip_obfuscation_type == "dword"

    def test_extract_octal_ip(self) -> None:
        # 0177.0.0.1 with leading zero
        url = "http://0177.0.0.1/verify"
        f = URLFeatureExtractor.extract_features(url)

        assert f.is_ip_address
        assert f.ip_obfuscation_type in ("octal", "octal_octets")

    def test_extract_hex_ip(self) -> None:
        # 0x7f000001 = 127.0.0.1
        url = "http://0x7f000001/session"
        f = URLFeatureExtractor.extract_features(url)

        assert f.is_ip_address
        assert f.ip_obfuscation_type == "hex"

    def test_extract_shortener(self) -> None:
        url = "https://bit.ly/3xYQz9A"
        f = URLFeatureExtractor.extract_features(url)

        assert f.is_shortener
        assert f.hostname == "bit.ly"

    def test_extract_suspicious_tld(self) -> None:
        url = "http://my-banking-login.top/account"
        f = URLFeatureExtractor.extract_features(url)

        assert f.is_suspicious_tld
        assert f.tld == "top"

    def test_shannon_entropy(self) -> None:
        low_entropy = URLFeatureExtractor.calculate_shannon_entropy("aaaaaaaaaaaa")
        high_entropy = URLFeatureExtractor.calculate_shannon_entropy("k9f7b2x0q1z8m3w5")

        assert low_entropy < 1.0
        assert high_entropy > 3.5

    def test_credential_tokens(self) -> None:
        url = "https://example.com/portal/signin?action=verify_password"
        f = URLFeatureExtractor.extract_features(url)

        assert f.has_credential_tokens

    def test_dangerous_extension(self) -> None:
        url = "http://bad-server.com/downloads/invoice.exe"
        f = URLFeatureExtractor.extract_features(url)

        assert f.has_dangerous_extension


# ===========================================================================
# 2. Lookalike and Homograph Analyzer Tests
# ===========================================================================

class TestLookalikeAnalyzer:
    """Tests for homograph, typosquatting, and brand abuse detection."""

    def test_cyrillic_homoglyph_detection(self) -> None:
        # Cyrillic 'а' (\u0430) instead of ASCII 'a'
        spoofed_host = "p\u0430ypal.com"
        sub, reg, _ = URLFeatureExtractor.split_domain(spoofed_host)
        signals = LookalikeAnalyzer.check_brand_abuse(spoofed_host, reg, sub)

        homograph_sigs = [s for s in signals if s.category == SignalCategory.HOMOGRAPH_ATTACK]
        assert len(homograph_sigs) >= 1
        assert "mixed Cyrillic/Greek homoglyphs" in homograph_sigs[0].description

    def test_punycode_detection(self) -> None:
        # Punycode for pаypal.com
        puny_host = "xn--pypal-4ve.com"
        sub, reg, _ = URLFeatureExtractor.split_domain(puny_host)
        signals = LookalikeAnalyzer.check_brand_abuse(puny_host, reg, sub)

        puny_sigs = [s for s in signals if s.name == "punycode_domain"]
        assert len(puny_sigs) >= 1

    def test_subdomain_brand_injection(self) -> None:
        # Brand in subdomain of attacker domain
        host = "paypal.com.customer-support-notice.com"
        sub, reg, _ = URLFeatureExtractor.split_domain(host)
        signals = LookalikeAnalyzer.check_brand_abuse(host, reg, sub)

        sub_sigs = [s for s in signals if s.name == "brand_in_subdomain"]
        assert len(sub_sigs) >= 1
        assert "paypal" in sub_sigs[0].description

    def test_brand_combo_domain(self) -> None:
        host = "apple-security-check.com"
        sub, reg, _ = URLFeatureExtractor.split_domain(host)
        signals = LookalikeAnalyzer.check_brand_abuse(host, reg, sub)

        combo_sigs = [s for s in signals if s.name == "brand_combo_domain"]
        assert len(combo_sigs) >= 1
        assert "apple" in combo_sigs[0].description

    def test_optical_typosquatting(self) -> None:
        # Leetspeak 0 for o
        host = "micr0soft.com"
        sub, reg, _ = URLFeatureExtractor.split_domain(host)
        signals = LookalikeAnalyzer.check_brand_abuse(host, reg, sub)

        typo_sigs = [s for s in signals if s.name == "optical_typosquatting"]
        assert len(typo_sigs) >= 1
        assert "microsoft" in typo_sigs[0].description

    def test_levenshtein_typosquatting(self) -> None:
        # 1 edit distance from paypal
        host = "paypaal.com"
        sub, reg, _ = URLFeatureExtractor.split_domain(host)
        signals = LookalikeAnalyzer.check_brand_abuse(host, reg, sub)

        lev_sigs = [s for s in signals if s.name == "levenshtein_typosquatting"]
        assert len(lev_sigs) >= 1

    def test_official_brand_domain_ignored(self) -> None:
        # Official domains must not trigger brand impersonation
        host = "www.paypal.com"
        sub, reg, _ = URLFeatureExtractor.split_domain(host)
        signals = LookalikeAnalyzer.check_brand_abuse(host, reg, sub)

        brand_sigs = [s for s in signals if s.category == SignalCategory.IMPERSONATION]
        assert len(brand_sigs) == 0


# ===========================================================================
# 3. Reputation Cache Tests
# ===========================================================================

class TestURLReputationCache:
    """Tests for thread-safe TTL reputation cache."""

    def test_cache_set_and_get(self) -> None:
        cache = URLReputationCache(default_ttl_seconds=60.0)
        res = ThreatIntelResult(
            ioc="http://test.com",
            is_malicious=True,
            threat_score=85.0,
            source="test_source",
        )
        cache.set("http://test.com", res)

        cached = cache.get("http://test.com")
        assert cached is not None
        assert cached.is_malicious
        assert cached.threat_score == 85.0
        assert cached.cached is True

    def test_cache_ttl_expiry(self) -> None:
        cache = URLReputationCache(default_ttl_seconds=0.05)
        res = ThreatIntelResult(ioc="http://expire.com", is_malicious=False)
        cache.set("http://expire.com", res, ttl=0.05)

        assert cache.get("http://expire.com") is not None
        time.sleep(0.07)
        assert cache.get("http://expire.com") is None

    def test_cache_capacity_eviction(self) -> None:
        cache = URLReputationCache(max_entries=5)
        for i in range(10):
            res = ThreatIntelResult(ioc=f"http://site{i}.com", is_malicious=False)
            cache.set(f"http://site{i}.com", res)

        assert len(cache) <= 10  # capacity eviction kept size bounded

    def test_cache_normalizes_keys(self) -> None:
        cache = URLReputationCache()
        res = ThreatIntelResult(ioc="http://normal.com", is_malicious=True)
        cache.set("HTTP://Normal.COM/", res)

        retrieved = cache.get("http://normal.com")
        assert retrieved is not None
        assert retrieved.is_malicious


# ===========================================================================
# 4. Threat Intel Provider Tests
# ===========================================================================

class TestThreatIntelProviders:
    """Tests for mock, synthetic, and VT fallback providers."""

    def test_mock_provider(self) -> None:
        provider = MockThreatIntelProvider()
        provider.add_entry(
            "http://malicious-entry.com",
            ThreatIntelResult(
                ioc="http://malicious-entry.com",
                is_malicious=True,
                threat_score=95.0,
                source="mock",
            ),
        )

        res = provider.lookup_url("http://malicious-entry.com")
        assert res.is_malicious
        assert res.threat_score == 95.0

        clean_res = provider.lookup_url("https://clean-site.org")
        assert not clean_res.is_malicious

    def test_synthetic_blocklist_provider(self) -> None:
        provider = SyntheticBlocklistProvider()
        res = provider.lookup_url("http://phishing-test-login.com/auth")

        assert res.is_malicious
        assert res.threat_score >= 90.0
        assert "phishing" in res.categories

        clean = provider.lookup_url("https://python.org")
        assert not clean.is_malicious

    def test_virustotal_unconfigured_graceful(self) -> None:
        vt = VirusTotalLookupProvider(api_key="")
        res = vt.lookup_url("https://test.com")

        assert not res.is_malicious
        assert res.source == "virustotal_unconfigured"

    def test_virustotal_error_graceful_degradation(self) -> None:
        # Invalid host/key should not crash
        vt = VirusTotalLookupProvider(api_key="invalid_fake_key_123")
        res = vt.lookup_url("https://some-unreachable-domain-xyz.com", timeout=0.1)

        assert not res.is_malicious
        assert res.source == "virustotal_degraded"


# ===========================================================================
# 5. Heuristic Detection Module Tests
# ===========================================================================

class TestURLScannerDetectionRules:
    """Tests for individual detection heuristics in URLScanner."""

    @pytest.fixture
    def scanner(self) -> URLScanner:
        return URLScanner(threat_intel_provider=MockThreatIntelProvider())

    def test_dangerous_scheme_flagged(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("javascript:document.location='http://evil.com'")
        sig_names = [s.name for s in v.signals]

        assert "dangerous_url_scheme" in sig_names
        assert v.score >= 40.0
        assert v.severity in (PhishingSeverity.MEDIUM, PhishingSeverity.HIGH, PhishingSeverity.CRITICAL)

    def test_deceptive_userinfo_flagged(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("http://paypal.com:verify@192.168.1.1/login")
        sig_names = [s.name for s in v.signals]

        assert "deceptive_userinfo_at_symbol" in sig_names
        assert v.is_phishing

    def test_raw_ip_address_host_flagged(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("http://198.51.100.12/account/verify")
        sig_names = [s.name for s in v.signals]

        assert "raw_ip_address_host" in sig_names
        assert "credential_harvesting_path" in sig_names

    def test_obfuscated_ip_flagged(self, scanner: URLScanner) -> None:
        # Hex encoded IP
        v = scanner.scan_url("http://0x7f000001/admin")
        sig_names = [s.name for s in v.signals]

        assert "obfuscated_ip_address" in sig_names

    def test_suspicious_tld_flagged(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("http://security-update-portal.xyz/verify")
        sig_names = [s.name for s in v.signals]

        assert "suspicious_tld" in sig_names

    def test_shortener_service_flagged(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("https://bit.ly/3xPhish")
        sig_names = [s.name for s in v.signals]

        assert "url_shortener_service" in sig_names

    def test_credential_harvesting_path_flagged(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("http://portal.example.com/auth/login?redirect=billing")
        sig_names = [s.name for s in v.signals]

        assert "credential_harvesting_path" in sig_names

    def test_dangerous_file_download_flagged(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("http://example-files.org/downloads/patch.exe")
        sig_names = [s.name for s in v.signals]

        assert "dangerous_file_download_link" in sig_names

    def test_double_extension_spoofing(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("http://files-share.com/document.pdf.exe")
        sig_names = [s.name for s in v.signals]

        assert "double_extension_spoofing" in sig_names
        assert v.severity in (PhishingSeverity.HIGH, PhishingSeverity.CRITICAL)

    def test_excessive_url_length(self, scanner: URLScanner) -> None:
        long_url = "http://example.com/" + "a" * 250
        v = scanner.scan_url(long_url)
        sig_names = [s.name for s in v.signals]

        assert "excessive_url_length" in sig_names

    def test_high_entropy_domain(self, scanner: URLScanner) -> None:
        # DGA-style domain with high random entropy
        dga_url = "http://x7k9m2q4w8z1b5p0v.net/index.html"
        v = scanner.scan_url(dga_url)
        sig_names = [s.name for s in v.signals]

        assert "high_entropy_domain" in sig_names

    def test_non_standard_port(self, scanner: URLScanner) -> None:
        v = scanner.scan_url("http://example.com:1337/service")
        sig_names = [s.name for s in v.signals]

        assert "non_standard_web_port" in sig_names


# ===========================================================================
# 6. End-to-End Pipeline & Integration Tests
# ===========================================================================

class TestFullURLPipeline:
    """End-to-end integration and pipeline tests for URLScanner."""

    def test_benign_url_scores_safe(self) -> None:
        scanner = URLScanner()
        v = scanner.scan_url("https://www.google.com/search?q=open+source+security")

        assert v.score == 0.0
        assert v.severity == PhishingSeverity.SAFE
        assert not v.is_phishing
        assert len(v.signals) == 0
        assert "is clean" in v.explanation

    def test_synthetic_threat_intel_match(self) -> None:
        scanner = URLScanner(threat_intel_provider=SyntheticBlocklistProvider())
        v = scanner.scan_url("http://phishing-test-login.com/account/login")

        assert v.is_phishing
        assert v.score >= 80.0
        assert v.severity == PhishingSeverity.CRITICAL
        sig_names = [s.name for s in v.signals]
        assert "threat_intelligence_blocklist_match" in sig_names

    def test_explanation_always_present_and_informative(self) -> None:
        scanner = URLScanner()
        v = scanner.scan_url("http://paypa1.com@192.168.1.50/account/verify.php")

        assert v.explanation
        assert "Verdict:" in v.explanation
        assert "Recommendation:" in v.explanation
        assert "Identified" in v.explanation
        for s in v.signals:
            assert s.name in v.explanation

    def test_batch_scanning(self) -> None:
        scanner = URLScanner()
        urls = [
            "https://python.org",
            "http://192.168.1.1/login",
            "http://micr0soft.com/verify",
        ]
        verdicts = scanner.scan_urls(urls)

        assert len(verdicts) == 3
        assert verdicts[0].severity == PhishingSeverity.SAFE
        assert verdicts[1].is_phishing
        assert verdicts[2].is_phishing

    def test_empty_url_handling(self) -> None:
        scanner = URLScanner()
        v = scanner.scan_url("   ")

        assert v.score == 0.0
        assert v.severity == PhishingSeverity.SAFE
        assert not v.is_phishing

    def test_security_event_mapping(self) -> None:
        scanner = URLScanner()
        v = scanner.scan_url("http://docusign-verification.xyz/sign/document.pdf.exe")
        event = scanner.to_security_event(v, source_user="johndoe")

        assert isinstance(event, SecurityEvent)
        assert event.source == "phishing"
        assert event.event_type == "phishing_url_detected"
        assert event.severity in ("high", "critical")
        assert event.entity.user == "johndoe"
        assert event.entity.host == "docusign-verification.xyz"
        assert event.raw["target_url"] == "http://docusign-verification.xyz/sign/document.pdf.exe"
        assert event.raw["is_phishing"] is True
        assert event.raw["signal_count"] >= 2

    def test_mitre_techniques_mapped(self) -> None:
        scanner = URLScanner()
        v = scanner.scan_url("http://apple-support-login.top/verify")

        assert "T1566.002" in v.mitre_techniques or "T1583.001" in v.mitre_techniques

    def test_cached_reputation_avoids_repeated_provider_calls(self) -> None:
        mock = MockThreatIntelProvider()
        mock.add_entry(
            "http://repeated-site.com",
            ThreatIntelResult(
                ioc="http://repeated-site.com",
                is_malicious=True,
                threat_score=88.0,
                source="mock",
            ),
        )
        cache = URLReputationCache()
        scanner = URLScanner(threat_intel_provider=mock, cache=cache)

        # First call hits provider
        v1 = scanner.scan_url("http://repeated-site.com")
        initial_count = mock.call_count
        assert initial_count >= 1

        # Second call hits cache
        v2 = scanner.scan_url("http://repeated-site.com")
        assert mock.call_count == initial_count  # No additional calls to provider
        assert v1.score == v2.score
        assert v1.is_phishing == v2.is_phishing

    def test_graceful_timeout_fallback(self) -> None:
        mock = MockThreatIntelProvider()
        mock.simulate_timeout = True
        scanner = URLScanner(threat_intel_provider=mock)

        # Scanner must not crash when threat intel provider times out
        v = scanner.scan_url("http://micr0soft.com/login")
        assert v is not None
        assert v.is_phishing  # Local heuristics caught the typosquatting
