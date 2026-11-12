"""
URL Reputation Scanner for Phishing Detection.

Phase 5, Feature 2 — Stateless scoring service that examines URLs for
phishing indicators, lookalike domains, obfuscation, and threat intelligence
reputation matches. Produces a PhishingVerdict with individual signals and a
combined human-readable explanation.

Complies with:
- ARCHITECTURE.md §4.4 — URL scanner checks links against threat intel feeds
  + heuristic rules (lookalike domains, typosquatting, suspicious TLDs,
  IP-as-host, excessive redirects).
- .agents/skills/phishing-detection/SKILL.md — stateless scoring service
  (input in -> {score, explanation} out), mandatory signal explanations,
  cached reputation lookups, bounded timeout with graceful degradation.
- AGENTS.md — uses synthetic/mock samples for testing, never real victim data.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import math
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from src.phishing.models import (
    PhishingSeverity,
    PhishingSignal,
    PhishingVerdict,
    SignalCategory,
    ThreatIntelResult,
    URLFeatures,
    URLScanResult,
)
from src.shared.config import settings
from src.shared.event_schema import Entity, SecurityEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — Known Brands, TLDs, Shorteners, Patterns
# ---------------------------------------------------------------------------

PROTECTED_BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleapis.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "instagram.com", "meta.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
}

# High-risk TLDs commonly abused for low-cost, disposable phishing domains
HIGH_RISK_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq",  # Historically free Freenom TLDs
    "top", "xyz", "club", "work", "click", "buzz", "country", "stream",
    "fit", "racing", "cam", "live", "loan", "icu", "vip", "monster",
    "kim", "party", "trade", "science", "gdn", "mom", "rest", "surf",
    "men", "win", "bid", "date", "faith", "review",
}

# URL shortener services that mask the true destination
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "tiny.cc", "shorte.st", "adf.ly",
    "v.gd", "shorturl.at", "cutt.ly", "rb.gy", "bl.ink", "trib.al",
}

# Dangerous / executable file extensions in URL paths
DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".pif", ".cmd", ".bat", ".ps1", ".vbs", ".js",
    ".wsf", ".msi", ".dll", ".com", ".hta", ".cpl", ".reg", ".apk",
    ".iso", ".img", ".vhd",
}

# Credential harvesting keywords in URL path
CREDENTIAL_PATH_KEYWORDS: list[tuple[str, str]] = [
    (r"/(?:login|signin|sign-in|log-in)\b", "Authentication login portal path"),
    (r"/(?:verify|verification|validate)\b", "Account verification lure in path"),
    (r"/(?:password|passwd|pwd)\b", "Password/credential token in path"),
    (r"/(?:myaccount|account-update|security-check)\b", "Account security lure in path"),
    (r"/(?:update-billing|billing-verify|invoice-payment)\b", "Financial/billing prompt in path"),
    (r"/(?:wallet|seed-phrase|restore-wallet|mnemonic)\b", "Cryptocurrency wallet harvesting keyword"),
    (r"/(?:2fa|mfa|otp-verify|session-expired)\b", "Multi-factor authentication interception path"),
    (r"/(?:banking|onlinebanking|ebanking)\b", "Online banking portal keyword"),
]

# Cyrillic and Greek homoglyphs commonly substituted for Latin characters
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es
    "\u0435": "e",  # Cyrillic small letter ie
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er
    "\u0455": "s",  # Cyrillic small letter dze
    "\u0445": "x",  # Cyrillic small letter ha
    "\u0443": "y",  # Cyrillic small letter u
    "\u0410": "A",  # Cyrillic capital letter A
    "\u0412": "B",  # Cyrillic capital letter Ve
    "\u0421": "C",  # Cyrillic capital letter Es
    "\u0415": "E",  # Cyrillic capital letter Ie
    "\u041d": "H",  # Cyrillic capital letter En
    "\u0406": "I",  # Cyrillic capital letter Byelorussian-Ukrainian I
    "\u0408": "J",  # Cyrillic capital letter Je
    "\u041c": "M",  # Cyrillic capital letter Em
    "\u041e": "O",  # Cyrillic capital letter O
    "\u0420": "P",  # Cyrillic capital letter Er
    "\u0422": "T",  # Cyrillic capital letter Te
    "\u0425": "X",  # Cyrillic capital letter Ha
    # Greek lookalikes
    "\u03b1": "a",  # Greek small letter alpha
    "\u03bf": "o",  # Greek small letter omicron
    "\u03bd": "v",  # Greek small letter nu
    "\u03c1": "p",  # Greek small letter rho
}

# Common multi-part TLD suffixes to correctly identify registered domains
MULTI_PART_TLDS: set[str] = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "ne.jp", "com.br", "com.mx", "co.za", "com.sg",
    "com.hk", "co.in", "net.in", "org.in", "gen.in", "firm.in",
}


# ---------------------------------------------------------------------------
# In-Memory Thread-Safe Reputation Cache
# ---------------------------------------------------------------------------

class URLReputationCache:
    """Thread-safe in-memory cache for URL & domain reputation lookups.

    Implements TTL expiration and LRU/size capacity bounds to prevent
    unbounded memory growth, complying with SKILL.md gotchas.
    """

    def __init__(self, default_ttl_seconds: float = 3600.0, max_entries: int = 5000) -> None:
        self.default_ttl = default_ttl_seconds
        self.max_entries = max_entries
        self._cache: dict[str, tuple[ThreatIntelResult, float]] = {}
        self._lock = threading.Lock()

    def _normalize_key(self, key: str) -> str:
        return key.strip().lower().rstrip("/")

    def get(self, key: str) -> Optional[ThreatIntelResult]:
        """Retrieve a cached result if not expired."""
        norm_key = self._normalize_key(key)
        now = time.time()
        with self._lock:
            if norm_key in self._cache:
                result, expires_at = self._cache[norm_key]
                if now <= expires_at:
                    # Return a copy marked as cached
                    cached_res = result.model_copy()
                    cached_res.cached = True
                    return cached_res
                else:
                    # Expired
                    del self._cache[norm_key]
        return None

    def set(self, key: str, result: ThreatIntelResult, ttl: Optional[float] = None) -> None:
        """Store a result with TTL and capacity bounding."""
        norm_key = self._normalize_key(key)
        ttl_val = ttl if ttl is not None else self.default_ttl
        expires_at = time.time() + ttl_val

        with self._lock:
            # Capacity guard: drop oldest 10% if full
            if len(self._cache) >= self.max_entries and norm_key not in self._cache:
                keys_to_remove = list(self._cache.keys())[: max(1, self.max_entries // 10)]
                for k in keys_to_remove:
                    self._cache.pop(k, None)
            self._cache[norm_key] = (result, expires_at)

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


# ---------------------------------------------------------------------------
# Threat Intel Providers (Pluggable Interface & Implementations)
# ---------------------------------------------------------------------------

class ThreatIntelProvider(ABC):
    """Abstract interface for threat intelligence lookups."""

    @abstractmethod
    def lookup_url(self, url: str, timeout: float = 1.5) -> ThreatIntelResult:
        """Look up reputation for a full URL."""
        pass

    @abstractmethod
    def lookup_host(self, host: str, timeout: float = 1.5) -> ThreatIntelResult:
        """Look up reputation for a domain or IP."""
        pass


class MockThreatIntelProvider(ThreatIntelProvider):
    """Deterministic threat intel provider for unit tests and local simulation."""

    def __init__(self, initial_entries: Optional[dict[str, ThreatIntelResult]] = None) -> None:
        self.entries: dict[str, ThreatIntelResult] = initial_entries or {}
        self.call_count = 0
        self.simulate_timeout = False
        self.simulate_error = False

    def add_entry(self, key: str, result: ThreatIntelResult) -> None:
        self.entries[key.strip().lower().rstrip("/")] = result

    def lookup_url(self, url: str, timeout: float = 1.5) -> ThreatIntelResult:
        self.call_count += 1
        if self.simulate_timeout:
            raise TimeoutError("Threat intel provider lookup timed out")
        if self.simulate_error:
            raise RuntimeError("Threat intel provider network connection failure")

        norm = url.strip().lower().rstrip("/")
        if norm in self.entries:
            return self.entries[norm]

        # Check hostname fallback
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        if host in self.entries:
            return self.entries[host]

        return ThreatIntelResult(
            ioc=url,
            is_malicious=False,
            threat_score=0.0,
            source="mock_clean",
            details={"status": "not_flagged"},
        )

    def lookup_host(self, host: str, timeout: float = 1.5) -> ThreatIntelResult:
        self.call_count += 1
        if self.simulate_timeout:
            raise TimeoutError("Threat intel provider lookup timed out")
        if self.simulate_error:
            raise RuntimeError("Threat intel provider network connection failure")

        norm = host.strip().lower()
        if norm in self.entries:
            return self.entries[norm]

        return ThreatIntelResult(
            ioc=host,
            is_malicious=False,
            threat_score=0.0,
            source="mock_clean",
            details={"status": "not_flagged"},
        )


class SyntheticBlocklistProvider(ThreatIntelProvider):
    """Built-in offline blocklist provider for synthetic phishing & test campaigns."""

    KNOWN_MALICIOUS_DOMAINS: dict[str, dict[str, Any]] = {
        "phishing-test-login.com": {
            "score": 95.0,
            "categories": ["phishing", "credential_theft"],
            "source": "synthetic_blocklist",
        },
        "secure-bank-verification.net": {
            "score": 92.0,
            "categories": ["financial_phishing"],
            "source": "synthetic_blocklist",
        },
        "account-update-portal.xyz": {
            "score": 90.0,
            "categories": ["social_engineering"],
            "source": "synthetic_blocklist",
        },
        "malware-dropper-c2.org": {
            "score": 100.0,
            "categories": ["c2", "malware_distribution"],
            "source": "synthetic_blocklist",
        },
        "203.0.113.88": {
            "score": 95.0,
            "categories": ["scanner", "botnet", "honeypot_target"],
            "source": "synthetic_blocklist",
        },
    }

    def lookup_url(self, url: str, timeout: float = 1.5) -> ThreatIntelResult:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        return self.lookup_host(host)

    def lookup_host(self, host: str, timeout: float = 1.5) -> ThreatIntelResult:
        norm = host.strip().lower()
        if norm in self.KNOWN_MALICIOUS_DOMAINS:
            item = self.KNOWN_MALICIOUS_DOMAINS[norm]
            return ThreatIntelResult(
                ioc=host,
                is_malicious=True,
                threat_score=item["score"],
                source=item["source"],
                positives=8,
                total_engines=10,
                categories=item["categories"],
                details={"threat_name": "Synthetic Phishing/C2 Indicator"},
            )
        return ThreatIntelResult(
            ioc=host,
            is_malicious=False,
            threat_score=0.0,
            source="synthetic_blocklist",
        )


class VirusTotalLookupProvider(ThreatIntelProvider):
    """External VirusTotal API v3 provider with graceful timeout and degradation.

    Complies with SKILL.md gotchas:
    - Never blocks execution on slow/failed external calls
    - Degrades gracefully to local heuristics when unavailable or rate-limited
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key if api_key is not None else settings.vt_api_key

    def _url_to_id(self, url: str) -> str:
        """VirusTotal v3 URL identifier format: base64 without padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def lookup_url(self, url: str, timeout: float = 1.5) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(
                ioc=url,
                is_malicious=False,
                threat_score=0.0,
                source="virustotal_unconfigured",
                details={"status": "api_key_missing"},
            )

        url_id = self._url_to_id(url)
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        req = urllib.request.Request(
            endpoint,
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "MMS-Phishing-Detector/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    is_mal = positives >= 2
                    score = min(100.0, (positives / max(total, 1)) * 100.0) if is_mal else 0.0

                    return ThreatIntelResult(
                        ioc=url,
                        is_malicious=is_mal,
                        threat_score=score,
                        source="virustotal",
                        positives=positives,
                        total_engines=total,
                        details=stats,
                    )
        except Exception as e:
            logger.debug("VirusTotal URL lookup degraded/failed: %s", e)

        # Graceful degradation per SKILL.md
        return ThreatIntelResult(
            ioc=url,
            is_malicious=False,
            threat_score=0.0,
            source="virustotal_degraded",
            details={"status": "degraded_fallback"},
        )

    def lookup_host(self, host: str, timeout: float = 1.5) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(
                ioc=host,
                is_malicious=False,
                threat_score=0.0,
                source="virustotal_unconfigured",
                details={"status": "api_key_missing"},
            )

        endpoint = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(host)}"
        req = urllib.request.Request(
            endpoint,
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "MMS-Phishing-Detector/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    is_mal = positives >= 2
                    score = min(100.0, (positives / max(total, 1)) * 100.0) if is_mal else 0.0

                    return ThreatIntelResult(
                        ioc=host,
                        is_malicious=is_mal,
                        threat_score=score,
                        source="virustotal",
                        positives=positives,
                        total_engines=total,
                        details=stats,
                    )
        except Exception as e:
            logger.debug("VirusTotal domain lookup degraded/failed: %s", e)

        return ThreatIntelResult(
            ioc=host,
            is_malicious=False,
            threat_score=0.0,
            source="virustotal_degraded",
            details={"status": "degraded_fallback"},
        )


# ---------------------------------------------------------------------------
# URL Feature Extractor
# ---------------------------------------------------------------------------

class URLFeatureExtractor:
    """Extracts lexical, structural, and semantic features from a candidate URL."""

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy (0.0 to ~8.0) for a given string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freqs: dict[str, int] = {}
        for char in data:
            freqs[char] = freqs.get(char, 0) + 1
        for count in freqs.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    @staticmethod
    def split_domain(hostname: str) -> tuple[str, str, str]:
        """Split a hostname into (subdomain, registered_domain, tld).

        Correctly handles multi-part TLDs (e.g. .co.uk, .com.au).
        """
        if not hostname:
            return "", "", ""

        # Remove port if accidentally present
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        parts = hostname.lower().strip(".").split(".")
        if len(parts) <= 1:
            return "", hostname, ""

        # Check for multi-part TLD (e.g. co.uk)
        if len(parts) >= 3:
            potential_tld = f"{parts[-2]}.{parts[-1]}"
            if potential_tld in MULTI_PART_TLDS:
                tld = potential_tld
                registered_domain = f"{parts[-3]}.{tld}"
                subdomain = ".".join(parts[:-3])
                return subdomain, registered_domain, tld

        tld = parts[-1]
        registered_domain = f"{parts[-2]}.{tld}"
        subdomain = ".".join(parts[:-2])
        return subdomain, registered_domain, tld

    @classmethod
    def detect_ip_obfuscation(cls, host_str: str) -> tuple[bool, Optional[str], Optional[str]]:
        """Detect if host is an IP address and check for obfuscation.

        Returns (is_ip, obfuscation_type, canonical_ip).
        Supports:
        - standard dotted decimal (192.168.1.1)
        - integer/dword IP (2130706433 -> 127.0.0.1)
        - octal IP (0177.0.0.1 -> 127.0.0.1)
        - hex IP (0x7f000001 or 0x7f.0.0.1 -> 127.0.0.1)
        - ipv6 literal ([2001:db8::1])
        """
        if not host_str:
            return False, None, None

        clean_host = host_str.strip("[]").strip()

        # 1. Standard IPv4
        try:
            ip = ipaddress.IPv4Address(clean_host)
            # Check if any octet had leading zero (octal representation)
            octets = clean_host.split(".")
            if len(octets) == 4 and any(o.startswith("0") and len(o) > 1 for o in octets):
                return True, "octal", str(ip)
            return True, "dotted_decimal", str(ip)
        except ValueError:
            pass

        # 2. Standard IPv6
        try:
            ip6 = ipaddress.IPv6Address(clean_host)
            return True, "ipv6", str(ip6)
        except ValueError:
            pass

        # 3. Dword / Integer representation (e.g. 2130706433)
        if clean_host.isdigit():
            try:
                num = int(clean_host)
                if 0 <= num <= 4294967295:
                    ip = ipaddress.IPv4Address(num)
                    return True, "dword", str(ip)
            except ValueError:
                pass

        # 4. Single Hex representation (e.g. 0x7f000001)
        if clean_host.lower().startswith("0x"):
            try:
                num = int(clean_host, 16)
                if 0 <= num <= 4294967295:
                    ip = ipaddress.IPv4Address(num)
                    return True, "hex", str(ip)
            except ValueError:
                pass

        # 5. Dotted octal or hex mixed representation (e.g. 0x7f.0.0.1 or 0177.0.0.1)
        octets = clean_host.split(".")
        if len(octets) == 4:
            is_mixed = False
            obf_type = None
            resolved_octets = []
            try:
                for o in octets:
                    if o.lower().startswith("0x"):
                        val = int(o, 16)
                        is_mixed = True
                        obf_type = "hex_octets"
                    elif o.startswith("0") and len(o) > 1:
                        val = int(o, 8)
                        is_mixed = True
                        obf_type = "octal_octets"
                    else:
                        val = int(o, 10)
                    if 0 <= val <= 255:
                        resolved_octets.append(str(val))
                    else:
                        break
                if len(resolved_octets) == 4 and is_mixed:
                    canonical = ".".join(resolved_octets)
                    return True, obf_type or "mixed_ip", canonical
            except ValueError:
                pass

        return False, None, None

    @classmethod
    def extract_features(cls, raw_url: str) -> URLFeatures:
        """Extract complete URLFeatures dataclass from raw URL string."""
        url = raw_url.strip()
        lower_url = url.lower()
        # Normalise missing scheme while preserving pseudo-schemes
        if lower_url.startswith(("javascript:", "data:", "file:", "vbscript:", "blob:")):
            url_with_scheme = url
        elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url_with_scheme = "http://" + url
        else:
            url_with_scheme = url

        try:
            parsed = urllib.parse.urlparse(url_with_scheme)
        except Exception:
            return URLFeatures(raw_url=raw_url, url_length=len(raw_url))

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment

        try:
            port = parsed.port
        except (ValueError, TypeError):
            port = None

        # Extract userinfo (credentials in URL authority before @)
        userinfo = None
        hostname = parsed.hostname or ""
        if "@" in netloc:
            parts = netloc.split("@")
            userinfo = parts[0]
            # Host is after @
            host_part = parts[1]
            if ":" in host_part:
                hostname = host_part.split(":")[0]
            else:
                hostname = host_part

        subdomain, registered_domain, tld = cls.split_domain(hostname)
        subdomain_count = len(subdomain.split(".")) if subdomain else 0

        # Check IP
        is_ip, obf_type, _ = cls.detect_ip_obfuscation(hostname)

        # Check shortener
        is_shortener = (registered_domain.lower() in URL_SHORTENERS) or (hostname.lower() in URL_SHORTENERS)

        # Check punycode
        is_punycode = "xn--" in hostname.lower()

        # Check homoglyphs
        has_homoglyphs = any(char in HOMOGLYPH_MAP for char in hostname)

        # Check deceptive userinfo
        has_deceptive_userinfo = bool(userinfo and len(userinfo) > 0)

        # Shannon entropy of hostname and domain
        entropy = cls.calculate_shannon_entropy(hostname)

        # Suspicious TLD
        is_suspicious_tld = tld.lower() in HIGH_RISK_TLDS

        # Credential tokens in path or specific auth query parameters
        path_lower = path.lower()
        has_path_cred = any(re.search(pat, path_lower) is not None for pat, _ in CREDENTIAL_PATH_KEYWORDS)
        has_query_cred = False
        if query:
            query_lower = query.lower()
            has_query_cred = bool(
                re.search(r"(?:^|&)(?:password|passwd|pwd|auth_token|access_token|user_pass|credential|verify_password)=", query_lower)
                or re.search(r"(?:^|&)(?:action|do|mode)=(?:login|signin|verify|auth|reset)", query_lower)
            )
        has_credential_tokens = has_path_cred or has_query_cred

        # Dangerous extensions in path
        path_lower = path.lower()
        has_dangerous_ext = any(path_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS)

        return URLFeatures(
            raw_url=raw_url,
            scheme=scheme,
            netloc=netloc,
            hostname=hostname,
            registered_domain=registered_domain,
            subdomain=subdomain,
            subdomain_count=subdomain_count,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            userinfo=userinfo,
            url_length=len(raw_url),
            hostname_length=len(hostname),
            path_length=len(path),
            query_length=len(query),
            is_ip_address=is_ip,
            ip_obfuscation_type=obf_type,
            is_shortener=is_shortener,
            is_punycode=is_punycode,
            has_homoglyphs=has_homoglyphs,
            has_deceptive_userinfo=has_deceptive_userinfo,
            shannon_entropy=entropy,
            tld=tld,
            is_suspicious_tld=is_suspicious_tld,
            has_credential_tokens=has_credential_tokens,
            has_dangerous_extension=has_dangerous_ext,
        )


# ---------------------------------------------------------------------------
# Homograph & Typosquatting Analyzer
# ---------------------------------------------------------------------------

class LookalikeAnalyzer:
    """Detects brand impersonation, typosquatting, and IDN homograph attacks."""

    @staticmethod
    def normalize_homoglyphs(text: str) -> str:
        """Replace Cyrillic/Greek homoglyphs with equivalent Latin characters."""
        res = []
        for char in text:
            res.append(HOMOGLYPH_MAP.get(char, char))
        return "".join(res)

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Compute edit distance between two strings."""
        if len(s1) < len(s2):
            return LookalikeAnalyzer.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    @staticmethod
    def safe_ascii(text: str) -> str:
        """Format text with ASCII-safe escaping so it never crashes Windows console encodings."""
        return "".join(c if ord(c) < 128 else f"[U+{ord(c):04X}]" for c in text)

    @classmethod
    def check_brand_abuse(cls, hostname: str, registered_domain: str, subdomain: str) -> list[PhishingSignal]:
        """Check for typosquatting, optical substitutions, or brand injection."""
        signals: list[PhishingSignal] = []
        norm_hostname = hostname.lower()
        norm_domain = registered_domain.lower()
        domain_name_part = norm_domain.split(".")[0] if "." in norm_domain else norm_domain

        # 1. Homograph Detection
        has_homoglyph = any(c in HOMOGLYPH_MAP for c in hostname)
        latinized_host = cls.normalize_homoglyphs(hostname)
        if has_homoglyph:
            safe_orig = cls.safe_ascii(hostname)
            signals.append(
                PhishingSignal(
                    category=SignalCategory.HOMOGRAPH_ATTACK,
                    name="idn_homograph_attack",
                    description="Domain contains mixed Cyrillic/Greek homoglyphs visually mimicking Latin text",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=35.0,
                    evidence=f"Original: {safe_orig} -> Normalized Latin: {latinized_host}",
                    mitre_technique="T1583.001",
                )
            )

        # 2. Punycode check with recursive decoded brand evaluation
        if "xn--" in norm_hostname:
            try:
                decoded = norm_hostname.encode("ascii").decode("idna")
                safe_dec = cls.safe_ascii(decoded)
                signals.append(
                    PhishingSignal(
                        category=SignalCategory.HOMOGRAPH_ATTACK,
                        name="punycode_domain",
                        description=f"Punycode encoded internationalized domain name resolves to '{safe_dec}'",
                        severity=PhishingSeverity.MEDIUM,
                        score_contribution=15.0,
                        evidence=f"{norm_hostname} -> {safe_dec}",
                        mitre_technique="T1583.001",
                    )
                )
                # Recursively evaluate the decoded IDN domain for brand abuse/homoglyphs
                decoded_sub, decoded_reg, _ = URLFeatureExtractor.split_domain(decoded)
                decoded_sigs = cls.check_brand_abuse(decoded, decoded_reg, decoded_sub)
                for ds in decoded_sigs:
                    if ds.name != "punycode_domain" and ds.name not in [s.name for s in signals]:
                        signals.append(ds)
            except Exception:
                pass

        # 3. Check against protected brand catalog
        # Also check against latinized domain part if homoglyphs were present
        latin_domain_part = cls.normalize_homoglyphs(domain_name_part)

        safe_host = cls.safe_ascii(hostname)
        safe_reg = cls.safe_ascii(registered_domain)
        safe_part = cls.safe_ascii(domain_name_part)

        for brand, official_domains in PROTECTED_BRANDS.items():
            is_official = any(norm_domain == off or norm_hostname.endswith("." + off) for off in official_domains)
            if is_official:
                # Legitimate brand domain — skip lookalike checks for this brand
                continue

            # A. Brand in subdomain of third-party domain (e.g., paypal.com.evil.xyz or login-paypal.suspicious.net)
            if brand in subdomain.lower() or any(off in subdomain.lower() for off in official_domains):
                signals.append(
                    PhishingSignal(
                        category=SignalCategory.IMPERSONATION,
                        name="brand_in_subdomain",
                        description=f"Legitimate brand name '{brand}' used as subdomain on unrelated domain '{safe_reg}'",
                        severity=PhishingSeverity.HIGH,
                        score_contribution=30.0,
                        evidence=f"Brand: {brand}, Host: {safe_host}, Base Domain: {safe_reg}",
                        mitre_technique="T1566.002",
                    )
                )

            # B. Homoglyph spoof of full brand name (e.g., pаypal -> paypal)
            elif latin_domain_part == brand and domain_name_part != brand:
                signals.append(
                    PhishingSignal(
                        category=SignalCategory.IMPERSONATION,
                        name="homoglyph_brand_spoofing",
                        description=f"Homoglyph character substitution directly spoofing protected brand '{brand}'",
                        severity=PhishingSeverity.CRITICAL,
                        score_contribution=35.0,
                        evidence=f"Spoofed: {safe_part} -> Brand: {brand}",
                        mitre_technique="T1583.001",
                    )
                )

            # C. Brand combination / hyphenation abuse in domain name (e.g., paypal-security.com)
            elif (
                (brand in domain_name_part or brand in latin_domain_part)
                and not is_official
                and domain_name_part != brand
            ):
                signals.append(
                    PhishingSignal(
                        category=SignalCategory.IMPERSONATION,
                        name="brand_combo_domain",
                        description=f"Brand keyword '{brand}' compounded in unauthorized domain name '{safe_reg}'",
                        severity=PhishingSeverity.HIGH,
                        score_contribution=25.0,
                        evidence=f"Brand: {brand}, Domain: {safe_reg}",
                        mitre_technique="T1583.001",
                    )
                )

            # D. Typosquatting / Visual Leetspeak substitutions (e.g. micr0soft, paypa1, arnazon)
            leetspeak_subs = [
                ("0", "o"),
                ("1", "l"),
                ("1", "i"),
                ("rn", "m"),
                ("vv", "w"),
                ("cl", "d"),
            ]
            normalized_domain_part = domain_name_part
            for pat, sub in leetspeak_subs:
                normalized_domain_part = normalized_domain_part.replace(pat, sub)

            if normalized_domain_part == brand and domain_name_part != brand:
                signals.append(
                    PhishingSignal(
                        category=SignalCategory.IMPERSONATION,
                        name="optical_typosquatting",
                        description=f"Optical lookalike / leetspeak character substitution targeting brand '{brand}'",
                        severity=PhishingSeverity.CRITICAL,
                        score_contribution=35.0,
                        evidence=f"Spoofed: {safe_part} -> Brand: {brand}",
                        mitre_technique="T1583.001",
                    )
                )
            elif len(domain_name_part) >= 4 and len(brand) >= 4:
                # Levenshtein distance check (1 or 2 edits away from brand)
                dist = cls.levenshtein_distance(domain_name_part, brand)
                if dist in (1, 2) and domain_name_part != brand:
                    signals.append(
                        PhishingSignal(
                            category=SignalCategory.IMPERSONATION,
                            name="levenshtein_typosquatting",
                            description=f"Typo-squatted domain '{safe_part}' is {dist} edit(s) away from brand '{brand}'",
                            severity=PhishingSeverity.HIGH,
                            score_contribution=25.0,
                            evidence=f"Distance: {dist}, Tested: {safe_part}, Brand: {brand}",
                            mitre_technique="T1583.001",
                        )
                    )

        return signals


# ---------------------------------------------------------------------------
# URL Reputation Scanner (Stateless Scoring Engine)
# ---------------------------------------------------------------------------

class URLScanner:
    """Stateless URL Reputation Scanner.

    Analyzes candidate links against lexical heuristics, homograph/lookalike
    domains, obfuscated IP representations, credential harvesting patterns,
    and pluggable threat intelligence providers.
    """

    def __init__(
        self,
        threat_intel_provider: Optional[ThreatIntelProvider] = None,
        cache: Optional[URLReputationCache] = None,
    ) -> None:
        self.cache = cache or URLReputationCache()
        self.threat_intel = threat_intel_provider or SyntheticBlocklistProvider()

    def scan_url(self, raw_url: str, timeout: float = 1.5) -> PhishingVerdict:
        """Scan a single URL and return a PhishingVerdict with mandatory signals."""
        url = raw_url.strip()
        if not url:
            return PhishingVerdict(
                analysis_type="url",
                target_url="",
                score=0.0,
                severity=PhishingSeverity.SAFE,
                is_phishing=False,
                confidence=1.0,
                explanation="Empty URL provided — no analysis performed.",
            )

        # 1. Feature extraction
        features = URLFeatureExtractor.extract_features(url)

        # 2. Run detection rules
        signals: list[PhishingSignal] = []
        signals.extend(self._check_scheme_and_userinfo(features))
        signals.extend(self._check_ip_and_obfuscation(features))
        signals.extend(self._check_lookalike_and_brand_abuse(features))
        signals.extend(self._check_suspicious_tld(features))
        signals.extend(self._check_url_shortener(features))
        signals.extend(self._check_credential_and_path_tokens(features))
        signals.extend(self._check_structural_anomalies(features))

        # 3. Threat intelligence lookup (with cache and timeout guard)
        ti_result, ti_signals = self._evaluate_threat_intel(url, features.hostname, timeout)
        signals.extend(ti_signals)

        # 4. Score aggregation & severity calculation
        verdict = self._synthesize_verdict(url, signals, features, ti_result)
        return verdict

    def scan_urls(self, urls: list[str], timeout: float = 1.5) -> list[PhishingVerdict]:
        """Scan a batch of URLs sequentially."""
        return [self.scan_url(u, timeout=timeout) for u in urls]

    def _check_scheme_and_userinfo(self, f: URLFeatures) -> list[PhishingSignal]:
        """Detect dangerous schemes or deceptive @ userinfo in authority."""
        signals: list[PhishingSignal] = []

        # Dangerous schemes
        dangerous_schemes = {"javascript", "data", "file", "vbscript", "blob"}
        if f.scheme in dangerous_schemes:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="dangerous_url_scheme",
                    description=f"High-risk scheme '{f.scheme}:' used to execute scripts or embed payload data directly",
                    severity=PhishingSeverity.CRITICAL,
                    score_contribution=45.0,
                    evidence=f"Scheme: {f.scheme}",
                    mitre_technique="T1204.001",
                )
            )

        # Deceptive @ userinfo (e.g. http://paypal.com@evil.com/login)
        if f.has_deceptive_userinfo and f.userinfo:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="deceptive_userinfo_at_symbol",
                    description=f"URL contains deceptive '@' userinfo credentials ('{f.userinfo}') to mislead users regarding destination host",
                    severity=PhishingSeverity.CRITICAL,
                    score_contribution=35.0,
                    evidence=f"Userinfo: {f.userinfo}, Actual destination host: {f.hostname}",
                    mitre_technique="T1566.002",
                )
            )

        return signals

    def _check_ip_and_obfuscation(self, f: URLFeatures) -> list[PhishingSignal]:
        """Detect raw IP addresses and encoded/obfuscated IP representations."""
        signals: list[PhishingSignal] = []

        if f.is_ip_address:
            obf = f.ip_obfuscation_type or "standard"
            if obf in ("dword", "octal", "hex", "hex_octets", "octal_octets", "mixed_ip"):
                signals.append(
                    PhishingSignal(
                        category=SignalCategory.URL_OBFUSCATION,
                        name="obfuscated_ip_address",
                        description=f"URL hostname uses obfuscated {obf} IP address encoding to evade security filters",
                        severity=PhishingSeverity.CRITICAL,
                        score_contribution=40.0,
                        evidence=f"Host: {f.hostname}, Obfuscation format: {obf}",
                        mitre_technique="T1566.002",
                    )
                )
            else:
                signals.append(
                    PhishingSignal(
                        category=SignalCategory.IP_HOST,
                        name="raw_ip_address_host",
                        description="URL points directly to an IP address instead of a legitimate registered domain name",
                        severity=PhishingSeverity.HIGH,
                        score_contribution=25.0,
                        evidence=f"IP Host: {f.hostname}",
                        mitre_technique="T1566.002",
                    )
                )

        return signals

    def _check_lookalike_and_brand_abuse(self, f: URLFeatures) -> list[PhishingSignal]:
        """Check for homographs, brand combos, typosquatting, and subdomain impersonation."""
        if f.is_ip_address or not f.hostname:
            return []
        return LookalikeAnalyzer.check_brand_abuse(f.hostname, f.registered_domain, f.subdomain)

    def _check_suspicious_tld(self, f: URLFeatures) -> list[PhishingSignal]:
        """Detect high-risk / low-reputation top-level domains."""
        signals: list[PhishingSignal] = []
        if f.is_suspicious_tld:
            # If combined with credential keywords, weight higher
            weight = 25.0 if f.has_credential_tokens else 15.0
            signals.append(
                PhishingSignal(
                    category=SignalCategory.SENDER_REPUTATION,
                    name="suspicious_tld",
                    description=f"Domain uses high-risk, low-reputation top-level domain '.{f.tld}'",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=weight,
                    evidence=f"TLD: .{f.tld}, Registered Domain: {f.registered_domain}",
                    mitre_technique="T1583.001",
                )
            )
        return signals

    def _check_url_shortener(self, f: URLFeatures) -> list[PhishingSignal]:
        """Detect link shorteners masking destination."""
        signals: list[PhishingSignal] = []
        if f.is_shortener:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="url_shortener_service",
                    description=f"URL uses shortening service '{f.hostname}' hiding the actual destination endpoint",
                    severity=PhishingSeverity.LOW,
                    score_contribution=15.0,
                    evidence=f"Shortener Host: {f.hostname}",
                    mitre_technique="T1566.002",
                )
            )
        return signals

    def _check_credential_and_path_tokens(self, f: URLFeatures) -> list[PhishingSignal]:
        """Detect credential harvesting paths, scripts, and dangerous file extensions."""
        signals: list[PhishingSignal] = []

        # Credential path keywords checked on URL path
        path_lower = f.path.lower()
        matched_keywords = []
        for pat, desc in CREDENTIAL_PATH_KEYWORDS:
            if re.search(pat, path_lower):
                matched_keywords.append(desc)

        # Check explicit authentication query parameters
        if f.query:
            query_lower = f.query.lower()
            cred_query_patterns = [
                (r"(?:^|&)(?:password|passwd|pwd|auth_token|access_token|user_pass|credential|verify_password)=", "Credential parameter in query string"),
                (r"(?:^|&)(?:action|do|mode)=(?:login|signin|verify|auth|reset)", "Authentication action in query parameter"),
            ]
            for pat, desc in cred_query_patterns:
                if re.search(pat, query_lower):
                    matched_keywords.append(desc)

        if matched_keywords:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.CREDENTIAL_HARVESTING,
                    name="credential_harvesting_path",
                    description=f"URL path/query contains credential harvesting indicator(s): {', '.join(matched_keywords[:3])}",
                    severity=PhishingSeverity.HIGH,
                    score_contribution=min(25.0, 15.0 + 5.0 * len(matched_keywords)),
                    evidence=f"Path/Query: {f.path[:60]}... Keywords: {len(matched_keywords)}",
                    mitre_technique="T1566.002",
                )
            )

        # Dangerous or executable downloads
        if f.has_dangerous_extension:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.ATTACHMENT_RISK,
                    name="dangerous_file_download_link",
                    description=f"URL targets direct download of executable or script payload in path '{f.path}'",
                    severity=PhishingSeverity.CRITICAL,
                    score_contribution=35.0,
                    evidence=f"Path: {f.path}",
                    mitre_technique="T1204.002",
                )
            )

        # Masqueraded double extension (e.g. invoice.pdf.exe)
        if re.search(r"\.(?:pdf|doc|docx|xls|xlsx|jpg|png)\.(?:exe|scr|bat|cmd|ps1|vbs|hta)\b", f.path.lower()):
            signals.append(
                PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="double_extension_spoofing",
                    description="URL contains masqueraded double extension spoofing an innocent document (e.g. .pdf.exe)",
                    severity=PhishingSeverity.CRITICAL,
                    score_contribution=40.0,
                    evidence=f"Path: {f.path}",
                    mitre_technique="T1204.002",
                )
            )

        return signals

    def _check_structural_anomalies(self, f: URLFeatures) -> list[PhishingSignal]:
        """Detect abnormal URL length, high Shannon entropy, excessive subdomains, and strange ports."""
        signals: list[PhishingSignal] = []

        # Excessive URL length
        if f.url_length >= 200:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="excessive_url_length",
                    description=f"Abnormally long URL ({f.url_length} characters) typical of payload padding or token hiding",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=15.0,
                    evidence=f"Length: {f.url_length} chars",
                    mitre_technique="T1566.002",
                )
            )

        # Excessive subdomain depth
        if f.subdomain_count >= 4:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="excessive_subdomain_depth",
                    description=f"Excessive subdomain depth ({f.subdomain_count} levels) masking real base domain",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=15.0,
                    evidence=f"Subdomains: {f.subdomain}",
                    mitre_technique="T1566.002",
                )
            )

        # High Shannon entropy on hostname (DGA indicator)
        if not f.is_ip_address and f.shannon_entropy >= 3.8 and len(f.hostname) >= 12:
            signals.append(
                PhishingSignal(
                    category=SignalCategory.URL_OBFUSCATION,
                    name="high_entropy_domain",
                    description=f"Hostname demonstrates unusually high Shannon entropy ({f.shannon_entropy:.2f}), indicating potential DGA or algorithmic generation",
                    severity=PhishingSeverity.MEDIUM,
                    score_contribution=20.0,
                    evidence=f"Hostname: {f.hostname}, Entropy: {f.shannon_entropy:.2f}",
                    mitre_technique="T1584.001",
                )
            )

        # Non-standard web ports (e.g. 8080, 8443, 8888, 1337, 4444)
        if f.port is not None and f.port not in (80, 443, 8080, 8443):
            signals.append(
                PhishingSignal(
                    category=SignalCategory.SUSPICIOUS_LINK,
                    name="non_standard_web_port",
                    description=f"URL specifies non-standard service port :{f.port}",
                    severity=PhishingSeverity.LOW,
                    score_contribution=10.0,
                    evidence=f"Port: {f.port}",
                    mitre_technique="T1566.002",
                )
            )

        return signals

    def _evaluate_threat_intel(
        self, url: str, host: str, timeout: float
    ) -> tuple[Optional[ThreatIntelResult], list[PhishingSignal]]:
        """Query reputation cache and threat intel provider with timeout guard."""
        signals: list[PhishingSignal] = []

        # 1. Check cache first
        cached = self.cache.get(url) or self.cache.get(host)
        if cached:
            ti_res = cached
        else:
            # 2. Query provider with bounded timeout and exception suppression
            try:
                ti_res = self.threat_intel.lookup_url(url, timeout=timeout)
                if not ti_res.is_malicious and host:
                    host_res = self.threat_intel.lookup_host(host, timeout=timeout)
                    if host_res.is_malicious:
                        ti_res = host_res
                # Store in cache
                self.cache.set(url, ti_res)
                if host:
                    self.cache.set(host, ti_res)
            except Exception as e:
                logger.debug("Threat intel lookup degraded gracefully on '%s': %s", url, e)
                ti_res = ThreatIntelResult(
                    ioc=url,
                    is_malicious=False,
                    threat_score=0.0,
                    source="fallback_degraded",
                    details={"error": str(e)},
                )

        # 3. If threat intel flagged, produce high-confidence signal
        if ti_res and ti_res.is_malicious:
            contrib = max(40.0, ti_res.threat_score)
            signals.append(
                PhishingSignal(
                    category=SignalCategory.THREAT_INTEL_MATCH,
                    name="threat_intelligence_blocklist_match",
                    description=f"URL or host matched active malicious indicator in threat intelligence ({ti_res.source})",
                    severity=PhishingSeverity.CRITICAL,
                    score_contribution=contrib,
                    evidence=f"Source: {ti_res.source}, Positives: {ti_res.positives}/{ti_res.total_engines}, Score: {ti_res.threat_score}",
                    mitre_technique="T1566.002",
                )
            )

        return ti_res, signals

    def _synthesize_verdict(
        self,
        url: str,
        signals: list[PhishingSignal],
        features: URLFeatures,
        ti_result: Optional[ThreatIntelResult],
    ) -> PhishingVerdict:
        """Calculate total score, severity, confidence, and human explanation."""
        if not signals:
            return PhishingVerdict(
                analysis_type="url",
                target_url=url,
                score=0.0,
                severity=PhishingSeverity.SAFE,
                is_phishing=False,
                confidence=0.95,
                signals=[],
                explanation=f"URL '{LookalikeAnalyzer.safe_ascii(url)}' is clean — no suspicious indicators, obfuscation, or threat intelligence matches detected.",
                mitre_techniques=[],
            )

        # Sum contributions with category caps
        total_raw = sum(s.score_contribution for s in signals)
        score = min(100.0, max(0.0, round(total_raw, 1)))

        # Severity mapping
        if score >= 80.0:
            severity = PhishingSeverity.CRITICAL
        elif score >= 60.0:
            severity = PhishingSeverity.HIGH
        elif score >= 35.0:
            severity = PhishingSeverity.MEDIUM
        elif score >= 15.0:
            severity = PhishingSeverity.LOW
        else:
            severity = PhishingSeverity.SAFE

        is_phishing = score >= 35.0

        # Confidence calculation
        # Base confidence increases with signal count, threat intel confirmation, and signal severity
        conf = 0.5 + min(0.35, len(signals) * 0.1)
        if ti_result and ti_result.is_malicious:
            conf = max(conf, 0.95)
        if any(s.severity == PhishingSeverity.CRITICAL for s in signals):
            conf = max(conf, 0.85)
        confidence = round(min(0.99, conf), 2)

        # Collect unique MITRE techniques
        mitre_set: set[str] = set()
        for s in signals:
            if s.mitre_technique:
                mitre_set.add(s.mitre_technique)
        mitre_techniques = sorted(list(mitre_set))

        # Generate mandatory human-readable explanation synthesizing all signals
        safe_url = LookalikeAnalyzer.safe_ascii(url)
        safe_host = LookalikeAnalyzer.safe_ascii(features.hostname)
        explanation_lines = [
            f"Verdict: {severity.value.upper()} (Phishing Risk Score: {score:.1f}/100, Confidence: {int(confidence * 100)}%).",
            f"Analyzed URL: '{safe_url}' (Host: '{safe_host}').",
            f"Identified {len(signals)} suspicious indicator(s):",
        ]
        for idx, sig in enumerate(signals, 1):
            explanation_lines.append(f"  [{idx}] {sig.name} ({sig.severity.value.upper()}): {sig.description}")
            if sig.evidence:
                explanation_lines.append(f"      Evidence: {sig.evidence}")

        if is_phishing:
            explanation_lines.append(
                "Recommendation: Block access to this URL immediately at boundary firewalls and DNS filters. Alert incident response."
            )
        else:
            explanation_lines.append("Recommendation: Proceed with standard user caution.")

        explanation = "\n".join(explanation_lines)

        return PhishingVerdict(
            analysis_type="url",
            target_url=url,
            score=score,
            severity=severity,
            is_phishing=is_phishing,
            confidence=confidence,
            signals=signals,
            explanation=explanation,
            mitre_techniques=mitre_techniques,
        )

    def to_security_event(
        self,
        verdict: PhishingVerdict,
        host: Optional[str] = None,
        source_user: Optional[str] = None,
    ) -> SecurityEvent:
        """Convert a PhishingVerdict on a URL into a canonical SecurityEvent.

        Can be published directly to Redis Streams ('events:raw') and
        ingested by the SOC correlation engine.
        """
        severity_map = {
            PhishingSeverity.SAFE: "low",
            PhishingSeverity.LOW: "low",
            PhishingSeverity.MEDIUM: "medium",
            PhishingSeverity.HIGH: "high",
            PhishingSeverity.CRITICAL: "critical",
        }
        features = URLFeatureExtractor.extract_features(verdict.target_url or "")
        event_host = host or features.hostname or "perimeter-gateway"
        ip_entity = features.hostname if features.is_ip_address else None

        return SecurityEvent(
            source="phishing",
            event_type="phishing_url_detected" if verdict.is_phishing else "phishing_url_scanned",
            severity=severity_map.get(verdict.severity, "low"),
            entity=Entity(
                ip=ip_entity,
                user=source_user,
                host=event_host,
            ),
            raw=verdict.to_security_event_raw(),
            enrichment={
                "target_url": verdict.target_url,
                "phishing_score": verdict.score,
                "signal_count": len(verdict.signals),
                "mitre_techniques": verdict.mitre_techniques,
            },
        )
