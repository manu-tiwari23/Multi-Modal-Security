"""Read-only report lookups against fixed vendor APIs; no scan submissions."""

import base64
import hashlib
import time
from urllib.parse import quote

import httpx

from .models import Indicator, ProviderResult


class DemoDatasetProvider:
    """Local synthetic reputation used only by the documented Simulation Lab indicators."""

    name = "mms_demo_dataset"
    local = True
    api_key = ""
    _records = {
        ("ip", "203.0.113.88"): (86, "Full platform showcase source"),
        ("domain", "account-verification.example.test"): (78, "Lookalike-domain demonstration"),
        ("url", "http://secure-login.example.test/verify/account?session=demo"): (92, "Credential-lure URL demonstration"),
        ("hash", "f36f9731c93cebe6dd00be680e7049d69261100c9e5ff00fe110752b6fbd9694"): (72, "Inert attachment demonstration"),
    }

    def lookup(self, indicator: Indicator):
        record = self._records.get((indicator.type, indicator.value))
        if record is None:
            return ProviderResult(
                provider=self.name,
                status="unsupported",
                explanation="Indicator is not part of the local Simulation Lab demo dataset",
                details={"synthetic": True, "dataset": "simulation_lab"},
            )
        score, scenario = record
        return ProviderResult(
            provider=self.name,
            status="ok",
            classification="flagged",
            score=score,
            explanation=(
                f"Synthetic MMS demo record: {scenario}. This score exists only to demonstrate the "
                "intelligence workflow and is not external reputation or proof of compromise."
            ),
            details={"synthetic": True, "dataset": "simulation_lab", "scenario": scenario},
        )


class HTTPProvider:
    name = "provider"

    def __init__(self, api_key="", timeout=2.0, transport=None):
        self.api_key = api_key.strip()
        self.timeout = timeout
        self.transport = transport

    def _get(self, url, headers, params=None):
        deadline = time.monotonic() + self.timeout
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport, follow_redirects=False, trust_env=False) as client:
                # Bound even vendor responses; error bodies are not exposed/logged.
                with client.stream("GET", url, headers=headers, params=params) as response:
                    if response.status_code != 200:
                        status = {404: "not_found", 429: "rate_limited", 401: "error", 403: "error"}.get(response.status_code, "error")
                        return ProviderResult(provider=self.name, status=status, explanation=f"Provider returned HTTP {response.status_code}")
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        if time.monotonic() > deadline:
                            raise ValueError("Provider exceeded request budget")
                        content.extend(chunk)
                        if len(content) > 1024 * 1024:
                            raise ValueError("Response too large")
                    import json
                    return json.loads(content)
        except (httpx.HTTPError, ValueError, TypeError):
            return ProviderResult(provider=self.name, status="error", explanation="Provider request failed, timed out or returned invalid data")


class VirusTotalProvider(HTTPProvider):
    name = "virustotal"

    def lookup(self, indicator: Indicator):
        if not self.api_key:
            return ProviderResult(provider=self.name, status="not_configured", explanation="VirusTotal API key is not configured")
        path = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}[indicator.type]
        identifier = base64.urlsafe_b64encode(indicator.value.encode()).decode().rstrip("=") if indicator.type == "url" else indicator.value
        gui_id = hashlib.sha256(indicator.value.encode()).hexdigest() if indicator.type == "url" else indicator.value
        response = self._get(f"https://www.virustotal.com/api/v3/{path}/{quote(identifier, safe='')}", {"x-apikey": self.api_key})
        if isinstance(response, ProviderResult):
            return response
        try:
            stats = response["data"]["attributes"]["last_analysis_stats"]
            if not isinstance(stats, dict) or any(type(n) is not int or n < 0 for n in stats.values()):
                raise ValueError("Invalid vendor statistics")
            total = sum(stats.values())
            malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
            score = round(100 * (malicious + 0.5 * suspicious) / total) if total else None
            verdict = "flagged" if malicious + suspicious else "no_known_flags" if total else "unknown"
            return ProviderResult(provider=self.name, status="ok", classification=verdict, score=score,
                explanation=f"{malicious} malicious and {suspicious} suspicious vendor results out of {total}; score is the weighted flag ratio, not a compromise probability",
                details={"malicious": malicious, "suspicious": suspicious, "total": total},
                source_url=f"https://www.virustotal.com/gui/{'ip-address' if indicator.type == 'ip' else 'file' if indicator.type == 'hash' else indicator.type}/{quote(gui_id, safe='')}")
        except (KeyError, TypeError, ValueError):
            return ProviderResult(provider=self.name, status="error", explanation="Provider report has no usable analysis statistics")


class AbuseIPDBProvider(HTTPProvider):
    name = "abuseipdb"
    supported_types = {"ip"}

    def lookup(self, indicator: Indicator):
        if indicator.type != "ip":
            return ProviderResult(provider=self.name, status="unsupported", explanation="AbuseIPDB supports IP indicators only")
        if not self.api_key:
            return ProviderResult(provider=self.name, status="not_configured", explanation="AbuseIPDB API key is not configured")
        response = self._get("https://api.abuseipdb.com/api/v2/check", {"Key": self.api_key, "Accept": "application/json"},
                             {"ipAddress": indicator.value, "maxAgeInDays": 90})
        if isinstance(response, ProviderResult):
            return response
        try:
            data = response["data"]
            score, reports = data["abuseConfidenceScore"], data["totalReports"]
            if type(score) is not int or not 0 <= score <= 100 or type(reports) is not int or reports < 0:
                raise ValueError("Invalid vendor scores")
            return ProviderResult(provider=self.name, status="ok", score=score,
                classification="flagged" if score > 0 else "no_known_flags",
                explanation=f"Provider abuse confidence {score}/100 from {reports} reports in the last 90 days",
                details={"total_reports": reports, "country_code": data.get("countryCode"), "last_reported_at": data.get("lastReportedAt")},
                source_url=f"https://www.abuseipdb.com/check/{quote(indicator.value, safe='')}")
        except (KeyError, TypeError, ValueError):
            return ProviderResult(provider=self.name, status="error", explanation="Provider report has no usable abuse statistics")
