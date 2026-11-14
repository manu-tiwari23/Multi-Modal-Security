from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from src.threat_intel.cache import CacheUnavailable, MemoryCache
from src.threat_intel.models import Indicator, ProviderResult
from src.threat_intel.providers import AbuseIPDBProvider, DemoDatasetProvider, VirusTotalProvider
from src.threat_intel.service import ThreatIntelService


class CountingProvider:
    name = "test-provider"
    api_key = "test-key"
    def __init__(self):
        self.calls = 0
    def lookup(self, indicator):
        self.calls += 1
        return ProviderResult(provider=self.name, status="ok", classification="flagged", score=80, explanation="Synthetic test response")


@pytest.mark.parametrize("value", ["example.com", "https://example.com/path", "a" * 64])
def test_non_ip_lookup_skips_abuseipdb(value):
    abuse = AbuseIPDBProvider("test-key")
    def unexpected_lookup(indicator):
        pytest.fail("Non-IP indicator must not be routed to AbuseIPDB")
    abuse.lookup = unexpected_lookup
    other = CountingProvider()
    result = ThreatIntelService([abuse, other]).lookup(value, allow_external=True)
    assert [p.provider for p in result.providers] == [other.name]
    assert other.calls == 1


@pytest.mark.parametrize("value", ["8.8.8.8", "2001:4860:4860::8888"])
def test_ip_lookup_routes_to_abuseipdb(value):
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 10, "totalReports": 2}})
    abuse = AbuseIPDBProvider("test-key", transport=httpx.MockTransport(respond))
    result = ThreatIntelService([abuse]).lookup(value, allow_external=True)
    assert result.providers[0].status == "ok"
    assert requests[0].url.params["ipAddress"] == value


@pytest.mark.parametrize("value,kind,normalized", [
    ("8.8.8.8", "ip", "8.8.8.8"), ("2001:4860:4860::8888", "ip", "2001:4860:4860::8888"),
    ("EXAMPLE.COM.", "domain", "example.com"), ("bücher.de", "domain", "xn--bcher-kva.de"),
    ("A" * 64, "hash", "a" * 64), ("HTTPS://Example.COM/path?q=one#fragment", "url", "https://example.com/path?q=one"),
])
def test_indicator_validation_and_normalization(value, kind, normalized):
    indicator = Indicator.parse(value)
    assert indicator.type == kind
    assert indicator.value == normalized


@pytest.mark.parametrize("value,kind", [("", None), ("bad domain", None), ("../etc/passwd", "domain"),
    ("https://user:password@example.com", "url"), ("file:///private", "url"), ("bad", "hash"), ("999.1.1.1", "ip"),
    ("999.1.1.1", None), ("https://999.1.1.1", None), ("https://@example.com", None),
    ("https://[2001:4860:4860::8888%25eth0]/", None)])
def test_invalid_indicators_do_not_reach_provider(value, kind):
    provider = CountingProvider()
    with pytest.raises(ValueError):
        ThreatIntelService([provider]).lookup(value, kind, True)
    assert provider.calls == 0


@pytest.mark.parametrize("value", ["127.0.0.1", "192.168.1.10", "203.0.113.88", "example.test", "https://10.0.0.1/admin"])
def test_private_and_synthetic_indicators_stay_local(value):
    provider = CountingProvider()
    result = ThreatIntelService([provider]).lookup(value, allow_external=True)
    assert result.classification == "unknown"
    assert result.score is None
    assert result.providers[0].status == "unsupported"
    assert provider.calls == 0


@pytest.mark.parametrize("value,expected_score", [
    ("203.0.113.88", 86),
    ("account-verification.example.test", 78),
    ("http://secure-login.example.test/verify/account?session=demo", 92),
    ("f36f9731c93cebe6dd00be680e7049d69261100c9e5ff00fe110752b6fbd9694", 72),
])
def test_local_demo_dataset_returns_explicit_synthetic_result(value, expected_score):
    external = CountingProvider()
    result = ThreatIntelService([DemoDatasetProvider(), external]).lookup(value)
    assert result.classification == "flagged"
    assert result.score == expected_score
    assert result.providers[0].details["synthetic"] is True
    assert "synthetic Simulation Lab result" in result.limitations[0]
    assert external.calls == 0


def test_local_demo_dataset_does_not_rate_unlisted_indicators():
    result = ThreatIntelService([DemoDatasetProvider()]).lookup("8.8.8.8")
    assert result.classification == "unknown"
    assert result.score is None


def test_opt_in_and_cache_coalesce_repeated_lookups():
    provider = CountingProvider()
    service = ThreatIntelService([provider])
    assert service.lookup("8.8.8.8").providers[0].status == "not_requested"
    assert provider.calls == 0
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: service.lookup("8.8.8.8", allow_external=True), range(12)))
    assert provider.calls == 1
    assert sum(r.cached for r in results) == 11
    assert service.lookup("8.8.8.8").cached  # Copilot may use an analyst's cached lookup.


def test_expiry_and_bounded_cache():
    provider = CountingProvider()
    cache = MemoryCache(capacity=1)
    service = ThreatIntelService([provider], cache)
    service.lookup("8.8.8.8", allow_external=True)
    service.lookup("1.1.1.1", allow_external=True)
    assert len(cache._items) == 1
    for result in cache._items.values():
        result.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert service.lookup("1.1.1.1", allow_external=True).cached is False
    assert provider.calls == 3


def test_unavailable_cache_does_not_fabricate_reputation():
    class BrokenCache:
        def get(self, key):
            raise CacheUnavailable()
    result = ThreatIntelService([], BrokenCache()).lookup("8.8.8.8")
    assert result.classification == "unknown" and result.score is None
    assert result.cache_status == "unavailable"


@pytest.mark.parametrize("kind,value,path", [
    ("ip", "8.8.8.8", "/ip_addresses/8.8.8.8"), ("domain", "example.com", "/domains/example.com"),
    ("hash", "a" * 64, "/files/" + "a" * 64), ("url", "https://example.com/path", "/urls/"),
])
def test_virustotal_uses_fixed_get_endpoint_and_parses_statistics(kind, value, path):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 8}}}})
    provider = VirusTotalProvider("synthetic-key", transport=httpx.MockTransport(handler))
    result = provider.lookup(Indicator.parse(value, kind))
    assert result.score == 20 and result.classification == "flagged"
    assert requests[0].method == "GET"
    assert requests[0].url.host == "www.virustotal.com"
    assert path in requests[0].url.path
    assert requests[0].headers["x-apikey"] == "synthetic-key"
    assert "synthetic-key" not in result.model_dump_json()


@pytest.mark.parametrize("status,expected", [(404, "not_found"), (429, "rate_limited"), (401, "error"), (503, "error"), (302, "error")])
def test_provider_http_errors_and_redirects_remain_unknown(status, expected):
    provider = VirusTotalProvider("key", transport=httpx.MockTransport(lambda r: httpx.Response(status, headers={"location": "https://example.test"})))
    result = provider.lookup(Indicator.parse("8.8.8.8"))
    assert result.status == expected
    assert result.score is None and result.classification == "unknown"


def test_abuseipdb_checks_only_and_preserves_vendor_confidence():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 4, "countryCode": "XX"}})
    provider = AbuseIPDBProvider("key", transport=httpx.MockTransport(handler))
    result = provider.lookup(Indicator.parse("8.8.8.8"))
    assert result.score == 90
    assert requests[0].url.path == "/api/v2/check"
    assert requests[0].url.params["maxAgeInDays"] == "90"
    assert provider.lookup(Indicator.parse("example.com")).status == "unsupported"


def test_provider_timeout_empty_statistics_and_missing_configuration():
    def timeout(request):
        raise httpx.ReadTimeout("timeout")
    assert VirusTotalProvider("key", transport=httpx.MockTransport(timeout)).lookup(Indicator.parse("8.8.8.8")).status == "error"
    empty = VirusTotalProvider("key", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {}}}})))
    assert empty.lookup(Indicator.parse("8.8.8.8")).score is None
    assert VirusTotalProvider().lookup(Indicator.parse("8.8.8.8")).status == "not_configured"
    assert AbuseIPDBProvider().lookup(Indicator.parse("8.8.8.8")).status == "not_configured"
