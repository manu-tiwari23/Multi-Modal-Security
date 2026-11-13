from functools import lru_cache

from src.shared.config import settings
from .cache import MemoryCache, PostgresCache
from .providers import AbuseIPDBProvider, VirusTotalProvider
from .service import ThreatIntelService


@lru_cache
def get_threat_intel():
    cache = (PostgresCache(settings.postgres_url, settings.threat_intel_db_schema,
                          capacity=settings.threat_intel_cache_capacity)
             if settings.threat_intel_cache_mode == "persistent"
             else MemoryCache(settings.threat_intel_cache_capacity))
    return ThreatIntelService(providers=[
        VirusTotalProvider(settings.vt_api_key, settings.threat_intel_timeout_seconds),
        AbuseIPDBProvider(settings.abuseipdb_api_key, settings.threat_intel_timeout_seconds),
    ], cache=cache, ttl_seconds=settings.threat_intel_cache_ttl_seconds)
