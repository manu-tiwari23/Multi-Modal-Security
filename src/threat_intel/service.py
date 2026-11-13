from datetime import datetime, timedelta, timezone
import hashlib
from threading import Lock
import time

from .cache import CacheUnavailable, MemoryCache
from .models import Indicator, LookupResult, ProviderResult


class ThreatIntelService:
    def __init__(self, providers=(), cache=None, ttl_seconds=3600):
        self.providers = list(providers)
        self.cache = cache if cache is not None else MemoryCache()
        self.ttl_seconds = ttl_seconds
        self._cache_retry_after = 0
        # Striped locks bound memory and coalesce simultaneous identical lookups.
        self._locks = [Lock() for _ in range(32)]

    def lookup(self, value, kind=None, allow_external=False):
        indicator = Indicator.parse(value, kind)
        key = hashlib.sha256(f"{indicator.type}:{indicator.value}".encode()).hexdigest()
        with self._locks[int(key[:4], 16) % len(self._locks)]:
            return self._lookup(indicator, key, allow_external)

    def _lookup(self, indicator, key, allow_external):
        cache_status = "memory" if isinstance(self.cache, MemoryCache) else "persistent"
        if time.monotonic() < self._cache_retry_after:
            cache_status = "unavailable"
        else:
            try:
                cached = self.cache.get(key)
                if cached:
                    cached.cached = True
                    cached.cache_status = cache_status
                    return cached
            except CacheUnavailable:
                cache_status = "unavailable"
                self._cache_retry_after = time.monotonic() + 30
        results = []
        for provider in self.providers:
            if not allow_external:
                result = ProviderResult(provider=provider.name, status="not_requested", explanation="External lookup was not requested; only cached reputation is available")
            elif not indicator.external_eligible:
                result = ProviderResult(provider=provider.name, status="unsupported", explanation="Private/reserved/test indicators are kept local")
            else:
                result = provider.lookup(indicator)
            results.append(result)
        scores = [r.score for r in results if r.status == "ok" and r.score is not None]
        verdict = "flagged" if any(r.classification == "flagged" for r in results) else "no_known_flags" if any(r.classification == "no_known_flags" for r in results) else "unknown"
        now = datetime.now(timezone.utc)
        result = LookupResult(indicator=indicator, classification=verdict, score=max(scores) if scores else None,
                              providers=results, checked_at=now, cache_status=cache_status)
        # Do not cache configuration failures as reputation, or an offline lookup
        # that would suppress a later explicitly requested provider lookup.
        if any(r.status in ("ok", "not_found") for r in results):
            result.expires_at = now + timedelta(seconds=self.ttl_seconds)
            if cache_status != "unavailable":
                try:
                    self.cache.put(key, result)
                except CacheUnavailable:
                    result.cache_status = "unavailable"
                    self._cache_retry_after = time.monotonic() + 30
        return result
