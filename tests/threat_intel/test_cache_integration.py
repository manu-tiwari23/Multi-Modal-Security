from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg2
from psycopg2 import sql
import pytest

from src.shared.config import settings
from src.threat_intel.cache import PostgresCache
from src.threat_intel.models import ProviderResult
from src.threat_intel.service import ThreatIntelService

pytestmark = pytest.mark.integration


def test_reputation_cache_survives_new_service_and_expires():
    schema = "mms_ti_test_" + uuid4().hex
    try:
        connection = psycopg2.connect(settings.postgres_url, connect_timeout=2)
        connection.close()
    except Exception:
        pytest.skip("Live Postgres required")

    class Provider:
        name = "synthetic"
        calls = 0
        def lookup(self, indicator):
            self.calls += 1
            return ProviderResult(provider=self.name, status="ok", classification="flagged", score=50, explanation="Synthetic provider test")

    provider = Provider()
    try:
        first = ThreatIntelService([provider], PostgresCache(settings.postgres_url, schema))
        expected = first.lookup("8.8.8.8", allow_external=True)
        assert expected.cache_status == "persistent"
        second = ThreatIntelService([provider], PostgresCache(settings.postgres_url, schema))
        cached = second.lookup("8.8.8.8")
        assert cached.cached and cached.score == 50
        assert cached.checked_at == expected.checked_at and provider.calls == 1
        with psycopg2.connect(settings.postgres_url) as connection, connection.cursor() as cur:
            cur.execute(sql.SQL("UPDATE {} SET expires_at=%s").format(sql.Identifier(schema, "mms_threat_intel_cache")),
                        (datetime.now(timezone.utc) - timedelta(seconds=1),))
        connection.close()
        refreshed = second.lookup("8.8.8.8", allow_external=True)
        assert not refreshed.cached and provider.calls == 2
    finally:
        assert schema.startswith("mms_ti_test_")
        with psycopg2.connect(settings.postgres_url) as connection, connection.cursor() as cur:
            cur.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        connection.close()
