"""Live API/OpenSearch test using a unique disposable index, never user data."""

from uuid import uuid4

import pytest
from httpx import AsyncClient, ASGITransport
from opensearchpy import OpenSearch

import src.api.main as api
from src.shared.event_schema import Entity, SecurityEvent

pytestmark = pytest.mark.integration


@pytest.fixture
def seeded_index(monkeypatch):
    client = OpenSearch(hosts=[api.settings.opensearch_url], timeout=2)
    if not client.ping():
        client.close()
        pytest.skip("OpenSearch is unavailable")
    index = f"mms-api-e2e-{uuid4().hex}"
    monkeypatch.setattr(api.settings, "opensearch_events_index", index)
    monkeypatch.setattr(api, "_os_client", client)
    monkeypatch.setattr(api, "RECENT_EVENTS_BUFFER", [])
    try:
        client.indices.create(index=index)
        for number in range(20):
            event = SecurityEvent(source="soc", event_type="integration_sample",
                                  severity="medium" if number < 12 else "low",
                                  entity=Entity(ip="203.0.113.18"))
            client.index(index=index, id=event.event_id, body=event.to_opensearch_doc())
        client.indices.refresh(index=index)
        yield index
    finally:
        client.indices.delete(index=index, ignore=[404])
        client.close()


@pytest.mark.asyncio
async def test_api_gateway_e2e(seeded_index):
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as client:
        health = await client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["service"] == "mms-api-gateway"
        response = await client.get("/api/events?size=10")
        assert response.status_code == 200
        assert response.json()["total"] == 20
        assert response.json()["count"] == 10
        filtered = await client.get("/api/events?severity=medium&size=5")
        assert filtered.status_code == 200
        assert filtered.json()["total"] == 12
        assert len(filtered.json()["events"]) == 5
        assert all(e["severity"] == "medium" for e in filtered.json()["events"])
