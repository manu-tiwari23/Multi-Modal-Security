"""End-to-end integration test for the API Gateway and OpenSearch."""

import pytest
from httpx import AsyncClient, ASGITransport
from src.api.main import app


@pytest.mark.asyncio
async def test_api_gateway_e2e():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health check
        res_health = await client.get("/api/health")
        assert res_health.status_code == 200
        assert res_health.json() == {"status": "ok", "service": "mms-api-gateway"}

        # 2. Query ingested events
        res_events = await client.get("/api/events?size=10")
        assert res_events.status_code == 200
        data = res_events.json()
        assert "events" in data
        assert data["total"] >= 20
        assert len(data["events"]) == 10

        # 3. Filter by severity
        res_filtered = await client.get("/api/events?severity=medium")
        assert res_filtered.status_code == 200
        filtered_data = res_filtered.json()
        for ev in filtered_data["events"]:
            assert ev["severity"] == "medium"
