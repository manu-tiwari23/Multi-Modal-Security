"""End-to-end integration test for the API Gateway and OpenSearch."""

import pytest
from httpx import AsyncClient, ASGITransport
from src.api.main import app

# Mark as integration test requiring live services
pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_api_gateway_e2e():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health check
        res_health = await client.get("/api/health")
        assert res_health.status_code == 200
        health_json = res_health.json()
        assert health_json["status"] == "ok"
        assert health_json["service"] == "mms-api-gateway"

        # Check if OpenSearch is reachable before querying ingested events
        from opensearchpy import OpenSearch
        from src.shared.config import settings
        opensearch_live = False
        try:
            os_client = OpenSearch(hosts=[settings.opensearch_url], timeout=2)
            opensearch_live = bool(os_client.ping())
            os_client.close()
        except Exception:
            opensearch_live = False

        if not opensearch_live:
            pytest.skip("OpenSearch container is not running on localhost:9200")

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
