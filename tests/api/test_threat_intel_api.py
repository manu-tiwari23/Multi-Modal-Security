from fastapi.testclient import TestClient
import pytest

import src.api.main as api
from src.threat_intel.models import ProviderResult
from src.threat_intel.providers import DemoDatasetProvider
from src.threat_intel.runtime import get_threat_intel
from src.threat_intel.service import ThreatIntelService


@pytest.fixture
def context():
    class Provider:
        name = "synthetic"
        api_key = "test-only-secret"
        calls = 0
        def lookup(self, indicator):
            self.calls += 1
            return ProviderResult(provider=self.name, status="ok", classification="flagged", score=70, explanation="Mock provider evidence")
    provider = Provider()
    service = ThreatIntelService([provider])
    api.app.dependency_overrides[get_threat_intel] = lambda: service
    try:
        yield TestClient(api.app), provider, service
    finally:
        api.app.dependency_overrides.pop(get_threat_intel, None)


def test_api_defaults_local_then_explicit_lookup_and_cache(context):
    client, provider, _ = context
    response = client.post("/api/threat-intel/lookup", json={"value": "8.8.8.8"})
    assert response.status_code == 200
    assert response.json()["score"] is None and provider.calls == 0
    response = client.post("/api/threat-intel/lookup", json={"value": "8.8.8.8", "allow_external": True})
    assert response.json()["score"] == 70 and provider.calls == 1
    assert client.post("/api/threat-intel/lookup", json={"value": "8.8.8.8"}).json()["cached"]
    status = client.get("/api/threat-intel/status")
    assert status.status_code == 200
    assert "test-only-secret" not in status.text
    assert client.post("/api/threat-intel/lookup", json={"value": "invalid domain"}).status_code == 422


def test_copilot_uses_cached_provider_evidence_without_external_request(context):
    from src.copilot.retrieval import ThreatIntelRetriever
    _, provider, service = context
    service.lookup("8.8.8.8", allow_external=True)
    retriever = ThreatIntelRetriever(lookup=lambda value, kind: service.lookup(value, kind).model_dump(mode="json"))
    result = retriever.lookup_ioc("8.8.8.8")
    assert result["threat_score"] == 70
    assert result["providers"][0]["explanation"] == "Mock provider evidence"
    assert result["found_in_threat_intel"] is True
    assert provider.calls == 1


def test_api_returns_labeled_demo_intelligence_for_simulation_indicator(context):
    client, _, original_service = context
    demo_service = ThreatIntelService([DemoDatasetProvider()])
    api.app.dependency_overrides[get_threat_intel] = lambda: demo_service
    try:
        response = client.post("/api/threat-intel/lookup", json={"value": "203.0.113.88"})
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "flagged"
        assert data["score"] == 86
        assert data["providers"][0]["details"]["synthetic"] is True
        assert "not observed or external" in data["limitations"][0]
    finally:
        api.app.dependency_overrides[get_threat_intel] = lambda: original_service
