from fastapi.testclient import TestClient

import src.api.main as api
from src.shared.event_schema import SecurityEvent


def test_memory_total_is_before_page_limit_and_after_filter(monkeypatch):
    monkeypatch.setattr(api, "_get_os", lambda: None)
    monkeypatch.setattr(api, "RECENT_EVENTS_BUFFER", [
        SecurityEvent(source="soc", event_type="sample", severity="high" if i < 4 else "low") for i in range(7)])
    response = TestClient(api.app).get("/api/events?size=2&severity=high")
    assert response.status_code == 200
    assert response.json()["total"] == 4
    assert response.json()["count"] == 2
