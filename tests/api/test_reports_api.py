import pytest
from fastapi.testclient import TestClient

import src.api.main as api
from src.shared.event_schema import Entity
from src.soc.correlation.incident_model import Incident, IncidentTimelineEntry


@pytest.fixture
def client(monkeypatch):
    incident = Incident(incident_id="report-api", title="Email review", event_count=1,
                        event_ids=["email-1"], primary_entity=Entity(ip="203.0.113.20"), timeline=[
        IncidentTimelineEntry(event_id="email-1", event_type="phishing_email_detected",
                              source="phishing", severity="medium", description="Synthetic email")])
    monkeypatch.setattr(api.correlation_engine, "get_incident", lambda key: incident if key == incident.incident_id else None)
    return TestClient(api.app)


@pytest.mark.parametrize("format,content_type", [("json", "application/json"), ("html", "text/html"), ("markdown", "text/markdown")])
def test_report_download_formats(client, format, content_type):
    response = client.get(f"/api/reports/incidents/report-api?format={format}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(content_type)
    assert ("email\\-1" if format == "markdown" else "email-1") in response.text
    if format != "json":
        assert "attachment;" in response.headers["content-disposition"]
        assert response.headers["x-content-type-options"] == "nosniff"


def test_missing_incident_and_invalid_download_format(client):
    assert client.get("/api/reports/incidents/missing").status_code == 404
    assert client.get("/api/reports/incidents/report-api?format=exe").status_code == 422


def test_report_uses_real_response_record(client, monkeypatch):
    monkeypatch.setattr(api.ir_state_tracker, "is_tracked", lambda key: True)
    monkeypatch.setattr(api.ir_state_tracker, "get_incident_record", lambda key: {"phase": "investigating", "transitions": []})
    assert "status investigating" in client.get("/api/reports/incidents/report-api").json()["summary"]


@pytest.mark.parametrize("format", ["json", "html", "markdown"])
def test_threat_reports_include_closed_incidents(client, monkeypatch, format):
    monkeypatch.setattr(api.correlation_engine, "list_incidents", lambda: [Incident(incident_id="closed-threat-case", title="Historical detection", status="closed")])
    monkeypatch.setattr(api, "RECENT_EVENTS_BUFFER", [])
    response = client.get(f"/api/reports/threats?format={format}")
    assert response.status_code == 200
    assert "Historical detection" in response.text
    assert "closed" in response.text


def test_incident_listing_uses_public_engine_interface(client, monkeypatch):
    monkeypatch.setattr(api.correlation_engine, "_incidents", {"listed": Incident(incident_id="listed", title="Listed incident")})
    response = client.get("/api/incidents")
    assert response.status_code == 200
    assert response.json()["incidents"][0]["incident_id"] == "listed"
