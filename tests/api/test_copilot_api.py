"""
API integration tests for Copilot endpoints using FastAPI TestClient.
"""

import pytest
from fastapi.testclient import TestClient

from src.api.main import app, correlation_engine
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.detection.rule_model import RuleMatch

client = TestClient(app)


def test_api_get_copilot_tools():
    res = client.get("/api/copilot/tools")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] >= 5
    assert len(data["tools"]) >= 5


def test_api_copilot_chat():
    res = client.post(
        "/api/copilot/chat",
        json={"prompt": "Investigate IP 203.0.113.88 and check threat reputation"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert "203.0.113.88" in data["answer"]
    assert len(data["tool_calls"]) >= 1


def test_api_copilot_report_generation():
    # Seed an incident
    ev = SecurityEvent(
        source="soc",
        severity="high",
        entity=Entity(ip="203.0.113.88", user="root", host="prod-web-01"),
        event_type="privilege_escalation",
    )
    match = RuleMatch(
        rule_id="SOC-RULE-002",
        rule_title="Sudo Escalation",
        severity="high",
        matched_event=ev,
        tags=["root"],
        context={"mitre_attack": ["T1548.003"]},
    )
    incident = correlation_engine.process_event(ev, rule_matches=[match])

    res = client.post(
        "/api/copilot/reports/generate",
        json={"incident_id": incident.incident_id},
    )
    assert res.status_code == 200
    data = res.json()
    assert "report" in data
    assert "markdown" in data
    assert incident.incident_id in data["markdown"]
