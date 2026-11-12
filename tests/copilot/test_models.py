"""
Unit tests for Copilot Pydantic data models.
"""

from datetime import datetime, timezone

from src.copilot.models import (
    Citation,
    ContainmentRecommendation,
    CopilotQuery,
    CopilotResponse,
    IncidentReport,
    ToolCallRecord,
)


def test_citation_model():
    cit = Citation(
        id="evt-12345",
        type="event",
        title="SSH Auth Failure",
        snippet="Failed password for root",
        source="soc",
    )
    assert cit.id == "evt-12345"
    assert cit.type == "event"
    assert "SSH" in cit.title
    dump = cit.model_dump(mode="json")
    assert dump["type"] == "event"


def test_tool_call_record():
    rec = ToolCallRecord(
        tool_name="query_logs",
        arguments={"entity_ip": "1.2.3.4"},
        result_summary="Found 5 events",
    )
    assert rec.tool_name == "query_logs"
    assert rec.arguments["entity_ip"] == "1.2.3.4"
    assert rec.success is True


def test_containment_recommendation_enforces_approval():
    rec = ContainmentRecommendation(
        action_type="block_ip",
        target="203.0.113.88",
        rationale="Brute force activity detected",
    )
    assert rec.requires_approval is True
    assert rec.action_type == "block_ip"
    assert rec.priority == "high"


def test_copilot_query_and_response():
    q = CopilotQuery(prompt="Who is attacking prod-web-01?")
    assert q.prompt == "Who is attacking prod-web-01?"

    resp = CopilotResponse(
        query=q.prompt,
        answer="Attacker IP is 203.0.113.88",
        citations=[
            Citation(id="203.0.113.88", type="ioc", title="Attacker IP", snippet="Threat Score 92/100")
        ],
        model="mms-copilot-gpt4",
    )
    assert len(resp.citations) == 1
    assert "203.0.113.88" in resp.answer


def test_incident_report_markdown_generation():
    rep = IncidentReport(
        incident_id="INC-TEST-001",
        title="SSH Brute Force and Privilege Escalation",
        risk_score=85.0,
        priority="P1-critical",
        executive_summary="Critical multi-stage attack detected on production web host.",
        technical_analysis="Attacker attempted 5 failed logins followed by sudo /bin/bash execution.",
        attack_timeline=[
            {"timestamp": "2026-08-22T10:00:00Z", "source": "soc", "severity": "medium", "description": "SSH auth failure"},
            {"timestamp": "2026-08-22T10:01:00Z", "source": "soc", "severity": "high", "description": "Sudo privilege escalation"},
        ],
        iocs=[{"type": "IPv4", "value": "203.0.113.88", "context": "Scanner Node"}],
        mitre_matrix=[{"id": "T1110", "name": "Brute Force", "source": "SOC"}],
        containment_actions=[
            ContainmentRecommendation(action_type="block_ip", target="203.0.113.88", rationale="Malicious IP")
        ],
    )

    md = rep.to_markdown()
    assert "# 🛡️ MMS Incident & Forensic Report" in md
    assert "INC-TEST-001" in md
    assert "85.0/100.0" in md
    assert "203.0.113.88" in md
    assert "T1110" in md
    assert "Pending Analyst Authorization" in md
