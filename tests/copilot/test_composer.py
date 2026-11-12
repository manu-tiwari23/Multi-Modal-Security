"""
Unit tests for ResponseComposer and citation extraction.
"""

from src.copilot.composer import ResponseComposer
from src.copilot.models import ToolCallRecord


def test_extract_citations_from_tools():
    tool_rec_logs = ToolCallRecord(tool_name="query_logs", arguments={})
    tool_out_logs = {
        "count": 1,
        "events": [
            {
                "event_id": "evt-cite-1",
                "source": "soc",
                "event_type": "auth_failure",
                "severity": "medium",
                "timestamp": "2026-08-22T12:00:00Z",
                "entity": {"ip": "1.2.3.4"},
            }
        ],
    }

    tool_rec_inc = ToolCallRecord(tool_name="get_incident", arguments={})
    tool_out_inc = {
        "incident_id": "INC-001",
        "title": "SSH Brute Force",
        "severity": "high",
        "risk_score": 75.0,
        "event_count": 5,
    }

    citations = ResponseComposer.extract_citations_from_tools(
        [tool_rec_logs, tool_rec_inc],
        [tool_out_logs, tool_out_inc],
    )

    assert len(citations) == 2
    types = [c.type for c in citations]
    assert "event" in types
    assert "incident" in types
    assert citations[0].id == "evt-cite-1"
    assert citations[1].id == "INC-001"


def test_extract_recommendations_from_text():
    text = (
        "Based on the analysis, I recommend we block IP 203.0.113.88 immediately at the perimeter "
        "and isolate host prod-web-01 from the internal network."
    )
    recs = ResponseComposer.extract_recommendations(text)

    assert len(recs) == 2
    types = [r.action_type for r in recs]
    assert "block_ip" in types
    assert "isolate_host" in types
    for r in recs:
        assert r.requires_approval is True


def test_compose_response_appends_grounding_footer():
    tool_rec = ToolCallRecord(tool_name="lookup_ioc", arguments={"ioc_value": "203.0.113.88"})
    tool_out = {
        "ioc": "203.0.113.88",
        "type": "ip",
        "classification": "Malicious Botnet",
        "threat_score": 92,
    }

    resp = ResponseComposer.compose_response(
        query="Check IP 203.0.113.88",
        raw_answer="This IP has high threat score and should be contained.",
        tool_records=[tool_rec],
        tool_outputs=[tool_out],
        execution_time_ms=45.0,
        model_name="test-model",
    )

    assert resp.query == "Check IP 203.0.113.88"
    assert len(resp.citations) == 1
    assert "Grounding Evidence & Citations" in resp.answer
    assert "[IOC: 203.0.113.88]" in resp.answer
    assert resp.execution_time_ms == 45.0
