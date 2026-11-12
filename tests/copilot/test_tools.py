"""
Unit tests for OpenAI tool schemas and ToolExecutor.
"""

from datetime import datetime, timezone

from src.copilot.report_generator import IncidentReportGenerator
from src.copilot.retrieval import IncidentRetriever, LogRetriever, ThreatIntelRetriever
from src.copilot.tools import OPENAI_TOOLS, ToolExecutor
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.correlation.engine import CorrelationEngine
from src.soc.detection.rule_model import RuleMatch


def test_openai_tool_schemas_validity():
    assert len(OPENAI_TOOLS) >= 5
    names = [t["function"]["name"] for t in OPENAI_TOOLS]
    assert "query_logs" in names
    assert "get_incident" in names
    assert "lookup_ioc" in names
    assert "run_correlation" in names
    assert "draft_report" in names

    for t in OPENAI_TOOLS:
        assert t["type"] == "function"
        assert "description" in t["function"]
        assert "parameters" in t["function"]


def test_tool_executor_query_logs():
    ev = SecurityEvent(
        event_id="evt-tool-1",
        timestamp=datetime.now(timezone.utc),
        source="soc",
        severity="medium",
        entity=Entity(ip="10.0.0.5", user="deploy", host="ci-cd-runner"),
        event_type="auth_failure",
    )
    log_ret = LogRetriever(memory_buffer=[ev])
    engine = CorrelationEngine()
    inc_ret = IncidentRetriever(engine)
    ti_ret = ThreatIntelRetriever()

    executor = ToolExecutor(log_ret, inc_ret, ti_ret)

    res, rec = executor.execute_tool("query_logs", {"entity_ip": "10.0.0.5"})
    assert rec.success is True
    assert rec.tool_name == "query_logs"
    assert res["count"] == 1
    assert res["events"][0]["event_id"] == "evt-tool-1"


def test_tool_executor_lookup_ioc():
    log_ret = LogRetriever()
    engine = CorrelationEngine()
    inc_ret = IncidentRetriever(engine)
    ti_ret = ThreatIntelRetriever()
    executor = ToolExecutor(log_ret, inc_ret, ti_ret)

    res, rec = executor.execute_tool("lookup_ioc", {"ioc_value": "203.0.113.88"})
    assert rec.success is True
    assert res["found_in_threat_intel"] is True
    assert res["threat_score"] == 92


def test_tool_executor_get_incident_and_draft_report():
    engine = CorrelationEngine()
    ev = SecurityEvent(
        event_id="evt-inc-tool",
        timestamp=datetime.now(timezone.utc),
        source="soc",
        severity="critical",
        entity=Entity(ip="203.0.113.88", user="root", host="prod-db"),
        event_type="privilege_escalation",
    )
    match = RuleMatch(
        rule_id="SOC-RULE-002",
        rule_title="Root Escalation",
        severity="critical",
        matched_event=ev,
        tags=["root"],
        context={"mitre_attack": ["T1548.003"]},
    )
    incident = engine.process_event(ev, rule_matches=[match])

    log_ret = LogRetriever()
    inc_ret = IncidentRetriever(engine)
    ti_ret = ThreatIntelRetriever()
    rep_gen = IncidentReportGenerator(inc_ret, ti_ret)
    executor = ToolExecutor(log_ret, inc_ret, ti_ret, report_generator=rep_gen)

    # Get Incident
    res_inc, rec_inc = executor.execute_tool("get_incident", {"incident_id": incident.incident_id})
    assert rec_inc.success is True
    assert res_inc["incident_id"] == incident.incident_id

    # Draft Report
    res_rep, rec_rep = executor.execute_tool("draft_report", {"incident_id": incident.incident_id})
    assert rec_rep.success is True
    assert res_rep["incident_id"] == incident.incident_id
    assert "Executive Summary" in res_rep["executive_summary"] or len(res_rep["executive_summary"]) > 20


def test_tool_executor_unknown_tool():
    executor = ToolExecutor(LogRetriever(), IncidentRetriever(CorrelationEngine()), ThreatIntelRetriever())
    res, rec = executor.execute_tool("unregistered_tool", {})
    assert rec.success is False
    assert "Unknown tool" in res["error"]
