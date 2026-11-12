"""
Unit tests for IncidentReportGenerator.
"""

from datetime import datetime, timezone

from src.copilot.report_generator import IncidentReportGenerator
from src.copilot.retrieval import IncidentRetriever, ThreatIntelRetriever
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.correlation.engine import CorrelationEngine
from src.soc.detection.rule_model import RuleMatch


def test_generate_report_success():
    engine = CorrelationEngine()
    ev = SecurityEvent(
        event_id="evt-rep-1",
        timestamp=datetime.now(timezone.utc),
        source="soc",
        severity="high",
        entity=Entity(ip="203.0.113.88", user="root", host="prod-web-01", hash="abcdef1234567890"),
        event_type="auth_failure",
    )
    match = RuleMatch(
        rule_id="SOC-RULE-001",
        rule_title="SSH Password Brute Force",
        severity="high",
        matched_event=ev,
        tags=["ssh_brute_force"],
        context={"mitre_attack": ["T1110"]},
    )
    incident = engine.process_event(ev, rule_matches=[match])

    inc_ret = IncidentRetriever(engine)
    ti_ret = ThreatIntelRetriever()
    gen = IncidentReportGenerator(inc_ret, ti_ret)

    report = gen.generate_report(incident.incident_id)

    assert report is not None
    assert report.incident_id == incident.incident_id
    assert report.priority in ("P1-critical", "P2-high", "P3-medium", "P4-low")
    assert len(report.iocs) >= 1
    assert any(i["value"] == "203.0.113.88" for i in report.iocs)
    assert any(m["id"] == "T1110" for m in report.mitre_matrix)
    assert len(report.containment_actions) >= 1
    assert report.containment_actions[0].requires_approval is True

    # Test Markdown rendering
    md = report.to_markdown()
    assert f"**Incident ID:** `{incident.incident_id}`" in md
    assert "203.0.113.88" in md
    assert "Pending Analyst Authorization" in md


def test_generate_report_nonexistent_incident():
    engine = CorrelationEngine()
    inc_ret = IncidentRetriever(engine)
    gen = IncidentReportGenerator(inc_ret)

    report = gen.generate_report("INC-DOES-NOT-EXIST")
    assert report is None
