"""
Unit tests for Copilot Retrieval Layer (LogRetriever, IncidentRetriever, ThreatIntelRetriever).
"""

from datetime import datetime, timezone

from src.copilot.retrieval import IncidentRetriever, LogRetriever, ThreatIntelRetriever
from src.honeypot.models import HoneypotSession
from src.honeypot.recorder import SessionRecorder
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.correlation.engine import CorrelationEngine
from src.soc.detection.rule_model import RuleMatch


def test_log_retriever_memory_fallback():
    ev1 = SecurityEvent(
        event_id="evt-1",
        timestamp=datetime.now(timezone.utc),
        source="soc",
        severity="high",
        entity=Entity(ip="203.0.113.88", user="root", host="web-01"),
        event_type="auth_failure",
    )
    ev2 = SecurityEvent(
        event_id="evt-2",
        timestamp=datetime.now(timezone.utc),
        source="honeypot",
        severity="medium",
        entity=Entity(ip="185.220.101.42", user="admin", host="honeypot-ssh"),
        event_type="command_exec",
    )

    retriever = LogRetriever(opensearch_client=None, memory_buffer=[ev1, ev2])

    # Filter by IP
    res_ip = retriever.query_logs(entity_ip="203.0.113.88")
    assert len(res_ip) == 1
    assert res_ip[0]["event_id"] == "evt-1"

    # Filter by source
    res_source = retriever.query_logs(source="honeypot")
    assert len(res_source) == 1
    assert res_source[0]["event_id"] == "evt-2"

    # Filter by severity
    res_sev = retriever.query_logs(severity="high")
    assert len(res_sev) == 1


def test_incident_retriever():
    engine = CorrelationEngine(correlation_window_seconds=300)
    ev = SecurityEvent(
        event_id="evt-inc-1",
        timestamp=datetime.now(timezone.utc),
        source="soc",
        severity="high",
        entity=Entity(ip="192.168.1.105", user="root", host="db-primary"),
        event_type="privilege_escalation",
    )
    match = RuleMatch(
        rule_id="SOC-RULE-002",
        rule_title="Sudo to root escalation",
        severity="high",
        matched_event=ev,
        tags=["privilege_escalation"],
        context={"mitre_attack": ["T1548.003"]},
    )

    incident = engine.process_event(ev, rule_matches=[match])
    assert incident is not None

    retriever = IncidentRetriever(engine)
    context = retriever.get_incident_context(incident.incident_id)

    assert context is not None
    assert context["incident_id"] == incident.incident_id
    assert context["primary_entity"]["ip"] == "192.168.1.105"
    assert "T1548.003" in context["mitre_techniques"]
    assert len(context["timeline"]) == 1

    active_list = retriever.list_active_incidents()
    assert len(active_list) == 1
    assert active_list[0]["incident_id"] == incident.incident_id


def test_threat_intel_retriever_does_not_invent_reputation():
    retriever = ThreatIntelRetriever()
    ioc_data = retriever.lookup_ioc("203.0.113.88")
    assert ioc_data["found_in_threat_intel"] is False
    assert ioc_data["threat_score"] is None
    assert ioc_data["classification"] == "unknown"
    assert "actor_group" not in ioc_data
    empty_hash = retriever.lookup_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert empty_hash["classification"] == "unknown"
    assert empty_hash["threat_score"] is None


def test_threat_intel_retriever_with_honeypot_correlation():
    recorder = SessionRecorder()
    sess = recorder.start_session("45.33.32.156", 54321, "ssh", "SSH-2.0-OpenSSH")
    recorder.record_command(sess.session_id, "cat /etc/passwd", output_preview="root:x:0:0")

    retriever = ThreatIntelRetriever(honeypot_recorder=recorder)
    ioc_data = retriever.lookup_ioc("45.33.32.156")

    assert ioc_data["honeypot_interactions"] == 1
    assert ioc_data["honeypot_commands_seen"] == 1
    assert ioc_data["threat_score"] is None
    assert sess.session_id in ioc_data["honeypot_session_ids"]


def test_empty_successful_opensearch_query_does_not_return_stale_memory():
    class Search:
        def search(self, **kwargs):
            return {"hits": {"hits": []}}
    event = SecurityEvent(event_id="stale", source="soc", event_type="auth_failure")
    retriever = LogRetriever(opensearch_client=Search(), memory_buffer=[event])
    assert retriever.query_logs() == []
