"""
Unit tests for the SOC Correlation Engine and Incident data models.
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest

from src.shared.event_schema import Entity, SecurityEvent
from src.soc.correlation.engine import CorrelationEngine
from src.soc.correlation.incident_model import Incident, IncidentTimelineEntry
from src.soc.detection.matcher import DetectionEngine
from src.soc.detection.rule_model import DetectionCondition, DetectionRule, RuleMatch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event(
    event_type: str = "auth_failure",
    severity: str = "medium",
    source: str = "soc",
    ip: str | None = "192.168.1.100",
    user: str | None = "admin",
    host: str | None = "server01",
    raw: dict[str, Any] | None = None,
    timestamp: datetime.datetime | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        source=source,
        timestamp=timestamp or datetime.datetime.now(datetime.timezone.utc),
        entity=Entity(ip=ip, user=user, host=host),
        raw=raw or {},
    )


# ---------------------------------------------------------------------------
# Test Incident Data Models
# ---------------------------------------------------------------------------


class TestIncidentModel:
    def test_incident_creation_and_defaults(self):
        inc = Incident(
            title="Test Incident",
            severity="high",
            primary_entity=Entity(ip="10.0.0.1"),
        )
        assert inc.incident_id is not None
        assert inc.status == "open"
        assert inc.severity == "high"
        assert inc.event_count == 0
        assert len(inc.timeline) == 0

    def test_timeline_entry_creation(self):
        entry = IncidentTimelineEntry(
            event_id="ev-123",
            event_type="auth_failure",
            source="soc",
            severity="medium",
            description="Failed password for root",
            entity=Entity(ip="10.0.0.1", user="root"),
        )
        assert entry.entry_id is not None
        assert entry.event_id == "ev-123"
        assert entry.severity == "medium"


# ---------------------------------------------------------------------------
# Test Correlation Engine Logic
# ---------------------------------------------------------------------------


class TestCorrelationEngine:
    def test_create_incident_on_rule_match(self):
        engine = CorrelationEngine(correlation_window_seconds=300)
        ev = make_event(ip="198.51.100.10", user="attacker", severity="medium")
        rm = RuleMatch(
            rule_id="SOC-RULE-001",
            rule_title="SSH Brute Force",
            severity="high",
            matched_event_ids=[ev.event_id],
            entity=ev.entity,
            context={"mitre_attack": ["T1110"]},
        )

        inc = engine.process_event(ev, rule_matches=[rm])
        assert inc is not None
        assert inc.severity == "high"
        assert inc.primary_entity.ip == "198.51.100.10"
        assert inc.mitre_techniques == ["T1110"]
        assert len(inc.rule_matches) == 1
        assert len(inc.timeline) == 1
        assert inc.event_count == 1

    def test_correlate_subsequent_events_same_ip(self):
        engine = CorrelationEngine(correlation_window_seconds=300)
        now = datetime.datetime.now(datetime.timezone.utc)

        ev1 = make_event(
            ip="198.51.100.20",
            event_type="auth_failure",
            severity="medium",
            timestamp=now,
        )
        ev2 = make_event(
            ip="198.51.100.20",
            event_type="firewall_block",
            severity="medium",
            timestamp=now + datetime.timedelta(seconds=15),
        )

        inc1 = engine.process_event(ev1)
        assert inc1 is not None
        initial_id = inc1.incident_id

        inc2 = engine.process_event(ev2)
        assert inc2 is not None
        # Must be correlated into the same incident
        assert inc2.incident_id == initial_id
        assert inc2.event_count == 2
        assert len(inc2.timeline) == 2
        assert ev1.event_id in inc2.event_ids
        assert ev2.event_id in inc2.event_ids

    def test_cross_entity_correlation(self):
        """Test correlation linking IP -> User -> Host across multi-source events."""
        engine = CorrelationEngine(correlation_window_seconds=300)
        now = datetime.datetime.now(datetime.timezone.utc)

        # Event 1: Auth failure with IP and user
        ev1 = make_event(
            ip="10.10.10.50",
            user="jdoe",
            host=None,
            event_type="auth_failure",
            timestamp=now,
        )
        inc1 = engine.process_event(ev1)
        assert inc1 is not None

        # Event 2: Session opened with user and host (no IP recorded in log)
        ev2 = make_event(
            ip=None,
            user="jdoe",
            host="workstation-9",
            event_type="session_open",
            timestamp=now + datetime.timedelta(seconds=10),
        )
        inc2 = engine.process_event(ev2)
        assert inc2 is not None
        assert inc2.incident_id == inc1.incident_id
        assert inc2.primary_entity.ip == "10.10.10.50"
        assert inc2.primary_entity.user == "jdoe"
        assert inc2.primary_entity.host == "workstation-9"

    def test_multi_stage_attack_scenario(self):
        """
        Simulate a realistic 3-stage attack:
        1. Brute force attempts (T1110)
        2. Successful interactive logon
        3. Privilege escalation command execution (T1548.003)
        """
        engine = CorrelationEngine(correlation_window_seconds=300)
        now = datetime.datetime.now(datetime.timezone.utc)

        # Stage 1: Brute force
        ev1 = make_event(
            ip="203.0.113.88",
            user="root",
            event_type="auth_failure",
            severity="medium",
            timestamp=now,
        )
        rm1 = RuleMatch(
            rule_id="SOC-RULE-001",
            rule_title="SSH Brute Force",
            severity="high",
            matched_event_ids=[ev1.event_id],
            entity=ev1.entity,
            context={"mitre_attack": ["T1110"]},
        )
        inc = engine.process_event(ev1, rule_matches=[rm1])
        assert inc is not None
        assert inc.severity == "high"

        # Stage 2: Successful session
        ev2 = make_event(
            ip="203.0.113.88",
            user="root",
            event_type="session_open",
            severity="medium",
            timestamp=now + datetime.timedelta(seconds=30),
        )
        inc = engine.process_event(ev2)
        assert inc.event_count == 2

        # Stage 3: Privilege escalation
        ev3 = make_event(
            ip="203.0.113.88",
            user="root",
            event_type="privilege_escalation",
            severity="high",
            raw={"command": "sudo /bin/bash"},
            timestamp=now + datetime.timedelta(seconds=60),
        )
        rm3 = RuleMatch(
            rule_id="SOC-RULE-002",
            rule_title="Suspicious Sudo Command",
            severity="critical",
            matched_event_ids=[ev3.event_id],
            entity=ev3.entity,
            context={"mitre_attack": ["T1548.003"]},
        )
        inc = engine.process_event(ev3, rule_matches=[rm3])

        # Verify unified incident state
        assert inc.event_count == 3
        assert inc.severity == "critical"  # Escalated to critical
        assert "T1110" in inc.mitre_techniques
        assert "T1548.003" in inc.mitre_techniques
        assert len(inc.timeline) == 3
        # Timeline strictly ordered
        assert inc.timeline[0].event_type == "auth_failure"
        assert inc.timeline[1].event_type == "session_open"
        assert inc.timeline[2].event_type == "privilege_escalation"

    def test_correlation_window_expiration(self):
        engine = CorrelationEngine(correlation_window_seconds=60)
        base_time = datetime.datetime.now(datetime.timezone.utc)

        ev1 = make_event(
            ip="1.2.3.4",
            event_type="auth_failure",
            timestamp=base_time,
        )
        inc1 = engine.process_event(ev1)
        assert inc1 is not None

        # ev2 arrives 120 seconds later (past 60s window)
        ev2 = make_event(
            ip="1.2.3.4",
            event_type="auth_failure",
            timestamp=base_time + datetime.timedelta(seconds=120),
        )
        inc2 = engine.process_event(ev2)
        assert inc2 is not None
        # Should create a separate new incident due to window expiration
        assert inc2.incident_id != inc1.incident_id

    def test_close_incident_clears_mapping(self):
        engine = CorrelationEngine(correlation_window_seconds=300)
        ev1 = make_event(ip="5.5.5.5", event_type="auth_failure")
        inc1 = engine.process_event(ev1)
        assert inc1 is not None

        # Close the incident
        closed = engine.close_incident(inc1.incident_id)
        assert closed is True
        assert inc1.status == "closed"

        # Subsequent event on same IP should start a fresh incident
        ev2 = make_event(ip="5.5.5.5", event_type="auth_failure")
        inc2 = engine.process_event(ev2)
        assert inc2 is not None
        assert inc2.incident_id != inc1.incident_id
        assert inc2.status == "open"

    def test_unrelated_entities_isolation(self):
        engine = CorrelationEngine(correlation_window_seconds=300)
        ev_ip_a = make_event(ip="10.1.1.1", user="user_a", host="host_a", event_type="auth_failure")
        ev_ip_b = make_event(ip="10.2.2.2", user="user_b", host="host_b", event_type="auth_failure")

        inc_a = engine.process_event(ev_ip_a)
        inc_b = engine.process_event(ev_ip_b)

        assert inc_a is not None
        assert inc_b is not None
        assert inc_a.incident_id != inc_b.incident_id
        assert len(engine.active_incidents) == 2
