"""
Unit tests for the SOC Alert Manager.

Covers: alert model, priority mapping, deduplication, score thresholding,
incident-to-alert conversion, callback dispatch, and the full end-to-end
pipeline (correlation → scoring → alerting).
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest

from src.shared.event_schema import Entity, SecurityEvent
from src.soc.alerting.alert_model import Alert, AlertPriority, priority_from_score
from src.soc.alerting.manager import AlertManager
from src.soc.correlation.engine import CorrelationEngine
from src.soc.correlation.incident_model import Incident, IncidentTimelineEntry
from src.soc.detection.rule_model import RuleMatch
from src.soc.scoring.calculator import SEVERITY_BASE_SCORES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime.datetime.now(datetime.timezone.utc)


def _make_incident(
    severity: str = "high",
    event_count: int = 5,
    user: str = "root",
    host: str = "prod-api",
    mitre_techniques: list[str] | None = None,
    rule_matches: list[RuleMatch] | None = None,
    timeline_sources: list[str] | None = None,
) -> Incident:
    """Build a test Incident with sensible defaults for scoring above threshold."""
    timeline = []
    for i, src in enumerate(timeline_sources or ["soc"]):
        timeline.append(
            IncidentTimelineEntry(
                timestamp=NOW + datetime.timedelta(seconds=i),
                event_id=f"ev-{i}",
                event_type="auth_failure",
                source=src,
                severity=severity,
                description=f"Test event {i}",
                entity=Entity(ip="10.0.0.1", user=user, host=host),
            )
        )

    return Incident(
        title="Test Attack Detected",
        severity=severity,
        event_count=event_count,
        primary_entity=Entity(ip="10.0.0.1", user=user, host=host),
        mitre_techniques=mitre_techniques or ["T1110"],
        rule_matches=rule_matches or [],
        timeline=timeline,
    )


# ---------------------------------------------------------------------------
# Test Alert Model
# ---------------------------------------------------------------------------


class TestAlertModel:
    def test_alert_creation(self):
        alert = Alert(
            title="Test Alert",
            incident_id="inc-001",
        )
        assert alert.status == "new"
        assert alert.priority == "P3-medium"
        assert alert.alert_id  # UUID auto-generated

    def test_alert_serialisation_round_trip(self):
        alert = Alert(
            title="SSH Brute Force",
            incident_id="inc-001",
            risk_score=85.0,
            priority="P1-critical",
        )
        stream_dict = alert.to_stream_dict()
        assert "data" in stream_dict

        restored = Alert.from_stream_dict(stream_dict)
        assert restored.alert_id == alert.alert_id
        assert restored.risk_score == 85.0
        assert restored.priority == "P1-critical"


# ---------------------------------------------------------------------------
# Test Priority Mapping
# ---------------------------------------------------------------------------


class TestPriorityMapping:
    def test_p1_critical(self):
        assert priority_from_score(80.0) == "P1-critical"
        assert priority_from_score(100.0) == "P1-critical"

    def test_p2_high(self):
        assert priority_from_score(50.0) == "P2-high"
        assert priority_from_score(79.9) == "P2-high"

    def test_p3_medium(self):
        assert priority_from_score(25.0) == "P3-medium"
        assert priority_from_score(49.9) == "P3-medium"

    def test_p4_low(self):
        assert priority_from_score(0.0) == "P4-low"
        assert priority_from_score(24.9) == "P4-low"


# ---------------------------------------------------------------------------
# Test Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_same_incident_produces_one_alert(self):
        """Two process_incident calls for the same incident should NOT create two alerts."""
        mgr = AlertManager()
        incident = _make_incident()

        alert1 = mgr.process_incident(incident)
        alert2 = mgr.process_incident(incident)

        assert alert1 is not None
        assert alert2 is not None
        assert alert1.alert_id == alert2.alert_id  # Same alert, updated
        assert mgr.alert_count == 1

    def test_different_incidents_produce_separate_alerts(self):
        mgr = AlertManager()
        inc1 = _make_incident()
        inc2 = _make_incident()
        # They have different auto-generated incident_ids

        a1 = mgr.process_incident(inc1)
        a2 = mgr.process_incident(inc2)

        assert a1 is not None
        assert a2 is not None
        assert a1.alert_id != a2.alert_id
        assert mgr.alert_count == 2

    def test_dedup_updates_event_count_and_score(self):
        mgr = AlertManager()
        incident = _make_incident(event_count=3)
        alert1 = mgr.process_incident(incident)

        # Simulate more events correlated into the same incident
        incident.event_count = 10
        alert2 = mgr.process_incident(incident)

        assert alert2.event_count == 10
        assert alert2.risk_score >= alert1.risk_score  # More events → higher score


# ---------------------------------------------------------------------------
# Test Score Threshold
# ---------------------------------------------------------------------------


class TestScoreThreshold:
    def test_below_threshold_produces_no_alert(self):
        """Low-severity, single-event, non-critical entity → no alert."""
        mgr = AlertManager(min_score_to_alert=15.0)
        incident = _make_incident(
            severity="low",
            event_count=1,
            user="jdoe",
            host="workstation-3",
            mitre_techniques=[],
        )
        result = mgr.process_incident(incident)
        assert result is None
        assert mgr.alert_count == 0

    def test_above_threshold_produces_alert(self):
        mgr = AlertManager(min_score_to_alert=15.0)
        incident = _make_incident(severity="high")
        result = mgr.process_incident(incident)
        assert result is not None
        assert mgr.alert_count == 1

    def test_custom_threshold(self):
        mgr = AlertManager(min_score_to_alert=90.0)
        # Medium severity on a normal workstation → probably won't score 90
        incident = _make_incident(
            severity="medium",
            event_count=2,
            user="analyst",
            host="workstation-7",
            mitre_techniques=[],
        )
        result = mgr.process_incident(incident)
        assert result is None


# ---------------------------------------------------------------------------
# Test Callback Dispatch
# ---------------------------------------------------------------------------


class TestCallbackDispatch:
    def test_on_alert_callback_fires_on_new(self):
        received: list[tuple[Alert, bool]] = []

        def callback(alert: Alert, is_new: bool) -> None:
            received.append((alert, is_new))

        mgr = AlertManager(on_alert=callback)
        incident = _make_incident()
        mgr.process_incident(incident)

        assert len(received) == 1
        assert received[0][1] is True  # is_new

    def test_on_alert_callback_fires_on_update(self):
        received: list[tuple[Alert, bool]] = []

        def callback(alert: Alert, is_new: bool) -> None:
            received.append((alert, is_new))

        mgr = AlertManager(on_alert=callback)
        incident = _make_incident()
        mgr.process_incident(incident)
        mgr.process_incident(incident)

        assert len(received) == 2
        assert received[0][1] is True   # first call → new
        assert received[1][1] is False  # second call → update

    def test_no_callback_when_below_threshold(self):
        received: list[tuple[Alert, bool]] = []

        def callback(alert: Alert, is_new: bool) -> None:
            received.append((alert, is_new))

        mgr = AlertManager(on_alert=callback, min_score_to_alert=99.0)
        incident = _make_incident(
            severity="low",
            event_count=1,
            user="jdoe",
            host="workstation-3",
            mitre_techniques=[],
        )
        mgr.process_incident(incident)
        assert len(received) == 0


# ---------------------------------------------------------------------------
# Test Alert Retrieval
# ---------------------------------------------------------------------------


class TestAlertRetrieval:
    def test_get_alert_by_id(self):
        mgr = AlertManager()
        alert = mgr.process_incident(_make_incident())
        assert alert is not None
        found = mgr.get_alert(alert.alert_id)
        assert found is alert

    def test_get_alert_for_incident(self):
        mgr = AlertManager()
        incident = _make_incident()
        alert = mgr.process_incident(incident)
        assert alert is not None
        found = mgr.get_alert_for_incident(incident.incident_id)
        assert found is alert

    def test_get_all_alerts_sorted(self):
        mgr = AlertManager()
        low = _make_incident(severity="medium", event_count=1, user="jdoe",
                             host="workstation", mitre_techniques=["T1110"])
        high = _make_incident(severity="critical", event_count=20, user="root",
                              host="dc-primary", mitre_techniques=["T1110", "T1548.003"])

        mgr.process_incident(low)
        mgr.process_incident(high)

        alerts = mgr.get_all_alerts(sort_by_score=True)
        assert len(alerts) == 2
        assert alerts[0].risk_score >= alerts[1].risk_score

    def test_get_alerts_by_priority(self):
        mgr = AlertManager()
        incident = _make_incident(severity="critical", event_count=50, user="root",
                                  host="dc-primary",
                                  mitre_techniques=["T1110", "T1548.003", "T1078"])
        mgr.process_incident(incident)

        p1_alerts = mgr.get_alerts_by_priority("P1-critical")
        assert len(p1_alerts) >= 1

    def test_stats(self):
        mgr = AlertManager()
        mgr.process_incident(_make_incident())
        stats = mgr.stats
        assert stats["total_alerts"] == 1
        assert sum(stats["by_priority"].values()) == 1


# ---------------------------------------------------------------------------
# Test Alert Content
# ---------------------------------------------------------------------------


class TestAlertContent:
    def test_alert_carries_provenance(self):
        rm = RuleMatch(
            rule_id="SOC-RULE-001",
            rule_title="SSH Brute Force",
            severity="high",
        )
        incident = _make_incident(rule_matches=[rm])
        mgr = AlertManager()
        alert = mgr.process_incident(incident)

        assert alert is not None
        assert alert.incident_id == incident.incident_id
        assert "SOC-RULE-001" in alert.rule_ids
        assert alert.primary_entity.user == "root"
        assert alert.mitre_techniques == ["T1110"]

    def test_alert_description_is_meaningful(self):
        mgr = AlertManager()
        alert = mgr.process_incident(_make_incident())
        assert alert is not None
        assert "root" in alert.description  # mentions critical user
        assert "Score:" in alert.description  # includes score explanation

    def test_score_breakdown_in_alert(self):
        mgr = AlertManager()
        alert = mgr.process_incident(_make_incident())
        assert alert is not None
        bd = alert.score_breakdown
        assert "base_severity" in bd
        assert "final_score" in bd


# ---------------------------------------------------------------------------
# Full Pipeline: Correlation → Scoring → Alerting
# ---------------------------------------------------------------------------


class TestFullPipeline:
    def test_end_to_end_multi_stage_attack(self):
        """
        Full integration: events → correlation engine → alert manager →
        deduplicated scored alert with correct priority.
        """
        # Track published alerts
        published: list[tuple[Alert, bool]] = []

        def on_alert(alert: Alert, is_new: bool) -> None:
            published.append((alert, is_new))

        engine = CorrelationEngine(correlation_window_seconds=300)
        mgr = AlertManager(on_alert=on_alert)
        now = datetime.datetime.now(datetime.timezone.utc)

        # Stage 1: SSH brute force
        ev1 = SecurityEvent(
            event_type="auth_failure",
            source="soc",
            severity="medium",
            timestamp=now,
            entity=Entity(ip="203.0.113.88", user="root", host="prod-web-01"),
        )
        rm1 = RuleMatch(
            rule_id="SOC-RULE-001",
            rule_title="SSH Brute Force",
            severity="high",
            matched_event_ids=[ev1.event_id],
            entity=ev1.entity,
            tags=["attack.t1110"],
            context={"mitre_attack": ["T1110"]},
        )
        inc = engine.process_event(ev1, rule_matches=[rm1])
        alert = mgr.process_incident(inc)
        assert alert is not None

        first_alert_id = alert.alert_id
        first_score = alert.risk_score

        # Stage 2: Privilege escalation
        ev2 = SecurityEvent(
            event_type="privilege_escalation",
            source="soc",
            severity="high",
            timestamp=now + datetime.timedelta(seconds=30),
            entity=Entity(ip="203.0.113.88", user="root", host="prod-web-01"),
            raw={"command": "sudo /bin/bash"},
        )
        rm2 = RuleMatch(
            rule_id="SOC-RULE-002",
            rule_title="Sudo Escalation",
            severity="critical",
            matched_event_ids=[ev2.event_id],
            entity=ev2.entity,
            tags=["attack.t1548.003"],
            context={"mitre_attack": ["T1548.003"]},
        )
        inc = engine.process_event(ev2, rule_matches=[rm2])
        alert = mgr.process_incident(inc)

        # Assertions
        # 1. Same alert (dedup): incident is the same
        assert alert.alert_id == first_alert_id
        assert mgr.alert_count == 1

        # 2. Score increased (more events, more MITRE techniques, escalated severity)
        assert alert.risk_score >= first_score

        # 3. Priority should be high or critical
        assert alert.priority in ("P1-critical", "P2-high")

        # 4. Both rules present
        assert "SOC-RULE-001" in alert.rule_ids
        assert "SOC-RULE-002" in alert.rule_ids

        # 5. Callback fired twice (create + update)
        assert len(published) == 2
        assert published[0][1] is True   # first = new
        assert published[1][1] is False  # second = update

        # 6. Alert carries full score breakdown for analyst transparency
        assert "base_severity" in alert.score_breakdown
        assert alert.score_breakdown["final_score"] == alert.risk_score
