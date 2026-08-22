"""
Unit tests for the SOC Risk Scoring Calculator.

Every test verifies both the numeric score *and* the human-readable breakdown,
because explainability is a first-class requirement (see ARCHITECTURE.md §4.1,
SOC SKILL.md).
"""

from __future__ import annotations

import datetime

import pytest

from src.shared.event_schema import Entity, SecurityEvent
from src.soc.correlation.engine import CorrelationEngine
from src.soc.correlation.incident_model import Incident, IncidentTimelineEntry
from src.soc.detection.rule_model import RuleMatch
from src.soc.scoring.calculator import (
    CRITICAL_HOST_BONUS,
    CRITICAL_USER_BONUS,
    FREQUENCY_CAP,
    FREQUENCY_MULTIPLIER,
    MAX_SCORE,
    MITRE_TECHNIQUE_BONUS,
    MITRE_TECHNIQUE_CAP,
    MULTI_SOURCE_BONUS,
    SEVERITY_BASE_SCORES,
    THREAT_INTEL_BONUS,
    ScoreBreakdown,
    score_incident,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime.datetime.now(datetime.timezone.utc)


def _make_incident(
    severity: str = "medium",
    event_count: int = 1,
    user: str | None = "analyst",
    host: str | None = "workstation-7",
    mitre_techniques: list[str] | None = None,
    rule_matches: list[RuleMatch] | None = None,
    timeline_sources: list[str] | None = None,
) -> Incident:
    """Build a minimal Incident for testing with controllable parameters."""
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
        title="Test Incident",
        severity=severity,
        event_count=event_count,
        primary_entity=Entity(ip="10.0.0.1", user=user, host=host),
        mitre_techniques=mitre_techniques or [],
        rule_matches=rule_matches or [],
        timeline=timeline,
    )


# ---------------------------------------------------------------------------
# Test Base Severity Scores
# ---------------------------------------------------------------------------


class TestBaseSeverity:
    def test_low_severity(self):
        inc = _make_incident(severity="low")
        score, bd = score_incident(inc)
        assert bd.base_severity == SEVERITY_BASE_SCORES["low"]
        assert bd.base_severity_label == "low"
        assert score == bd.final_score

    def test_medium_severity(self):
        inc = _make_incident(severity="medium")
        score, bd = score_incident(inc)
        assert bd.base_severity == SEVERITY_BASE_SCORES["medium"]

    def test_high_severity(self):
        inc = _make_incident(severity="high")
        score, bd = score_incident(inc)
        assert bd.base_severity == SEVERITY_BASE_SCORES["high"]

    def test_critical_severity(self):
        inc = _make_incident(severity="critical")
        score, bd = score_incident(inc)
        assert bd.base_severity == SEVERITY_BASE_SCORES["critical"]


# ---------------------------------------------------------------------------
# Test Frequency Bonus
# ---------------------------------------------------------------------------


class TestFrequencyBonus:
    def test_single_event_no_bonus(self):
        inc = _make_incident(event_count=1)
        _, bd = score_incident(inc)
        assert bd.frequency_bonus == 0.0

    def test_multiple_events_get_bonus(self):
        inc = _make_incident(event_count=8)
        _, bd = score_incident(inc)
        # log2(8) = 3.0, * 2.5 = 7.5
        assert bd.frequency_bonus == pytest.approx(7.5, abs=0.1)

    def test_frequency_is_capped(self):
        inc = _make_incident(event_count=100_000)
        _, bd = score_incident(inc)
        assert bd.frequency_bonus <= FREQUENCY_CAP


# ---------------------------------------------------------------------------
# Test MITRE Technique Bonus
# ---------------------------------------------------------------------------


class TestMitreBonus:
    def test_no_techniques_no_bonus(self):
        inc = _make_incident(mitre_techniques=[])
        _, bd = score_incident(inc)
        assert bd.mitre_bonus == 0.0

    def test_single_technique(self):
        inc = _make_incident(mitre_techniques=["T1110"])
        _, bd = score_incident(inc)
        assert bd.mitre_bonus == MITRE_TECHNIQUE_BONUS

    def test_multiple_techniques(self):
        inc = _make_incident(mitre_techniques=["T1110", "T1548.003", "T1078"])
        _, bd = score_incident(inc)
        assert bd.mitre_bonus == 3 * MITRE_TECHNIQUE_BONUS

    def test_mitre_bonus_is_capped(self):
        many_techs = [f"T{i}" for i in range(1000, 1020)]
        inc = _make_incident(mitre_techniques=many_techs)
        _, bd = score_incident(inc)
        assert bd.mitre_bonus <= MITRE_TECHNIQUE_CAP


# ---------------------------------------------------------------------------
# Test Critical User Bonus
# ---------------------------------------------------------------------------


class TestCriticalUserBonus:
    def test_root_user_gets_bonus(self):
        inc = _make_incident(user="root")
        _, bd = score_incident(inc)
        assert bd.critical_user_bonus == CRITICAL_USER_BONUS
        assert bd.critical_user == "root"

    def test_admin_user_gets_bonus(self):
        inc = _make_incident(user="Administrator")
        _, bd = score_incident(inc)
        assert bd.critical_user_bonus == CRITICAL_USER_BONUS

    def test_normal_user_no_bonus(self):
        inc = _make_incident(user="jdoe")
        _, bd = score_incident(inc)
        assert bd.critical_user_bonus == 0.0
        assert bd.critical_user == ""


# ---------------------------------------------------------------------------
# Test Critical Host Bonus
# ---------------------------------------------------------------------------


class TestCriticalHostBonus:
    def test_domain_controller_gets_bonus(self):
        inc = _make_incident(host="dc-primary-01")
        _, bd = score_incident(inc)
        assert bd.critical_host_bonus == CRITICAL_HOST_BONUS
        assert bd.critical_host == "dc-primary-01"

    def test_production_server_gets_bonus(self):
        inc = _make_incident(host="prod-api-server")
        _, bd = score_incident(inc)
        assert bd.critical_host_bonus == CRITICAL_HOST_BONUS

    def test_workstation_no_bonus(self):
        inc = _make_incident(host="workstation-7")
        _, bd = score_incident(inc)
        assert bd.critical_host_bonus == 0.0


# ---------------------------------------------------------------------------
# Test Threat Intel Bonus
# ---------------------------------------------------------------------------


class TestThreatIntelBonus:
    def test_no_threat_intel_no_bonus(self):
        inc = _make_incident()
        _, bd = score_incident(inc)
        assert bd.threat_intel_bonus == 0.0

    def test_threat_intel_match_gets_bonus(self):
        rm = RuleMatch(
            rule_id="R1",
            rule_title="Test",
            severity="high",
            context={"threat_intel_match": True},
        )
        inc = _make_incident(rule_matches=[rm])
        _, bd = score_incident(inc)
        assert bd.threat_intel_bonus == THREAT_INTEL_BONUS


# ---------------------------------------------------------------------------
# Test Multi-Source Correlation Bonus
# ---------------------------------------------------------------------------


class TestMultiSourceBonus:
    def test_single_source_no_bonus(self):
        inc = _make_incident(timeline_sources=["soc"])
        _, bd = score_incident(inc)
        assert bd.multi_source_bonus == 0.0

    def test_two_sources_get_bonus(self):
        inc = _make_incident(timeline_sources=["soc", "honeypot"])
        _, bd = score_incident(inc)
        assert bd.multi_source_bonus == MULTI_SOURCE_BONUS
        assert sorted(bd.sources_seen) == ["honeypot", "soc"]


# ---------------------------------------------------------------------------
# Test Score Clamping & Explainability
# ---------------------------------------------------------------------------


class TestScoreBoundaries:
    def test_score_never_exceeds_100(self):
        """Worst-case scenario: every bonus maxed out."""
        rm = RuleMatch(
            rule_id="R1",
            rule_title="Test",
            severity="critical",
            context={"threat_intel_match": True, "mitre_attack": ["T1110"]},
        )
        inc = _make_incident(
            severity="critical",
            event_count=100_000,
            user="root",
            host="dc-primary-01",
            mitre_techniques=[f"T{i}" for i in range(1000, 1020)],
            rule_matches=[rm],
            timeline_sources=["soc", "honeypot", "phishing"],
        )
        score, bd = score_incident(inc)
        assert score <= MAX_SCORE
        assert bd.final_score <= MAX_SCORE

    def test_minimum_score_is_base_severity(self):
        inc = _make_incident(severity="low", event_count=1)
        score, _ = score_incident(inc)
        assert score == SEVERITY_BASE_SCORES["low"]


class TestExplainability:
    def test_breakdown_to_dict_contains_all_components(self):
        inc = _make_incident(
            severity="high",
            event_count=4,
            user="root",
            mitre_techniques=["T1110"],
        )
        _, bd = score_incident(inc)
        d = bd.to_dict()
        assert "base_severity" in d
        assert "frequency" in d
        assert "mitre_techniques" in d
        assert "critical_user" in d
        assert "critical_host" in d
        assert "threat_intel" in d
        assert "multi_source" in d
        assert "final_score" in d

    def test_explain_returns_readable_string(self):
        inc = _make_incident(
            severity="high",
            event_count=4,
            user="root",
            mitre_techniques=["T1110", "T1548.003"],
        )
        _, bd = score_incident(inc)
        explanation = bd.explain()
        assert "Base severity (high)" in explanation
        assert "Critical user 'root'" in explanation
        assert "MITRE techniques" in explanation
        assert "Final score" in explanation

    def test_score_applied_to_incident(self):
        """Verify score_incident result can be stored back on the Incident."""
        inc = _make_incident(severity="high", event_count=10, user="admin")
        score, bd = score_incident(inc)
        inc.risk_score = score
        assert inc.risk_score == score
        assert 0.0 <= inc.risk_score <= 100.0


# ---------------------------------------------------------------------------
# Integration: Correlation Engine → Risk Scoring
# ---------------------------------------------------------------------------


class TestCorrelationToScoring:
    def test_multi_stage_attack_scored_high(self):
        """
        Simulate a 3-stage attack through the correlation engine, then score it.
        Expected: high score due to critical severity, multiple MITRE techniques,
        critical user (root), and high event count.
        """
        engine = CorrelationEngine(correlation_window_seconds=300)
        now = datetime.datetime.now(datetime.timezone.utc)

        # Stage 1: Brute force
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

        # Stage 2: Successful login
        ev2 = SecurityEvent(
            event_type="session_open",
            source="soc",
            severity="medium",
            timestamp=now + datetime.timedelta(seconds=30),
            entity=Entity(ip="203.0.113.88", user="root", host="prod-web-01"),
        )
        inc = engine.process_event(ev2)

        # Stage 3: Privilege escalation
        ev3 = SecurityEvent(
            event_type="privilege_escalation",
            source="soc",
            severity="high",
            timestamp=now + datetime.timedelta(seconds=60),
            entity=Entity(ip="203.0.113.88", user="root", host="prod-web-01"),
            raw={"command": "sudo /bin/bash"},
        )
        rm3 = RuleMatch(
            rule_id="SOC-RULE-002",
            rule_title="Sudo Escalation",
            severity="critical",
            matched_event_ids=[ev3.event_id],
            entity=ev3.entity,
            tags=["attack.t1548.003"],
            context={"mitre_attack": ["T1548.003"]},
        )
        inc = engine.process_event(ev3, rule_matches=[rm3])

        # Now score the correlated incident
        score, bd = score_incident(inc)

        # Verify high score components
        assert bd.base_severity == SEVERITY_BASE_SCORES["critical"]
        assert bd.critical_user_bonus == CRITICAL_USER_BONUS
        assert bd.critical_host_bonus == CRITICAL_HOST_BONUS  # "prod-web-01" matches "prod"
        assert bd.mitre_bonus > 0  # T1110 + T1548.003
        assert bd.frequency_bonus > 0  # 3 events
        assert score >= 80.0  # Multi-stage attack on critical user/host should be 80+
        assert score <= 100.0

        # Verify explainability
        explanation = bd.explain()
        assert "root" in explanation
        assert "Final score" in explanation
