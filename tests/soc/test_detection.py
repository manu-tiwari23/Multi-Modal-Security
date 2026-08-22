"""
Unit tests for the SOC Rule-Based Detection Engine, Rule Loader, and Stream Matcher.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import pytest

from src.shared.event_schema import Entity, SecurityEvent
from src.soc.detection.matcher import DetectionEngine, ThresholdStateTracker, _get_nested_field
from src.soc.detection.rule_loader import RuleLoader, _extract_mitre_techniques
from src.soc.detection.rule_model import (
    DetectionCondition,
    DetectionRule,
    RuleMatch,
    ThresholdConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event(
    event_type: str = "auth_failure",
    severity: str = "medium",
    source: str = "soc",
    ip: str = "192.168.1.100",
    user: str = "admin",
    host: str = "server01",
    raw: dict[str, Any] | None = None,
    enrichment: dict[str, Any] | None = None,
    timestamp: datetime.datetime | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        source=source,
        timestamp=timestamp or datetime.datetime.now(datetime.timezone.utc),
        entity=Entity(ip=ip, user=user, host=host),
        raw=raw or {},
        enrichment=enrichment or {},
    )


# ---------------------------------------------------------------------------
# Test Rule Model Validation
# ---------------------------------------------------------------------------


class TestRuleModel:
    def test_valid_rule_creation(self):
        rule = DetectionRule(
            id="TEST-001",
            title="Test Rule",
            description="A test detection rule",
            severity="high",
            tags=["attack.t1110"],
            detection=DetectionCondition(
                selection={"event_type": "auth_failure"},
            ),
        )
        assert rule.id == "TEST-001"
        assert rule.severity == "high"
        assert rule.status == "stable"
        assert rule.detection.selection == {"event_type": "auth_failure"}

    def test_threshold_config_validation(self):
        rule = DetectionRule(
            id="TEST-002",
            title="Threshold Rule",
            severity="critical",
            detection=DetectionCondition(
                selection={"event_type": "auth_failure"},
                threshold=ThresholdConfig(count=5, timeframe=60, by=["entity.ip"]),
            ),
        )
        assert rule.detection.threshold is not None
        assert rule.detection.threshold.count == 5
        assert rule.detection.threshold.timeframe == 60
        assert rule.detection.threshold.by == ["entity.ip"]

    def test_invalid_severity_raises(self):
        with pytest.raises(Exception):
            DetectionRule(
                id="TEST-003",
                title="Bad Rule",
                severity="unknown_severity",  # type: ignore
                detection=DetectionCondition(selection={}),
            )


# ---------------------------------------------------------------------------
# Test MITRE Extraction & Rule Loader
# ---------------------------------------------------------------------------


class TestRuleLoader:
    def test_extract_mitre_techniques(self):
        tags = ["attack.t1110", "attack.1548.003", "platform.linux", "service.ssh", "attack.t1078"]
        techniques = _extract_mitre_techniques(tags)
        assert techniques == ["T1078", "T1110", "T1548.003"]

    def test_load_default_rule_pack(self):
        rules_dir = Path(__file__).parents[2] / "src" / "soc" / "rules"
        loader = RuleLoader(rules_dir)
        rules = loader.load_from_directory()

        assert len(rules) >= 5
        rule_ids = {r.id for r in rules}
        assert "SOC-RULE-001" in rule_ids
        assert "SOC-RULE-002" in rule_ids
        assert "SOC-RULE-003" in rule_ids
        assert "SOC-RULE-004" in rule_ids
        assert "SOC-RULE-005" in rule_ids
        assert len(loader.load_errors) == 0

    def test_load_nonexistent_file(self, tmp_path):
        loader = RuleLoader()
        rule = loader.load_from_file(tmp_path / "nonexistent.yml")
        assert rule is None
        assert len(loader.load_errors) == 1

    def test_load_invalid_yaml(self, tmp_path):
        bad_yaml = tmp_path / "bad.yml"
        bad_yaml.write_text("id: [unclosed list", encoding="utf-8")

        loader = RuleLoader()
        rule = loader.load_from_file(bad_yaml)
        assert rule is None
        assert len(loader.load_errors) == 1

    def test_load_non_dict_yaml(self, tmp_path):
        bad_yaml = tmp_path / "not_dict.yml"
        bad_yaml.write_text("- item 1\n- item 2", encoding="utf-8")

        loader = RuleLoader()
        rule = loader.load_from_file(bad_yaml)
        assert rule is None
        assert len(loader.load_errors) == 1


# ---------------------------------------------------------------------------
# Test Field Extraction & Modifiers
# ---------------------------------------------------------------------------


class TestFieldMatching:
    def test_get_nested_field(self):
        ev = make_event(
            ip="10.0.0.5",
            user="alice",
            raw={"command": "sudo su", "network": {"dst_port": 80}},
        )
        assert _get_nested_field(ev, "event_type") == "auth_failure"
        assert _get_nested_field(ev, "entity.ip") == "10.0.0.5"
        assert _get_nested_field(ev, "entity.user") == "alice"
        assert _get_nested_field(ev, "raw.command") == "sudo su"
        assert _get_nested_field(ev, "raw.network.dst_port") == 80
        assert _get_nested_field(ev, "nonexistent.field") is None

    def test_single_event_exact_match(self):
        rule = DetectionRule(
            id="R1",
            title="Exact Match Rule",
            severity="high",
            detection=DetectionCondition(
                selection={"event_type": "auth_failure", "entity.user": "root"}
            ),
        )
        engine = DetectionEngine([rule])

        ev_match = make_event(event_type="auth_failure", user="root")
        ev_nomatch = make_event(event_type="auth_failure", user="bob")

        assert len(engine.evaluate(ev_match)) == 1
        assert len(engine.evaluate(ev_nomatch)) == 0

    def test_contains_modifier(self):
        rule = DetectionRule(
            id="R-CONTAINS",
            title="Contains Rule",
            severity="high",
            detection=DetectionCondition(
                selection={"raw.command|contains": ["/bin/bash", "visudo"]}
            ),
        )
        engine = DetectionEngine([rule])

        ev1 = make_event(raw={"command": "sudo /bin/bash -c whoami"})
        ev2 = make_event(raw={"command": "sudo vi /etc/hosts"})

        assert len(engine.evaluate(ev1)) == 1
        assert len(engine.evaluate(ev2)) == 0

    def test_regex_modifier(self):
        rule = DetectionRule(
            id="R-REGEX",
            title="Regex Rule",
            severity="medium",
            detection=DetectionCondition(
                selection={"entity.ip|re": r"^10\.0\.\d+\.1$"}
            ),
        )
        engine = DetectionEngine([rule])

        ev_match = make_event(ip="10.0.5.1")
        ev_nomatch = make_event(ip="10.0.5.2")

        assert len(engine.evaluate(ev_match)) == 1
        assert len(engine.evaluate(ev_nomatch)) == 0

    def test_startswith_and_endswith_modifiers(self):
        rule = DetectionRule(
            id="R-PREFIX-SUFFIX",
            title="Prefix Suffix",
            severity="low",
            detection=DetectionCondition(
                selection={
                    "raw.path|startswith": "/var/log",
                    "raw.filename|endswith": ".pcap",
                }
            ),
        )
        engine = DetectionEngine([rule])

        ev1 = make_event(raw={"path": "/var/log/traffic", "filename": "dump.pcap"})
        ev2 = make_event(raw={"path": "/tmp/traffic", "filename": "dump.pcap"})
        ev3 = make_event(raw={"path": "/var/log/traffic", "filename": "dump.txt"})

        assert len(engine.evaluate(ev1)) == 1
        assert len(engine.evaluate(ev2)) == 0
        assert len(engine.evaluate(ev3)) == 0

    def test_filter_exclusion(self):
        rule = DetectionRule(
            id="R-FILTER",
            title="Rule with Filter",
            severity="medium",
            detection=DetectionCondition(
                selection={"event_type": "session_open", "entity.user": "root"},
                filter={"raw.service": "cron"},
            ),
        )
        engine = DetectionEngine([rule])

        ev_ssh_root = make_event(
            event_type="session_open", user="root", raw={"service": "sshd"}
        )
        ev_cron_root = make_event(
            event_type="session_open", user="root", raw={"service": "cron"}
        )

        assert len(engine.evaluate(ev_ssh_root)) == 1
        assert len(engine.evaluate(ev_cron_root)) == 0


# ---------------------------------------------------------------------------
# Test Threshold & Sliding Window Aggregation
# ---------------------------------------------------------------------------


class TestThresholdAggregation:
    def test_threshold_triggers_after_n_events(self):
        rule = DetectionRule(
            id="R-THRESH",
            title="Brute Force 3 Attempts",
            severity="high",
            tags=["attack.t1110"],
            detection=DetectionCondition(
                selection={"event_type": "auth_failure"},
                threshold=ThresholdConfig(count=3, timeframe=60, by=["entity.ip"]),
            ),
        )
        engine = DetectionEngine([rule])
        now = datetime.datetime.now(datetime.timezone.utc)

        ev1 = make_event(ip="192.168.1.50", timestamp=now)
        ev2 = make_event(ip="192.168.1.50", timestamp=now + datetime.timedelta(seconds=5))
        ev3 = make_event(ip="192.168.1.50", timestamp=now + datetime.timedelta(seconds=10))

        # First two events should not trigger
        assert len(engine.evaluate(ev1)) == 0
        assert len(engine.evaluate(ev2)) == 0

        # Third event reaches threshold -> triggers 1 match
        matches = engine.evaluate(ev3)
        assert len(matches) == 1
        match = matches[0]
        assert match.rule_id == "R-THRESH"
        assert match.severity == "high"
        assert len(match.matched_event_ids) == 3
        assert ev1.event_id in match.matched_event_ids
        assert ev2.event_id in match.matched_event_ids
        assert ev3.event_id in match.matched_event_ids

    def test_threshold_per_ip_isolation(self):
        rule = DetectionRule(
            id="R-THRESH-ISO",
            title="Brute Force per IP",
            severity="high",
            detection=DetectionCondition(
                selection={"event_type": "auth_failure"},
                threshold=ThresholdConfig(count=2, timeframe=60, by=["entity.ip"]),
            ),
        )
        engine = DetectionEngine([rule])

        ev_ip1_a = make_event(ip="10.0.0.1")
        ev_ip2_a = make_event(ip="10.0.0.2")
        ev_ip1_b = make_event(ip="10.0.0.1")

        assert len(engine.evaluate(ev_ip1_a)) == 0
        assert len(engine.evaluate(ev_ip2_a)) == 0
        
        # IP1 hits 2 events -> triggers
        matches_ip1 = engine.evaluate(ev_ip1_b)
        assert len(matches_ip1) == 1
        assert matches_ip1[0].entity.ip == "10.0.0.1"

    def test_threshold_window_expiration(self):
        rule = DetectionRule(
            id="R-THRESH-EXP",
            title="Window Expiration Test",
            severity="high",
            detection=DetectionCondition(
                selection={"event_type": "auth_failure"},
                threshold=ThresholdConfig(count=2, timeframe=10, by=["entity.ip"]),
            ),
        )
        engine = DetectionEngine([rule])
        base_time = datetime.datetime.now(datetime.timezone.utc)

        ev1 = make_event(ip="1.1.1.1", timestamp=base_time)
        # ev2 arrives 20 seconds later (past the 10s timeframe)
        ev2 = make_event(ip="1.1.1.1", timestamp=base_time + datetime.timedelta(seconds=20))

        assert len(engine.evaluate(ev1)) == 0
        # Should not trigger because ev1 has expired out of the 10s sliding window
        assert len(engine.evaluate(ev2)) == 0


# ---------------------------------------------------------------------------
# Test Default Rules with Realistic Events
# ---------------------------------------------------------------------------


class TestDefaultRulesPack:
    @pytest.fixture(autouse=True)
    def setup_engine(self):
        rules_dir = Path(__file__).parents[2] / "src" / "soc" / "rules"
        loader = RuleLoader(rules_dir)
        rules = loader.load_from_directory()
        self.engine = DetectionEngine(rules)

    def test_rule_002_sudo_escalation(self):
        ev = make_event(
            event_type="privilege_escalation",
            severity="high",
            user="attacker",
            raw={"command": "sudo /bin/bash", "action": "sudo_exec"},
        )
        matches = self.engine.evaluate(ev)
        assert len(matches) == 1
        assert matches[0].rule_id == "SOC-RULE-002"
        assert "T1548.003" in matches[0].context.get("mitre_attack", [])

    def test_rule_004_invalid_user_ssh(self):
        ev = make_event(
            event_type="auth_failure",
            severity="medium",
            user="guest99",
            raw={"action": "invalid_user", "service": "sshd"},
        )
        matches = self.engine.evaluate(ev)
        assert len(matches) == 1
        assert matches[0].rule_id == "SOC-RULE-004"
        assert "T1078" in matches[0].context.get("mitre_attack", [])

    def test_rule_005_root_session_with_filter(self):
        # Interactive root session -> match
        ev_interactive = make_event(
            event_type="session_open",
            user="root",
            raw={"service": "systemd"},
        )
        matches_1 = self.engine.evaluate(ev_interactive)
        assert any(m.rule_id == "SOC-RULE-005" for m in matches_1)

        # Cron root session -> filtered out
        ev_cron = make_event(
            event_type="session_open",
            user="root",
            raw={"service": "cron"},
        )
        matches_2 = self.engine.evaluate(ev_cron)
        assert not any(m.rule_id == "SOC-RULE-005" for m in matches_2)

    def test_rule_001_ssh_brute_force_5_attempts(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        matches = []
        for i in range(5):
            ev = make_event(
                event_type="auth_failure",
                ip="198.51.100.22",
                raw={"service": "sshd"},
                timestamp=now + datetime.timedelta(seconds=i * 2),
            )
            res = self.engine.evaluate(ev)
            if res:
                matches.extend(res)

        assert len(matches) == 1
        assert matches[0].rule_id == "SOC-RULE-001"
        assert len(matches[0].matched_event_ids) == 5
