"""
Tests for the Incident Response - Response Recommender.

Covers:
  - Model validation (requires_approval guardrail enforcement)
  - Default playbook loading
  - Playbook matching by event type, MITRE technique, severity gate,
    source modality, tags, and alert-based recommendation
  - Target entity auto-population
  - Action deduplication
  - Priority sorting
  - Summary generation
  - Custom playbook management
  - Edge cases (no match, empty incident, disabled playbook)
"""

import pytest
from datetime import datetime, timezone

from src.incident_response.models import (
    ActionPriority,
    ActionType,
    ApprovalStatus,
    ExecutionStatus,
    IncidentPhase,
    ResponseAction,
    ResponsePlan,
    ResponsePlaybook,
    ApprovalRequest,
    ApprovalDecision,
    ActionResult,
    IncidentStateTransition,
)
from src.incident_response.recommender import (
    ResponseRecommender,
    _make_default_playbooks,
)
from src.shared.event_schema import Entity
from src.soc.alerting.alert_model import Alert
from src.soc.correlation.incident_model import (
    Incident,
    IncidentTimelineEntry,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def recommender():
    """ResponseRecommender with default playbooks."""
    return ResponseRecommender()


@pytest.fixture
def brute_force_incident():
    """Incident representing a brute force attack."""
    return Incident(
        incident_id="inc-bf-001",
        title="SSH Brute Force from 10.0.0.99",
        description="Multiple failed authentication attempts detected",
        severity="high",
        risk_score=72.5,
        primary_entity=Entity(ip="10.0.0.99", user="admin"),
        mitre_techniques=["T1110", "T1110.001"],
        mitre_tactics=["Credential Access"],
        event_count=50,
        tags=["brute_force", "ssh"],
        timeline=[
            IncidentTimelineEntry(
                event_id="evt-1",
                event_type="auth_failure",
                source="soc",
                severity="high",
                description="SSH auth failure from 10.0.0.99",
                entity=Entity(ip="10.0.0.99", user="admin"),
            ),
        ],
    )


@pytest.fixture
def phishing_incident():
    """Incident representing a phishing attack."""
    return Incident(
        incident_id="inc-ph-001",
        title="Phishing Email Campaign Detected",
        description="Spearphishing email with malicious URL targeting HR department",
        severity="high",
        risk_score=65.0,
        primary_entity=Entity(ip="192.168.1.50", user="hr_user"),
        mitre_techniques=["T1566.001", "T1204.001"],
        mitre_tactics=["Initial Access"],
        event_count=3,
        tags=["phishing", "spearphishing"],
        timeline=[
            IncidentTimelineEntry(
                event_id="evt-ph-1",
                event_type="phishing_email_detected",
                source="phishing",
                severity="high",
                description="Phishing email detected with malicious link",
                entity=Entity(ip="192.168.1.50", user="hr_user"),
            ),
        ],
    )


@pytest.fixture
def honeypot_incident():
    """Incident from honeypot detection."""
    return Incident(
        incident_id="inc-hp-001",
        title="Honeypot SSH Intrusion",
        description="Interactive attacker session on honeypot",
        severity="medium",
        risk_score=45.0,
        primary_entity=Entity(ip="203.0.113.42"),
        mitre_techniques=["T1110", "T1059"],
        mitre_tactics=["Initial Access", "Execution"],
        event_count=15,
        tags=["honeypot"],
        timeline=[
            IncidentTimelineEntry(
                event_id="evt-hp-1",
                event_type="honeypot_session",
                source="honeypot",
                severity="medium",
                description="SSH session on honeypot",
                entity=Entity(ip="203.0.113.42"),
            ),
        ],
    )


@pytest.fixture
def low_severity_incident():
    """Low-severity incident that should not match high-severity playbooks."""
    return Incident(
        incident_id="inc-low-001",
        title="Minor port scan",
        description="Quick SYN scan from external IP",
        severity="low",
        risk_score=12.0,
        primary_entity=Entity(ip="198.51.100.1"),
        mitre_techniques=["T1046"],
        mitre_tactics=["Discovery"],
        event_count=5,
        tags=["port_scan"],
        timeline=[
            IncidentTimelineEntry(
                event_id="evt-low-1",
                event_type="port_scan",
                source="soc",
                severity="low",
                description="SYN scan detected",
                entity=Entity(ip="198.51.100.1"),
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Model Validation Tests
# ---------------------------------------------------------------------------

class TestModelValidation:
    """Test model invariants and validation."""

    def test_response_action_requires_approval_default(self):
        """ResponseAction.requires_approval defaults to True."""
        action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            title="Block IP",
        )
        assert action.requires_approval is True

    def test_response_action_rejects_false_approval(self):
        """Setting requires_approval=False raises ValidationError (AGENTS.md guardrail)."""
        with pytest.raises(Exception) as exc_info:
            ResponseAction(
                action_type=ActionType.BLOCK_IP,
                title="Block IP",
                requires_approval=False,
            )
        assert "requires_approval must be True" in str(exc_info.value)

    def test_response_action_accepts_true_approval(self):
        """Explicitly setting requires_approval=True works fine."""
        action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            title="Block IP",
            requires_approval=True,
        )
        assert action.requires_approval is True

    def test_action_type_enum_values(self):
        """All ActionType variants are accessible."""
        assert ActionType.BLOCK_IP.value == "block_ip"
        assert ActionType.ISOLATE_HOST.value == "isolate_host"
        assert ActionType.DISABLE_ACCOUNT.value == "disable_account"
        assert ActionType.QUARANTINE_EMAIL.value == "quarantine_email"

    def test_approval_status_enum(self):
        assert ApprovalStatus.PENDING.value == "pending"
        assert ApprovalStatus.APPROVED.value == "approved"
        assert ApprovalStatus.REJECTED.value == "rejected"
        assert ApprovalStatus.EXPIRED.value == "expired"

    def test_execution_status_enum(self):
        assert ExecutionStatus.PENDING_APPROVAL.value == "pending_approval"
        assert ExecutionStatus.COMPLETED.value == "completed"

    def test_incident_phase_enum(self):
        assert IncidentPhase.NEW.value == "new"
        assert IncidentPhase.CONTAINING.value == "containing"
        assert IncidentPhase.CLOSED.value == "closed"

    def test_response_plan_properties(self):
        """ResponsePlan computed properties work correctly."""
        plan = ResponsePlan(
            incident_id="test-inc",
            actions=[
                ResponseAction(
                    action_type=ActionType.BLOCK_IP,
                    title="Block IP",
                    priority=ActionPriority.IMMEDIATE,
                ),
                ResponseAction(
                    action_type=ActionType.ALERT_SOC,
                    title="Alert SOC",
                    priority=ActionPriority.LOW,
                ),
            ],
        )
        assert plan.action_count == 2
        assert plan.has_immediate_actions is True

    def test_response_plan_no_immediate(self):
        """has_immediate_actions returns False when none are immediate."""
        plan = ResponsePlan(
            incident_id="test-inc",
            actions=[
                ResponseAction(
                    action_type=ActionType.ALERT_SOC,
                    title="Alert SOC",
                    priority=ActionPriority.LOW,
                ),
            ],
        )
        assert plan.has_immediate_actions is False

    def test_approval_request_model(self):
        """ApprovalRequest can be instantiated correctly."""
        req = ApprovalRequest(
            action_id="act-1",
            incident_id="inc-1",
            plan_id="plan-1",
            action_type=ActionType.BLOCK_IP,
            action_title="Block IP",
        )
        assert req.status == ApprovalStatus.PENDING
        assert req.decided_at is None
        assert req.decided_by is None

    def test_approval_decision_model(self):
        """ApprovalDecision model works."""
        dec = ApprovalDecision(
            request_id="req-1",
            status="approved",
            decided_by="analyst@soc",
        )
        assert dec.status == "approved"
        assert dec.decided_by == "analyst@soc"

    def test_action_result_model(self):
        """ActionResult model works."""
        result = ActionResult(
            action_id="act-1",
            success=True,
            backend="mock_firewall",
            message="IP blocked successfully",
        )
        assert result.success is True
        assert result.backend == "mock_firewall"

    def test_incident_state_transition_model(self):
        """IncidentStateTransition model works."""
        t = IncidentStateTransition(
            incident_id="inc-1",
            from_phase=IncidentPhase.NEW,
            to_phase=IncidentPhase.INVESTIGATING,
            transitioned_by="analyst@soc",
            reason="Starting investigation",
        )
        assert t.from_phase == IncidentPhase.NEW
        assert t.to_phase == IncidentPhase.INVESTIGATING


# ---------------------------------------------------------------------------
# Default Playbook Tests
# ---------------------------------------------------------------------------

class TestDefaultPlaybooks:
    """Test the built-in playbook library."""

    def test_default_playbooks_loaded(self, recommender):
        """Default playbooks are loaded on construction."""
        assert recommender.playbook_count >= 8

    def test_all_default_playbooks_enabled(self, recommender):
        """All default playbooks are enabled."""
        for pb in recommender.playbooks:
            assert pb.enabled is True

    def test_all_default_actions_require_approval(self, recommender):
        """Every action in every default playbook requires approval."""
        for pb in recommender.playbooks:
            for action in pb.actions:
                assert action.requires_approval is True, (
                    f"Playbook '{pb.name}' action '{action.title}' "
                    f"does not require approval!"
                )

    def test_all_default_actions_have_mitre_context(self, recommender):
        """Every default action has MITRE technique and tactic metadata."""
        for pb in recommender.playbooks:
            for action in pb.actions:
                assert action.mitre_technique, (
                    f"Playbook '{pb.name}' action '{action.title}' "
                    f"missing mitre_technique"
                )
                assert action.mitre_tactic, (
                    f"Playbook '{pb.name}' action '{action.title}' "
                    f"missing mitre_tactic"
                )

    def test_playbook_names_unique(self, recommender):
        """All playbook names are unique."""
        names = [pb.name for pb in recommender.playbooks]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Matching Tests
# ---------------------------------------------------------------------------

class TestPlaybookMatching:
    """Test playbook matching logic."""

    def test_brute_force_matches(self, recommender, brute_force_incident):
        """Brute force incident matches the brute force playbook."""
        plan = recommender.recommend(brute_force_incident)
        assert "Brute Force Response" in plan.matched_playbooks

    def test_phishing_matches(self, recommender, phishing_incident):
        """Phishing incident matches the phishing playbook."""
        plan = recommender.recommend(phishing_incident)
        assert "Phishing Response" in plan.matched_playbooks

    def test_honeypot_matches(self, recommender, honeypot_incident):
        """Honeypot incident matches by source modality."""
        plan = recommender.recommend(honeypot_incident)
        assert "Honeypot Intrusion Response" in plan.matched_playbooks

    def test_low_severity_skips_high_min(self, recommender, low_severity_incident):
        """Low-severity incident does not match playbooks requiring high severity."""
        plan = recommender.recommend(low_severity_incident)
        # Should NOT match malware, privesc, exfiltration, or tampering
        for name in plan.matched_playbooks:
            assert name not in [
                "Malware Response",
                "Privilege Escalation Response",
                "Data Exfiltration Response",
                "Evidence Tampering Response",
            ]

    def test_low_severity_matches_recon(self, recommender, low_severity_incident):
        """Low-severity port scan matches the reconnaissance playbook."""
        plan = recommender.recommend(low_severity_incident)
        assert "Reconnaissance Response" in plan.matched_playbooks

    def test_mitre_technique_matching(self, recommender):
        """Matching works on MITRE technique IDs alone."""
        incident = Incident(
            incident_id="inc-tech",
            title="Suspicious activity",
            severity="high",
            risk_score=60.0,
            primary_entity=Entity(ip="10.0.0.1"),
            mitre_techniques=["T1041"],  # Exfiltration
            tags=[],
        )
        plan = recommender.recommend(incident)
        assert "Data Exfiltration Response" in plan.matched_playbooks

    def test_tag_matching(self, recommender):
        """Matching works via tags (substring)."""
        incident = Incident(
            incident_id="inc-tag",
            title="Suspicious activity",
            severity="medium",
            risk_score=40.0,
            primary_entity=Entity(ip="10.0.0.1"),
            tags=["honeypot"],
            timeline=[
                IncidentTimelineEntry(
                    event_id="evt-1",
                    event_type="suspicious",
                    source="honeypot",
                    severity="medium",
                    description="Activity on honeypot",
                ),
            ],
        )
        plan = recommender.recommend(incident)
        assert "Honeypot Intrusion Response" in plan.matched_playbooks

    def test_no_match_empty_incident(self, recommender):
        """Empty incident with no distinguishing features produces no matches."""
        incident = Incident(
            incident_id="inc-empty",
            title="Unknown event",
            severity="low",
            risk_score=5.0,
            primary_entity=Entity(),
        )
        plan = recommender.recommend(incident)
        assert len(plan.matched_playbooks) == 0
        assert len(plan.actions) == 0
        assert "No playbooks matched" in plan.summary

    def test_disabled_playbook_skipped(self):
        """Disabled playbooks are not evaluated."""
        disabled_pb = ResponsePlaybook(
            name="Disabled Playbook",
            match_event_types=["auth_failure"],
            enabled=False,
            actions=[
                ResponseAction(
                    action_type=ActionType.BLOCK_IP,
                    title="Should not appear",
                ),
            ],
        )
        recommender = ResponseRecommender(playbooks=[disabled_pb])
        incident = Incident(
            incident_id="inc-test",
            title="auth_failure event",
            severity="medium",
            risk_score=30.0,
            primary_entity=Entity(ip="10.0.0.1"),
            timeline=[
                IncidentTimelineEntry(
                    event_id="e1",
                    event_type="auth_failure",
                    source="soc",
                    severity="medium",
                    description="Auth failure",
                ),
            ],
        )
        plan = recommender.recommend(incident)
        assert len(plan.actions) == 0

    def test_multiple_playbooks_match(self, recommender):
        """An incident can match multiple playbooks, merging actions."""
        incident = Incident(
            incident_id="inc-multi",
            title="Complex attack with brute force and honeypot activity",
            severity="high",
            risk_score=80.0,
            primary_entity=Entity(ip="10.0.0.99"),
            mitre_techniques=["T1110", "T1059"],
            tags=["brute_force", "honeypot"],
            timeline=[
                IncidentTimelineEntry(
                    event_id="evt-1",
                    event_type="auth_failure",
                    source="soc",
                    severity="high",
                    description="Brute force via SOC",
                ),
                IncidentTimelineEntry(
                    event_id="evt-2",
                    event_type="honeypot_session",
                    source="honeypot",
                    severity="medium",
                    description="Same IP on honeypot",
                ),
            ],
        )
        plan = recommender.recommend(incident)
        assert len(plan.matched_playbooks) >= 2
        assert len(plan.actions) >= 3  # Actions from both playbooks


# ---------------------------------------------------------------------------
# Target Population Tests
# ---------------------------------------------------------------------------

class TestTargetPopulation:
    """Test auto-population of target entities from incidents."""

    def test_block_ip_gets_ip(self, recommender, brute_force_incident):
        """BLOCK_IP actions auto-populate with incident's IP."""
        plan = recommender.recommend(brute_force_incident)
        block_ip_actions = [
            a for a in plan.actions if a.action_type == ActionType.BLOCK_IP
        ]
        assert len(block_ip_actions) >= 1
        assert block_ip_actions[0].target_entity.get("ip") == "10.0.0.99"

    def test_force_reset_gets_user(self, recommender, brute_force_incident):
        """FORCE_PASSWORD_RESET actions auto-populate with incident's user."""
        plan = recommender.recommend(brute_force_incident)
        reset_actions = [
            a for a in plan.actions
            if a.action_type == ActionType.FORCE_PASSWORD_RESET
        ]
        assert len(reset_actions) >= 1
        assert reset_actions[0].target_entity.get("user") == "admin"


# ---------------------------------------------------------------------------
# Deduplication Tests
# ---------------------------------------------------------------------------

class TestDeduplication:
    """Test action deduplication logic."""

    def test_duplicate_block_ip_merged(self):
        """Two BLOCK_IP actions for the same IP are deduplicated."""
        pb1 = ResponsePlaybook(
            name="PB1",
            match_event_types=["test"],
            actions=[
                ResponseAction(
                    action_type=ActionType.BLOCK_IP,
                    title="Block from PB1",
                    priority=ActionPriority.MEDIUM,
                    target_entity={"ip": "10.0.0.1"},
                ),
            ],
        )
        pb2 = ResponsePlaybook(
            name="PB2",
            match_event_types=["test"],
            actions=[
                ResponseAction(
                    action_type=ActionType.BLOCK_IP,
                    title="Block from PB2",
                    priority=ActionPriority.HIGH,
                    target_entity={"ip": "10.0.0.1"},
                ),
            ],
        )
        recommender = ResponseRecommender(playbooks=[pb1, pb2])
        incident = Incident(
            incident_id="inc-dedup",
            title="Test dedup",
            severity="medium",
            risk_score=40.0,
            primary_entity=Entity(ip="10.0.0.1"),
            timeline=[
                IncidentTimelineEntry(
                    event_id="e1",
                    event_type="test",
                    source="soc",
                    severity="medium",
                    description="Test event",
                ),
            ],
        )
        plan = recommender.recommend(incident)
        block_ips = [a for a in plan.actions if a.action_type == ActionType.BLOCK_IP]
        assert len(block_ips) == 1
        # Higher priority wins
        assert block_ips[0].priority == ActionPriority.HIGH


# ---------------------------------------------------------------------------
# Priority Sorting Tests
# ---------------------------------------------------------------------------

class TestPrioritySorting:
    """Test that actions are sorted by priority (IMMEDIATE first)."""

    def test_immediate_actions_first(self, recommender, brute_force_incident):
        """IMMEDIATE-priority actions appear before lower-priority ones."""
        plan = recommender.recommend(brute_force_incident)
        if len(plan.actions) >= 2:
            priorities = [a.priority for a in plan.actions]
            immediate_indices = [
                i for i, p in enumerate(priorities)
                if p == ActionPriority.IMMEDIATE
            ]
            non_immediate_indices = [
                i for i, p in enumerate(priorities)
                if p != ActionPriority.IMMEDIATE
            ]
            if immediate_indices and non_immediate_indices:
                assert max(immediate_indices) < min(non_immediate_indices)


# ---------------------------------------------------------------------------
# Summary Tests
# ---------------------------------------------------------------------------

class TestSummaryGeneration:
    """Test human-readable summary generation."""

    def test_matched_summary(self, recommender, brute_force_incident):
        """Summary includes playbook names and action count."""
        plan = recommender.recommend(brute_force_incident)
        assert "Brute Force" in plan.summary
        assert "analyst approval" in plan.summary.lower()

    def test_no_match_summary(self, recommender):
        """No-match summary indicates manual investigation needed."""
        incident = Incident(
            incident_id="inc-nomatch",
            title="Strange event",
            severity="low",
            risk_score=3.0,
            primary_entity=Entity(),
        )
        plan = recommender.recommend(incident)
        assert "No playbooks matched" in plan.summary
        assert "Manual investigation" in plan.summary

    def test_urgent_summary_callout(self, recommender, brute_force_incident):
        """Summary calls out immediate actions when present."""
        plan = recommender.recommend(brute_force_incident)
        assert "URGENT" in plan.summary or "immediate" in plan.summary.lower()


# ---------------------------------------------------------------------------
# Custom Playbook Management Tests
# ---------------------------------------------------------------------------

class TestPlaybookManagement:
    """Test add/remove playbook operations."""

    def test_add_custom_playbook(self, recommender):
        """Adding a custom playbook increases the count."""
        initial = recommender.playbook_count
        custom = ResponsePlaybook(
            name="Custom Playbook",
            match_event_types=["custom_event"],
            actions=[
                ResponseAction(
                    action_type=ActionType.CUSTOM,
                    title="Custom action",
                ),
            ],
        )
        recommender.add_playbook(custom)
        assert recommender.playbook_count == initial + 1

    def test_remove_playbook(self, recommender):
        """Removing a playbook by ID works."""
        initial = recommender.playbook_count
        pb_id = recommender.playbooks[0].playbook_id
        result = recommender.remove_playbook(pb_id)
        assert result is True
        assert recommender.playbook_count == initial - 1

    def test_remove_nonexistent_playbook(self, recommender):
        """Removing a non-existent playbook returns False."""
        result = recommender.remove_playbook("nonexistent-id")
        assert result is False

    def test_empty_playbooks(self):
        """Recommender with empty playbook list produces empty plans."""
        recommender = ResponseRecommender(playbooks=[])
        incident = Incident(
            incident_id="inc-test",
            title="Test",
            severity="high",
            risk_score=50.0,
            primary_entity=Entity(ip="10.0.0.1"),
        )
        plan = recommender.recommend(incident)
        assert plan.action_count == 0


# ---------------------------------------------------------------------------
# Alert-based Recommendation Tests
# ---------------------------------------------------------------------------

class TestAlertRecommendation:
    """Test recommend_from_alert convenience method."""

    def test_from_alert_with_incident(self, recommender, brute_force_incident):
        """recommend_from_alert uses the full incident when provided."""
        alert = Alert(
            title="SSH Brute Force",
            incident_id=brute_force_incident.incident_id,
            severity="high",
            risk_score=72.5,
            primary_entity=Entity(ip="10.0.0.99"),
            mitre_techniques=["T1110"],
        )
        plan = recommender.recommend_from_alert(alert, incident=brute_force_incident)
        assert "Brute Force Response" in plan.matched_playbooks

    def test_from_alert_without_incident(self, recommender):
        """recommend_from_alert builds a minimal incident from the alert."""
        alert = Alert(
            title="Phishing detected",
            incident_id="inc-alert-ph",
            severity="high",
            risk_score=65.0,
            primary_entity=Entity(ip="10.0.0.50"),
            mitre_techniques=["T1566.001"],
            tags=["phishing"],
        )
        plan = recommender.recommend_from_alert(alert)
        assert plan.incident_id == "inc-alert-ph"
        # Should match phishing playbook via MITRE technique
        assert "Phishing Response" in plan.matched_playbooks


# ---------------------------------------------------------------------------
# Incident Metadata Tests
# ---------------------------------------------------------------------------

class TestPlanMetadata:
    """Test that plan captures incident metadata correctly."""

    def test_plan_has_incident_id(self, recommender, brute_force_incident):
        plan = recommender.recommend(brute_force_incident)
        assert plan.incident_id == "inc-bf-001"

    def test_plan_has_severity(self, recommender, brute_force_incident):
        plan = recommender.recommend(brute_force_incident)
        assert plan.incident_severity == "high"

    def test_plan_has_risk_score(self, recommender, brute_force_incident):
        plan = recommender.recommend(brute_force_incident)
        assert plan.incident_risk_score == 72.5

    def test_plan_has_creation_timestamp(self, recommender, brute_force_incident):
        plan = recommender.recommend(brute_force_incident)
        assert plan.created_at is not None
        assert isinstance(plan.created_at, datetime)

    def test_all_plan_actions_require_approval(self, recommender, brute_force_incident):
        """Every action in a generated plan requires approval."""
        plan = recommender.recommend(brute_force_incident)
        for action in plan.actions:
            assert action.requires_approval is True

