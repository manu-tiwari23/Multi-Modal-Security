"""
Tests for the Incident Response - Incident State Tracker & End-to-End IR Flow.

Covers:
  - Registration (default NEW, custom initial phase, idempotency)
  - Valid FSM transitions across full lifecycle
  - Invalid transitions and self-transitions raise InvalidStateTransitionError
  - Unregistered incident raises IncidentNotTrackedError
  - Reopening CLOSED incidents
  - Linking plans and recording executed actions
  - Summary phase counts & on_transition callback
  - End-to-end Phase 7 workflow: Recommend -> Request Approval -> Analyst
    Approve -> Execute -> Track State
"""

import pytest

from src.incident_response import (
    ActionExecutor,
    ActionType,
    ApprovalManager,
    IncidentNotTrackedError,
    IncidentPhase,
    IncidentStateTracker,
    InvalidStateTransitionError,
    MockFirewallBackend,
    ResponseRecommender,
    UnapprovedActionError,
)
from src.shared.event_schema import Entity
from src.soc.correlation.incident_model import Incident, IncidentTimelineEntry


@pytest.fixture
def tracker():
    return IncidentStateTracker()


class TestRegistrationAndLifecycle:
    def test_register_defaults_to_new(self, tracker):
        phase = tracker.register_incident("inc-1")
        assert phase == IncidentPhase.NEW
        assert tracker.is_tracked("inc-1") is True
        assert tracker.get_phase("inc-1") == IncidentPhase.NEW
        assert len(tracker.get_history("inc-1")) == 1

    def test_register_is_idempotent(self, tracker):
        tracker.register_incident("inc-1")
        tracker.transition("inc-1", IncidentPhase.INVESTIGATING, actor="alice@soc")
        phase = tracker.register_incident("inc-1")
        assert phase == IncidentPhase.INVESTIGATING

    def test_full_valid_lifecycle(self, tracker):
        tracker.register_incident("inc-1", actor="system")
        tracker.transition("inc-1", IncidentPhase.INVESTIGATING, actor="alice@soc", reason="Triaging")
        tracker.transition("inc-1", IncidentPhase.CONTAINING, actor="alice@soc", reason="Blocking IP")
        tracker.transition("inc-1", IncidentPhase.CONTAINED, actor="alice@soc", reason="IP blocked")
        tracker.transition("inc-1", IncidentPhase.REMEDIATING, actor="alice@soc", reason="Rotating creds")
        tracker.transition("inc-1", IncidentPhase.REMEDIATED, actor="alice@soc", reason="Creds rotated")
        tracker.transition("inc-1", IncidentPhase.CLOSED, actor="alice@soc", reason="All clear")

        assert tracker.get_phase("inc-1") == IncidentPhase.CLOSED
        history = tracker.get_history("inc-1")
        assert len(history) == 7
        assert history[-1].to_phase == IncidentPhase.CLOSED

    def test_reopen_closed_incident(self, tracker):
        tracker.register_incident("inc-2")
        tracker.transition("inc-2", IncidentPhase.CLOSED, actor="alice@soc", reason="FP")
        tracker.transition("inc-2", IncidentPhase.INVESTIGATING, actor="bob@soc", reason="New activity")
        assert tracker.get_phase("inc-2") == IncidentPhase.INVESTIGATING

    def test_invalid_jump_raises(self, tracker):
        tracker.register_incident("inc-3")
        with pytest.raises(InvalidStateTransitionError):
            tracker.transition("inc-3", IncidentPhase.REMEDIATED, actor="alice@soc")

    def test_self_transition_raises(self, tracker):
        tracker.register_incident("inc-4")
        with pytest.raises(InvalidStateTransitionError):
            tracker.transition("inc-4", IncidentPhase.NEW, actor="alice@soc")

    def test_untracked_incident_raises(self, tracker):
        with pytest.raises(IncidentNotTrackedError):
            tracker.get_phase("unknown")
        with pytest.raises(IncidentNotTrackedError):
            tracker.transition("unknown", IncidentPhase.INVESTIGATING)
        with pytest.raises(IncidentNotTrackedError):
            tracker.get_history("unknown")


class TestQueriesLinkingAndCallbacks:
    def test_link_plan_and_record_action(self, tracker):
        tracker.link_plan("inc-5", "plan-1")
        tracker.record_executed_action("inc-5", "act-1")
        record = tracker.get_incident_record("inc-5")
        assert record["phase"] == "new"
        assert record["plan_ids"] == ["plan-1"]
        assert record["executed_action_ids"] == ["act-1"]

    def test_list_and_summary(self, tracker):
        tracker.register_incident("inc-a")
        tracker.register_incident("inc-b")
        tracker.transition("inc-b", IncidentPhase.INVESTIGATING, actor="alice@soc")

        assert len(tracker.list_incidents()) == 2
        assert len(tracker.list_incidents(phase=IncidentPhase.INVESTIGATING)) == 1
        summary = tracker.get_summary()
        assert summary["new"] == 1
        assert summary["investigating"] == 1
        assert summary["closed"] == 0

    def test_on_transition_callback(self):
        transitions = []
        t = IncidentStateTracker(on_transition=lambda rec: transitions.append(rec.to_phase))
        t.register_incident("inc-cb")
        t.transition("inc-cb", IncidentPhase.INVESTIGATING, actor="alice@soc")
        t.transition("inc-cb", IncidentPhase.CONTAINED, actor="alice@soc")
        assert transitions == [IncidentPhase.INVESTIGATING, IncidentPhase.CONTAINED]


class TestEndToEndIncidentResponse:
    def test_full_ir_pipeline_with_human_gate(self):
        recommender = ResponseRecommender()
        approval_mgr = ApprovalManager()
        firewall = MockFirewallBackend()
        executor = ActionExecutor(approval_manager=approval_mgr, backends=[firewall])
        tracker = IncidentStateTracker()

        incident = Incident(
            incident_id="inc-e2e-1",
            title="SSH Brute Force from 203.0.113.77",
            severity="high",
            risk_score=78.0,
            primary_entity=Entity(ip="203.0.113.77", user="root"),
            mitre_techniques=["T1110"],
            tags=["brute_force"],
            timeline=[
                IncidentTimelineEntry(
                    event_id="evt-1",
                    event_type="auth_failure",
                    source="soc",
                    severity="high",
                    description="Repeated SSH auth failures",
                    entity=Entity(ip="203.0.113.77", user="root"),
                ),
            ],
        )

        # 1. Track & Recommend
        tracker.register_incident(incident.incident_id)
        tracker.transition(incident.incident_id, IncidentPhase.INVESTIGATING, actor="alice@soc")
        plan = recommender.recommend(incident)
        tracker.link_plan(incident.incident_id, plan.plan_id)

        block_action = next(a for a in plan.actions if a.action_type == ActionType.BLOCK_IP)

        # 2. Request approval — verify cannot execute before analyst sign-off
        req = approval_mgr.request_approval(block_action, incident.incident_id, plan.plan_id)
        with pytest.raises(UnapprovedActionError):
            executor.execute(block_action)
        assert "203.0.113.77" not in firewall.blocked_ips

        # 3. Analyst approves -> execute -> mark contained
        approval_mgr.approve(req.request_id, analyst_id="alice@soc", reason="Confirmed attacker IP", action=block_action)
        tracker.transition(incident.incident_id, IncidentPhase.CONTAINING, actor="alice@soc")
        result = executor.execute(block_action)
        assert result.success is True
        assert "203.0.113.77" in firewall.blocked_ips

        tracker.record_executed_action(incident.incident_id, block_action.action_id)
        tracker.transition(incident.incident_id, IncidentPhase.CONTAINED, actor="alice@soc")
        assert tracker.get_phase(incident.incident_id) == IncidentPhase.CONTAINED

