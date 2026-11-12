"""
Tests for the Incident Response - Approval Workflow (ApprovalManager).

Covers:
  - Creating single and plan-level approval requests
  - Approving and rejecting requests with human analyst identity
  - Guardrail: rejecting empty/system/copilot/ai approver identities
  - Double-decision protection (cannot approve/reject twice)
  - Duplicate active request prevention & re-requesting after rejection/expiry
  - TTL expiration (both during decide() and via expire_stale() / list_pending())
  - Action execution_status updates when action is passed
  - is_approved() and get_decision_for_action() queries
  - Callback firing and append-only audit log
"""

from datetime import datetime, timedelta, timezone
import pytest

from src.incident_response.approval import (
    ApprovalExpiredError,
    ApprovalManager,
    ApprovalNotFoundError,
    DuplicateApprovalRequestError,
    InvalidApprovalStateError,
    InvalidApproverError,
)
from src.incident_response.models import (
    ActionPriority,
    ActionType,
    ApprovalStatus,
    ExecutionStatus,
    ResponseAction,
    ResponsePlan,
)


@pytest.fixture
def manager():
    return ApprovalManager(default_ttl_seconds=3600)


@pytest.fixture
def sample_action():
    return ResponseAction(
        action_id="act-block-1",
        action_type=ActionType.BLOCK_IP,
        title="Block attacker IP",
        description="Block 10.0.0.99 at firewall",
        priority=ActionPriority.IMMEDIATE,
        target_entity={"ip": "10.0.0.99"},
    )


@pytest.fixture
def sample_plan(sample_action):
    action2 = ResponseAction(
        action_id="act-reset-2",
        action_type=ActionType.FORCE_PASSWORD_RESET,
        title="Reset user password",
        priority=ActionPriority.HIGH,
        target_entity={"user": "jdoe"},
    )
    return ResponsePlan(
        plan_id="plan-1",
        incident_id="inc-1",
        actions=[sample_action, action2],
    )


class TestRequestCreation:
    def test_request_approval_creates_pending(self, manager, sample_action):
        now = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
        req = manager.request_approval(sample_action, "inc-1", "plan-1", now=now)

        assert req.status == ApprovalStatus.PENDING
        assert req.action_id == "act-block-1"
        assert req.incident_id == "inc-1"
        assert req.plan_id == "plan-1"
        assert req.target_entity == {"ip": "10.0.0.99"}
        assert req.expires_at == now + timedelta(seconds=3600)
        assert manager.is_approved(sample_action.action_id) is False

    def test_request_plan_approvals(self, manager, sample_plan):
        reqs = manager.request_plan_approvals(sample_plan)
        assert len(reqs) == 2
        assert len(manager.list_pending(incident_id="inc-1")) == 2

    def test_duplicate_active_request_rejected(self, manager, sample_action):
        manager.request_approval(sample_action, "inc-1", "plan-1")
        with pytest.raises(DuplicateApprovalRequestError):
            manager.request_approval(sample_action, "inc-1", "plan-1")

    def test_invalid_ttl_raises(self, manager, sample_action):
        with pytest.raises(ValueError):
            manager.request_approval(sample_action, "inc-1", "plan-1", ttl_seconds=0)


class TestAnalystDecisions:
    def test_approve_workflow(self, manager, sample_action):
        req = manager.request_approval(sample_action, "inc-1", "plan-1")
        dec = manager.approve(
            req.request_id,
            analyst_id="alice@soc",
            reason="Verified brute force logs",
            action=sample_action,
        )

        assert dec.status == "approved"
        assert dec.decided_by == "alice@soc"
        assert manager.is_approved(sample_action.action_id) is True
        assert sample_action.execution_status == ExecutionStatus.APPROVED

        stored_req = manager.get_request(req.request_id)
        assert stored_req.status == ApprovalStatus.APPROVED
        assert stored_req.decided_by == "alice@soc"
        assert stored_req.decision_reason == "Verified brute force logs"

    def test_reject_workflow(self, manager, sample_action):
        req = manager.request_approval(sample_action, "inc-1", "plan-1")
        dec = manager.reject(
            req.request_id,
            analyst_id="bob@soc",
            reason="False positive from scanner",
            action=sample_action,
        )

        assert dec.status == "rejected"
        assert manager.is_approved(sample_action.action_id) is False
        assert sample_action.execution_status == ExecutionStatus.SKIPPED
        assert manager.get_request(req.request_id).status == ApprovalStatus.REJECTED

    def test_re_request_allowed_after_rejection(self, manager, sample_action):
        req1 = manager.request_approval(sample_action, "inc-1", "plan-1")
        manager.reject(req1.request_id, analyst_id="bob@soc", reason="Wait")

        req2 = manager.request_approval(sample_action, "inc-1", "plan-1")
        assert req2.request_id != req1.request_id
        assert req2.status == ApprovalStatus.PENDING

    @pytest.mark.parametrize("bad_actor", ["", "   ", "system", "copilot", "AI", "autonomous", "bot"])
    def test_disallowed_approver_identities_rejected(self, manager, sample_action, bad_actor):
        req = manager.request_approval(sample_action, "inc-1", "plan-1")
        with pytest.raises(InvalidApproverError):
            manager.approve(req.request_id, analyst_id=bad_actor)
        assert manager.is_approved(sample_action.action_id) is False

    def test_double_decision_blocked(self, manager, sample_action):
        req = manager.request_approval(sample_action, "inc-1", "plan-1")
        manager.approve(req.request_id, analyst_id="alice@soc")

        with pytest.raises(InvalidApprovalStateError):
            manager.reject(req.request_id, analyst_id="bob@soc")

    def test_unknown_request_raises(self, manager):
        with pytest.raises(ApprovalNotFoundError):
            manager.approve("nonexistent", analyst_id="alice@soc")


class TestExpiration:
    def test_approve_expired_request_raises(self, manager, sample_action):
        t0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
        req = manager.request_approval(sample_action, "inc-1", "plan-1", ttl_seconds=60, now=t0)

        t_later = t0 + timedelta(seconds=61)
        with pytest.raises(ApprovalExpiredError):
            manager.approve(req.request_id, analyst_id="alice@soc", now=t_later)

        assert manager.get_request(req.request_id).status == ApprovalStatus.EXPIRED
        assert manager.is_approved(sample_action.action_id) is False

    def test_list_pending_expires_stale(self, manager, sample_action):
        t0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
        manager.request_approval(sample_action, "inc-1", "plan-1", ttl_seconds=30, now=t0)

        assert len(manager.list_pending(now=t0 + timedelta(seconds=10))) == 1
        assert len(manager.list_pending(now=t0 + timedelta(seconds=31))) == 0

    def test_re_request_allowed_after_expiry(self, manager, sample_action):
        t0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
        manager.request_approval(sample_action, "inc-1", "plan-1", ttl_seconds=30, now=t0)
        manager.expire_stale(now=t0 + timedelta(seconds=35))

        req2 = manager.request_approval(
            sample_action, "inc-1", "plan-1", ttl_seconds=60, now=t0 + timedelta(seconds=36)
        )
        assert req2.status == ApprovalStatus.PENDING


class TestCallbacksAndAudit:
    def test_on_decision_callback_fired(self, sample_action):
        events = []
        mgr = ApprovalManager(on_decision=lambda req, dec: events.append((req.request_id, dec.status)))
        req = mgr.request_approval(sample_action, "inc-1", "plan-1")
        mgr.approve(req.request_id, analyst_id="alice@soc")

        assert events == [(req.request_id, "approved")]

    def test_audit_log_records_lifecycle(self, manager, sample_action):
        t0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
        req = manager.request_approval(sample_action, "inc-1", "plan-1", now=t0)
        manager.approve(req.request_id, analyst_id="alice@soc", reason="OK", now=t0 + timedelta(seconds=5))

        log = manager.get_audit_log(incident_id="inc-1")
        assert len(log) == 2
        assert log[0]["event"] == "approval_requested"
        assert log[1]["event"] == "approval_approved"
        assert log[1]["actor"] == "alice@soc"

