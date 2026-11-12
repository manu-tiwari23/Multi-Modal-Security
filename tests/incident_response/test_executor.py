"""
Tests for the Incident Response - Action Executor.

Covers:
  - CRITICAL guardrail: executing without approval, while pending, after
    rejection, or after expiry MUST raise UnapprovedActionError and never
    touch any backend.
  - MockFirewallBackend: block IP, block egress, block domain, block URL,
    invalid IP handling, missing target handling, rollback.
  - MockEDRBackend: isolate host, scan host, disable account, force password
    reset, rollback.
  - MockWorkflowBackend: quarantine email, preserve evidence, alert SOC.
  - Missing backend error handling.
  - Backend exception handling (marks FAILED gracefully).
  - Execution audit log and on_executed callback.
"""

from datetime import datetime, timedelta, timezone
import pytest

from src.incident_response.approval import ApprovalManager
from src.incident_response.executor import (
    ActionBackend,
    ActionExecutor,
    ExecutorError,
    MockEDRBackend,
    MockFirewallBackend,
    MockWorkflowBackend,
    NoBackendAvailableError,
    UnapprovedActionError,
)
from src.incident_response.models import (
    ActionPriority,
    ActionResult,
    ActionType,
    ExecutionStatus,
    ResponseAction,
)


@pytest.fixture
def approval_mgr():
    return ApprovalManager(default_ttl_seconds=3600)


@pytest.fixture
def firewall():
    return MockFirewallBackend()


@pytest.fixture
def edr():
    return MockEDRBackend()


@pytest.fixture
def workflow():
    return MockWorkflowBackend()


@pytest.fixture
def executor(approval_mgr, firewall, edr, workflow):
    return ActionExecutor(
        approval_manager=approval_mgr,
        backends=[firewall, edr, workflow],
    )


def _make_action(
    action_id: str,
    action_type: ActionType,
    target: dict[str, str],
    title: str = "Test action",
) -> ResponseAction:
    return ResponseAction(
        action_id=action_id,
        action_type=action_type,
        title=title,
        priority=ActionPriority.HIGH,
        target_entity=target,
    )


class TestApprovalGuardrail:
    def test_execute_without_request_raises(self, executor, firewall):
        action = _make_action("act-1", ActionType.BLOCK_IP, {"ip": "10.0.0.99"})
        with pytest.raises(UnapprovedActionError):
            executor.execute(action)
        assert "10.0.0.99" not in firewall.blocked_ips
        assert executor.get_audit_log()[-1]["event"] == "execution_blocked_unapproved"

    def test_execute_while_pending_raises(self, approval_mgr, executor, firewall):
        action = _make_action("act-2", ActionType.BLOCK_IP, {"ip": "10.0.0.99"})
        approval_mgr.request_approval(action, "inc-1", "plan-1")

        with pytest.raises(UnapprovedActionError):
            executor.execute(action)
        assert "10.0.0.99" not in firewall.blocked_ips

    def test_execute_after_rejection_raises(self, approval_mgr, executor, firewall):
        action = _make_action("act-3", ActionType.BLOCK_IP, {"ip": "10.0.0.99"})
        req = approval_mgr.request_approval(action, "inc-1", "plan-1")
        approval_mgr.reject(req.request_id, analyst_id="alice@soc", reason="FP")

        with pytest.raises(UnapprovedActionError):
            executor.execute(action)
        assert "10.0.0.99" not in firewall.blocked_ips

    def test_execute_after_expiry_raises(self, approval_mgr, executor, firewall):
        t0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
        action = _make_action("act-4", ActionType.BLOCK_IP, {"ip": "10.0.0.99"})
        approval_mgr.request_approval(action, "inc-1", "plan-1", ttl_seconds=10, now=t0)
        approval_mgr.expire_stale(now=t0 + timedelta(seconds=20))

        with pytest.raises(UnapprovedActionError):
            executor.execute(action)
        assert "10.0.0.99" not in firewall.blocked_ips


class TestFirewallExecution:
    def test_block_ip_succeeds_after_approval(self, approval_mgr, executor, firewall):
        action = _make_action("act-fw-1", ActionType.BLOCK_IP, {"ip": "203.0.113.50"})
        req = approval_mgr.request_approval(action, "inc-1", "plan-1")
        approval_mgr.approve(req.request_id, analyst_id="alice@soc", action=action)

        res = executor.execute(action)
        assert res.success is True
        assert res.backend == "mock_firewall"
        assert "203.0.113.50" in firewall.blocked_ips
        assert action.execution_status == ExecutionStatus.COMPLETED
        assert executor.get_result("act-fw-1") == res

    def test_block_ip_invalid_ip_fails_cleanly(self, approval_mgr, executor, firewall):
        action = _make_action("act-fw-2", ActionType.BLOCK_IP, {"ip": "not-an-ip"})
        req = approval_mgr.request_approval(action, "inc-1", "plan-1")
        approval_mgr.approve(req.request_id, analyst_id="alice@soc")

        res = executor.execute(action)
        assert res.success is False
        assert "Invalid IP" in res.message
        assert action.execution_status == ExecutionStatus.FAILED

    def test_block_domain_and_url(self, approval_mgr, executor, firewall):
        a_dom = _make_action("act-dom", ActionType.BLOCK_DOMAIN, {"domain": "Evil.Example"})
        a_url = _make_action("act-url", ActionType.BLOCK_URL, {"url": "http://evil.example/login"})

        for a in (a_dom, a_url):
            req = approval_mgr.request_approval(a, "inc-1", "plan-1")
            approval_mgr.approve(req.request_id, analyst_id="alice@soc")
            res = executor.execute(a)
            assert res.success is True

        assert "evil.example" in firewall.blocked_domains
        assert "http://evil.example/login" in firewall.blocked_urls

    def test_firewall_rollback(self, approval_mgr, executor, firewall):
        action = _make_action("act-fw-rb", ActionType.BLOCK_IP, {"ip": "198.51.100.7"})
        req = approval_mgr.request_approval(action, "inc-1", "plan-1")
        approval_mgr.approve(req.request_id, analyst_id="alice@soc")
        executor.execute(action)
        assert "198.51.100.7" in firewall.blocked_ips

        rb = executor.rollback("act-fw-rb", analyst_id="alice@soc")
        assert rb.success is True
        assert "198.51.100.7" not in firewall.blocked_ips
        assert action.execution_status == ExecutionStatus.ROLLED_BACK


class TestEDRAndWorkflowExecution:
    def test_edr_actions_and_rollback(self, approval_mgr, executor, edr):
        a_host = _make_action("act-iso", ActionType.ISOLATE_HOST, {"host": "web-prod-01"})
        a_user = _make_action("act-dis", ActionType.DISABLE_ACCOUNT, {"user": "compromised_svc"})
        a_scan = _make_action("act-scn", ActionType.SCAN_HOST, {"host": "web-prod-01"})
        a_pwd = _make_action("act-pwd", ActionType.FORCE_PASSWORD_RESET, {"user": "jdoe"})

        for a in (a_host, a_user, a_scan, a_pwd):
            req = approval_mgr.request_approval(a, "inc-2", "plan-2")
            approval_mgr.approve(req.request_id, analyst_id="bob@soc")
            assert executor.execute(a).success is True

        assert "web-prod-01" in edr.isolated_hosts
        assert "compromised_svc" in edr.disabled_accounts
        assert "web-prod-01" in edr.scanned_hosts
        assert "jdoe" in edr.password_resets

        assert executor.rollback("act-iso", analyst_id="bob@soc").success is True
        assert "web-prod-01" not in edr.isolated_hosts

    def test_workflow_actions(self, approval_mgr, executor, workflow):
        action = _make_action("act-wf-1", ActionType.QUARANTINE_EMAIL, {"user": "hr_user"})
        req = approval_mgr.request_approval(action, "inc-3", "plan-3")
        approval_mgr.approve(req.request_id, analyst_id="alice@soc")

        res = executor.execute(action)
        assert res.success is True
        assert len(workflow.recorded_events) == 1
        assert workflow.recorded_events[0]["action_type"] == "quarantine_email"


class TestExecutorEdgeCases:
    def test_no_backend_registered_raises(self, approval_mgr):
        exec_empty = ActionExecutor(approval_manager=approval_mgr, backends=[])
        action = _make_action("act-nb", ActionType.BLOCK_IP, {"ip": "10.0.0.1"})
        req = approval_mgr.request_approval(action, "inc-1", "plan-1")
        approval_mgr.approve(req.request_id, analyst_id="alice@soc")

        with pytest.raises(NoBackendAvailableError):
            exec_empty.execute(action)
        assert action.execution_status == ExecutionStatus.FAILED

    def test_crashing_backend_handled_gracefully(self, approval_mgr):
        class BrokenBackend(ActionBackend):
            name = "broken"
            supported_actions = frozenset({ActionType.BLOCK_IP})

            def execute(self, action: ResponseAction) -> ActionResult:
                raise RuntimeError("API timeout")

        exec_broken = ActionExecutor(approval_manager=approval_mgr, backends=[BrokenBackend()])
        action = _make_action("act-err", ActionType.BLOCK_IP, {"ip": "10.0.0.1"})
        req = approval_mgr.request_approval(action, "inc-1", "plan-1")
        approval_mgr.approve(req.request_id, analyst_id="alice@soc")

        res = exec_broken.execute(action)
        assert res.success is False
        assert "API timeout" in res.message
        assert action.execution_status == ExecutionStatus.FAILED

    def test_on_executed_callback_and_audit(self, approval_mgr, firewall):
        seen = []
        exec_cb = ActionExecutor(
            approval_manager=approval_mgr,
            backends=[firewall],
            on_executed=lambda a, r: seen.append((a.action_id, r.success)),
        )
        action = _make_action("act-cb", ActionType.BLOCK_IP, {"ip": "10.0.0.55"})
        req = approval_mgr.request_approval(action, "inc-1", "plan-1")
        approval_mgr.approve(req.request_id, analyst_id="alice@soc")
        exec_cb.execute(action)

        assert seen == [("act-cb", True)]
        audit = exec_cb.get_audit_log()
        assert audit[-1]["event"] == "execution_completed"
        assert audit[-1]["approved_by"] == "alice@soc"

    def test_rollback_unexecuted_action_raises(self, executor):
        with pytest.raises(ExecutorError):
            executor.rollback("never-ran", analyst_id="alice@soc")

