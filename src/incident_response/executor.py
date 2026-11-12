"""
Action Executor — pluggable containment execution with mandatory approval gate.

Per AGENTS.md and ARCHITECTURE.md §4.8 / §8:
  - The ActionExecutor is the ONLY component permitted to invoke containment
    backends (firewall, EDR, email gateway, etc.).
  - Every execution call hard-checks ``ApprovalManager.is_approved(action_id)``.
    Any unapproved, rejected, expired, or missing-approval action raises
    ``UnapprovedActionError`` and is logged in the audit trail without
    touching any backend.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from src.incident_response.approval import ApprovalManager
from src.incident_response.models import (
    ActionResult,
    ActionType,
    ExecutionStatus,
    ResponseAction,
)

logger = logging.getLogger(__name__)


class ExecutorError(Exception):
    """Base exception for ActionExecutor errors."""


class UnapprovedActionError(ExecutorError):
    """Raised when attempting to execute an action without analyst approval."""


class NoBackendAvailableError(ExecutorError):
    """Raised when no registered backend handles the requested ActionType."""


# ---------------------------------------------------------------------------
# Backend Abstraction & Built-in Simulated Backends
# ---------------------------------------------------------------------------

class ActionBackend(ABC):
    """Abstract base class for containment / response action backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique backend identifier."""

    @property
    @abstractmethod
    def supported_actions(self) -> frozenset[ActionType]:
        """Set of ActionTypes this backend can execute."""

    @abstractmethod
    def execute(self, action: ResponseAction) -> ActionResult:
        """Execute the approved response action."""

    def rollback(self, action: ResponseAction) -> ActionResult:
        """Optional rollback/undo of a previously executed action."""
        return ActionResult(
            action_id=action.action_id,
            success=False,
            backend=self.name,
            message=f"Rollback not supported by backend '{self.name}'",
        )


class MockFirewallBackend(ActionBackend):
    """Simulated perimeter firewall & web-proxy API integration.

    Supports ``BLOCK_IP``, ``BLOCK_EGRESS``, ``BLOCK_DOMAIN``, and ``BLOCK_URL``.
    Optional ``IR_FIREWALL_API_URL`` env var records target endpoint metadata
    without making live network calls in test/standalone environments.
    """

    def __init__(self, api_url: Optional[str] = None) -> None:
        self._api_url = api_url or os.getenv("IR_FIREWALL_API_URL", "mock://firewall.local/api/v1")
        self._lock = threading.RLock()
        self.blocked_ips: set[str] = set()
        self.blocked_domains: set[str] = set()
        self.blocked_urls: set[str] = set()

    @property
    def name(self) -> str:
        return "mock_firewall"

    @property
    def supported_actions(self) -> frozenset[ActionType]:
        return frozenset({
            ActionType.BLOCK_IP,
            ActionType.BLOCK_EGRESS,
            ActionType.BLOCK_DOMAIN,
            ActionType.BLOCK_URL,
        })

    def execute(self, action: ResponseAction) -> ActionResult:
        target = action.target_entity
        with self._lock:
            if action.action_type in (ActionType.BLOCK_IP, ActionType.BLOCK_EGRESS):
                ip = (target.get("ip") or "").strip()
                if not ip:
                    return ActionResult(
                        action_id=action.action_id,
                        success=False,
                        backend=self.name,
                        message="Missing target 'ip' for firewall IP block",
                    )
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    return ActionResult(
                        action_id=action.action_id,
                        success=False,
                        backend=self.name,
                        message=f"Invalid IP address: '{ip}'",
                    )
                self.blocked_ips.add(ip)
                return ActionResult(
                    action_id=action.action_id,
                    success=True,
                    backend=self.name,
                    message=f"Blocked IP {ip} via firewall API",
                    details={"ip": ip, "api_url": self._api_url, "rule_action": "DROP"},
                )

            if action.action_type == ActionType.BLOCK_DOMAIN:
                domain = (target.get("domain") or target.get("host") or "").strip().lower()
                if not domain:
                    return ActionResult(
                        action_id=action.action_id,
                        success=False,
                        backend=self.name,
                        message="Missing target 'domain' for domain block",
                    )
                self.blocked_domains.add(domain)
                return ActionResult(
                    action_id=action.action_id,
                    success=True,
                    backend=self.name,
                    message=f"Blocked domain {domain} at gateway",
                    details={"domain": domain, "api_url": self._api_url},
                )

            # BLOCK_URL
            url = (target.get("url") or target.get("ip") or "").strip()
            if not url:
                return ActionResult(
                    action_id=action.action_id,
                    success=False,
                    backend=self.name,
                    message="Missing target 'url' for URL block",
                )
            self.blocked_urls.add(url)
            return ActionResult(
                action_id=action.action_id,
                success=True,
                backend=self.name,
                message=f"Blocked URL {url} at web proxy",
                details={"url": url, "api_url": self._api_url},
            )

    def rollback(self, action: ResponseAction) -> ActionResult:
        target = action.target_entity
        with self._lock:
            if action.action_type in (ActionType.BLOCK_IP, ActionType.BLOCK_EGRESS):
                ip = (target.get("ip") or "").strip()
                removed = ip in self.blocked_ips
                self.blocked_ips.discard(ip)
                return ActionResult(
                    action_id=action.action_id,
                    success=removed,
                    backend=self.name,
                    message=f"Unblocked IP {ip}" if removed else f"IP {ip} was not blocked",
                    details={"ip": ip},
                )
            if action.action_type == ActionType.BLOCK_DOMAIN:
                domain = (target.get("domain") or target.get("host") or "").strip().lower()
                removed = domain in self.blocked_domains
                self.blocked_domains.discard(domain)
                return ActionResult(
                    action_id=action.action_id,
                    success=removed,
                    backend=self.name,
                    message=f"Unblocked domain {domain}" if removed else f"Domain {domain} not blocked",
                )
            url = (target.get("url") or target.get("ip") or "").strip()
            removed = url in self.blocked_urls
            self.blocked_urls.discard(url)
            return ActionResult(
                action_id=action.action_id,
                success=removed,
                backend=self.name,
                message=f"Unblocked URL {url}" if removed else f"URL {url} not blocked",
            )


class MockEDRBackend(ActionBackend):
    """Simulated EDR / IAM containment backend.

    Supports ``ISOLATE_HOST``, ``SCAN_HOST``, ``DISABLE_ACCOUNT``, and
    ``FORCE_PASSWORD_RESET``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.isolated_hosts: set[str] = set()
        self.scanned_hosts: list[str] = []
        self.disabled_accounts: set[str] = set()
        self.password_resets: list[str] = []

    @property
    def name(self) -> str:
        return "mock_edr"

    @property
    def supported_actions(self) -> frozenset[ActionType]:
        return frozenset({
            ActionType.ISOLATE_HOST,
            ActionType.SCAN_HOST,
            ActionType.DISABLE_ACCOUNT,
            ActionType.FORCE_PASSWORD_RESET,
        })

    def execute(self, action: ResponseAction) -> ActionResult:
        target = action.target_entity
        with self._lock:
            if action.action_type == ActionType.ISOLATE_HOST:
                host = (target.get("host") or target.get("ip") or "").strip()
                if not host:
                    return ActionResult(
                        action_id=action.action_id,
                        success=False,
                        backend=self.name,
                        message="Missing target 'host' for host isolation",
                    )
                self.isolated_hosts.add(host)
                return ActionResult(
                    action_id=action.action_id,
                    success=True,
                    backend=self.name,
                    message=f"Isolated host {host} via EDR",
                    details={"host": host},
                )

            if action.action_type == ActionType.SCAN_HOST:
                host = (target.get("host") or target.get("ip") or "").strip()
                if not host:
                    return ActionResult(
                        action_id=action.action_id,
                        success=False,
                        backend=self.name,
                        message="Missing target 'host' for host scan",
                    )
                self.scanned_hosts.append(host)
                return ActionResult(
                    action_id=action.action_id,
                    success=True,
                    backend=self.name,
                    message=f"Initiated full EDR scan on {host}",
                    details={"host": host},
                )

            user = (target.get("user") or "").strip()
            if not user:
                return ActionResult(
                    action_id=action.action_id,
                    success=False,
                    backend=self.name,
                    message=f"Missing target 'user' for {action.action_type.value}",
                )

            if action.action_type == ActionType.DISABLE_ACCOUNT:
                self.disabled_accounts.add(user)
                return ActionResult(
                    action_id=action.action_id,
                    success=True,
                    backend=self.name,
                    message=f"Disabled account '{user}'",
                    details={"user": user},
                )

            # FORCE_PASSWORD_RESET
            self.password_resets.append(user)
            return ActionResult(
                action_id=action.action_id,
                success=True,
                backend=self.name,
                message=f"Forced password reset for '{user}'",
                details={"user": user},
            )

    def rollback(self, action: ResponseAction) -> ActionResult:
        target = action.target_entity
        with self._lock:
            if action.action_type == ActionType.ISOLATE_HOST:
                host = (target.get("host") or target.get("ip") or "").strip()
                removed = host in self.isolated_hosts
                self.isolated_hosts.discard(host)
                return ActionResult(
                    action_id=action.action_id,
                    success=removed,
                    backend=self.name,
                    message=f"Removed isolation on {host}" if removed else f"Host {host} not isolated",
                )
            if action.action_type == ActionType.DISABLE_ACCOUNT:
                user = (target.get("user") or "").strip()
                removed = user in self.disabled_accounts
                self.disabled_accounts.discard(user)
                return ActionResult(
                    action_id=action.action_id,
                    success=removed,
                    backend=self.name,
                    message=f"Re-enabled account '{user}'" if removed else f"Account '{user}' not disabled",
                )
            return super().rollback(action)


class MockWorkflowBackend(ActionBackend):
    """Simulated SOC/Email/Forensics workflow backend.

    Supports ``QUARANTINE_EMAIL``, ``PRESERVE_EVIDENCE``, ``ALERT_SOC``,
    ``ESCALATE``, and ``CUSTOM``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.recorded_events: list[dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "mock_workflow"

    @property
    def supported_actions(self) -> frozenset[ActionType]:
        return frozenset({
            ActionType.QUARANTINE_EMAIL,
            ActionType.PRESERVE_EVIDENCE,
            ActionType.ALERT_SOC,
            ActionType.ESCALATE,
            ActionType.CUSTOM,
        })

    def execute(self, action: ResponseAction) -> ActionResult:
        with self._lock:
            self.recorded_events.append({
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "title": action.title,
                "target": dict(action.target_entity),
            })
        return ActionResult(
            action_id=action.action_id,
            success=True,
            backend=self.name,
            message=f"Executed {action.action_type.value}: {action.title}",
            details={"target": dict(action.target_entity)},
        )


# ---------------------------------------------------------------------------
# Action Executor
# ---------------------------------------------------------------------------

class ActionExecutor:
    """Executes analyst-approved response actions through registered backends.

    Parameters
    ----------
    approval_manager : ApprovalManager
        Mandatory approval gate checked before every execution.
    backends : list[ActionBackend] | None
        Backends to register. Defaults to ``[MockFirewallBackend(),
        MockEDRBackend(), MockWorkflowBackend()]``.
    on_executed : callable, optional
        Optional callback invoked with ``(action, result)`` after execution.
    """

    def __init__(
        self,
        approval_manager: ApprovalManager,
        backends: Optional[list[ActionBackend]] = None,
        on_executed: Optional[Callable[[ResponseAction, ActionResult], None]] = None,
    ) -> None:
        if approval_manager is None:
            raise ValueError("approval_manager is required")

        self._approval_manager = approval_manager
        self._on_executed = on_executed
        self._lock = threading.RLock()

        self._backends: dict[ActionType, ActionBackend] = {}
        self._results: dict[str, ActionResult] = {}
        self._executed_actions: dict[str, ResponseAction] = {}
        self._audit_log: list[dict[str, Any]] = []

        default_backends = (
            backends
            if backends is not None
            else [MockFirewallBackend(), MockEDRBackend(), MockWorkflowBackend()]
        )
        for backend in default_backends:
            self.register_backend(backend)

    def register_backend(self, backend: ActionBackend) -> None:
        """Register an ``ActionBackend`` for its supported ``ActionType``s."""
        with self._lock:
            for action_type in backend.supported_actions:
                self._backends[action_type] = backend

    def get_backend(self, action_type: ActionType) -> Optional[ActionBackend]:
        """Return the registered backend for ``action_type``, if any."""
        with self._lock:
            return self._backends.get(action_type)

    def execute(self, action: ResponseAction) -> ActionResult:
        """Execute an action ONLY if it has an active analyst approval.

        Raises
        ------
        UnapprovedActionError
            If the action is not approved in ``ApprovalManager``.
        NoBackendAvailableError
            If no backend is registered for ``action.action_type``.
        """
        # MANDATORY HUMAN-IN-THE-LOOP CHECK (AGENTS.md guardrail)
        if not self._approval_manager.is_approved(action.action_id):
            self._record_audit(
                event="execution_blocked_unapproved",
                action=action,
                approver=None,
                success=False,
                message="Execution denied: missing analyst approval",
            )
            raise UnapprovedActionError(
                f"Cannot execute action '{action.action_id}' ({action.action_type.value}): "
                "explicit analyst approval is required."
            )

        decision = self._approval_manager.get_decision_for_action(action.action_id)
        approver = decision.decided_by if decision else "unknown"

        with self._lock:
            backend = self._backends.get(action.action_type)
            if backend is None:
                action.execution_status = ExecutionStatus.FAILED
                self._record_audit(
                    event="execution_failed_no_backend",
                    action=action,
                    approver=approver,
                    success=False,
                    message=f"No backend registered for {action.action_type.value}",
                )
                raise NoBackendAvailableError(
                    f"No backend registered for action type '{action.action_type.value}'"
                )

            action.execution_status = ExecutionStatus.EXECUTING

        try:
            result = backend.execute(action)
        except Exception as exc:
            logger.exception("Backend '%s' raised exception for action %s", backend.name, action.action_id)
            result = ActionResult(
                action_id=action.action_id,
                success=False,
                backend=backend.name,
                message=f"Backend execution error: {exc}",
            )

        with self._lock:
            action.execution_status = (
                ExecutionStatus.COMPLETED if result.success else ExecutionStatus.FAILED
            )
            self._results[action.action_id] = result
            self._executed_actions[action.action_id] = action
            self._record_audit(
                event="execution_completed" if result.success else "execution_failed",
                action=action,
                approver=approver,
                success=result.success,
                message=result.message,
                backend=result.backend,
            )

        if self._on_executed is not None:
            self._on_executed(action, result)

        return result

    def rollback(self, action_id: str, analyst_id: str) -> ActionResult:
        """Roll back a previously executed action (requires non-empty analyst_id)."""
        cleaned = (analyst_id or "").strip()
        if not cleaned:
            raise ValueError("analyst_id is required for rollback")

        with self._lock:
            action = self._executed_actions.get(action_id)
            if action is None:
                raise ExecutorError(f"Action '{action_id}' has not been executed")
            backend = self._backends.get(action.action_type)
            if backend is None:
                raise NoBackendAvailableError(
                    f"No backend registered for action type '{action.action_type.value}'"
                )

        result = backend.rollback(action)
        with self._lock:
            if result.success:
                action.execution_status = ExecutionStatus.ROLLED_BACK
            self._record_audit(
                event="execution_rolled_back" if result.success else "rollback_failed",
                action=action,
                approver=cleaned,
                success=result.success,
                message=result.message,
                backend=result.backend,
            )
        return result

    def get_result(self, action_id: str) -> Optional[ActionResult]:
        with self._lock:
            return self._results.get(action_id)

    def get_audit_log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._audit_log)

    def _record_audit(
        self,
        event: str,
        action: ResponseAction,
        approver: Optional[str],
        success: bool,
        message: str,
        backend: str = "",
    ) -> None:
        self._audit_log.append({
            "event": event,
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target_entity": dict(action.target_entity),
            "approved_by": approver,
            "backend": backend,
            "success": success,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

