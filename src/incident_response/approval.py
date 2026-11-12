"""
Approval Workflow — mandatory analyst sign-off gate for Incident Response.

All containment and response actions produced by ``ResponseRecommender``
must pass through ``ApprovalManager`` before ``ActionExecutor`` can run
them (AGENTS.md guardrail & ARCHITECTURE.md §4.8 / §8).

Key guarantees:
  - Explicit human analyst identity required (rejects empty or automated
    identities such as ``system``, ``copilot``, ``ai``, ``autonomous``).
  - Thread-safe request and decision tracking with TTL expiration.
  - Double-decision protection (cannot approve/reject an already decided
    or expired request).
  - Immutable append-only audit log of every request, decision, and expiry.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from src.incident_response.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ExecutionStatus,
    ResponseAction,
    ResponsePlan,
)

logger = logging.getLogger(__name__)

# Identities that are explicitly blocked from approving containment actions.
_DISALLOWED_APPROVER_IDENTITIES = frozenset({
    "",
    "system",
    "copilot",
    "ai",
    "ai_copilot",
    "autonomous",
    "auto",
    "bot",
})


class ApprovalError(Exception):
    """Base exception for approval workflow errors."""


class ApprovalNotFoundError(ApprovalError):
    """Raised when an approval request ID cannot be found."""


class InvalidApprovalStateError(ApprovalError):
    """Raised when attempting to decide a non-pending approval request."""


class ApprovalExpiredError(ApprovalError):
    """Raised when attempting to decide an expired approval request."""


class InvalidApproverError(ApprovalError):
    """Raised when an approver identity is missing or non-human."""


class DuplicateApprovalRequestError(ApprovalError):
    """Raised when an active approval request already exists for an action."""


def _default_ttl_seconds() -> int:
    raw = os.getenv("IR_APPROVAL_TTL_SECONDS", "3600")
    try:
        val = int(raw)
        return val if val > 0 else 3600
    except ValueError:
        return 3600


class ApprovalManager:
    """Manages analyst approval requests and decisions for response actions.

    Parameters
    ----------
    default_ttl_seconds : int | None
        Default lifetime for pending approval requests before expiration.
        Falls back to ``IR_APPROVAL_TTL_SECONDS`` env var (default 3600s).
    on_decision : callable, optional
        Optional callback invoked with ``(request, decision)`` whenever an
        analyst approves or rejects a request.
    """

    def __init__(
        self,
        default_ttl_seconds: Optional[int] = None,
        on_decision: Optional[Callable[[ApprovalRequest, ApprovalDecision], None]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._default_ttl = (
            default_ttl_seconds if default_ttl_seconds is not None else _default_ttl_seconds()
        )
        self._on_decision = on_decision

        self._requests: dict[str, ApprovalRequest] = {}
        self._requests_by_action: dict[str, str] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._audit_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Request creation
    # ------------------------------------------------------------------

    def request_approval(
        self,
        action: ResponseAction,
        incident_id: str,
        plan_id: str,
        ttl_seconds: Optional[int] = None,
        now: Optional[datetime] = None,
    ) -> ApprovalRequest:
        """Create a pending ``ApprovalRequest`` for a single ``ResponseAction``."""
        if not action.requires_approval:
            raise ApprovalError("Action must have requires_approval=True")

        ts = now or datetime.now(timezone.utc)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        if ttl <= 0:
            raise ValueError("ttl_seconds must be positive")

        with self._lock:
            existing_id = self._requests_by_action.get(action.action_id)
            if existing_id is not None:
                existing = self._requests[existing_id]
                if existing.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
                    raise DuplicateApprovalRequestError(
                        f"Active approval request '{existing_id}' already exists "
                        f"for action '{action.action_id}'"
                    )

            req = ApprovalRequest(
                action_id=action.action_id,
                incident_id=incident_id,
                plan_id=plan_id,
                action_type=action.action_type,
                action_title=action.title,
                action_description=action.description,
                target_entity=dict(action.target_entity),
                status=ApprovalStatus.PENDING,
                requested_at=ts,
                expires_at=ts + timedelta(seconds=ttl),
            )
            self._requests[req.request_id] = req
            self._requests_by_action[action.action_id] = req.request_id
            self._record_audit(
                event="approval_requested",
                request=req,
                actor="system",
                reason=f"Requested approval for {action.action_type.value}",
                timestamp=ts,
            )

        logger.info(
            "Created approval request %s for action %s (incident %s)",
            req.request_id, action.action_id, incident_id,
        )
        return req

    def request_plan_approvals(
        self,
        plan: ResponsePlan,
        ttl_seconds: Optional[int] = None,
        now: Optional[datetime] = None,
    ) -> list[ApprovalRequest]:
        """Create approval requests for every action in a ``ResponsePlan``."""
        created: list[ApprovalRequest] = []
        for action in plan.actions:
            req = self.request_approval(
                action=action,
                incident_id=plan.incident_id,
                plan_id=plan.plan_id,
                ttl_seconds=ttl_seconds,
                now=now,
            )
            created.append(req)
        return created

    # ------------------------------------------------------------------
    # Analyst decisions
    # ------------------------------------------------------------------

    def approve(
        self,
        request_id: str,
        analyst_id: str,
        reason: str = "",
        now: Optional[datetime] = None,
        action: Optional[ResponseAction] = None,
    ) -> ApprovalDecision:
        """Record an analyst's approval for a pending request."""
        return self._decide(
            request_id=request_id,
            status="approved",
            analyst_id=analyst_id,
            reason=reason,
            now=now,
            action=action,
        )

    def reject(
        self,
        request_id: str,
        analyst_id: str,
        reason: str = "",
        now: Optional[datetime] = None,
        action: Optional[ResponseAction] = None,
    ) -> ApprovalDecision:
        """Record an analyst's rejection for a pending request."""
        return self._decide(
            request_id=request_id,
            status="rejected",
            analyst_id=analyst_id,
            reason=reason,
            now=now,
            action=action,
        )

    def _decide(
        self,
        request_id: str,
        status: str,
        analyst_id: str,
        reason: str,
        now: Optional[datetime],
        action: Optional[ResponseAction],
    ) -> ApprovalDecision:
        cleaned_analyst = (analyst_id or "").strip()
        if cleaned_analyst.lower() in _DISALLOWED_APPROVER_IDENTITIES:
            raise InvalidApproverError(
                f"Approver identity '{analyst_id}' is not permitted; "
                "explicit human analyst identity is required."
            )

        ts = now or datetime.now(timezone.utc)
        callback_req: Optional[ApprovalRequest] = None
        callback_dec: Optional[ApprovalDecision] = None

        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                raise ApprovalNotFoundError(f"Approval request '{request_id}' not found")

            if req.status == ApprovalStatus.EXPIRED:
                raise ApprovalExpiredError(
                    f"Approval request '{request_id}' has already expired"
                )

            if req.status != ApprovalStatus.PENDING:
                raise InvalidApprovalStateError(
                    f"Approval request '{request_id}' is already {req.status.value}"
                )

            if req.expires_at is not None and ts >= req.expires_at:
                req.status = ApprovalStatus.EXPIRED
                self._record_audit(
                    event="approval_expired",
                    request=req,
                    actor="system",
                    reason="Request expired before analyst decision",
                    timestamp=ts,
                )
                raise ApprovalExpiredError(
                    f"Approval request '{request_id}' expired at {req.expires_at.isoformat()}"
                )

            new_status = (
                ApprovalStatus.APPROVED if status == "approved" else ApprovalStatus.REJECTED
            )
            req.status = new_status
            req.decided_at = ts
            req.decided_by = cleaned_analyst
            req.decision_reason = reason

            decision = ApprovalDecision(
                request_id=req.request_id,
                status="approved" if status == "approved" else "rejected",
                decided_by=cleaned_analyst,
                decided_at=ts,
                reason=reason,
            )
            self._decisions[req.request_id] = decision

            if action is not None and action.action_id == req.action_id:
                if new_status == ApprovalStatus.APPROVED:
                    action.execution_status = ExecutionStatus.APPROVED
                else:
                    action.execution_status = ExecutionStatus.SKIPPED

            self._record_audit(
                event=f"approval_{decision.status}",
                request=req,
                actor=cleaned_analyst,
                reason=reason,
                timestamp=ts,
            )

            callback_req = req
            callback_dec = decision

        logger.info(
            "Approval request %s %s by %s",
            request_id, decision.status, cleaned_analyst,
        )

        if self._on_decision is not None and callback_req is not None and callback_dec is not None:
            self._on_decision(callback_req, callback_dec)

        return decision

    # ------------------------------------------------------------------
    # Expiration & Queries
    # ------------------------------------------------------------------

    def expire_stale(self, now: Optional[datetime] = None) -> list[ApprovalRequest]:
        """Mark any pending requests past ``expires_at`` as ``EXPIRED``."""
        ts = now or datetime.now(timezone.utc)
        expired: list[ApprovalRequest] = []
        with self._lock:
            for req in self._requests.values():
                if (
                    req.status == ApprovalStatus.PENDING
                    and req.expires_at is not None
                    and ts >= req.expires_at
                ):
                    req.status = ApprovalStatus.EXPIRED
                    self._record_audit(
                        event="approval_expired",
                        request=req,
                        actor="system",
                        reason="Approval request TTL exceeded",
                        timestamp=ts,
                    )
                    expired.append(req)
        return expired

    def is_approved(self, action_id: str) -> bool:
        """Return True iff the action has an active ``APPROVED`` decision."""
        with self._lock:
            req_id = self._requests_by_action.get(action_id)
            if req_id is None:
                return False
            req = self._requests.get(req_id)
            if req is None or req.status != ApprovalStatus.APPROVED:
                return False
            dec = self._decisions.get(req_id)
            return dec is not None and dec.status == "approved"

    def get_decision_for_action(self, action_id: str) -> Optional[ApprovalDecision]:
        """Return the ``ApprovalDecision`` for an action if one exists."""
        with self._lock:
            req_id = self._requests_by_action.get(action_id)
            if req_id is None:
                return None
            return self._decisions.get(req_id)

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Retrieve an ``ApprovalRequest`` by ID."""
        with self._lock:
            return self._requests.get(request_id)

    def get_request_for_action(self, action_id: str) -> Optional[ApprovalRequest]:
        """Retrieve the latest ``ApprovalRequest`` for a given action ID."""
        with self._lock:
            req_id = self._requests_by_action.get(action_id)
            if req_id is None:
                return None
            return self._requests.get(req_id)

    def list_requests(
        self,
        incident_id: Optional[str] = None,
        status: Optional[ApprovalStatus] = None,
    ) -> list[ApprovalRequest]:
        """List approval requests, optionally filtered by incident or status."""
        with self._lock:
            results = list(self._requests.values())
            if incident_id is not None:
                results = [r for r in results if r.incident_id == incident_id]
            if status is not None:
                results = [r for r in results if r.status == status]
            return results

    def list_pending(
        self,
        incident_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> list[ApprovalRequest]:
        """Expire stale requests and return all currently pending requests."""
        self.expire_stale(now=now)
        return self.list_requests(incident_id=incident_id, status=ApprovalStatus.PENDING)

    def get_audit_log(self, incident_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Return a copy of the append-only approval audit log."""
        with self._lock:
            if incident_id is None:
                return list(self._audit_log)
            return [e for e in self._audit_log if e.get("incident_id") == incident_id]

    def _record_audit(
        self,
        event: str,
        request: ApprovalRequest,
        actor: str,
        reason: str,
        timestamp: datetime,
    ) -> None:
        self._audit_log.append({
            "event": event,
            "request_id": request.request_id,
            "action_id": request.action_id,
            "incident_id": request.incident_id,
            "action_type": request.action_type.value,
            "actor": actor,
            "reason": reason,
            "timestamp": timestamp.isoformat(),
        })

