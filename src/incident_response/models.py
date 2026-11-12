"""
Data models for the Incident Response module.

Defines the core abstractions: response playbooks, individual response
actions, response plans, approval requests/decisions, action execution
results, and incident state machine entries.

All response actions carry ``requires_approval = True`` by default and
cannot be set to False (AGENTS.md guardrail: no fully autonomous
containment).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    """Categories of containment / response actions."""
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_EMAIL = "quarantine_email"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    FORCE_PASSWORD_RESET = "force_password_reset"
    BLOCK_EGRESS = "block_egress"
    PRESERVE_EVIDENCE = "preserve_evidence"
    SCAN_HOST = "scan_host"
    ALERT_SOC = "alert_soc"
    ESCALATE = "escalate"
    CUSTOM = "custom"


class ActionPriority(str, Enum):
    """Urgency of the recommended action."""
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ApprovalStatus(str, Enum):
    """Lifecycle state of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ExecutionStatus(str, Enum):
    """Lifecycle state of an action execution."""
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


class IncidentPhase(str, Enum):
    """Incident lifecycle state machine phases."""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    CONTAINED = "contained"
    REMEDIATING = "remediating"
    REMEDIATED = "remediated"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Response Recommendation Models
# ---------------------------------------------------------------------------

class ResponseAction(BaseModel):
    """A single recommended response action.

    INVARIANT: ``requires_approval`` is always ``True``.
    The field_validator rejects any attempt to set it to False.
    """

    action_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this action recommendation",
    )
    action_type: ActionType = Field(
        ..., description="Category of response action",
    )
    title: str = Field(
        ..., description="Short human-readable action title",
    )
    description: str = Field(
        default="", description="Detailed explanation of what this action does",
    )
    priority: ActionPriority = Field(
        default=ActionPriority.MEDIUM,
        description="Urgency ranking for triage ordering",
    )
    target_entity: dict[str, str] = Field(
        default_factory=dict,
        description="Target of the action, e.g. {'ip': '10.0.0.1'} or {'user': 'jdoe'}",
    )
    mitre_technique: str = Field(
        default="",
        description="MITRE ATT&CK technique this action addresses (e.g. T1110)",
    )
    mitre_tactic: str = Field(
        default="",
        description="MITRE ATT&CK tactic this action addresses",
    )
    requires_approval: bool = Field(
        default=True,
        description="Whether analyst approval is required (always True)",
    )
    execution_status: ExecutionStatus = Field(
        default=ExecutionStatus.PENDING_APPROVAL,
        description="Current execution lifecycle state",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context for action execution backends",
    )

    @field_validator("requires_approval")
    @classmethod
    def _enforce_approval_required(cls, v: bool) -> bool:
        """AGENTS.md guardrail: containment actions MUST require approval."""
        if not v:
            raise ValueError(
                "requires_approval must be True. "
                "Autonomous containment is prohibited (AGENTS.md guardrail)."
            )
        return True


class ResponsePlaybook(BaseModel):
    """A declarative playbook mapping incident characteristics to response actions.

    Playbooks define pattern-matching criteria (incident types, MITRE
    techniques, severity levels, source modalities) and the ordered list of
    response actions that should be recommended when a match is found.
    """

    playbook_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique playbook identifier",
    )
    name: str = Field(
        ..., description="Short playbook name (e.g. 'Brute Force Response')",
    )
    description: str = Field(
        default="", description="Human-readable description of the playbook",
    )
    # --- Matching criteria ---
    match_event_types: list[str] = Field(
        default_factory=list,
        description="Event type patterns to match (substring matching)",
    )
    match_mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE technique IDs that trigger this playbook",
    )
    match_mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE tactic names that trigger this playbook",
    )
    match_sources: list[str] = Field(
        default_factory=list,
        description="Source modalities (soc, honeypot, phishing, forensics)",
    )
    match_severity_min: Literal["low", "medium", "high", "critical"] = Field(
        default="low",
        description="Minimum severity required for this playbook to apply",
    )
    match_tags: list[str] = Field(
        default_factory=list,
        description="Tags that trigger this playbook (substring matching)",
    )
    # --- Actions template ---
    actions: list[ResponseAction] = Field(
        default_factory=list,
        description="Ordered list of response actions to recommend",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this playbook is active",
    )


class ResponsePlan(BaseModel):
    """An ordered collection of recommended response actions for an incident.

    Produced by the ResponseRecommender when evaluating an incident against
    the loaded playbooks.
    """

    plan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique plan identifier",
    )
    incident_id: str = Field(
        ..., description="ID of the incident this plan addresses",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the plan was generated",
    )
    matched_playbooks: list[str] = Field(
        default_factory=list,
        description="Names of playbooks that matched and contributed actions",
    )
    actions: list[ResponseAction] = Field(
        default_factory=list,
        description="Ordered list of recommended response actions",
    )
    incident_severity: Literal["low", "medium", "high", "critical"] = Field(
        default="medium",
        description="Severity of the incident at plan creation time",
    )
    incident_risk_score: float = Field(
        default=0.0,
        description="Risk score of the incident at plan creation time",
    )
    summary: str = Field(
        default="",
        description="Human-readable summary of the response plan",
    )

    @property
    def action_count(self) -> int:
        return len(self.actions)

    @property
    def has_immediate_actions(self) -> bool:
        return any(a.priority == ActionPriority.IMMEDIATE for a in self.actions)


# ---------------------------------------------------------------------------
# Approval Models
# ---------------------------------------------------------------------------

class ApprovalRequest(BaseModel):
    """A request for analyst approval of a specific response action."""

    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique approval request identifier",
    )
    action_id: str = Field(
        ..., description="ID of the ResponseAction requiring approval",
    )
    incident_id: str = Field(
        ..., description="ID of the associated incident",
    )
    plan_id: str = Field(
        ..., description="ID of the response plan containing this action",
    )
    action_type: ActionType = Field(
        ..., description="Type of action being requested",
    )
    action_title: str = Field(
        ..., description="Human-readable title of the action",
    )
    action_description: str = Field(
        default="", description="Detailed description of the action",
    )
    target_entity: dict[str, str] = Field(
        default_factory=dict,
        description="Target of the action",
    )
    status: ApprovalStatus = Field(
        default=ApprovalStatus.PENDING,
        description="Current approval status",
    )
    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the approval was requested",
    )
    decided_at: Optional[datetime] = Field(
        default=None,
        description="When the approval decision was made",
    )
    decided_by: Optional[str] = Field(
        default=None,
        description="Identity of the analyst who approved/rejected",
    )
    decision_reason: str = Field(
        default="",
        description="Analyst's reason for approving or rejecting",
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="When this approval request expires if not acted upon",
    )


class ApprovalDecision(BaseModel):
    """An analyst's decision on an approval request."""

    request_id: str = Field(
        ..., description="ID of the approval request being decided",
    )
    status: Literal["approved", "rejected"] = Field(
        ..., description="The decision",
    )
    decided_by: str = Field(
        ..., description="Analyst identity making the decision",
    )
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the decision",
    )
    reason: str = Field(
        default="", description="Reason for the decision",
    )


# ---------------------------------------------------------------------------
# Action Execution Models
# ---------------------------------------------------------------------------

class ActionResult(BaseModel):
    """Result of executing a response action."""

    action_id: str = Field(
        ..., description="ID of the executed action",
    )
    success: bool = Field(
        ..., description="Whether the action executed successfully",
    )
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of execution",
    )
    backend: str = Field(
        default="", description="Name of the backend that executed the action",
    )
    message: str = Field(
        default="", description="Human-readable result message",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Backend-specific execution details",
    )


# ---------------------------------------------------------------------------
# Incident State Tracking Models
# ---------------------------------------------------------------------------

class IncidentStateTransition(BaseModel):
    """A record of an incident state change in the audit log."""

    transition_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique transition record ID",
    )
    incident_id: str = Field(
        ..., description="ID of the incident",
    )
    from_phase: IncidentPhase = Field(
        ..., description="Previous phase",
    )
    to_phase: IncidentPhase = Field(
        ..., description="New phase",
    )
    transitioned_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the transition occurred",
    )
    transitioned_by: str = Field(
        default="system",
        description="Who/what triggered the transition",
    )
    reason: str = Field(
        default="",
        description="Reason for the transition",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context about the transition",
    )

