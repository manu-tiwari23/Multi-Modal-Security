"""
Incident Response module for Multi Modal Security (MMS).

Provides response recommendation, approval workflow, action execution,
and incident state tracking.  All containment actions require explicit
analyst approval before execution (AGENTS.md guardrail).
"""

from src.incident_response.approval import (
    ApprovalError,
    ApprovalExpiredError,
    ApprovalManager,
    ApprovalNotFoundError,
    DuplicateApprovalRequestError,
    InvalidApprovalStateError,
    InvalidApproverError,
)
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
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ExecutionStatus,
    IncidentPhase,
    IncidentStateTransition,
    ResponseAction,
    ResponsePlan,
    ResponsePlaybook,
)
from src.incident_response.recommender import ResponseRecommender
from src.incident_response.state_tracker import (
    ALLOWED_TRANSITIONS,
    IncidentNotTrackedError,
    IncidentStateTracker,
    InvalidStateTransitionError,
    StateTrackerError,
)

__all__ = [
    "ALLOWED_TRANSITIONS",
    "ActionBackend",
    "ActionExecutor",
    "ActionPriority",
    "ActionResult",
    "ActionType",
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalExpiredError",
    "ApprovalManager",
    "ApprovalNotFoundError",
    "ApprovalRequest",
    "ApprovalStatus",
    "DuplicateApprovalRequestError",
    "ExecutionStatus",
    "ExecutorError",
    "IncidentNotTrackedError",
    "IncidentPhase",
    "IncidentStateTracker",
    "IncidentStateTransition",
    "InvalidApprovalStateError",
    "InvalidApproverError",
    "InvalidStateTransitionError",
    "MockEDRBackend",
    "MockFirewallBackend",
    "MockWorkflowBackend",
    "NoBackendAvailableError",
    "ResponseAction",
    "ResponsePlan",
    "ResponsePlaybook",
    "ResponseRecommender",
    "StateTrackerError",
    "UnapprovedActionError",
]
