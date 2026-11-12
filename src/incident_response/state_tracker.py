"""
Incident State Tracker — finite state machine and audit log for incident lifecycle.

Tracks incidents through the Incident Response phases:
    NEW -> INVESTIGATING -> CONTAINING -> CONTAINED -> REMEDIATING -> REMEDIATED -> CLOSED

Every transition is validated against an explicit transition table and
recorded in an immutable per-incident audit history with actor, reason,
and UTC timestamp.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from src.incident_response.models import (
    IncidentPhase,
    IncidentStateTransition,
)

logger = logging.getLogger(__name__)


class StateTrackerError(Exception):
    """Base exception for IncidentStateTracker errors."""


class IncidentNotTrackedError(StateTrackerError):
    """Raised when querying or transitioning an unregistered incident."""


class InvalidStateTransitionError(StateTrackerError):
    """Raised when a requested phase transition is not permitted."""


# Valid finite state machine transitions.
ALLOWED_TRANSITIONS: dict[IncidentPhase, frozenset[IncidentPhase]] = {
    IncidentPhase.NEW: frozenset({
        IncidentPhase.INVESTIGATING,
        IncidentPhase.CONTAINING,
        IncidentPhase.CLOSED,
    }),
    IncidentPhase.INVESTIGATING: frozenset({
        IncidentPhase.CONTAINING,
        IncidentPhase.CONTAINED,
        IncidentPhase.REMEDIATING,
        IncidentPhase.CLOSED,
    }),
    IncidentPhase.CONTAINING: frozenset({
        IncidentPhase.CONTAINED,
        IncidentPhase.INVESTIGATING,
        IncidentPhase.CLOSED,
    }),
    IncidentPhase.CONTAINED: frozenset({
        IncidentPhase.REMEDIATING,
        IncidentPhase.REMEDIATED,
        IncidentPhase.CONTAINING,
        IncidentPhase.CLOSED,
    }),
    IncidentPhase.REMEDIATING: frozenset({
        IncidentPhase.REMEDIATED,
        IncidentPhase.CONTAINING,
        IncidentPhase.CLOSED,
    }),
    IncidentPhase.REMEDIATED: frozenset({
        IncidentPhase.CLOSED,
        IncidentPhase.INVESTIGATING,
    }),
    IncidentPhase.CLOSED: frozenset({
        IncidentPhase.INVESTIGATING,
    }),
}


class IncidentStateTracker:
    """Thread-safe incident lifecycle state machine with transition audit log.

    Parameters
    ----------
    on_transition : callable, optional
        Optional callback invoked with ``IncidentStateTransition`` on every
        state change.
    """

    def __init__(
        self,
        on_transition: Optional[Callable[[IncidentStateTransition], None]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._on_transition = on_transition
        self._phases: dict[str, IncidentPhase] = {}
        self._history: dict[str, list[IncidentStateTransition]] = {}
        self._plan_ids: dict[str, list[str]] = {}
        self._executed_action_ids: dict[str, list[str]] = {}

    def register_incident(
        self,
        incident_id: str,
        initial_phase: IncidentPhase = IncidentPhase.NEW,
        actor: str = "system",
        reason: str = "Incident registered in response tracker",
    ) -> IncidentPhase:
        """Register an incident in the tracker (idempotent if already tracked)."""
        with self._lock:
            if incident_id in self._phases:
                return self._phases[incident_id]
            self._phases[incident_id] = initial_phase
            self._history[incident_id] = [
                IncidentStateTransition(
                    incident_id=incident_id,
                    from_phase=initial_phase,
                    to_phase=initial_phase,
                    transitioned_by=actor,
                    reason=reason,
                )
            ]
            self._plan_ids[incident_id] = []
            self._executed_action_ids[incident_id] = []
        return initial_phase

    def is_tracked(self, incident_id: str) -> bool:
        with self._lock:
            return incident_id in self._phases

    def transition(
        self,
        incident_id: str,
        to_phase: IncidentPhase,
        actor: str = "system",
        reason: str = "",
        metadata: Optional[dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> IncidentStateTransition:
        """Transition an incident to ``to_phase`` if permitted by the FSM."""
        ts = now or datetime.now(timezone.utc)
        cleaned_actor = (actor or "system").strip() or "system"

        with self._lock:
            if incident_id not in self._phases:
                raise IncidentNotTrackedError(
                    f"Incident '{incident_id}' is not registered in state tracker"
                )
            from_phase = self._phases[incident_id]
            if from_phase == to_phase:
                raise InvalidStateTransitionError(
                    f"Incident '{incident_id}' is already in phase '{to_phase.value}'"
                )

            allowed = ALLOWED_TRANSITIONS.get(from_phase, frozenset())
            if to_phase not in allowed:
                raise InvalidStateTransitionError(
                    f"Transition from '{from_phase.value}' to '{to_phase.value}' "
                    f"is not permitted for incident '{incident_id}'"
                )

            record = IncidentStateTransition(
                incident_id=incident_id,
                from_phase=from_phase,
                to_phase=to_phase,
                transitioned_at=ts,
                transitioned_by=cleaned_actor,
                reason=reason,
                metadata=dict(metadata or {}),
            )
            self._phases[incident_id] = to_phase
            self._history[incident_id].append(record)

        logger.info(
            "Incident %s transitioned %s -> %s by %s",
            incident_id, from_phase.value, to_phase.value, cleaned_actor,
        )

        if self._on_transition is not None:
            self._on_transition(record)

        return record

    def link_plan(self, incident_id: str, plan_id: str) -> None:
        """Record a ResponsePlan ID associated with this incident."""
        with self._lock:
            if incident_id not in self._phases:
                self.register_incident(incident_id)
            if plan_id not in self._plan_ids[incident_id]:
                self._plan_ids[incident_id].append(plan_id)

    def record_executed_action(self, incident_id: str, action_id: str) -> None:
        """Record an executed containment action ID for this incident."""
        with self._lock:
            if incident_id not in self._phases:
                self.register_incident(incident_id)
            if action_id not in self._executed_action_ids[incident_id]:
                self._executed_action_ids[incident_id].append(action_id)

    def get_phase(self, incident_id: str) -> IncidentPhase:
        with self._lock:
            if incident_id not in self._phases:
                raise IncidentNotTrackedError(
                    f"Incident '{incident_id}' is not registered in state tracker"
                )
            return self._phases[incident_id]

    def get_history(self, incident_id: str) -> list[IncidentStateTransition]:
        with self._lock:
            if incident_id not in self._history:
                raise IncidentNotTrackedError(
                    f"Incident '{incident_id}' is not registered in state tracker"
                )
            return list(self._history[incident_id])

    def get_incident_record(self, incident_id: str) -> dict[str, Any]:
        """Return full state, linked plans, executed actions, and history."""
        with self._lock:
            if incident_id not in self._phases:
                raise IncidentNotTrackedError(
                    f"Incident '{incident_id}' is not registered in state tracker"
                )
            return {
                "incident_id": incident_id,
                "phase": self._phases[incident_id].value,
                "plan_ids": list(self._plan_ids[incident_id]),
                "executed_action_ids": list(self._executed_action_ids[incident_id]),
                "transitions": [t.model_dump(mode="json") for t in self._history[incident_id]],
            }

    def list_incidents(
        self, phase: Optional[IncidentPhase] = None
    ) -> dict[str, IncidentPhase]:
        with self._lock:
            if phase is None:
                return dict(self._phases)
            return {k: v for k, v in self._phases.items() if v == phase}

    def get_summary(self) -> dict[str, int]:
        """Return incident counts per phase."""
        counts = {p.value: 0 for p in IncidentPhase}
        with self._lock:
            for phase in self._phases.values():
                counts[phase.value] += 1
        return counts

