"""
SOC Alert Manager — deduplication, prioritisation, and alert publishing.

Responsibilities:
1. **Deduplication**: Tracks which Incident IDs have already produced alerts
   and merges new events into existing alerts instead of creating duplicates.
2. **Prioritisation**: Uses risk score → priority bucket mapping (P1–P4) to
   sort alerts for analyst dashboards.
3. **Publishing**: Emits finished ``Alert`` objects to the ``alerts:soc``
   Redis Stream and (optionally) indexes them in OpenSearch.

The AlertManager is intentionally stateless-friendly: its deduplication map
can be rebuilt from OpenSearch on restart, though the in-memory fast path
handles the common case.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from src.soc.alerting.alert_model import Alert, AlertPriority, priority_from_score
from src.soc.correlation.incident_model import Incident
from src.soc.scoring.calculator import ScoreBreakdown, score_incident

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Alert Manager
# ---------------------------------------------------------------------------

class AlertManager:
    """Converts scored Incidents into deduplicated, prioritised Alerts.

    Parameters
    ----------
    on_alert : callable, optional
        Callback fired for every new or updated alert. Signature:
        ``(alert: Alert, is_new: bool) -> None``.  This is the hook for
        publishing to Redis Streams, OpenSearch, WebSocket, etc.
    min_score_to_alert : float
        Incidents scoring below this threshold produce no alert.
        Prevents noise from benign low-severity events.
    """

    def __init__(
        self,
        on_alert: Optional[Callable[[Alert, bool], None]] = None,
        min_score_to_alert: float = 15.0,
    ) -> None:
        self._on_alert = on_alert
        self._min_score = min_score_to_alert

        # Deduplication map: incident_id → Alert
        self._alerts_by_incident: dict[str, Alert] = {}

        # All alerts by alert_id for quick retrieval
        self._alerts: dict[str, Alert] = {}

    # ------------------------------------------------------------------
    # Core public method
    # ------------------------------------------------------------------

    def process_incident(self, incident: Incident) -> Optional[Alert]:
        """Score the incident and create/update an alert.

        Returns
        -------
        Alert if one was created or updated, ``None`` if the score was
        below ``min_score_to_alert``.
        """
        # 1. Score the incident
        score, breakdown = score_incident(incident)
        incident.risk_score = score

        # 2. Check threshold
        if score < self._min_score:
            logger.debug(
                "Incident %s scored %.1f (below threshold %.1f) — no alert",
                incident.incident_id,
                score,
                self._min_score,
            )
            return None

        # 3. Deduplicate: check if this incident already has an alert
        existing = self._alerts_by_incident.get(incident.incident_id)
        if existing is not None:
            alert = self._update_existing_alert(existing, incident, score, breakdown)
            is_new = False
        else:
            alert = self._create_new_alert(incident, score, breakdown)
            is_new = True

        # 4. Fire callback (publish to Redis, OpenSearch, etc.)
        if self._on_alert:
            self._on_alert(alert, is_new)

        return alert

    # ------------------------------------------------------------------
    # Alert creation and update
    # ------------------------------------------------------------------

    def _create_new_alert(
        self,
        incident: Incident,
        score: float,
        breakdown: ScoreBreakdown,
    ) -> Alert:
        """Build a fresh Alert from an Incident."""
        priority = priority_from_score(score)

        alert = Alert(
            title=incident.title,
            description=self._build_description(incident, breakdown),
            priority=priority,
            severity=incident.severity,
            risk_score=score,
            score_breakdown=breakdown.to_dict(),
            incident_id=incident.incident_id,
            primary_entity=incident.primary_entity,
            event_count=incident.event_count,
            event_ids=list(incident.event_ids),
            rule_ids=[rm.rule_id for rm in incident.rule_matches],
            mitre_tactics=list(incident.mitre_tactics),
            mitre_techniques=list(incident.mitre_techniques),
            tags=list(incident.tags),
        )

        # Store for dedup
        self._alerts_by_incident[incident.incident_id] = alert
        self._alerts[alert.alert_id] = alert

        logger.info(
            "Created alert %s [%s] score=%.1f for incident %s",
            alert.alert_id,
            priority,
            score,
            incident.incident_id,
        )
        return alert

    def _update_existing_alert(
        self,
        alert: Alert,
        incident: Incident,
        score: float,
        breakdown: ScoreBreakdown,
    ) -> Alert:
        """Merge updated incident data into an existing alert (dedup path)."""
        alert.risk_score = score
        alert.score_breakdown = breakdown.to_dict()
        alert.priority = priority_from_score(score)
        alert.severity = incident.severity
        alert.event_count = incident.event_count
        alert.event_ids = list(incident.event_ids)
        alert.rule_ids = [rm.rule_id for rm in incident.rule_matches]
        alert.mitre_tactics = list(incident.mitre_tactics)
        alert.mitre_techniques = list(incident.mitre_techniques)
        alert.tags = list(incident.tags)
        alert.description = self._build_description(incident, breakdown)
        alert.updated_at = datetime.now(timezone.utc)

        logger.info(
            "Updated alert %s [%s] score=%.1f (incident %s now has %d events)",
            alert.alert_id,
            alert.priority,
            score,
            incident.incident_id,
            incident.event_count,
        )
        return alert

    # ------------------------------------------------------------------
    # Description builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_description(incident: Incident, breakdown: ScoreBreakdown) -> str:
        """Build an analyst-facing narrative from the incident and score."""
        parts: list[str] = []

        # Entity summary
        entity = incident.primary_entity
        entity_parts: list[str] = []
        if entity.ip:
            entity_parts.append(f"IP {entity.ip}")
        if entity.user:
            entity_parts.append(f"user '{entity.user}'")
        if entity.host:
            entity_parts.append(f"host '{entity.host}'")
        if entity_parts:
            parts.append(f"Entity: {', '.join(entity_parts)}")

        # Event count
        parts.append(f"{incident.event_count} correlated event(s)")

        # MITRE mapping
        if incident.mitre_techniques:
            techs = ", ".join(incident.mitre_techniques)
            parts.append(f"MITRE techniques: {techs}")

        # Score explanation
        parts.append(f"Score: {breakdown.explain()}")

        return " | ".join(parts)

    # ------------------------------------------------------------------
    # Retrieval helpers
    # ------------------------------------------------------------------

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Look up an alert by its ID."""
        return self._alerts.get(alert_id)

    def get_alert_for_incident(self, incident_id: str) -> Optional[Alert]:
        """Look up the alert linked to a specific incident."""
        return self._alerts_by_incident.get(incident_id)

    def get_all_alerts(self, sort_by_score: bool = True) -> list[Alert]:
        """Return all active alerts, optionally sorted by risk score descending."""
        alerts = list(self._alerts.values())
        if sort_by_score:
            alerts.sort(key=lambda a: a.risk_score, reverse=True)
        return alerts

    def get_alerts_by_priority(self, priority: AlertPriority) -> list[Alert]:
        """Return alerts filtered by priority bucket."""
        return [a for a in self._alerts.values() if a.priority == priority]

    @property
    def alert_count(self) -> int:
        """Total number of tracked alerts."""
        return len(self._alerts)

    @property
    def stats(self) -> dict[str, Any]:
        """Summary statistics for monitoring/dashboard widgets."""
        priorities: dict[str, int] = {}
        for alert in self._alerts.values():
            priorities[alert.priority] = priorities.get(alert.priority, 0) + 1
        return {
            "total_alerts": self.alert_count,
            "by_priority": priorities,
        }
