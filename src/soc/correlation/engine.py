"""
Correlation Engine: groups related SecurityEvents and RuleMatches into unified Incidents
using sliding-window entity linking (IP, user, host, hash).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from src.shared.event_schema import Entity, SecurityEvent, SeverityLevel
from src.soc.correlation.incident_model import Incident, IncidentStatus, IncidentTimelineEntry
from src.soc.detection.rule_model import RuleMatch

logger = logging.getLogger(__name__)

SEVERITY_RANKS: dict[SeverityLevel, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _max_severity(s1: SeverityLevel, s2: SeverityLevel) -> SeverityLevel:
    """Return the higher of two severity levels."""
    return s1 if SEVERITY_RANKS.get(s1, 1) >= SEVERITY_RANKS.get(s2, 1) else s2


def _extract_entity_keys(entity: Entity | None) -> list[str]:
    """Extract indexed lookup keys from an Entity."""
    if not entity:
        return []
    keys: list[str] = []
    if entity.ip and entity.ip.strip() and entity.ip != "unknown":
        keys.append(f"ip:{entity.ip.strip().lower()}")
    if entity.user and entity.user.strip() and entity.user != "unknown":
        keys.append(f"user:{entity.user.strip().lower()}")
    if entity.host and entity.host.strip() and entity.host != "unknown":
        keys.append(f"host:{entity.host.strip().lower()}")
    if entity.hash and entity.hash.strip():
        keys.append(f"hash:{entity.hash.strip().lower()}")
    return keys


class CorrelationEngine:
    """
    Stateful correlation engine linking events across sources and detection rules
    within a sliding time window.
    """

    def __init__(self, correlation_window_seconds: int = 300) -> None:
        self.correlation_window = correlation_window_seconds
        self._incidents: dict[str, Incident] = {}
        # Maps entity key (e.g. 'ip:192.168.1.100') -> incident_id
        self._entity_map: dict[str, str] = {}

    @property
    def active_incidents(self) -> list[Incident]:
        """Return list of all currently open/investigating incidents."""
        return [inc for inc in self._incidents.values() if inc.status in ("open", "investigating")]

    @property
    def active_incident_count(self) -> int:
        """Return total count of active open/investigating incidents."""
        return len(self.active_incidents)

    def get_incident(self, incident_id: str) -> Incident | None:
        """Get an incident by ID."""
        return self._incidents.get(incident_id)

    def list_incidents(self, status: IncidentStatus | None = None) -> list[Incident]:
        """List all incidents, optionally filtered by status."""
        if status:
            return [inc for inc in self._incidents.values() if inc.status == status]
        return list(self._incidents.values())

    def close_incident(self, incident_id: str) -> bool:
        """Close an incident and unregister its entity mapping."""
        inc = self._incidents.get(incident_id)
        if not inc:
            return False
        inc.status = "closed"
        inc.updated_at = datetime.now(timezone.utc)
        # Clear entity mappings pointing to this closed incident
        keys_to_remove = [k for k, v in self._entity_map.items() if v == incident_id]
        for k in keys_to_remove:
            del self._entity_map[k]
        return True

    def _find_matching_incident(
        self,
        entity_keys: list[str],
        event_time: datetime,
    ) -> Incident | None:
        """
        Check if any entity key matches an active incident within the correlation window.
        """
        for key in entity_keys:
            inc_id = self._entity_map.get(key)
            if not inc_id:
                continue

            incident = self._incidents.get(inc_id)
            if not incident or incident.status not in ("open", "investigating"):
                continue

            # Check sliding window
            delta_sec = abs((event_time - incident.updated_at).total_seconds())
            if delta_sec <= self.correlation_window:
                return incident

        return None

    def _create_timeline_entry(
        self,
        event: SecurityEvent,
        rule_matches: list[RuleMatch] | None = None,
    ) -> IncidentTimelineEntry:
        """Construct a timeline entry from a security event and optional matches."""
        desc = f"Event: {event.event_type} from {event.source}"
        if rule_matches:
            rule_titles = ", ".join(rm.rule_title for rm in rule_matches)
            desc = f"Detection [{rule_titles}] on {event.event_type}"
        elif event.raw and "action" in event.raw:
            desc = f"{event.event_type} ({event.raw['action']})"

        return IncidentTimelineEntry(
            timestamp=event.timestamp,
            event_id=event.event_id,
            event_type=event.event_type,
            source=event.source,
            severity=event.severity,
            description=desc,
            entity=event.entity or Entity(),
            raw=event.raw,
        )

    def process_event(
        self,
        event: SecurityEvent,
        rule_matches: list[RuleMatch] | None = None,
    ) -> Incident | None:
        """
        Correlate an incoming SecurityEvent and any triggered RuleMatches.
        Attaches to an existing active incident if an entity matches within the window,
        or creates a new incident if detection thresholds or severity warrant it.
        """
        matches = rule_matches or []
        entity = event.entity or Entity()
        entity_keys = _extract_entity_keys(entity)

        # Determine target severity
        highest_severity: SeverityLevel = event.severity
        for rm in matches:
            highest_severity = _max_severity(highest_severity, rm.severity)

        # 1. Look for existing active incident linked to this entity
        existing_incident = self._find_matching_incident(entity_keys, event.timestamp)

        if existing_incident is not None:
            # Correlate into existing incident
            if event.event_id not in existing_incident.event_ids:
                existing_incident.event_ids.append(event.event_id)
                existing_incident.event_count += 1

            # Merge entity details
            if not existing_incident.primary_entity.ip and entity.ip:
                existing_incident.primary_entity.ip = entity.ip
            if not existing_incident.primary_entity.user and entity.user:
                existing_incident.primary_entity.user = entity.user
            if not existing_incident.primary_entity.host and entity.host:
                existing_incident.primary_entity.host = entity.host

            if entity not in existing_incident.linked_entities:
                existing_incident.linked_entities.append(entity)

            # Update severity to highest seen
            existing_incident.severity = _max_severity(existing_incident.severity, highest_severity)
            existing_incident.updated_at = event.timestamp

            # Attach rule matches and MITRE tags
            for rm in matches:
                if rm.match_id not in [m.match_id for m in existing_incident.rule_matches]:
                    existing_incident.rule_matches.append(rm)
                    for tech in rm.context.get("mitre_attack", []):
                        if tech not in existing_incident.mitre_techniques:
                            existing_incident.mitre_techniques.append(tech)
                    for tag in rm.tags:
                        if tag not in existing_incident.tags:
                            existing_incident.tags.append(tag)

            # Add timeline entry
            entry = self._create_timeline_entry(event, matches)
            existing_incident.timeline.append(entry)
            # Keep timeline sorted chronologically
            existing_incident.timeline.sort(key=lambda t: t.timestamp)

            # Re-index all entity keys for this incident
            for key in entity_keys:
                self._entity_map[key] = existing_incident.incident_id

            logger.info(
                f"Correlated event {event.event_id} into Incident {existing_incident.incident_id} "
                f"(total events: {existing_incident.event_count}, severity: {existing_incident.severity})"
            )
            return existing_incident

        # 2. If no existing incident, determine if a new incident should be created
        should_create = (
            len(matches) > 0
            or highest_severity in ("high", "critical")
            or event.event_type in ("auth_failure", "privilege_escalation", "firewall_block")
        )

        if not should_create:
            return None

        # Create new Incident
        primary_entity_label = entity.ip or entity.user or entity.host or "Unknown entity"
        if matches:
            title = f"{matches[0].rule_title} targeting {primary_entity_label}"
        else:
            title = f"Suspicious {event.event_type} activity on {primary_entity_label}"

        all_mitre: list[str] = []
        all_tags: list[str] = []
        for rm in matches:
            for tech in rm.context.get("mitre_attack", []):
                if tech not in all_mitre:
                    all_mitre.append(tech)
            for tag in rm.tags:
                if tag not in all_tags:
                    all_tags.append(tag)

        new_incident = Incident(
            title=title,
            description=f"Correlated security incident initiated by {event.source} event {event.event_type}.",
            status="open",
            severity=highest_severity,
            created_at=event.timestamp,
            updated_at=event.timestamp,
            primary_entity=entity,
            linked_entities=[entity],
            event_ids=[event.event_id],
            rule_matches=matches,
            mitre_techniques=all_mitre,
            timeline=[self._create_timeline_entry(event, matches)],
            event_count=1,
            tags=all_tags,
        )

        self._incidents[new_incident.incident_id] = new_incident
        for key in entity_keys:
            self._entity_map[key] = new_incident.incident_id

        logger.info(
            f"Created new Incident {new_incident.incident_id}: '{new_incident.title}' (severity: {new_incident.severity})"
        )
        return new_incident

    def reset(self) -> None:
        """Clear all active incident state."""
        self._incidents.clear()
        self._entity_map.clear()
