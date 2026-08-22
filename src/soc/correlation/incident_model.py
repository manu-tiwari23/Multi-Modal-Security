"""
Pydantic data models for correlated security incidents and timeline entries.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.shared.event_schema import Entity, SeverityLevel
from src.soc.detection.rule_model import RuleMatch

IncidentStatus = Literal["open", "investigating", "contained", "resolved", "closed"]


class IncidentTimelineEntry(BaseModel):
    """A chronological event or detection step in an incident's progression."""

    entry_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique ID for this timeline entry",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the event in the timeline",
    )
    event_id: str = Field(..., description="ID of the underlying SecurityEvent")
    event_type: str = Field(..., description="Type of event (e.g. auth_failure, privilege_escalation)")
    source: str = Field(..., description="Source module (e.g. soc, honeypot)")
    severity: SeverityLevel = Field(..., description="Severity of this event")
    description: str = Field(..., description="Human-readable description of what happened")
    entity: Entity = Field(default_factory=Entity, description="Associated entity fields")
    raw: dict[str, Any] = Field(default_factory=dict, description="Raw event context")


class Incident(BaseModel):
    """A correlated security incident grouping related events, rule matches, and entities."""

    incident_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the incident",
    )
    title: str = Field(..., description="Short descriptive summary of the incident")
    description: str = Field(default="", description="Detailed narrative of the incident")
    status: IncidentStatus = Field(default="open", description="Lifecycle state of the incident")
    severity: SeverityLevel = Field(default="medium", description="Current overall incident severity")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the incident was first opened",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the incident was last updated with new events",
    )
    primary_entity: Entity = Field(
        default_factory=Entity,
        description="Primary identifying entity (e.g. attacker IP or compromised user)",
    )
    linked_entities: list[Entity] = Field(
        default_factory=list,
        description="All distinct entities linked to this incident",
    )
    event_ids: list[str] = Field(
        default_factory=list,
        description="List of all SecurityEvent IDs grouped into this incident",
    )
    rule_matches: list[RuleMatch] = Field(
        default_factory=list,
        description="Detection rule matches associated with this incident",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="Aggregated MITRE ATT&CK tactics involved",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="Aggregated MITRE ATT&CK technique IDs (e.g. T1110, T1548.003)",
    )
    timeline: list[IncidentTimelineEntry] = Field(
        default_factory=list,
        description="Chronologically sorted timeline of events and detections",
    )
    event_count: int = Field(default=0, description="Total number of events in this incident")
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Computed risk score (0-100)",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags describing attack pattern, service, or modalities",
    )
