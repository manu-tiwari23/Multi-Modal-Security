"""
Alert data models for the SOC Alert Manager.

An Alert is the analyst-facing output of the SOC pipeline:
    Event → Detection → Correlation → Scoring → **Alert**

Alerts are serialisable Pydantic models that can be published to Redis
Streams, stored in OpenSearch, and rendered on the dashboard.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.shared.event_schema import Entity, SeverityLevel


AlertStatus = Literal["new", "acknowledged", "investigating", "resolved", "false_positive"]

# Priority buckets — derived from risk score
AlertPriority = Literal["P1-critical", "P2-high", "P3-medium", "P4-low"]


class Alert(BaseModel):
    """A deduplicated, scored, prioritised alert ready for analyst consumption.

    Every alert carries the full provenance chain (incident_id, rule_ids,
    event_ids) so the analyst can trace back to raw data.
    """

    alert_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique alert identifier",
    )
    title: str = Field(..., description="Short human-readable alert title")
    description: str = Field(
        default="",
        description="Analyst-facing narrative built from the incident timeline",
    )
    status: AlertStatus = Field(default="new", description="Alert lifecycle state")
    priority: AlertPriority = Field(
        default="P3-medium",
        description="Priority bucket derived from risk score",
    )
    severity: SeverityLevel = Field(
        default="medium",
        description="Severity inherited from the incident",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Risk score (0-100) from the scoring calculator",
    )
    score_breakdown: dict[str, Any] = Field(
        default_factory=dict,
        description="Full ScoreBreakdown.to_dict() for transparency",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the alert was generated",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the alert was last updated (e.g. new events merged)",
    )
    incident_id: str = Field(..., description="Linked incident ID for traceability")
    primary_entity: Entity = Field(
        default_factory=Entity,
        description="Primary entity (attacker IP, compromised user, etc.)",
    )
    event_count: int = Field(
        default=0,
        description="Total events contributing to this alert",
    )
    event_ids: list[str] = Field(
        default_factory=list,
        description="All SecurityEvent IDs grouped into this alert",
    )
    rule_ids: list[str] = Field(
        default_factory=list,
        description="Detection rule IDs that triggered this alert",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics involved",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs involved",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Searchable tags for dashboard filtering",
    )

    def to_stream_dict(self) -> dict[str, str]:
        """Serialise for Redis Streams XADD (flat string dict)."""
        return {"data": self.model_dump_json()}

    @classmethod
    def from_stream_dict(cls, data: dict[str, str]) -> "Alert":
        """Deserialise from Redis Streams XREADGROUP."""
        return cls.model_validate_json(data["data"])


def priority_from_score(score: float) -> AlertPriority:
    """Map a 0-100 risk score to a priority bucket.

    Thresholds are intentionally simple and documented:
        >=80 → P1-critical
        >=50 → P2-high
        >=25 → P3-medium
        <25  → P4-low
    """
    if score >= 80.0:
        return "P1-critical"
    elif score >= 50.0:
        return "P2-high"
    elif score >= 25.0:
        return "P3-medium"
    else:
        return "P4-low"
