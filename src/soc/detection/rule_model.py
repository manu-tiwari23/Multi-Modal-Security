"""
Pydantic data models for Sigma-style detection rules and rule matches.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.shared.event_schema import Entity, SeverityLevel


class ThresholdConfig(BaseModel):
    """Configuration for aggregation/threshold-based rules."""

    count: int = Field(
        ...,
        ge=1,
        description="Number of matching events required within the timeframe",
    )
    timeframe: int = Field(
        ...,
        ge=1,
        description="Sliding window timeframe in seconds",
    )
    by: list[str] = Field(
        default_factory=lambda: ["entity.ip"],
        description="Entity or event fields to group matches by (e.g. ['entity.ip'])",
    )


class DetectionCondition(BaseModel):
    """Detection logic definition inside a rule."""

    selection: dict[str, Any] = Field(
        default_factory=dict,
        description="Field criteria that must match (supports modifiers e.g. field|contains)",
    )
    filter: dict[str, Any] | None = Field(
        default=None,
        description="Optional field criteria that will exclude an event if matched",
    )
    threshold: ThresholdConfig | None = Field(
        default=None,
        description="Optional threshold condition (e.g. 5 occurrences in 60s)",
    )
    condition: str = Field(
        default="selection",
        description="Logical condition expression (e.g. 'selection', 'selection and not filter')",
    )


class DetectionRule(BaseModel):
    """A Sigma-style detection rule."""

    id: str = Field(..., description="Unique rule identifier (e.g. sigma-ssh-brute-force)")
    title: str = Field(..., description="Short descriptive title of the rule")
    description: str = Field(default="", description="Detailed description of what the rule detects")
    severity: SeverityLevel = Field(
        default="medium",
        description="Severity level assigned when rule matches",
    )
    status: Literal["stable", "experimental", "testing", "deprecated"] = Field(
        default="stable",
        description="Lifecycle status of the rule",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags (e.g. MITRE ATT&CK tags like attack.t1110)",
    )
    falsepositives: list[str] = Field(
        default_factory=list,
        description="Known false positive scenarios",
    )
    detection: DetectionCondition = Field(
        ...,
        description="Detection selection, filter, and threshold logic",
    )
    mitre_attack: list[str] = Field(
        default_factory=list,
        description="Extracted MITRE ATT&CK technique IDs (e.g. T1110)",
    )


class RuleMatch(BaseModel):
    """Result emitted when a detection rule matches one or more events."""

    match_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this match instance",
    )
    rule_id: str = Field(..., description="ID of the matching rule")
    rule_title: str = Field(..., description="Title of the matching rule")
    severity: SeverityLevel = Field(..., description="Severity of the detection")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the detection match occurred",
    )
    matched_event_ids: list[str] = Field(
        default_factory=list,
        description="IDs of the SecurityEvents that triggered this match",
    )
    entity: Entity = Field(
        default_factory=Entity,
        description="Primary entity associated with the detection",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags from the detection rule",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual details (e.g. matched values, threshold count)",
    )
