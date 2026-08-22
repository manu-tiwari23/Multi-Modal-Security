"""
Common event schema for Multi Modal Security.

Every module normalises its data into this schema before publishing to the
event bus.  This is the single source of truth for the event structure — see
ARCHITECTURE.md §5 for the rationale.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Entity — the "who / what / where" of an event
# ---------------------------------------------------------------------------

class Entity(BaseModel):
    """Identifies the actors and targets involved in a security event.

    All fields are optional because not every log source provides every field.
    The correlation engine uses whichever fields are present for entity linking.
    """

    ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    hash: Optional[str] = None


# ---------------------------------------------------------------------------
# SecurityEvent — the canonical event envelope
# ---------------------------------------------------------------------------

SourceType = Literal["soc", "honeypot", "phishing", "forensics", "threat_intel"]
SeverityLevel = Literal["low", "medium", "high", "critical"]


class SecurityEvent(BaseModel):
    """Canonical security event that flows through the entire MMS pipeline.

    Every ingestion source (SOC log collector, honeypot sensor, phishing
    analyser, forensics toolkit, threat intel feed) normalises its output
    into this model before publishing to the event bus.

    Attributes:
        event_id:    Unique identifier, auto-generated if not provided.
        timestamp:   When the event occurred (ISO-8601, UTC preferred).
        source:      Which module produced this event.
        entity:      Extracted entity fields for correlation.
        event_type:  Free-form event descriptor (e.g. "ssh_auth_failure").
        severity:    Risk level assigned by the source module.
        raw:         Original, unparsed data — preserved for auditability.
        enrichment:  Any enrichment added later (threat intel, risk score).
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: SourceType
    entity: Entity = Field(default_factory=Entity)
    event_type: str
    severity: SeverityLevel = "low"
    raw: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialise to a JSON string (for Redis Streams / WebSocket)."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> SecurityEvent:
        """Deserialise from a JSON string."""
        return cls.model_validate_json(data)

    def to_opensearch_doc(self) -> dict[str, Any]:
        """Return a dict suitable for indexing into OpenSearch.

        Converts the timestamp to an ISO-8601 string so OpenSearch maps it
        as a ``date`` field automatically.
        """
        doc = self.model_dump()
        doc["timestamp"] = self.timestamp.isoformat()
        return doc
