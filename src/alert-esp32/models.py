"""
Data models for the ESP32 Physical Alert System.

Strict guardrail: The notification payload must ONLY contain severity, incident_type,
source, and timestamp. Never raw logs, IOCs, credentials, or evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field


class AlertNotification(BaseModel):
    """Sanitized, lightweight alert payload published to the ESP32 via MQTT."""

    severity: Literal["normal", "low", "medium", "high", "critical"] = Field(
        description="Severity level mapping directly to LED and buzzer patterns"
    )
    incident_type: str = Field(
        default="general",
        description="High-level category of the incident (e.g., brute_force, privilege_escalation)"
    )
    source: str = Field(
        default="soc",
        description="Source subsystem reporting the alert (e.g., soc, honeypot, phishing)"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp of notification emission"
    )

    @classmethod
    def from_alert(cls, alert: dict | object) -> AlertNotification:
        """Construct a sanitized notification from an internal SOC alert or incident."""
        if hasattr(alert, "model_dump"):
            data = alert.model_dump()
        elif isinstance(alert, dict):
            data = alert
        else:
            data = {}

        raw_sev = str(data.get("severity") or data.get("priority") or "normal").lower()
        if "crit" in raw_sev or "p1" in raw_sev:
            sev = "critical"
        elif "high" in raw_sev or "p2" in raw_sev:
            sev = "high"
        elif "med" in raw_sev or "p3" in raw_sev:
            sev = "medium"
        elif "low" in raw_sev or "p4" in raw_sev:
            sev = "low"
        else:
            sev = "normal"

        inc_type = str(data.get("title") or data.get("incident_type") or "detection")
        # Sanitize incident_type to avoid leaking sensitive hostnames/credentials
        cleaned_type = inc_type.split(" from ")[0].split(" on ")[0].strip().replace(" ", "_").lower()

        src = str(data.get("source") or "soc").lower()
        ts = str(data.get("timestamp") or data.get("created_at") or datetime.now(timezone.utc).isoformat())

        return cls(
            severity=sev,
            incident_type=cleaned_type or "alert",
            source=src,
            timestamp=ts,
        )


class AlertAcknowledgeMessage(BaseModel):
    """Payload received from the ESP32 physical push-button."""

    acknowledged: bool = True
    device_id: str = "esp32-desk-01"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

