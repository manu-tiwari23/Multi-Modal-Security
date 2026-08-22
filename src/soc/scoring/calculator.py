"""
Transparent, explainable risk scoring calculator for SOC incidents and events.

The formula is a documented weighted sum — every component is recorded in the
score breakdown so analysts can see *why* a score is what it is.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

from src.shared.event_schema import SeverityLevel
from src.soc.correlation.incident_model import Incident

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configurable scoring weights — documented here, not buried in logic
# ---------------------------------------------------------------------------

SEVERITY_BASE_SCORES: dict[SeverityLevel, float] = {
    "low": 10.0,
    "medium": 25.0,
    "high": 50.0,
    "critical": 75.0,
}

# Each additional MITRE technique adds breadth-of-attack bonus
MITRE_TECHNIQUE_BONUS = 3.0
# Cap so a single incident can't score 100 from MITRE alone
MITRE_TECHNIQUE_CAP = 15.0

# Frequency: log2(event_count) * multiplier, capped
FREQUENCY_MULTIPLIER = 2.5
FREQUENCY_CAP = 10.0

# Critical user/asset names that raise the score
CRITICAL_USERS = frozenset({
    "root", "admin", "administrator", "system",
    "sa", "dba", "backup", "service",
})
CRITICAL_USER_BONUS = 8.0

# Critical hosts (patterns checked via substring)
CRITICAL_HOST_PATTERNS = (
    "dc", "domain", "ad-", "exchange", "sql", "db-",
    "firewall", "vpn", "gateway", "prod",
)
CRITICAL_HOST_BONUS = 5.0

# Threat intel enrichment present on the incident
THREAT_INTEL_BONUS = 7.0

# Multi-source correlation bonus (honeypot + soc, etc.)
MULTI_SOURCE_BONUS = 5.0

# Maximum possible score
MAX_SCORE = 100.0


@dataclass
class ScoreBreakdown:
    """Transparent, human-readable breakdown of how a risk score was computed.

    Every component that contributed to the final score is listed with its
    value and a short explanation.  This is what makes the score auditable.
    """

    base_severity: float = 0.0
    base_severity_label: str = ""
    frequency_bonus: float = 0.0
    frequency_event_count: int = 0
    mitre_bonus: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    critical_user_bonus: float = 0.0
    critical_user: str = ""
    critical_host_bonus: float = 0.0
    critical_host: str = ""
    threat_intel_bonus: float = 0.0
    multi_source_bonus: float = 0.0
    sources_seen: list[str] = field(default_factory=list)
    raw_total: float = 0.0
    final_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise breakdown for API / OpenSearch storage."""
        return {
            "base_severity": {
                "value": self.base_severity,
                "label": self.base_severity_label,
            },
            "frequency": {
                "value": self.frequency_bonus,
                "event_count": self.frequency_event_count,
            },
            "mitre_techniques": {
                "value": self.mitre_bonus,
                "techniques": self.mitre_techniques,
            },
            "critical_user": {
                "value": self.critical_user_bonus,
                "user": self.critical_user,
            },
            "critical_host": {
                "value": self.critical_host_bonus,
                "host": self.critical_host,
            },
            "threat_intel": {
                "value": self.threat_intel_bonus,
            },
            "multi_source": {
                "value": self.multi_source_bonus,
                "sources": self.sources_seen,
            },
            "raw_total": self.raw_total,
            "final_score": self.final_score,
        }

    def explain(self) -> str:
        """Return a concise human-readable explanation string."""
        parts: list[str] = []
        parts.append(f"Base severity ({self.base_severity_label}): {self.base_severity:.1f}")
        if self.frequency_bonus > 0:
            parts.append(
                f"Event frequency ({self.frequency_event_count} events): "
                f"+{self.frequency_bonus:.1f}"
            )
        if self.mitre_bonus > 0:
            techs = ", ".join(self.mitre_techniques)
            parts.append(f"MITRE techniques ({techs}): +{self.mitre_bonus:.1f}")
        if self.critical_user_bonus > 0:
            parts.append(f"Critical user '{self.critical_user}': +{self.critical_user_bonus:.1f}")
        if self.critical_host_bonus > 0:
            parts.append(f"Critical host '{self.critical_host}': +{self.critical_host_bonus:.1f}")
        if self.threat_intel_bonus > 0:
            parts.append(f"Threat intel match: +{self.threat_intel_bonus:.1f}")
        if self.multi_source_bonus > 0:
            srcs = ", ".join(self.sources_seen)
            parts.append(f"Multi-source correlation ({srcs}): +{self.multi_source_bonus:.1f}")
        parts.append(f"Final score: {self.final_score:.1f}/100")
        return " | ".join(parts)


def score_incident(incident: Incident) -> tuple[float, ScoreBreakdown]:
    """
    Compute a transparent risk score (0-100) for an Incident.

    Returns
    -------
    (score, breakdown) — the numeric score and the full ScoreBreakdown
    showing every component that contributed.
    """
    bd = ScoreBreakdown()

    # 1. Base severity
    bd.base_severity = SEVERITY_BASE_SCORES.get(incident.severity, 25.0)
    bd.base_severity_label = incident.severity

    # 2. Frequency bonus — log2(event_count) * multiplier, capped
    count = max(incident.event_count, 1)
    bd.frequency_event_count = count
    if count > 1:
        bd.frequency_bonus = min(
            math.log2(count) * FREQUENCY_MULTIPLIER,
            FREQUENCY_CAP,
        )

    # 3. MITRE technique breadth bonus
    techniques = incident.mitre_techniques or []
    bd.mitre_techniques = list(techniques)
    if techniques:
        bd.mitre_bonus = min(
            len(techniques) * MITRE_TECHNIQUE_BONUS,
            MITRE_TECHNIQUE_CAP,
        )

    # 4. Critical user bonus
    primary = incident.primary_entity
    if primary and primary.user:
        user_lower = primary.user.strip().lower()
        if user_lower in CRITICAL_USERS:
            bd.critical_user_bonus = CRITICAL_USER_BONUS
            bd.critical_user = primary.user

    # 5. Critical host bonus
    if primary and primary.host:
        host_lower = primary.host.strip().lower()
        for pattern in CRITICAL_HOST_PATTERNS:
            if pattern in host_lower:
                bd.critical_host_bonus = CRITICAL_HOST_BONUS
                bd.critical_host = primary.host
                break

    # 6. Threat intel enrichment bonus
    #    Check if any linked event or rule match has threat intel data
    for rm in incident.rule_matches:
        ctx = rm.context or {}
        if ctx.get("threat_intel_match") or ctx.get("threat_intel"):
            bd.threat_intel_bonus = THREAT_INTEL_BONUS
            break

    # 7. Multi-source correlation bonus
    sources: set[str] = set()
    for entry in incident.timeline:
        sources.add(entry.source)
    bd.sources_seen = sorted(sources)
    if len(sources) > 1:
        bd.multi_source_bonus = MULTI_SOURCE_BONUS

    # Sum and clamp
    bd.raw_total = (
        bd.base_severity
        + bd.frequency_bonus
        + bd.mitre_bonus
        + bd.critical_user_bonus
        + bd.critical_host_bonus
        + bd.threat_intel_bonus
        + bd.multi_source_bonus
    )
    bd.final_score = min(bd.raw_total, MAX_SCORE)

    logger.debug(
        f"Scored Incident {incident.incident_id}: {bd.final_score:.1f}/100 — {bd.explain()}"
    )
    return bd.final_score, bd
