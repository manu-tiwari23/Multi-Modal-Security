"""
Automated Incident and Forensic Report Generator for MMS Copilot.

Assembles comprehensive executive summaries, technical timelines, MITRE matrices,
IOC registries, and containment recommendations into structured IncidentReport models.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from src.copilot.models import ContainmentRecommendation, IncidentReport
from src.copilot.retrieval import IncidentRetriever, ThreatIntelRetriever

logger = logging.getLogger(__name__)

# MITRE Technique Definitions Mapping for Reporting
MITRE_DESCRIPTIONS = {
    "T1110": "Brute Force / Password Guessing (Credential Access)",
    "T1110.001": "Password Guessing (Credential Access)",
    "T1548.003": "Sudo and Sudo Caching (Privilege Escalation)",
    "T1059": "Command and Scripting Interpreter (Execution)",
    "T1059.004": "Unix Shell (Execution)",
    "T1105": "Ingress Tool Transfer / Dropper Download (Command and Control)",
    "T1082": "System Information Discovery (Discovery)",
    "T1016": "System Network Configuration Discovery (Discovery)",
    "T1057": "Process Discovery (Discovery)",
    "T1087": "Account Discovery (Discovery)",
    "T1078.003": "Local Accounts (Defense Evasion / Persistence)",
}


class IncidentReportGenerator:
    """Generates structured forensic and response reports for security incidents."""

    def __init__(
        self,
        incident_retriever: IncidentRetriever,
        threat_intel_retriever: Optional[ThreatIntelRetriever] = None,
    ) -> None:
        self.incident_retriever = incident_retriever
        self.threat_intel = threat_intel_retriever

    def generate_report(self, incident_id: str) -> Optional[IncidentReport]:
        """Generate a complete structured report for the specified incident ID."""
        ctx = self.incident_retriever.get_incident_context(incident_id)
        if not ctx:
            logger.warning("Cannot generate report: Incident %s not found", incident_id)
            return None

        title = ctx.get("title", f"Security Incident {incident_id}")
        risk_score = float(ctx.get("risk_score", 50.0))
        severity = ctx.get("severity", "medium")
        primary_entity = ctx.get("primary_entity", {})
        attacker_ip = primary_entity.get("ip") or "Unknown"
        target_user = primary_entity.get("user") or "N/A"
        target_host = primary_entity.get("host") or "N/A"
        event_count = ctx.get("event_count", 0)

        # Priority calculation
        if risk_score >= 80.0:
            priority = "P1-critical"
        elif risk_score >= 50.0:
            priority = "P2-high"
        elif risk_score >= 25.0:
            priority = "P3-medium"
        else:
            priority = "P4-low"

        # Narrate only the observations in this retrieved incident.
        timeline = ctx.get("timeline", [])
        observed_types = sorted({entry.get("event_type", "unknown") for entry in timeline})
        sources = sorted({entry.get("source", "unknown") for entry in timeline})
        exec_summary = (
            f"Incident {incident_id} has recorded severity {severity} and risk score "
            f"{risk_score:.1f}/100 ({priority}) across {event_count} recorded events. "
            f"Observed event types: {', '.join(observed_types) or 'none recorded'}. "
            f"Telemetry sources: {', '.join(sources) or 'none recorded'}. [INCIDENT:{incident_id}]"
        )

        # 2. Technical Analysis
        rules_triggered = [rm.get("rule_title", rm.get("rule_id")) for rm in ctx.get("rule_matches", [])]
        rules_str = ", ".join(rules_triggered) if rules_triggered else "No rule matches recorded"
        references = " ".join(f"[EVENT:{entry['event_id']}]" for entry in timeline if entry.get("event_id"))
        tech_analysis = (
            f"Recorded detections: {rules_str}. Associated entities: IP {attacker_ip}, "
            f"user {target_user}, host {target_host}. Entity association and detection matches "
            f"require analyst validation; they do not by themselves prove compromise or intent. {references}"
        )

        # 3. Chronological Attack Timeline
        timeline = ctx.get("timeline", [])

        # 4. Extract IOCs
        iocs: list[dict[str, Any]] = []
        if attacker_ip and attacker_ip != "Unknown":
            iocs.append({
                "type": "IP Address",
                "value": attacker_ip,
                "context": f"Observed primary entity [INCIDENT:{incident_id}]",
            })

        for e in ctx.get("linked_entities", []):
            if e.get("hash"):
                iocs.append({
                    "type": "File Hash",
                    "value": e.get("hash"),
                    "context": f"Observed linked entity [INCIDENT:{incident_id}]",
                })
            if e.get("user") and e.get("user") not in (attacker_ip, target_user):
                iocs.append({
                    "type": "Username",
                    "value": e.get("user"),
                    "context": f"Observed linked entity [INCIDENT:{incident_id}]",
                })

        # 5. MITRE ATT&CK Mapping
        mitre_matrix: list[dict[str, Any]] = []
        for tech in ctx.get("mitre_techniques", []):
            mitre_matrix.append({
                "id": tech,
                "name": MITRE_DESCRIPTIONS.get(tech, "Recorded technique mapping"),
                "source": f"Incident detection annotation [INCIDENT:{incident_id}]",
            })

        # 6. Containment Recommendations (Always require human analyst sign-off)
        containment: list[ContainmentRecommendation] = []
        if attacker_ip and attacker_ip != "Unknown":
            containment.append(
                ContainmentRecommendation(
                    action_type="block_ip",
                    target=attacker_ip,
                    rationale=f"If investigation confirms malicious activity from {attacker_ip}, consider a scoped block after analyst review.",
                    requires_approval=True,
                    priority="critical" if risk_score >= 50 else "high",
                )
            )

        if target_host and target_host != "N/A":
            containment.append(
                ContainmentRecommendation(
                    action_type="isolate_host",
                    target=target_host,
                    rationale=f"If evidence confirms compromise of '{target_host}', assess impact and request approval for temporary isolation.",
                    requires_approval=True,
                    priority="high",
                )
            )

        if target_user and target_user in ("root", "admin", "sysop"):
            containment.append(
                ContainmentRecommendation(
                    action_type="revoke_credentials",
                    target=target_user,
                    rationale=f"If credential compromise is confirmed for '{target_user}', plan credential rotation and session revocation with analyst approval.",
                    requires_approval=True,
                    priority="high",
                )
            )

        return IncidentReport(
            incident_id=incident_id,
            title=title,
            risk_score=risk_score,
            priority=priority,
            executive_summary=exec_summary,
            technical_analysis=tech_analysis,
            attack_timeline=timeline,
            iocs=iocs,
            mitre_matrix=mitre_matrix,
            containment_actions=containment,
            analyst_notes="Deterministic summary of retrieved incident evidence. Recommendations require analyst validation and approval.",
            created_at=datetime.now(timezone.utc),
        )
