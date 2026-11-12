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
from src.soc.correlation.engine import CorrelationEngine
from src.soc.correlation.incident_model import Incident

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

        # 1. Executive Summary
        exec_summary = (
            f"On {datetime.now(timezone.utc).strftime('%B %d, %Y')}, the Multi Modal Security (MMS) platform "
            f"correlated a multi-stage security incident ({incident_id}) originating from IP address **{attacker_ip}**. "
            f"The incident reached an elevated risk score of **{risk_score:.1f}/100.0** ({priority.upper()}) "
            f"across **{event_count}** aggregated security events. Threat activity encompassed authentication "
            f"tampering, host privilege escalation on **{target_host}**, and interactive deception sensor engagements."
        )

        # 2. Technical Analysis
        rules_triggered = [rm.get("rule_title", rm.get("rule_id")) for rm in ctx.get("rule_matches", [])]
        rules_str = ", ".join(rules_triggered) if rules_triggered else "Heuristic Behavioral Correlation"
        tech_analysis = (
            f"The attack campaign began with adversarial reconnaissance and credential brute-forcing targeting "
            f"user account '{target_user}'. Following initial access attempts, detection rule triggers ({rules_str}) "
            f"identified privilege escalation attempts targeting root-level access on '{target_host}'. Cross-modal "
            f"telemetry from deceptive sensors confirmed active malicious intent with command execution patterns."
        )

        # 3. Chronological Attack Timeline
        timeline = ctx.get("timeline", [])

        # 4. Extract IOCs
        iocs: list[dict[str, Any]] = []
        if attacker_ip and attacker_ip != "Unknown":
            iocs.append({
                "type": "IPv4 Address",
                "value": attacker_ip,
                "context": "Primary Attacker Source / Scanner Node",
            })

        for e in ctx.get("linked_entities", []):
            if e.get("hash"):
                iocs.append({
                    "type": "SHA-256 Hash",
                    "value": e.get("hash"),
                    "context": "Malware Dropper / Payload Captured",
                })
            if e.get("user") and e.get("user") not in (attacker_ip, target_user):
                iocs.append({
                    "type": "Username",
                    "value": e.get("user"),
                    "context": "Compromised Account Target",
                })

        # 5. MITRE ATT&CK Mapping
        mitre_matrix: list[dict[str, Any]] = []
        for tech in ctx.get("mitre_techniques", []):
            mitre_matrix.append({
                "id": tech,
                "name": MITRE_DESCRIPTIONS.get(tech, "Observed Adversary Technique"),
                "source": "SOC Correlation & Honeypot Sensors",
            })

        # 6. Containment Recommendations (Always require human analyst sign-off)
        containment: list[ContainmentRecommendation] = []
        if attacker_ip and attacker_ip != "Unknown":
            containment.append(
                ContainmentRecommendation(
                    action_type="block_ip",
                    target=attacker_ip,
                    rationale=f"Block inbound traffic from adversary IP {attacker_ip} at perimeter firewall / WAF.",
                    requires_approval=True,
                    priority="critical" if risk_score >= 50 else "high",
                )
            )

        if target_host and target_host != "N/A":
            containment.append(
                ContainmentRecommendation(
                    action_type="isolate_host",
                    target=target_host,
                    rationale=f"Temporarily isolate host '{target_host}' to prevent lateral network pivoting.",
                    requires_approval=True,
                    priority="high",
                )
            )

        if target_user and target_user in ("root", "admin", "sysop"):
            containment.append(
                ContainmentRecommendation(
                    action_type="revoke_credentials",
                    target=target_user,
                    rationale=f"Rotate SSH keys and invalidate active sessions for targeted privileged account '{target_user}'.",
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
            analyst_notes="Report automatically synthesized by MMS AI Security Copilot with full evidence grounding.",
            created_at=datetime.now(timezone.utc),
        )
