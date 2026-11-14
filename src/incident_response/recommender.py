"""
Response Recommender — rule-based playbook matching for incident response.

Given an ``Incident`` (from the SOC Correlation Engine) or an ``Alert``
(from the Alert Manager), the ``ResponseRecommender`` evaluates loaded
playbooks and produces a ``ResponsePlan`` containing prioritised, ordered
response actions.

Every recommended action carries ``requires_approval = True`` — the system
never executes containment autonomously (AGENTS.md guardrail).

Design decisions:
  - Playbooks are declarative and data-driven (easy to extend without code)
  - Multiple playbooks can match a single incident; actions are merged and
    deduplicated by (action_type, target_entity) to avoid duplicate blocks
  - Target entities are auto-populated from the incident's primary_entity
  - Actions are sorted by priority (IMMEDIATE > HIGH > MEDIUM > LOW)
"""

from __future__ import annotations

import copy
import logging
import uuid
from typing import Any

from src.incident_response.models import (
    ActionPriority,
    ActionType,
    ResponseAction,
    ResponsePlan,
    ResponsePlaybook,
)
from src.soc.alerting.alert_model import Alert
from src.soc.correlation.incident_model import Incident

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ranking for comparison
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_PRIORITY_RANK: dict[ActionPriority, int] = {
    ActionPriority.LOW: 1,
    ActionPriority.MEDIUM: 2,
    ActionPriority.HIGH: 3,
    ActionPriority.IMMEDIATE: 4,
}


# ---------------------------------------------------------------------------
# Default Playbook Library
# ---------------------------------------------------------------------------

def _make_default_playbooks() -> list[ResponsePlaybook]:
    """Return the built-in playbook library.

    Covers the most common incident archetypes:
      1. Brute Force / Credential Stuffing
      2. Privilege Escalation
      3. Phishing (email/URL/attachment)
      4. Malware / Suspicious Executable
      5. Data Exfiltration
      6. Honeypot Intrusion
      7. Evidence Tampering
      8. Port Scan / Reconnaissance
    """
    playbooks: list[ResponsePlaybook] = []

    # 1. Brute Force
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-brute-force",
        name="Brute Force Response",
        description="Respond to credential brute force or stuffing attacks",
        match_event_types=["brute_force", "auth_failure", "credential_stuffing"],
        match_mitre_techniques=["T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004"],
        match_severity_min="medium",
        actions=[
            ResponseAction(
                action_id="bf-block-ip",
                action_type=ActionType.BLOCK_IP,
                title="Block attacker IP at perimeter firewall",
                description="Add the attacking source IP to the firewall blocklist to stop ongoing brute force attempts",
                priority=ActionPriority.IMMEDIATE,
                mitre_technique="T1110",
                mitre_tactic="Credential Access",
            ),
            ResponseAction(
                action_id="bf-force-reset",
                action_type=ActionType.FORCE_PASSWORD_RESET,
                title="Force password reset for targeted accounts",
                description="Require immediate password change for any accounts that were targeted by the brute force attack",
                priority=ActionPriority.HIGH,
                mitre_technique="T1110",
                mitre_tactic="Credential Access",
            ),
            ResponseAction(
                action_id="bf-alert-soc",
                action_type=ActionType.ALERT_SOC,
                title="Notify SOC team of brute force campaign",
                description="Alert the SOC team for manual investigation and potential lateral movement detection",
                priority=ActionPriority.MEDIUM,
                mitre_technique="T1110",
                mitre_tactic="Credential Access",
            ),
        ],
    ))

    # 2. Privilege Escalation
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-privesc",
        name="Privilege Escalation Response",
        description="Respond to detected privilege escalation attempts",
        match_event_types=["privilege_escalation", "sudo_escalation", "admin_logon"],
        match_mitre_techniques=["T1548", "T1548.003", "T1068", "T1078"],
        match_severity_min="high",
        actions=[
            ResponseAction(
                action_id="pe-disable-account",
                action_type=ActionType.DISABLE_ACCOUNT,
                title="Disable compromised user account",
                description="Immediately disable the account showing privilege escalation activity to prevent further abuse",
                priority=ActionPriority.IMMEDIATE,
                mitre_technique="T1548",
                mitre_tactic="Privilege Escalation",
            ),
            ResponseAction(
                action_id="pe-alert-soc",
                action_type=ActionType.ALERT_SOC,
                title="Escalate to SOC for investigation",
                description="Alert the SOC team to investigate the scope of the privilege escalation and check for lateral movement",
                priority=ActionPriority.HIGH,
                mitre_technique="T1548",
                mitre_tactic="Privilege Escalation",
            ),
            ResponseAction(
                action_id="pe-preserve-evidence",
                action_type=ActionType.PRESERVE_EVIDENCE,
                title="Preserve logs and session artifacts",
                description="Capture and preserve authentication logs, session recordings, and command history for forensic analysis",
                priority=ActionPriority.HIGH,
                mitre_technique="T1548",
                mitre_tactic="Privilege Escalation",
            ),
        ],
    ))

    # 3. Phishing
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-phishing",
        name="Phishing Response",
        description="Respond to detected phishing emails, URLs, or attachments",
        match_event_types=[
            "phishing_email_detected", "phishing_url_detected",
            "phishing_attachment_detected", "phishing",
        ],
        match_mitre_techniques=["T1566", "T1566.001", "T1566.002", "T1204", "T1204.001", "T1204.002"],
        match_sources=["phishing"],
        match_severity_min="medium",
        actions=[
            ResponseAction(
                action_id="ph-quarantine-email",
                action_type=ActionType.QUARANTINE_EMAIL,
                title="Quarantine phishing email",
                description="Remove the phishing email from all recipient mailboxes and quarantine it for analysis",
                priority=ActionPriority.IMMEDIATE,
                mitre_technique="T1566.001",
                mitre_tactic="Initial Access",
            ),
            ResponseAction(
                action_id="ph-block-domain",
                action_type=ActionType.BLOCK_DOMAIN,
                title="Block phishing sender domain",
                description="Add the sender domain to the email gateway blocklist to prevent future phishing from the same source",
                priority=ActionPriority.HIGH,
                mitre_technique="T1566",
                mitre_tactic="Initial Access",
            ),
            ResponseAction(
                action_id="ph-block-url",
                action_type=ActionType.BLOCK_URL,
                title="Block malicious URL at web proxy",
                description="Add the phishing URL to the web proxy blocklist to prevent users from accessing it",
                priority=ActionPriority.HIGH,
                mitre_technique="T1204.001",
                mitre_tactic="Execution",
            ),
            ResponseAction(
                action_id="ph-alert-soc",
                action_type=ActionType.ALERT_SOC,
                title="Alert SOC for phishing campaign assessment",
                description="Notify the SOC team to assess if this is part of a broader phishing campaign targeting the organization",
                priority=ActionPriority.MEDIUM,
                mitre_technique="T1566",
                mitre_tactic="Initial Access",
            ),
        ],
    ))

    # 4. Malware / Suspicious Executable
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-malware",
        name="Malware Response",
        description="Respond to malware detection, suspicious executables, or payload delivery",
        match_event_types=[
            "malware_detected", "suspicious_executable", "payload_delivery",
            "dropper_detected",
        ],
        match_mitre_techniques=["T1059", "T1105", "T1204.002", "T1027"],
        match_severity_min="high",
        actions=[
            ResponseAction(
                action_id="mw-isolate-host",
                action_type=ActionType.ISOLATE_HOST,
                title="Network-isolate infected host",
                description="Quarantine the affected host from the network to prevent lateral movement and C2 communication",
                priority=ActionPriority.IMMEDIATE,
                mitre_technique="T1105",
                mitre_tactic="Command and Control",
            ),
            ResponseAction(
                action_id="mw-scan-host",
                action_type=ActionType.SCAN_HOST,
                title="Run full antimalware scan on host",
                description="Trigger an endpoint detection and response (EDR) full scan on the affected host",
                priority=ActionPriority.HIGH,
                mitre_technique="T1059",
                mitre_tactic="Execution",
            ),
            ResponseAction(
                action_id="mw-block-ip",
                action_type=ActionType.BLOCK_IP,
                title="Block C2/download source IP",
                description="Block the IP address from which the malware was downloaded or the C2 server address",
                priority=ActionPriority.HIGH,
                mitre_technique="T1105",
                mitre_tactic="Command and Control",
            ),
            ResponseAction(
                action_id="mw-preserve",
                action_type=ActionType.PRESERVE_EVIDENCE,
                title="Preserve malware sample and artifacts",
                description="Collect and preserve the malware binary, process memory, and related artifacts for forensic analysis",
                priority=ActionPriority.MEDIUM,
                mitre_technique="T1059",
                mitre_tactic="Execution",
            ),
        ],
    ))

    # 5. Data Exfiltration
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-exfiltration",
        name="Data Exfiltration Response",
        description="Respond to data exfiltration or large outbound data transfer anomalies",
        match_event_types=["data_exfiltration", "large_outbound_transfer", "dns_exfiltration"],
        match_mitre_techniques=["T1041", "T1048", "T1567", "T1020"],
        match_severity_min="high",
        actions=[
            ResponseAction(
                action_id="ex-block-egress",
                action_type=ActionType.BLOCK_EGRESS,
                title="Block outbound traffic to exfiltration destination",
                description="Block egress network traffic to the identified exfiltration destination IP/domain",
                priority=ActionPriority.IMMEDIATE,
                mitre_technique="T1041",
                mitre_tactic="Exfiltration",
            ),
            ResponseAction(
                action_id="ex-preserve",
                action_type=ActionType.PRESERVE_EVIDENCE,
                title="Preserve network captures and transfer logs",
                description="Capture PCAPs, flow data, and transfer logs to quantify the data loss and identify what was exfiltrated",
                priority=ActionPriority.HIGH,
                mitre_technique="T1041",
                mitre_tactic="Exfiltration",
            ),
            ResponseAction(
                action_id="ex-isolate",
                action_type=ActionType.ISOLATE_HOST,
                title="Isolate source host",
                description="Isolate the host performing the exfiltration to prevent further data loss",
                priority=ActionPriority.HIGH,
                mitre_technique="T1041",
                mitre_tactic="Exfiltration",
            ),
            ResponseAction(
                action_id="ex-escalate",
                action_type=ActionType.ESCALATE,
                title="Escalate to management / legal",
                description="Escalate to senior management and legal team for potential data breach notification requirements",
                priority=ActionPriority.HIGH,
                mitre_technique="T1041",
                mitre_tactic="Exfiltration",
            ),
        ],
    ))

    # 6. Honeypot Intrusion
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-honeypot",
        name="Honeypot Intrusion Response",
        description="Respond to attacker activity detected by honeypot sensors",
        match_sources=["honeypot"],
        match_event_types=["honeypot_session", "honeypot_login", "honeypot_command"],
        match_mitre_techniques=["T1110", "T1059", "T1105", "T1082"],
        match_severity_min="medium",
        actions=[
            ResponseAction(
                action_id="hp-block-ip",
                action_type=ActionType.BLOCK_IP,
                title="Block honeypot attacker IP",
                description="Block the attacker IP detected on the honeypot at the perimeter firewall",
                priority=ActionPriority.HIGH,
                mitre_technique="T1110",
                mitre_tactic="Initial Access",
            ),
            ResponseAction(
                action_id="hp-preserve",
                action_type=ActionType.PRESERVE_EVIDENCE,
                title="Preserve honeypot session recording",
                description="Preserve the full attacker session recording (commands, credentials, payloads) for threat intelligence analysis",
                priority=ActionPriority.MEDIUM,
                mitre_technique="T1059",
                mitre_tactic="Execution",
            ),
            ResponseAction(
                action_id="hp-alert-soc",
                action_type=ActionType.ALERT_SOC,
                title="Cross-correlate with production logs",
                description="Alert the SOC team to check if the honeypot attacker IP appears in production system logs",
                priority=ActionPriority.MEDIUM,
                mitre_technique="T1082",
                mitre_tactic="Discovery",
            ),
        ],
    ))

    # 7. Evidence Tampering
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-tampering",
        name="Evidence Tampering Response",
        description="Respond to detected tampering with forensic evidence or audit logs",
        match_event_types=["evidence_tampering_detected", "evidence_missing_detected", "log_tampering"],
        match_mitre_techniques=["T1565", "T1070", "T1070.001"],
        match_severity_min="high",
        actions=[
            ResponseAction(
                action_id="tp-preserve",
                action_type=ActionType.PRESERVE_EVIDENCE,
                title="Preserve current evidence state",
                description="Immediately preserve all accessible evidence and audit logs before further tampering occurs",
                priority=ActionPriority.IMMEDIATE,
                mitre_technique="T1565",
                mitre_tactic="Impact",
            ),
            ResponseAction(
                action_id="tp-isolate",
                action_type=ActionType.ISOLATE_HOST,
                title="Isolate evidence storage system",
                description="Isolate the system hosting the tampered evidence to prevent further modification",
                priority=ActionPriority.IMMEDIATE,
                mitre_technique="T1070",
                mitre_tactic="Defense Evasion",
            ),
            ResponseAction(
                action_id="tp-escalate",
                action_type=ActionType.ESCALATE,
                title="Escalate tampering incident",
                description="Escalate to senior analysts and management -- evidence tampering indicates a sophisticated adversary or insider threat",
                priority=ActionPriority.HIGH,
                mitre_technique="T1565",
                mitre_tactic="Impact",
            ),
        ],
    ))

    # 8. Port Scan / Reconnaissance
    playbooks.append(ResponsePlaybook(
        playbook_id="pb-recon",
        name="Reconnaissance Response",
        description="Respond to port scanning, network reconnaissance, or service enumeration",
        match_event_types=["port_scan", "network_scan", "service_enumeration", "recon"],
        match_mitre_techniques=["T1046", "T1595", "T1595.001"],
        match_severity_min="low",
        actions=[
            ResponseAction(
                action_id="rc-block-ip",
                action_type=ActionType.BLOCK_IP,
                title="Block scanning source IP",
                description="Block the IP performing reconnaissance at the perimeter firewall",
                priority=ActionPriority.MEDIUM,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
            ),
            ResponseAction(
                action_id="rc-alert-soc",
                action_type=ActionType.ALERT_SOC,
                title="Alert SOC of reconnaissance activity",
                description="Notify the SOC team to monitor for follow-up exploitation attempts from this source",
                priority=ActionPriority.LOW,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
            ),
        ],
    ))

    return playbooks


# ---------------------------------------------------------------------------
# Response Recommender
# ---------------------------------------------------------------------------

class ResponseRecommender:
    """Stateless service that evaluates incidents against playbooks and
    produces ResponsePlans with recommended actions.

    Parameters
    ----------
    playbooks : list[ResponsePlaybook] | None
        Custom playbooks. If None, the default built-in library is loaded.
    """

    def __init__(self, playbooks: list[ResponsePlaybook] | None = None) -> None:
        self._playbooks: list[ResponsePlaybook] = (
            playbooks if playbooks is not None else _make_default_playbooks()
        )

    @property
    def playbooks(self) -> list[ResponsePlaybook]:
        """Return a copy of the loaded playbooks."""
        return list(self._playbooks)

    @property
    def playbook_count(self) -> int:
        return len(self._playbooks)

    def add_playbook(self, playbook: ResponsePlaybook) -> None:
        """Register an additional playbook."""
        self._playbooks.append(playbook)

    def remove_playbook(self, playbook_id: str) -> bool:
        """Remove a playbook by ID. Returns True if found and removed."""
        before = len(self._playbooks)
        self._playbooks = [p for p in self._playbooks if p.playbook_id != playbook_id]
        return len(self._playbooks) < before

    # ------------------------------------------------------------------
    # Core recommendation engine
    # ------------------------------------------------------------------

    def recommend(self, incident: Incident) -> ResponsePlan:
        """Evaluate the incident against all playbooks and produce a plan.

        Steps:
          1. Filter playbooks to those whose criteria match the incident
          2. Collect all actions from matching playbooks
          3. Populate target_entity from the incident's primary entity
          4. Deduplicate by (action_type, target_entity)
          5. Sort by priority (IMMEDIATE first)
          6. Build a summary narrative
        """
        matched_playbooks: list[ResponsePlaybook] = []
        raw_actions: list[ResponseAction] = []

        for pb in self._playbooks:
            if not pb.enabled:
                continue
            if self._matches(pb, incident):
                matched_playbooks.append(pb)
                raw_actions.extend(pb.actions)

        # Populate target entities from incident
        populated = self._populate_targets(raw_actions, incident)

        # Deduplicate
        deduped = self._deduplicate(populated)

        # Sort by priority (highest first)
        deduped.sort(key=lambda a: _PRIORITY_RANK.get(a.priority, 0), reverse=True)

        # Build summary
        summary = self._build_summary(incident, matched_playbooks, deduped)

        plan = ResponsePlan(
            incident_id=incident.incident_id,
            matched_playbooks=[pb.name for pb in matched_playbooks],
            actions=deduped,
            incident_severity=incident.severity,
            incident_risk_score=incident.risk_score,
            summary=summary,
        )

        logger.info(
            "Generated response plan %s for incident %s: %d playbooks matched, %d actions",
            plan.plan_id, incident.incident_id,
            len(matched_playbooks), len(deduped),
        )

        return plan

    def recommend_from_alert(self, alert: Alert, incident: Incident | None = None) -> ResponsePlan:
        """Convenience method to recommend from an Alert.

        If the full Incident is available, uses it for richer matching.
        Otherwise, constructs a minimal incident-like context from the alert.
        """
        if incident is not None:
            return self.recommend(incident)

        # Build a minimal Incident from the Alert for matching
        minimal = Incident(
            incident_id=alert.incident_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            primary_entity=alert.primary_entity,
            event_count=alert.event_count,
            event_ids=alert.event_ids,
            mitre_tactics=alert.mitre_tactics,
            mitre_techniques=alert.mitre_techniques,
            risk_score=alert.risk_score,
            tags=alert.tags,
        )
        return self.recommend(minimal)

    # ------------------------------------------------------------------
    # Matching logic
    # ------------------------------------------------------------------

    def _matches(self, playbook: ResponsePlaybook, incident: Incident) -> bool:
        """Check if a playbook's criteria match the incident.

        A playbook matches if ANY of its non-empty criteria groups has a hit,
        AND the incident severity meets the minimum threshold.
        """
        # Severity gate
        inc_sev_rank = _SEVERITY_RANK.get(incident.severity, 1)
        min_sev_rank = _SEVERITY_RANK.get(playbook.match_severity_min, 1)
        if inc_sev_rank < min_sev_rank:
            return False

        # Collect match signals
        has_criteria = False
        matched = False

        # Event type matching (substring)
        if playbook.match_event_types:
            has_criteria = True
            inc_types = self._collect_event_types(incident)
            for pattern in playbook.match_event_types:
                p_lower = pattern.lower()
                for t in inc_types:
                    if p_lower in t.lower():
                        matched = True
                        break
                if matched:
                    break

        # MITRE technique matching
        if playbook.match_mitre_techniques and not matched:
            has_criteria = True
            inc_techniques = set(t.upper() for t in incident.mitre_techniques)
            for tech in playbook.match_mitre_techniques:
                if tech.upper() in inc_techniques:
                    matched = True
                    break

        # MITRE tactic matching
        if playbook.match_mitre_tactics and not matched:
            has_criteria = True
            inc_tactics = set(t.lower() for t in incident.mitre_tactics)
            for tactic in playbook.match_mitre_tactics:
                if tactic.lower() in inc_tactics:
                    matched = True
                    break

        # Source matching
        if playbook.match_sources and not matched:
            has_criteria = True
            inc_sources = self._collect_sources(incident)
            for source in playbook.match_sources:
                if source.lower() in inc_sources:
                    matched = True
                    break

        # Tag matching (substring)
        if playbook.match_tags and not matched:
            has_criteria = True
            inc_tags = set(t.lower() for t in incident.tags)
            for pattern in playbook.match_tags:
                p_lower = pattern.lower()
                for t in inc_tags:
                    if p_lower in t:
                        matched = True
                        break
                if matched:
                    break

        # If the playbook has no specific criteria (catch-all), skip it
        if not has_criteria:
            return False

        return matched

    def _collect_event_types(self, incident: Incident) -> set[str]:
        """Extract event types from incident title, description, tags, and timeline."""
        types: set[str] = set()
        if incident.title:
            types.add(incident.title)
        if incident.description:
            types.add(incident.description)
        for tag in incident.tags:
            types.add(tag)
        for entry in incident.timeline:
            types.add(entry.event_type)
        return types

    def _collect_sources(self, incident: Incident) -> set[str]:
        """Extract source modalities from incident timeline."""
        sources: set[str] = set()
        for entry in incident.timeline:
            sources.add(entry.source.lower())
        # Also check tags for source hints
        for tag in incident.tags:
            tag_l = tag.lower()
            if tag_l in ("soc", "honeypot", "phishing", "forensics", "threat_intel"):
                sources.add(tag_l)
        return sources

    # ------------------------------------------------------------------
    # Target population & deduplication
    # ------------------------------------------------------------------

    def _populate_targets(
        self, actions: list[ResponseAction], incident: Incident
    ) -> list[ResponseAction]:
        """Fill in target_entity from incident's primary entity if not set."""
        populated: list[ResponseAction] = []
        entity = incident.primary_entity

        for action in actions:
            # Deep copy to avoid mutating playbook templates
            a = action.model_copy(deep=True)
            # Template identifiers must never identify executable actions across incidents.
            a.action_id = str(uuid.uuid4())

            if not a.target_entity:
                target: dict[str, str] = {}
                if a.action_type in (
                    ActionType.BLOCK_IP, ActionType.BLOCK_EGRESS,
                ) and entity.ip:
                    target["ip"] = entity.ip
                elif a.action_type in (
                    ActionType.DISABLE_ACCOUNT, ActionType.FORCE_PASSWORD_RESET,
                ) and entity.user:
                    target["user"] = entity.user
                elif a.action_type in (
                    ActionType.ISOLATE_HOST, ActionType.SCAN_HOST,
                ) and entity.host:
                    target["host"] = entity.host
                elif entity.ip:
                    target["ip"] = entity.ip
                elif entity.user:
                    target["user"] = entity.user
                elif entity.host:
                    target["host"] = entity.host

                a.target_entity = target

            populated.append(a)

        return populated

    def _deduplicate(self, actions: list[ResponseAction]) -> list[ResponseAction]:
        """Deduplicate actions by (action_type, sorted target_entity items).

        When duplicates are found, keep the one with the higher priority.
        """
        seen: dict[str, ResponseAction] = {}
        for action in actions:
            target_key = str(sorted(action.target_entity.items()))
            key = f"{action.action_type.value}:{target_key}"
            if key not in seen:
                seen[key] = action
            else:
                existing = seen[key]
                if _PRIORITY_RANK.get(action.priority, 0) > _PRIORITY_RANK.get(existing.priority, 0):
                    seen[key] = action
        return list(seen.values())

    # ------------------------------------------------------------------
    # Summary generation
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        incident: Incident,
        matched_playbooks: list[ResponsePlaybook],
        actions: list[ResponseAction],
    ) -> str:
        """Build a human-readable summary of the response plan."""
        if not matched_playbooks:
            return (
                f"No playbooks matched incident '{incident.title}' "
                f"(severity: {incident.severity}, risk: {incident.risk_score:.1f}). "
                f"Manual investigation recommended."
            )

        pb_names = ", ".join(pb.name for pb in matched_playbooks)
        immediate_count = sum(
            1 for a in actions if a.priority == ActionPriority.IMMEDIATE
        )

        lines = [
            f"Response plan for incident '{incident.title}' "
            f"(severity: {incident.severity}, risk score: {incident.risk_score:.1f}).",
            f"Matched playbooks: {pb_names}.",
            f"Total recommended actions: {len(actions)}.",
        ]
        if immediate_count:
            lines.append(
                f"URGENT: {immediate_count} action(s) require immediate attention."
            )
        lines.append(
            "All actions require analyst approval before execution."
        )
        return " ".join(lines)

