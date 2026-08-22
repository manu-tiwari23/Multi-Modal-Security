"""
Attacker behavior analyzer and TTP clustering for honeypot sessions.

Clusters attacker sessions by Tactics, Techniques, and Procedures (TTPs),
extracts attacker behavioral profiles, and categorizes attack campaign archetypes.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Sequence

from src.honeypot.models import AttackerProfile, CommandRecord, HoneypotSession
from src.shared.event_schema import SeverityLevel

logger = logging.getLogger(__name__)

# TTP category definitions with associated MITRE techniques
TTP_DEFINITIONS: dict[str, dict[str, Any]] = {
    "brute_force": {
        "title": "Credential Brute Force / Spraying",
        "mitre": ["T1110", "T1110.001", "T1110.003"],
        "description": "Systematic testing of passwords across single or multiple accounts",
    },
    "recon": {
        "title": "System & Network Reconnaissance",
        "mitre": ["T1082", "T1016", "T1057", "T1033"],
        "description": "Host architecture, OS release, active processes, and IP discovery",
    },
    "credential_access": {
        "title": "Credential Access & Extraction",
        "mitre": ["T1087.001", "T1003.008"],
        "description": "Accessing password files, shadow hashes, or account tables",
    },
    "download": {
        "title": "Ingress Tool Transfer / Dropper",
        "mitre": ["T1105"],
        "description": "Fetching external malware payloads via wget, curl, or ftp",
    },
    "privilege_escalation": {
        "title": "Privilege Escalation",
        "mitre": ["T1548.003", "T1078.003"],
        "description": "Attempting sudo or root privilege transitions",
    },
    "persistence": {
        "title": "Persistence Mechanism",
        "mitre": ["T1053.003", "T1543"],
        "description": "Installing cron jobs, services, or scheduled tasks",
    },
    "defense_evasion": {
        "title": "Defense Evasion & Log Tampering",
        "mitre": ["T1070.004", "T1070.003"],
        "description": "Clearing bash history, deleting log files, or disabling auditing",
    },
}

# Campaign archetypes derived from combined TTP clusters
ARCHETYPES = {
    "automated_dropper": "Automated Scanner / Payload Dropper (Mirai/Botnet style)",
    "interactive_recon": "Interactive Manual Reconnaissance (Human Operator)",
    "credential_bruteforce": "Dedicated Credential Spraying Campaign",
    "targeted_multi_stage": "Targeted Multi-Stage Intrusion (Recon + Exploit + Persistence)",
    "opportunistic_probe": "Low-Interaction Opportunistic Scanner",
}


class BehaviorAnalyzer:
    """Analyzes and clusters deceptive honeypot sessions into behavioral profiles."""

    def __init__(self) -> None:
        pass

    def analyze_session(self, session: HoneypotSession) -> dict[str, Any]:
        """Extract TTP categories, dominant techniques, and threat rating for a session."""
        categories: set[str] = set()
        techniques: set[str] = set(session.mitre_techniques)

        if len(session.credentials) >= 3 or (session.credentials and not session.authenticated):
            categories.add("brute_force")
            techniques.add("T1110")

        for cmd in session.commands:
            for tag in cmd.tags:
                if tag in TTP_DEFINITIONS:
                    categories.add(tag)
                    techniques.update(TTP_DEFINITIONS[tag]["mitre"])

        if session.artifacts:
            categories.add("download")
            techniques.add("T1105")

        # Determine Archetype
        archetype = self._determine_archetype(categories, len(session.commands), len(session.artifacts))

        # Threat Level
        threat_level = self._compute_threat_level(categories, len(session.artifacts), session.authenticated)

        return {
            "session_id": session.session_id,
            "source_ip": session.source_ip,
            "ttp_categories": sorted(list(categories)),
            "mitre_techniques": sorted(list(techniques)),
            "archetype": archetype,
            "threat_level": threat_level,
        }

    def build_attacker_profile(
        self,
        ip: str,
        sessions: Sequence[HoneypotSession],
    ) -> AttackerProfile:
        """Aggregate multiple sessions from an IP into an AttackerProfile."""
        if not sessions:
            return AttackerProfile(ip=ip)

        matching_sessions = [s for s in sessions if s.source_ip == ip]
        if not matching_sessions:
            return AttackerProfile(ip=ip)

        first_seen = min(s.start_time for s in matching_sessions)
        last_seen = max(s.end_time or s.start_time for s in matching_sessions)

        usernames: set[str] = set()
        passwords: set[str] = set()
        commands: list[str] = []
        ttp_categories: set[str] = set()
        mitre_techs: set[str] = set()
        banners: set[str] = set()
        total_artifacts = 0
        total_creds = 0

        for s in matching_sessions:
            analysis = self.analyze_session(s)
            ttp_categories.update(analysis["ttp_categories"])
            mitre_techs.update(analysis["mitre_techniques"])

            for c in s.credentials:
                total_creds += 1
                usernames.add(c.username)
                passwords.add(c.password)

            for cmd in s.commands:
                commands.append(cmd.command)

            total_artifacts += len(s.artifacts)
            if s.client_version:
                banners.add(s.client_version)

        # Most common commands
        cmd_counts = Counter(commands)
        unique_cmds = [cmd for cmd, _ in cmd_counts.most_common(20)]

        threat_level = self._compute_threat_level(
            ttp_categories,
            total_artifacts,
            any(s.authenticated for s in matching_sessions),
        )

        return AttackerProfile(
            ip=ip,
            first_seen=first_seen,
            last_seen=last_seen,
            session_count=len(matching_sessions),
            total_credentials_tried=total_creds,
            total_commands_executed=len(commands),
            total_payloads_attempted=total_artifacts,
            usernames_targeted=sorted(list(usernames)),
            passwords_targeted=sorted(list(passwords)),
            unique_commands=unique_cmds,
            ttp_categories=sorted(list(ttp_categories)),
            mitre_techniques=sorted(list(mitre_techs)),
            client_banners=sorted(list(banners)),
            threat_level=threat_level,
        )

    def cluster_attackers(
        self,
        sessions: Sequence[HoneypotSession],
    ) -> dict[str, list[AttackerProfile]]:
        """Group all unique attacker IPs into campaign archetypes."""
        sessions_by_ip: dict[str, list[HoneypotSession]] = defaultdict(list)
        for s in sessions:
            sessions_by_ip[s.source_ip].append(s)

        clusters: dict[str, list[AttackerProfile]] = {
            ARCHETYPES["targeted_multi_stage"]: [],
            ARCHETYPES["automated_dropper"]: [],
            ARCHETYPES["interactive_recon"]: [],
            ARCHETYPES["credential_bruteforce"]: [],
            ARCHETYPES["opportunistic_probe"]: [],
        }

        for ip, sess_list in sessions_by_ip.items():
            profile = self.build_attacker_profile(ip, sess_list)
            cats = set(profile.ttp_categories)
            arch = self._determine_archetype(cats, profile.total_commands_executed, profile.total_payloads_attempted)
            arch_title = ARCHETYPES.get(arch, ARCHETYPES["opportunistic_probe"])
            clusters[arch_title].append(profile)

        return clusters

    def generate_statistics(self, sessions: Sequence[HoneypotSession]) -> dict[str, Any]:
        """Compute aggregate intelligence metrics across all captured honeypot sessions."""
        all_creds = [c for s in sessions for c in s.credentials]
        all_cmds = [cmd.command for s in sessions for cmd in s.commands]
        all_ips = {s.source_ip for s in sessions}

        user_counter = Counter(c.username for c in all_creds)
        pass_counter = Counter(c.password for c in all_creds)
        cmd_counter = Counter(all_cmds)

        all_techs = Counter(
            t for s in sessions for t in self.analyze_session(s)["mitre_techniques"]
        )

        return {
            "total_sessions": len(sessions),
            "unique_attackers": len(all_ips),
            "total_credentials_tried": len(all_creds),
            "total_commands_executed": len(all_cmds),
            "top_usernames": user_counter.most_common(10),
            "top_passwords": pass_counter.most_common(10),
            "top_commands": cmd_counter.most_common(10),
            "mitre_technique_distribution": dict(all_techs.most_common(10)),
        }

    # ----------------------------------------------------------------------
    # Internal Classification Logic
    # ----------------------------------------------------------------------

    @staticmethod
    def _determine_archetype(
        categories: set[str],
        command_count: int,
        artifact_count: int,
    ) -> str:
        """Determine primary campaign archetype based on observed TTPs."""
        if (
            ("privilege_escalation" in categories or "persistence" in categories)
            and ("download" in categories or "recon" in categories)
        ):
            return "targeted_multi_stage"
        elif "download" in categories or artifact_count > 0:
            return "automated_dropper"
        elif "recon" in categories and command_count >= 3:
            return "interactive_recon"
        elif "brute_force" in categories or "credential_access" in categories:
            return "credential_bruteforce"
        else:
            return "opportunistic_probe"

    @staticmethod
    def _compute_threat_level(
        categories: set[str],
        artifact_count: int,
        authenticated: bool,
    ) -> SeverityLevel:
        """Compute severity level rating for the attacker."""
        if (
            artifact_count > 0
            and ("privilege_escalation" in categories or "persistence" in categories)
        ):
            return "critical"
        elif (
            artifact_count > 0
            or "privilege_escalation" in categories
            or "persistence" in categories
            or len(categories) >= 3
        ):
            return "high"
        elif authenticated or "recon" in categories or "brute_force" in categories:
            return "medium"
        else:
            return "low"
