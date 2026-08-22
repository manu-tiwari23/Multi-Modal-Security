"""
Honeypot event normalizer.

Converts honeypot sessions, credential attempts, interactive shell commands,
and payload download events into canonical ``SecurityEvent`` objects (source: "honeypot").
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from src.honeypot.models import (
    CommandRecord,
    CredentialAttempt,
    FileArtifact,
    HoneypotSession,
)
from src.shared.event_schema import Entity, SecurityEvent, SeverityLevel

logger = logging.getLogger(__name__)

# High-risk TTP categories that bump event severity to 'high'
HIGH_SEVERITY_CATEGORIES = frozenset({
    "download",
    "privilege_escalation",
    "persistence",
    "defense_evasion",
})


def normalise_credential_attempt(
    session: HoneypotSession,
    attempt: CredentialAttempt,
) -> SecurityEvent:
    """Normalise an authentication attempt into a SecurityEvent."""
    event_type = "honeypot_auth_success" if attempt.success else "honeypot_auth_failure"
    severity: SeverityLevel = "medium"

    return SecurityEvent(
        timestamp=attempt.timestamp,
        source="honeypot",
        entity=Entity(
            ip=session.source_ip,
            user=attempt.username,
            host=session.target_host,
        ),
        event_type=event_type,
        severity=severity,
        raw={
            "session_id": session.session_id,
            "protocol": session.protocol,
            "username": attempt.username,
            "password": attempt.password,
            "success": attempt.success,
            "source_port": session.source_port,
            "client_version": session.client_version,
        },
        enrichment={
            "mitre_attack": ["T1110"],
            "deception_target": session.target_host,
        },
    )


def normalise_command_record(
    session: HoneypotSession,
    cmd: CommandRecord,
) -> SecurityEvent:
    """Normalise an interactive command into a SecurityEvent."""
    is_high = any(tag in HIGH_SEVERITY_CATEGORIES for tag in cmd.tags)
    severity: SeverityLevel = "high" if is_high else "medium"

    # Extract user
    user = session.authenticated_user or (session.credentials[-1].username if session.credentials else "root")

    return SecurityEvent(
        timestamp=cmd.timestamp,
        source="honeypot",
        entity=Entity(
            ip=session.source_ip,
            user=user,
            host=session.target_host,
        ),
        event_type="honeypot_command",
        severity=severity,
        raw={
            "session_id": session.session_id,
            "protocol": session.protocol,
            "command": cmd.command,
            "working_dir": cmd.working_dir,
            "output_preview": cmd.output_preview,
            "return_code": cmd.return_code,
            "tags": cmd.tags,
        },
        enrichment={
            "ttp_tags": cmd.tags,
            "mitre_attack": session.mitre_techniques or ["T1059.004"],
            "deception_target": session.target_host,
        },
    )


def normalise_artifact_record(
    session: HoneypotSession,
    artifact: FileArtifact,
) -> SecurityEvent:
    """Normalise a file transfer or dropper download into a SecurityEvent."""
    user = session.authenticated_user or (session.credentials[-1].username if session.credentials else "root")

    return SecurityEvent(
        timestamp=artifact.timestamp,
        source="honeypot",
        entity=Entity(
            ip=session.source_ip,
            user=user,
            host=session.target_host,
            hash=artifact.file_hash,
        ),
        event_type="honeypot_payload_download",
        severity="high",
        raw={
            "session_id": session.session_id,
            "protocol": session.protocol,
            "filename_or_url": artifact.filename_or_url,
            "file_hash": artifact.file_hash,
            "size_bytes": artifact.size_bytes,
            "transfer_type": artifact.transfer_type,
        },
        enrichment={
            "mitre_attack": ["T1105"],
            "deception_target": session.target_host,
        },
    )


def normalise_session_to_event(session: HoneypotSession) -> SecurityEvent:
    """Normalise an entire closed session into a comprehensive aggregate SecurityEvent."""
    # Determine severity based on depth of attacker activity
    if session.artifacts or any("download" in c.tags or "privilege_escalation" in c.tags for c in session.commands):
        severity: SeverityLevel = "high"
    elif session.commands or session.authenticated:
        severity = "high" if session.authenticated else "medium"
    else:
        severity = "medium"

    last_hash = session.artifacts[-1].file_hash if session.artifacts else None
    user = session.authenticated_user or (session.credentials[-1].username if session.credentials else None)

    return SecurityEvent(
        timestamp=session.end_time or session.start_time,
        source="honeypot",
        entity=Entity(
            ip=session.source_ip,
            user=user,
            host=session.target_host,
            hash=last_hash,
        ),
        event_type="honeypot_session",
        severity=severity,
        raw={
            "session_id": session.session_id,
            "protocol": session.protocol,
            "source_ip": session.source_ip,
            "source_port": session.source_port,
            "target_host": session.target_host,
            "target_port": session.target_port,
            "duration_seconds": session.duration_seconds,
            "authenticated": session.authenticated,
            "authenticated_user": session.authenticated_user,
            "credentials_count": len(session.credentials),
            "commands_count": len(session.commands),
            "artifacts_count": len(session.artifacts),
            "summary": session.summary,
            "client_version": session.client_version,
        },
        enrichment={
            "mitre_attack": session.mitre_techniques or ["T1078"],
            "ttp_tags": session.tags,
            "deception_target": session.target_host,
        },
    )
