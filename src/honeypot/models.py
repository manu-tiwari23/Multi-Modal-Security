"""
Pydantic data models for honeypot sessions, attacker interactions, and behavioral profiles.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from src.shared.event_schema import Entity, SeverityLevel

HoneypotProtocol = Literal["ssh", "http", "telnet", "generic"]


class CredentialAttempt(BaseModel):
    """A credential pair tested by an attacker on the deceptive service."""

    attempt_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    username: str = Field(..., description="Username attempted")
    password: str = Field(..., description="Password attempted (safe synthetic test value)")
    success: bool = Field(default=False, description="Whether the honeypot accepted the login")
    source_ip: Optional[str] = Field(default=None, description="Originating IP address")


class CommandRecord(BaseModel):
    """An interactive shell command executed inside the deceptive environment."""

    command_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    command: str = Field(..., description="Raw command line input")
    working_dir: str = Field(default="/root", description="Simulated current working directory")
    output_preview: str = Field(default="", description="Simulated command output preview (capped)")
    return_code: int = Field(default=0, description="Simulated process exit code")
    tags: list[str] = Field(default_factory=list, description="TTP tags (e.g. recon, download, privilege_escalation)")


class FileArtifact(BaseModel):
    """A file download, dropper, or payload transfer attempt captured during a session."""

    artifact_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    filename_or_url: str = Field(..., description="Filename, remote URL, or path attempted")
    file_hash: Optional[str] = Field(default=None, description="SHA-256 hash of captured payload")
    size_bytes: int = Field(default=0, description="Size of the payload in bytes")
    transfer_type: Literal["download", "upload"] = Field(default="download")


class HoneypotSession(BaseModel):
    """A complete deceptive interaction session capturing an attacker's entire lifecycle."""

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    protocol: HoneypotProtocol = Field(default="ssh", description="Deceptive protocol")
    source_ip: str = Field(..., description="Attacker source IP")
    source_port: int = Field(default=0, description="Attacker source port")
    target_host: str = Field(default="honeypot-ssh-01", description="Virtual honeypot sensor hostname")
    target_port: int = Field(default=22, description="Listening port of the deceptive service")
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = Field(default=None, description="When the session closed")
    duration_seconds: float = Field(default=0.0, description="Total session duration in seconds")
    client_version: Optional[str] = Field(default=None, description="Client SSH banner or HTTP User-Agent")

    # Interactive activity
    credentials: list[CredentialAttempt] = Field(default_factory=list)
    authenticated: bool = Field(default=False)
    authenticated_user: Optional[str] = Field(default=None)
    commands: list[CommandRecord] = Field(default_factory=list)
    artifacts: list[FileArtifact] = Field(default_factory=list)

    # Classification & summary
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    is_active: bool = Field(default=True)
    summary: str = Field(default="", description="Auto-generated session activity summary")

    def close(self, end_time: Optional[datetime] = None) -> None:
        """Mark the session as completed and calculate duration."""
        self.is_active = False
        self.end_time = end_time or datetime.now(timezone.utc)
        self.duration_seconds = max(0.0, (self.end_time - self.start_time).total_seconds())

    @property
    def entity(self) -> Entity:
        """Convert session identifying details into canonical Entity."""
        return Entity(
            ip=self.source_ip,
            user=self.authenticated_user or (self.credentials[-1].username if self.credentials else None),
            host=self.target_host,
            hash=self.artifacts[0].file_hash if self.artifacts else None,
        )


class AttackerProfile(BaseModel):
    """Behavioral summary and TTP classification for a tracked attacker IP."""

    ip: str = Field(..., description="Attacker IP address")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_count: int = Field(default=0)
    total_credentials_tried: int = Field(default=0)
    total_commands_executed: int = Field(default=0)
    total_payloads_attempted: int = Field(default=0)
    usernames_targeted: list[str] = Field(default_factory=list)
    passwords_targeted: list[str] = Field(default_factory=list)
    unique_commands: list[str] = Field(default_factory=list)
    ttp_categories: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    client_banners: list[str] = Field(default_factory=list)
    threat_level: SeverityLevel = Field(default="medium")
