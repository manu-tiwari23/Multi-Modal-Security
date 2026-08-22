"""
Unit tests for Honeypot Pydantic data models.
"""

from __future__ import annotations

import datetime

import pytest

from src.honeypot.models import (
    AttackerProfile,
    CommandRecord,
    CredentialAttempt,
    FileArtifact,
    HoneypotSession,
)


def test_credential_attempt_creation():
    attempt = CredentialAttempt(
        username="admin",
        password="password123",
        success=False,
        source_ip="192.168.1.100",
    )
    assert attempt.username == "admin"
    assert attempt.password == "password123"
    assert not attempt.success
    assert attempt.source_ip == "192.168.1.100"
    assert attempt.attempt_id


def test_command_record_creation():
    cmd = CommandRecord(
        command="uname -a",
        working_dir="/root",
        output_preview="Linux honeypot",
        return_code=0,
        tags=["recon"],
    )
    assert cmd.command == "uname -a"
    assert cmd.working_dir == "/root"
    assert "recon" in cmd.tags


def test_file_artifact_creation():
    art = FileArtifact(
        filename_or_url="http://malware.com/dropper.sh",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=1024,
        transfer_type="download",
    )
    assert art.filename_or_url == "http://malware.com/dropper.sh"
    assert art.size_bytes == 1024
    assert art.transfer_type == "download"


def test_honeypot_session_lifecycle():
    now = datetime.datetime.now(datetime.timezone.utc)
    session = HoneypotSession(
        source_ip="203.0.113.50",
        source_port=44512,
        protocol="ssh",
        target_host="honeypot-ssh-01",
        target_port=22,
        start_time=now,
    )

    assert session.is_active
    assert session.protocol == "ssh"
    assert session.source_ip == "203.0.113.50"
    assert session.entity.ip == "203.0.113.50"
    assert session.entity.host == "honeypot-ssh-01"

    # Close session
    end_time = now + datetime.timedelta(seconds=45)
    session.close(end_time=end_time)

    assert not session.is_active
    assert session.duration_seconds == pytest.approx(45.0)


def test_attacker_profile_model():
    prof = AttackerProfile(
        ip="198.51.100.22",
        session_count=3,
        total_commands_executed=12,
        ttp_categories=["recon", "download"],
        threat_level="high",
    )
    assert prof.ip == "198.51.100.22"
    assert prof.session_count == 3
    assert "download" in prof.ttp_categories
    assert prof.threat_level == "high"
