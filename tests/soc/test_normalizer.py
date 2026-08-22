"""Unit tests for the syslog normaliser."""

import pytest

from src.shared.event_schema import SecurityEvent
from src.soc.ingestion.normalizer import normalise_syslog_line


# ---------------------------------------------------------------------------
# Valid syslog lines — should produce a SecurityEvent
# ---------------------------------------------------------------------------


class TestNormaliseSyslogLine:
    """Test the syslog → SecurityEvent normaliser."""

    def test_ssh_failed_password(self):
        line = "Aug 16 14:22:01 webserver01 sshd[12345]: Failed password for admin from 185.220.101.42 port 52413 ssh2"
        event = normalise_syslog_line(line)

        assert event is not None
        assert isinstance(event, SecurityEvent)
        assert event.source == "soc"
        assert event.event_type == "ssh_auth_failure"
        assert event.severity == "medium"
        assert event.entity.ip == "185.220.101.42"
        assert event.entity.user == "admin"
        assert event.entity.host == "webserver01"

    def test_ssh_accepted_publickey(self):
        line = "Aug 16 10:00:00 jumpbox sshd[999]: Accepted publickey for deploy from 10.0.1.10 port 44100 ssh2"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "ssh_auth_success"
        assert event.severity == "low"
        assert event.entity.user == "deploy"
        assert event.entity.ip == "10.0.1.10"

    def test_ssh_invalid_user(self):
        line = "Aug 16 03:12:55 db-primary sshd[5000]: Invalid user root from 91.240.118.73 port 61234"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "ssh_invalid_user"
        assert event.entity.user == "root"
        assert event.entity.ip == "91.240.118.73"

    def test_firewall_block(self):
        line = "Aug 16 08:30:00 vpn-gateway kernel[0]: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=45.155.205.233 DST=10.0.1.10 PROTO=TCP SPT=12345 DPT=22"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "firewall_block"
        assert event.severity == "medium"
        # Should extract the first IP (SRC)
        assert event.entity.ip == "45.155.205.233"
        assert event.entity.host == "vpn-gateway"

    def test_sudo_command(self):
        line = "Aug 16 11:00:00 webserver01 sudo[7777]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "sudo_command"

    def test_session_open(self):
        line = "Aug 16 09:00:00 mail-gw systemd-logind[500]: New session 42 of user bob."
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "session_open"
        assert event.severity == "low"

    def test_session_close(self):
        line = "Aug 16 17:00:00 mail-gw systemd-logind[500]: session closed for user bob"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "session_close"

    def test_system_error(self):
        line = "Aug 16 02:00:00 monitoring systemd[1]: CRITICAL: disk /dev/sdb1 is 98% full"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "system_error"
        assert event.severity == "high"

    def test_generic_syslog(self):
        line = "Aug 16 12:00:00 fileserver cron[999]: INFO Starting scheduled backup"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.event_type == "generic_syslog"
        assert event.severity == "low"

    def test_raw_field_preserved(self):
        """The original line must be preserved in raw.line for auditability."""
        line = "Aug 16 14:22:01 webserver01 sshd[12345]: Failed password for admin from 185.220.101.42 port 52413 ssh2"
        event = normalise_syslog_line(line)

        assert event is not None
        assert event.raw["line"] == line
        assert event.raw["process"] == "sshd"


# ---------------------------------------------------------------------------
# Malformed / empty lines — should return None gracefully
# ---------------------------------------------------------------------------


class TestMalformedInput:
    """Test that bad input doesn't crash the normaliser."""

    def test_empty_string(self):
        assert normalise_syslog_line("") is None

    def test_whitespace_only(self):
        assert normalise_syslog_line("   \t  \n") is None

    def test_random_garbage(self):
        assert normalise_syslog_line("xyzzy 12345 not a syslog line at all") is None

    def test_partial_syslog(self):
        """Missing the message part after the colon."""
        assert normalise_syslog_line("Aug 16 14:22:01 host") is None

    def test_json_line(self):
        """A JSON log line is not syslog — should return None, not crash."""
        assert normalise_syslog_line('{"level": "error", "msg": "something failed"}') is None
