"""
Syslog normaliser for the SOC ingestion pipeline.

Parses raw syslog-format lines into ``SecurityEvent`` objects.  This is the
first real normaliser — additional parsers (Windows Event Log, cloud audit
logs, etc.) will follow the same interface and be registered as the project
grows.

Convention (from SKILL.md for soc-module): never let a raw, unnormalised log
format leak into OpenSearch — everything goes through a normaliser first.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from src.shared.event_schema import Entity, SecurityEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for common syslog fields
# ---------------------------------------------------------------------------

# Standard syslog: "Aug 16 14:22:01 webserver01 sshd[12345]: ..."
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[\d+\])?\s*:\s+"
    r"(?P<message>.*)$"
)

# IP address extraction (v4)
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# User extraction from common syslog messages
_USER_RE = re.compile(
    r"(?:user(?:name)?[=:\s]+|for\s+(?:invalid\s+user\s+)?|"
    r"User\s+)(\w[\w.-]*)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Event type and severity classification
# ---------------------------------------------------------------------------

_EVENT_CLASSIFICATIONS: list[tuple[re.Pattern, str, str]] = [
    # (pattern, event_type, severity)
    (re.compile(r"Failed password|authentication failure", re.I), "ssh_auth_failure", "medium"),
    (re.compile(r"Accepted password|Accepted publickey", re.I), "ssh_auth_success", "low"),
    (re.compile(r"Invalid user", re.I), "ssh_invalid_user", "medium"),
    (re.compile(r"COMMAND|sudo", re.I), "sudo_command", "medium"),
    (re.compile(r"UFW BLOCK|iptables.*DROP|DENY", re.I), "firewall_block", "medium"),
    (re.compile(r"error|crit|alert|emerg", re.I), "system_error", "high"),
    (re.compile(r"session opened|New session", re.I), "session_open", "low"),
    (re.compile(r"session closed", re.I), "session_close", "low"),
]


def _classify(message: str) -> tuple[str, str]:
    """Return ``(event_type, severity)`` for a syslog message body."""
    for pattern, event_type, severity in _EVENT_CLASSIFICATIONS:
        if pattern.search(message):
            return event_type, severity
    return "generic_syslog", "low"


def _extract_ips(text: str) -> list[str]:
    """Extract all IPv4 addresses from *text*."""
    return _IPV4_RE.findall(text)


def _extract_user(text: str) -> Optional[str]:
    """Extract a username from common syslog patterns."""
    match = _USER_RE.search(text)
    return match.group(1) if match else None


def _parse_syslog_timestamp(ts_str: str) -> datetime:
    """Parse a syslog timestamp (no year) and pin it to the current year, UTC."""
    now = datetime.now(timezone.utc)
    try:
        parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return parsed.replace(year=now.year, tzinfo=timezone.utc)
    except ValueError:
        return now


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalise_syslog_line(line: str) -> Optional[SecurityEvent]:
    """Parse a single syslog line into a ``SecurityEvent``.

    Returns ``None`` (and logs a warning) if the line can't be parsed.
    """
    line = line.strip()
    if not line:
        return None

    match = _SYSLOG_RE.match(line)
    if not match:
        logger.warning("Could not parse syslog line: %.120s", line)
        return None

    timestamp = _parse_syslog_timestamp(match.group("timestamp"))
    host = match.group("host")
    message = match.group("message")

    event_type, severity = _classify(message)
    ips = _extract_ips(message)
    user = _extract_user(message)

    entity = Entity(
        ip=ips[0] if ips else None,
        user=user,
        host=host,
    )

    return SecurityEvent(
        timestamp=timestamp,
        source="soc",
        entity=entity,
        event_type=event_type,
        severity=severity,
        raw={"line": line, "process": match.group("process")},
    )
