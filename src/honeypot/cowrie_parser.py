"""
Cowrie JSON log parser.

Parses raw Cowrie honeypot JSON event lines (e.g. from cowrie.json) into
HoneypotSession objects and canonical SecurityEvents.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from src.honeypot.models import CommandRecord, CredentialAttempt, FileArtifact, HoneypotSession
from src.honeypot.normalizer import (
    normalise_artifact_record,
    normalise_command_record,
    normalise_credential_attempt,
    normalise_session_to_event,
)
from src.honeypot.recorder import SessionRecorder
from src.shared.event_schema import SecurityEvent

logger = logging.getLogger(__name__)


def _parse_cowrie_timestamp(ts_str: Optional[str]) -> datetime:
    """Parse Cowrie ISO-8601 timestamp string into UTC datetime."""
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        # Handle formats like "2026-08-22T14:32:10.123456Z" or "2026-08-22T14:32:10Z"
        cleaned = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


class CowrieLogParser:
    """Parses Cowrie JSON log streams and integrates with SessionRecorder."""

    def __init__(self, recorder: Optional[SessionRecorder] = None) -> None:
        self.recorder = recorder or SessionRecorder()

    def parse_event_dict(self, event_data: dict[str, Any]) -> Optional[SecurityEvent]:
        """Process a single decoded Cowrie log event dictionary.

        Returns a normalized SecurityEvent if this event produces an immediate signal.
        """
        eventid = event_data.get("eventid", "")
        session_id = event_data.get("session", "")
        src_ip = event_data.get("src_ip", "0.0.0.0")
        src_port = int(event_data.get("src_port", 0))
        dst_port = int(event_data.get("dst_port", 22))
        timestamp = _parse_cowrie_timestamp(event_data.get("timestamp"))

        # 1. Connection established
        if eventid == "cowrie.session.connect":
            session = self.recorder.start_session(
                session_id=session_id,
                source_ip=src_ip,
                source_port=src_port,
                target_port=dst_port,
                protocol="ssh" if dst_port == 22 else "telnet",
            )
            session.start_time = timestamp
            return None

        # Ensure session exists in recorder
        session = self.recorder.get_session(session_id)
        if not session and src_ip:
            session = self.recorder.start_session(
                session_id=session_id,
                source_ip=src_ip,
                source_port=src_port,
                target_port=dst_port,
            )

        if not session:
            return None

        # 2. Client banner / version identification
        if eventid == "cowrie.client.version":
            session.client_version = event_data.get("version")
            return None

        # 3. Authentication attempts
        elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
            success = (eventid == "cowrie.login.success")
            username = event_data.get("username", "unknown")
            password = event_data.get("password", "")
            attempt = self.recorder.record_credential(
                session_id=session_id,
                username=username,
                password=password,
                success=success,
            )
            if attempt:
                attempt.timestamp = timestamp
                return normalise_credential_attempt(session, attempt)

        # 4. Interactive command execution
        elif eventid in ("cowrie.command.input", "cowrie.command.failed"):
            cmd_line = event_data.get("input", "")
            if cmd_line:
                cmd_rec = self.recorder.record_command(
                    session_id=session_id,
                    command=cmd_line,
                )
                if cmd_rec:
                    cmd_rec.timestamp = timestamp
                    return normalise_command_record(session, cmd_rec)

        # 5. File download / dropper ingress
        elif eventid == "cowrie.session.file_download":
            url = event_data.get("url", event_data.get("outfile", "downloaded_file"))
            shasum = event_data.get("shasum")
            art = self.recorder.record_artifact(
                session_id=session_id,
                filename_or_url=url,
                file_hash=shasum,
                transfer_type="download",
            )
            if art:
                art.timestamp = timestamp
                return normalise_artifact_record(session, art)

        # 6. Session closed
        elif eventid == "cowrie.session.closed":
            closed = self.recorder.close_session(session_id=session_id, end_time=timestamp)
            if closed:
                return normalise_session_to_event(closed)

        return None

    def parse_line(self, line: str) -> Optional[SecurityEvent]:
        """Parse a single JSON string line from a Cowrie log."""
        raw = line.strip()
        if not raw:
            return None
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return self.parse_event_dict(data)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in Cowrie log line: %.100s", raw)
        return None

    def parse_stream(self, stream: Generator[str, None, None]) -> Generator[SecurityEvent, None, None]:
        """Yield normalized SecurityEvents from an iterable stream of log lines."""
        for line in stream:
            event = self.parse_line(line)
            if event:
                yield event
