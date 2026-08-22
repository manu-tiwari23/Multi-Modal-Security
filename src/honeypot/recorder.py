"""
Session recorder for tracking and bounding interactive deceptive honeypot sessions.

Enforces bounds on commands, credentials, and artifacts per session to prevent
unbounded memory consumption, while generating structured session records.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Optional

from src.honeypot.models import (
    CommandRecord,
    CredentialAttempt,
    FileArtifact,
    HoneypotProtocol,
    HoneypotSession,
)

logger = logging.getLogger(__name__)


class SessionRecorder:
    """Thread-safe in-memory session tracker for honeypot services."""

    def __init__(
        self,
        max_commands_per_session: int = 200,
        max_credentials_per_session: int = 100,
        max_artifacts_per_session: int = 50,
        max_active_sessions: int = 1000,
        max_closed_history: int = 500,
    ) -> None:
        self.max_commands = max_commands_per_session
        self.max_credentials = max_credentials_per_session
        self.max_artifacts = max_artifacts_per_session
        self.max_active = max_active_sessions
        self.max_history = max_closed_history

        self._lock = threading.RLock()
        self._active_sessions: dict[str, HoneypotSession] = {}
        self._closed_sessions: OrderedDict[str, HoneypotSession] = OrderedDict()

    # ----------------------------------------------------------------------
    # Session Lifecycle
    # ----------------------------------------------------------------------

    def start_session(
        self,
        source_ip: str,
        source_port: int = 0,
        protocol: HoneypotProtocol = "ssh",
        target_host: str = "honeypot-ssh-01",
        target_port: int = 22,
        client_version: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> HoneypotSession:
        """Initialize a new active deceptive session."""
        with self._lock:
            # Evict oldest if active capacity exceeded
            if len(self._active_sessions) >= self.max_active:
                oldest_id = next(iter(self._active_sessions))
                evicted = self._active_sessions.pop(oldest_id)
                evicted.close()
                self._store_closed(evicted)
                logger.warning("Evicted oldest active session %s due to capacity", oldest_id)

            kwargs: dict[str, Any] = {
                "protocol": protocol,
                "source_ip": source_ip,
                "source_port": source_port,
                "target_host": target_host,
                "target_port": target_port,
                "client_version": client_version,
                "start_time": datetime.now(timezone.utc),
            }
            if session_id:
                kwargs["session_id"] = session_id

            session = HoneypotSession(**kwargs)
            self._active_sessions[session.session_id] = session
            logger.info(
                "Started honeypot %s session %s from %s:%d",
                protocol,
                session.session_id,
                source_ip,
                source_port,
            )
            return session

    def get_session(self, session_id: str) -> Optional[HoneypotSession]:
        """Retrieve a session by ID from active or history."""
        with self._lock:
            if session_id in self._active_sessions:
                return self._active_sessions[session_id]
            return self._closed_sessions.get(session_id)

    def record_credential(
        self,
        session_id: str,
        username: str,
        password: str,
        success: bool = False,
    ) -> Optional[CredentialAttempt]:
        """Record an authentication attempt within a session."""
        with self._lock:
            session = self._active_sessions.get(session_id)
            if not session:
                return None

            attempt = CredentialAttempt(
                username=username,
                password=password,
                success=success,
                source_ip=session.source_ip,
            )
            if len(session.credentials) < self.max_credentials:
                session.credentials.append(attempt)

            if success:
                session.authenticated = True
                session.authenticated_user = username

            return attempt

    def record_command(
        self,
        session_id: str,
        command: str,
        working_dir: str = "/root",
        output_preview: str = "",
        return_code: int = 0,
        tags: Optional[list[str]] = None,
    ) -> Optional[CommandRecord]:
        """Record a simulated shell command executed during a session."""
        with self._lock:
            session = self._active_sessions.get(session_id)
            if not session:
                return None

            # Cap output preview length to avoid huge strings
            capped_output = output_preview[:500] if output_preview else ""
            cmd_rec = CommandRecord(
                command=command.strip(),
                working_dir=working_dir,
                output_preview=capped_output,
                return_code=return_code,
                tags=tags or [],
            )

            if len(session.commands) < self.max_commands:
                session.commands.append(cmd_rec)

            return cmd_rec

    def record_artifact(
        self,
        session_id: str,
        filename_or_url: str,
        file_hash: Optional[str] = None,
        size_bytes: int = 0,
        transfer_type: str = "download",
    ) -> Optional[FileArtifact]:
        """Record a file download, dropper, or upload attempt."""
        with self._lock:
            session = self._active_sessions.get(session_id)
            if not session:
                return None

            art = FileArtifact(
                filename_or_url=filename_or_url,
                file_hash=file_hash,
                size_bytes=size_bytes,
                transfer_type=transfer_type,  # type: ignore[arg-type]
            )
            if len(session.artifacts) < self.max_artifacts:
                session.artifacts.append(art)

            return art

    def close_session(
        self,
        session_id: str,
        end_time: Optional[datetime] = None,
    ) -> Optional[HoneypotSession]:
        """Close an active session, generate summary, and move to history."""
        with self._lock:
            session = self._active_sessions.pop(session_id, None)
            if not session:
                return self._closed_sessions.get(session_id)

            session.close(end_time=end_time)
            session.summary = self._generate_session_summary(session)
            self._store_closed(session)

            logger.info(
                "Closed honeypot session %s (duration=%.1fs, cmds=%d, creds=%d)",
                session.session_id,
                session.duration_seconds,
                len(session.commands),
                len(session.credentials),
            )
            return session

    def _store_closed(self, session: HoneypotSession) -> None:
        """Store closed session with LRU eviction."""
        self._closed_sessions[session.session_id] = session
        if len(self._closed_sessions) > self.max_history:
            self._closed_sessions.popitem(last=False)

    # ----------------------------------------------------------------------
    # Query & Analysis Helpers
    # ----------------------------------------------------------------------

    def get_active_sessions(self) -> list[HoneypotSession]:
        """Return all currently active sessions."""
        with self._lock:
            return list(self._active_sessions.values())

    def get_closed_sessions(self) -> list[HoneypotSession]:
        """Return all stored closed sessions."""
        with self._lock:
            return list(self._closed_sessions.values())

    def get_sessions_for_ip(self, ip: str) -> list[HoneypotSession]:
        """Return all active and historical sessions from a specific source IP."""
        with self._lock:
            active = [s for s in self._active_sessions.values() if s.source_ip == ip]
            history = [s for s in self._closed_sessions.values() if s.source_ip == ip]
            return active + history

    def clear(self) -> None:
        """Clear all session data (useful for test teardown)."""
        with self._lock:
            self._active_sessions.clear()
            self._closed_sessions.clear()

    # ----------------------------------------------------------------------
    # Summary Generation
    # ----------------------------------------------------------------------

    @staticmethod
    def _generate_session_summary(session: HoneypotSession) -> str:
        """Generate human-readable narrative of session interaction."""
        parts: list[str] = [
            f"Honeypot {session.protocol.upper()} session from {session.source_ip}:{session.source_port}"
        ]

        if session.client_version:
            parts.append(f"Client: {session.client_version}")

        if session.credentials:
            tested = [f"{c.username}:{c.password}" for c in session.credentials[:5]]
            extra = f" (+{len(session.credentials)-5} more)" if len(session.credentials) > 5 else ""
            parts.append(f"Credentials tested ({len(session.credentials)}): {', '.join(tested)}{extra}")

        if session.authenticated:
            parts.append(f"Authenticated as '{session.authenticated_user}'")

        if session.commands:
            cmd_sample = [c.command for c in session.commands[:5]]
            extra = f" (+{len(session.commands)-5} more)" if len(session.commands) > 5 else ""
            parts.append(f"Commands executed ({len(session.commands)}): {', '.join(cmd_sample)}{extra}")

        if session.artifacts:
            art_sample = [a.filename_or_url for a in session.artifacts[:3]]
            parts.append(f"Artifacts attempted ({len(session.artifacts)}): {', '.join(art_sample)}")

        parts.append(f"Duration: {session.duration_seconds:.1f}s")
        return " | ".join(parts)
