"""
Honeypot package: deceptive services, session recording, event normalization, and behavior analysis.
"""

from src.honeypot.behavior import ARCHETYPES, TTP_DEFINITIONS, BehaviorAnalyzer
from src.honeypot.cowrie_parser import CowrieLogParser
from src.honeypot.models import (
    AttackerProfile,
    CommandRecord,
    CredentialAttempt,
    FileArtifact,
    HoneypotProtocol,
    HoneypotSession,
)
from src.honeypot.normalizer import (
    normalise_artifact_record,
    normalise_command_record,
    normalise_credential_attempt,
    normalise_session_to_event,
)
from src.honeypot.recorder import SessionRecorder
from src.honeypot.server import DeceptionService, VirtualShell

__all__ = [
    "ARCHETYPES",
    "AttackerProfile",
    "BehaviorAnalyzer",
    "CommandRecord",
    "CowrieLogParser",
    "CredentialAttempt",
    "DeceptionService",
    "FileArtifact",
    "HoneypotProtocol",
    "HoneypotSession",
    "SessionRecorder",
    "TTP_DEFINITIONS",
    "VirtualShell",
    "normalise_artifact_record",
    "normalise_command_record",
    "normalise_credential_attempt",
    "normalise_session_to_event",
]
