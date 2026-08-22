"""
Shared library for Multi Modal Security (MMS).

Exports the common event schema and configuration utilities used by all modules.
"""

from src.shared.event_schema import SecurityEvent, Entity  # noqa: F401
from src.shared.config import settings  # noqa: F401
