"""
SOC Correlation package: Incident models and sliding-window correlation engine.
"""

from src.soc.correlation.engine import CorrelationEngine
from src.soc.correlation.incident_model import (
    Incident,
    IncidentStatus,
    IncidentTimelineEntry,
)

__all__ = [
    "Incident",
    "IncidentStatus",
    "IncidentTimelineEntry",
    "CorrelationEngine",
]
