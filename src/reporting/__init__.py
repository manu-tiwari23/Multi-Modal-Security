"""Deterministic reporting over serialized snapshots supplied by the API."""

from .incident import build_incident_report
from .models import Report, ReportSection

__all__ = ["Report", "ReportSection", "build_incident_report"]
