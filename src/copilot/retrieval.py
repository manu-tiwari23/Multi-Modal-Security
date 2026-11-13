"""
Retrieval Layer for AI Security Copilot (RAG Engine).

Fetches scoped logs, incident timelines, and threat intelligence context from
OpenSearch, the SOC Correlation Engine, and the Honeypot subsystem.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Protocol

from opensearchpy import OpenSearch

from src.shared.config import settings
from src.shared.event_schema import SecurityEvent

logger = logging.getLogger(__name__)


class IncidentSource(Protocol):
    """API-injected source interface; no import of another module's internals."""
    @property
    def active_incidents(self) -> list[Any]: ...

    def get_incident(self, incident_id: str) -> Any: ...


# ---------------------------------------------------------------------------
# Threat reputation is supplied by the API layer; no fabricated fallback data.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Log Retriever (OpenSearch + In-Memory Buffer)
# ---------------------------------------------------------------------------


class LogRetriever:
    """Retrieves scoped security logs based on entity keys, time filters, and severities."""

    def __init__(
        self,
        opensearch_client: Optional[OpenSearch] = None,
        memory_buffer: Optional[list[SecurityEvent]] = None,
    ) -> None:
        self.os_client = opensearch_client
        self.memory_buffer = memory_buffer if memory_buffer is not None else []

    def query_logs(
        self,
        entity_ip: Optional[str] = None,
        entity_user: Optional[str] = None,
        entity_host: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Query security logs matching the specified filters."""
        results: list[dict[str, Any]] = []
        if type(limit) is not int or not 1 <= limit <= 25:
            raise ValueError("Log retrieval limit must be between 1 and 25")

        # 1. Try OpenSearch query if client is active
        if self.os_client is not None:
            try:
                must_clauses: list[dict[str, Any]] = []
                if entity_ip:
                    must_clauses.append({"term": {"entity.ip": entity_ip}})
                if entity_user:
                    must_clauses.append({"term": {"entity.user": entity_user}})
                if entity_host:
                    must_clauses.append({"term": {"entity.host": entity_host}})
                if event_type:
                    must_clauses.append({"term": {"event_type": event_type}})
                if severity:
                    must_clauses.append({"term": {"severity": severity}})
                if source:
                    must_clauses.append({"term": {"source": source}})

                query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}
                body = {
                    "query": query,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": limit,
                }
                res = self.os_client.search(index=settings.opensearch_events_index, body=body)
                for hit in res.get("hits", {}).get("hits", []):
                    results.append(hit["_source"])
                return results  # An empty successful query is authoritative.
            except Exception as exc:
                logger.debug("OpenSearch search failed in LogRetriever: %s", exc)

        # 2. In-memory buffer fallback
        if not results:
            filtered = list(self.memory_buffer)
            if entity_ip:
                filtered = [e for e in filtered if e.entity and e.entity.ip == entity_ip]
            if entity_user:
                filtered = [e for e in filtered if e.entity and e.entity.user == entity_user]
            if entity_host:
                filtered = [e for e in filtered if e.entity and e.entity.host == entity_host]
            if event_type:
                filtered = [e for e in filtered if e.event_type == event_type]
            if severity:
                filtered = [e for e in filtered if e.severity == severity]
            if source:
                filtered = [e for e in filtered if e.source == source]

            filtered.sort(key=lambda e: e.timestamp, reverse=True)
            results = [e.model_dump(mode="json") for e in filtered[:limit]]

        return results


# ---------------------------------------------------------------------------
# Incident Retriever
# ---------------------------------------------------------------------------


class IncidentRetriever:
    """Retrieves full incident records, timelines, linked entities, and score breakdowns."""

    def __init__(self, correlation_engine: IncidentSource) -> None:
        self.engine = correlation_engine

    def get_incident_context(self, incident_id: str) -> Optional[dict[str, Any]]:
        """Retrieve structured incident context for Copilot analysis."""
        incident = self.engine.get_incident(incident_id)
        if not incident:
            return None

        # Build timeline entries
        timeline_entries = []
        for t in incident.timeline:
            timeline_entries.append({
                "timestamp": t.timestamp.isoformat() if isinstance(t.timestamp, datetime) else str(t.timestamp),
                "event_id": t.event_id,
                "event_type": t.event_type,
                "source": t.source,
                "severity": t.severity,
                "description": t.description,
                "entity": t.entity.model_dump(mode="json"),
            })

        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "risk_score": incident.risk_score,
            "created_at": incident.created_at.isoformat() if isinstance(incident.created_at, datetime) else str(incident.created_at),
            "updated_at": incident.updated_at.isoformat() if isinstance(incident.updated_at, datetime) else str(incident.updated_at),
            "primary_entity": incident.primary_entity.model_dump(mode="json"),
            "linked_entities": [e.model_dump(mode="json") for e in incident.linked_entities],
            "event_count": incident.event_count,
            "rule_matches": [rm.model_dump(mode="json") for rm in incident.rule_matches],
            "mitre_techniques": incident.mitre_techniques,
            "tags": incident.tags,
            "timeline": timeline_entries,
        }

    def list_active_incidents(self) -> list[dict[str, Any]]:
        """List active incidents summary."""
        return [
            {
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "event_count": inc.event_count,
                "primary_ip": inc.primary_entity.ip,
                "primary_user": inc.primary_entity.user,
                "primary_host": inc.primary_entity.host,
            }
            for inc in sorted(self.engine.active_incidents, key=lambda item: item.updated_at, reverse=True)
        ]

    def correlated_incidents(self, ip: str) -> list[dict[str, Any]]:
        ids = {inc.incident_id for inc in self.engine.active_incidents
               if any(entity.ip == ip for entity in [inc.primary_entity, *inc.linked_entities])}
        return [inc for inc in self.list_active_incidents() if inc["incident_id"] in ids]


# ---------------------------------------------------------------------------
# Threat Intel Retriever
# ---------------------------------------------------------------------------


class ThreatIntelRetriever:
    """Queries known IOC databases and correlates with honeypot profiles."""

    def __init__(self, honeypot_recorder: Optional[Any] = None, lookup=None) -> None:
        self.honeypot_recorder = honeypot_recorder
        self.lookup = lookup

    def lookup_ioc(self, ioc_value: str, ioc_type: Optional[str] = None) -> dict[str, Any]:
        """Perform IOC lookup across threat intel registry and honeypot captures."""
        val = ioc_value.strip().lower()

        info = {"ioc": ioc_value, "type": ioc_type or "unknown", "threat_score": None,
                "classification": "unknown", "found_in_threat_intel": False, "tags": [],
                "providers": [], "limitations": ["No external reputation is available; absence of reputation does not imply safety."]}
        if self.lookup is not None:
            reputation = self.lookup(ioc_value, "hash" if ioc_type in ("sha256", "sha1", "md5") else ioc_type)
            info.update({"ioc": reputation["indicator"]["value"], "type": reputation["indicator"]["type"],
                "threat_score": reputation["score"], "classification": reputation["classification"],
                "found_in_threat_intel": any(p["status"] == "ok" for p in reputation["providers"]),
                "providers": reputation["providers"], "cached": reputation["cached"],
                "checked_at": reputation["checked_at"], "limitations": reputation["limitations"]})

        # Check honeypot interaction history
        if self.honeypot_recorder is not None:
            all_sessions = self.honeypot_recorder.get_active_sessions() + self.honeypot_recorder.get_closed_sessions()
            matched_sessions = [s for s in all_sessions if s.source_ip.lower() == val]
            if matched_sessions:
                info["honeypot_interactions"] = len(matched_sessions)
                info["honeypot_commands_seen"] = sum(len(s.commands) for s in matched_sessions)
                info["honeypot_files_dropped"] = sum(len(s.artifacts) for s in matched_sessions)
                info["honeypot_session_ids"] = [s.session_id for s in matched_sessions]
                info["local_observation"] = "Observed in local honeypot telemetry; this is separate from external reputation"

        return info
