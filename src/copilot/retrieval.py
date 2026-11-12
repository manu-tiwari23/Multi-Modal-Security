"""
Retrieval Layer for AI Security Copilot (RAG Engine).

Fetches scoped logs, incident timelines, and threat intelligence context from
OpenSearch, the SOC Correlation Engine, and the Honeypot subsystem.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from opensearchpy import OpenSearch

from src.shared.config import settings
from src.shared.event_schema import SecurityEvent
from src.soc.correlation.engine import CorrelationEngine
from src.soc.correlation.incident_model import Incident

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known Mock Threat Intelligence Database (Enrichment Fallback)
# ---------------------------------------------------------------------------

KNOWN_IOC_DATABASE: dict[str, dict[str, Any]] = {
    "203.0.113.88": {
        "ioc": "203.0.113.88",
        "type": "ip",
        "threat_score": 92,
        "classification": "Malicious Scanner / Botnet Node",
        "actor_group": "DarkMirai-Cluster",
        "country": "NL",
        "asn": "AS12345 Suspicious Hosting LLC",
        "tags": ["brute_force", "honeypot_target", "ssh_scanner"],
        "known_cve": ["CVE-2023-48795", "CVE-2024-6387"],
    },
    "185.220.101.42": {
        "ioc": "185.220.101.42",
        "type": "ip",
        "threat_score": 85,
        "classification": "Tor Exit Node / Reconnaissance Source",
        "actor_group": "Unknown",
        "country": "DE",
        "asn": "AS54321 Privacy Net",
        "tags": ["tor_exit", "port_scanner", "anonymizer"],
        "known_cve": [],
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "sha256",
        "threat_score": 100,
        "classification": "Linux ELF Mirai Dropper Binary",
        "actor_group": "Mirai Variant",
        "tags": ["dropper", "elf_binary", "malware"],
    },
}


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
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Query security logs matching the specified filters."""
        results: list[dict[str, Any]] = []

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

            results = [e.model_dump(mode="json") for e in filtered[:limit]]

        return results


# ---------------------------------------------------------------------------
# Incident Retriever
# ---------------------------------------------------------------------------


class IncidentRetriever:
    """Retrieves full incident records, timelines, linked entities, and score breakdowns."""

    def __init__(self, correlation_engine: CorrelationEngine) -> None:
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
            for inc in self.engine.active_incidents
        ]


# ---------------------------------------------------------------------------
# Threat Intel Retriever
# ---------------------------------------------------------------------------


class ThreatIntelRetriever:
    """Queries known IOC databases and correlates with honeypot profiles."""

    def __init__(self, honeypot_recorder: Optional[Any] = None) -> None:
        self.honeypot_recorder = honeypot_recorder

    def lookup_ioc(self, ioc_value: str, ioc_type: Optional[str] = None) -> dict[str, Any]:
        """Perform IOC lookup across threat intel registry and honeypot captures."""
        val = ioc_value.strip().lower()

        # Check threat intel database
        if val in KNOWN_IOC_DATABASE:
            info = dict(KNOWN_IOC_DATABASE[val])
            info["found_in_threat_intel"] = True
        else:
            info = {
                "ioc": ioc_value,
                "type": ioc_type or ("ip" if "." in ioc_value else "hash"),
                "threat_score": 10,
                "classification": "Unclassified / Low Known Reputation",
                "found_in_threat_intel": False,
                "tags": [],
            }

        # Check honeypot interaction history
        if self.honeypot_recorder is not None:
            all_sessions = self.honeypot_recorder.get_active_sessions() + self.honeypot_recorder.get_closed_sessions()
            matched_sessions = [s for s in all_sessions if s.source_ip.lower() == val]
            if matched_sessions:
                info["honeypot_interactions"] = len(matched_sessions)
                info["honeypot_commands_seen"] = sum(len(s.commands) for s in matched_sessions)
                info["honeypot_files_dropped"] = sum(len(s.artifacts) for s in matched_sessions)
                info["threat_score"] = max(info.get("threat_score", 0), 85)
                info["classification"] = "Active Attacker (Trapped in Honeypot)"

        return info
