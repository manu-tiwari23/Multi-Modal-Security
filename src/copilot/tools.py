"""
OpenAI Tool Calling Definitions & Execution Engine for MMS AI Copilot.

Exposes deterministic, auditable security tools:
  - query_logs()
  - get_incident()
  - lookup_ioc()
  - run_correlation()
  - draft_report()
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional

from src.copilot.models import ToolCallRecord
from src.copilot.retrieval import IncidentRetriever, LogRetriever, ThreatIntelRetriever

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenAI Tool Schemas (Function Calling Specs)
# ---------------------------------------------------------------------------

OPENAI_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "query_logs",
            "description": "Search security events across all modules (SOC, honeypot, authentication, network) by entity IP, username, hostname, severity, or event type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_ip": {
                        "type": "string",
                        "description": "IP address to search for (e.g. '203.0.113.88')",
                    },
                    "entity_user": {
                        "type": "string",
                        "description": "Username to search for (e.g. 'root', 'admin')",
                    },
                    "entity_host": {
                        "type": "string",
                        "description": "Target hostname (e.g. 'prod-web-01')",
                    },
                    "event_type": {
                        "type": "string",
                        "description": "Type of event (e.g. 'auth_failure', 'privilege_escalation', 'firewall_block', 'command_exec')",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Severity level filter",
                    },
                    "source": {
                        "type": "string",
                        "enum": ["soc", "honeypot", "phishing", "forensics", "threat_intel"],
                        "description": "Originating module source",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum events to return (default: 10)",
                        "default": 10,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_incident",
            "description": "Retrieve comprehensive details for a correlated security incident, including full timeline, linked entities, rule matches, and risk score.",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_id": {
                        "type": "string",
                        "description": "Unique incident ID (e.g. 'INC-A1B2C3D4')",
                    },
                },
                "required": ["incident_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_ioc",
            "description": "Look up threat intelligence reputation, classification, and honeypot interaction history for an IP address, file hash, or domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_value": {
                        "type": "string",
                        "description": "The IOC string to inspect (e.g. '203.0.113.88' or SHA-256 hash)",
                    },
                    "ioc_type": {
                        "type": "string",
                        "enum": ["ip", "hash", "domain", "url"],
                        "description": "Type of the indicator (optional, auto-detected)",
                    },
                },
                "required": ["ioc_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_correlation",
            "description": "Query active incidents linked to an entity to determine if multiple attack stages have been correlated together.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_ip": {
                        "type": "string",
                        "description": "IP address to check correlation status for",
                    },
                },
                "required": ["entity_ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "draft_report",
            "description": "Generate a structured, executive and technical incident report for an incident ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_id": {
                        "type": "string",
                        "description": "Target incident ID to generate report for",
                    },
                },
                "required": ["incident_id"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool Executor
# ---------------------------------------------------------------------------


class ToolExecutor:
    """Executes registered tools on behalf of the AI Copilot."""

    def __init__(
        self,
        log_retriever: LogRetriever,
        incident_retriever: IncidentRetriever,
        threat_intel_retriever: ThreatIntelRetriever,
        report_generator: Optional[Any] = None,
    ) -> None:
        self.log_retriever = log_retriever
        self.incident_retriever = incident_retriever
        self.threat_intel_retriever = threat_intel_retriever
        self.report_generator = report_generator

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], ToolCallRecord]:
        """Execute tool by name and return result dictionary and audit record."""
        record = ToolCallRecord(tool_name=tool_name, arguments=arguments)

        try:
            if tool_name == "query_logs":
                result = self._tool_query_logs(arguments)
            elif tool_name == "get_incident":
                result = self._tool_get_incident(arguments)
            elif tool_name == "lookup_ioc":
                result = self._tool_lookup_ioc(arguments)
            elif tool_name == "run_correlation":
                result = self._tool_run_correlation(arguments)
            elif tool_name == "draft_report":
                result = self._tool_draft_report(arguments)
            else:
                result = {"error": f"Unknown tool '{tool_name}'"}
                record.success = False
                record.error_message = f"Unknown tool: {tool_name}"

            record.result_summary = f"Returned {len(result)} items/fields" if isinstance(result, (list, dict)) else str(result)
            return result, record

        except Exception as exc:
            logger.exception("Error executing tool %s with args %s: %s", tool_name, arguments, exc)
            record.success = False
            record.error_message = str(exc)
            return {"error": str(exc)}, record

    # -----------------------------------------------------------------------
    # Tool Implementations
    # -----------------------------------------------------------------------

    def _tool_query_logs(self, args: dict[str, Any]) -> dict[str, Any]:
        logs = self.log_retriever.query_logs(
            entity_ip=args.get("entity_ip"),
            entity_user=args.get("entity_user"),
            entity_host=args.get("entity_host"),
            event_type=args.get("event_type"),
            severity=args.get("severity"),
            source=args.get("source"),
            limit=args.get("limit", 10),
        )
        return {"count": len(logs), "events": logs}

    def _tool_get_incident(self, args: dict[str, Any]) -> dict[str, Any]:
        inc_id = args.get("incident_id", "")
        context = self.incident_retriever.get_incident_context(inc_id)
        if not context:
            # Fallback check: if incident_id not found, return list of active ones
            active = self.incident_retriever.list_active_incidents()
            return {
                "error": f"Incident '{inc_id}' not found.",
                "available_incidents": active,
            }
        return context

    def _tool_lookup_ioc(self, args: dict[str, Any]) -> dict[str, Any]:
        ioc_val = args.get("ioc_value", "")
        ioc_type = args.get("ioc_type")
        return self.threat_intel_retriever.lookup_ioc(ioc_val, ioc_type)

    def _tool_run_correlation(self, args: dict[str, Any]) -> dict[str, Any]:
        ip = args.get("entity_ip", "")
        active_incidents = self.incident_retriever.list_active_incidents()
        matching = [inc for inc in active_incidents if inc.get("primary_ip") == ip]
        return {
            "entity_ip": ip,
            "is_correlated": len(matching) > 0,
            "matched_incidents": matching,
        }

    def _tool_draft_report(self, args: dict[str, Any]) -> dict[str, Any]:
        inc_id = args.get("incident_id", "")
        if self.report_generator is not None:
            rep = self.report_generator.generate_report(inc_id)
            if rep:
                return rep.model_dump(mode="json")
        
        # Fallback basic report from incident context
        ctx = self.incident_retriever.get_incident_context(inc_id)
        if not ctx:
            return {"error": f"Cannot draft report: incident '{inc_id}' not found"}
        return {
            "title": f"Incident Report: {ctx.get('title')}",
            "incident_id": inc_id,
            "risk_score": ctx.get("risk_score", 0.0),
            "event_count": ctx.get("event_count", 0),
            "summary": ctx.get("description", ""),
        }
