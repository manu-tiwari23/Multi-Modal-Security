"""Read-only, validated Copilot tools with evidence provenance records."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from src.copilot.models import ToolCallRecord
from src.copilot.retrieval import IncidentRetriever, LogRetriever, ThreatIntelRetriever

logger = logging.getLogger(__name__)


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LogArguments(ToolArguments):
    entity_ip: str | None = Field(default=None, max_length=64)
    entity_user: str | None = Field(default=None, max_length=128)
    entity_host: str | None = Field(default=None, max_length=253)
    event_type: str | None = Field(default=None, max_length=128)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    source: Literal["soc", "honeypot", "phishing", "forensics", "threat_intel"] | None = None
    limit: int | None = Field(default=10, ge=1, le=25)

    @field_validator("entity_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ipaddress.ip_address(value)) if value is not None else None


class IncidentArguments(ToolArguments):
    incident_id: str = Field(min_length=1, max_length=128)


class HistoryArguments(ToolArguments):
    query: str = Field(min_length=1, max_length=4000)
    exclude_incident_id: str | None = Field(default=None, max_length=128)
    limit: int | None = Field(default=5, ge=1, le=10)


class IndicatorArguments(ToolArguments):
    ioc_value: str = Field(min_length=1, max_length=4096)
    ioc_type: Literal["ip", "hash", "domain", "url"] | None = None


class CorrelationArguments(ToolArguments):
    entity_ip: str = Field(min_length=1, max_length=64)

    @field_validator("entity_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ipaddress.ip_address(value))


TOOL_ARGUMENTS = {
    "query_logs": LogArguments,
    "get_incident": IncidentArguments,
    "lookup_ioc": IndicatorArguments,
    "run_correlation": CorrelationArguments,
    "draft_report": IncidentArguments,
    "list_incidents": ToolArguments,
    "search_past_incidents": HistoryArguments,
}
TOOL_DESCRIPTIONS = {
    "query_logs": "Retrieve at most 25 recent security events filtered by entity, severity, source or event type. Count is returned rows, not a total population count.",
    "get_incident": "Retrieve one incident, its recorded severity/risk, detections and evidence timeline.",
    "lookup_ioc": "Retrieve cached reputation and local honeypot observations for an IP, domain, URL or hash. Never performs external provider requests.",
    "run_correlation": "Find active incidents with an IP in primary or linked entities. Correlation alone does not prove an attack sequence.",
    "draft_report": "Generate an evidence-grounded incident report and conditional recommendations requiring analyst approval.",
    "list_incidents": "List active incidents ordered by most recently updated. Request a specific incident for details.",
    "search_past_incidents": "Retrieve historical incident summaries by local lexical vector similarity. Similarity is contextual, not evidence of a shared attack. No paid embeddings or external requests.",
}


def strict_schema(model):
    schema = model.model_json_schema()
    schema["required"] = list(schema["properties"])
    for prop in schema["properties"].values():
        prop.pop("default", None)
    return schema


OPENAI_TOOLS = [{"type": "function", "function": {
    "name": name, "description": TOOL_DESCRIPTIONS[name], "strict": True,
    "parameters": strict_schema(model),
}} for name, model in TOOL_ARGUMENTS.items()]


def evidence_ids(value):
    """Collect identifiers, not raw log bodies or credentials, for provenance."""
    result = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("event_id", "incident_id", "ioc", "session_id") and isinstance(item, str):
                result.add(item)
            elif key in ("events", "timeline", "attack_timeline", "matched_incidents", "incidents"):
                result.update(evidence_ids(item))
            elif key == "honeypot_session_ids":
                result.update(str(v) for v in item)
    elif isinstance(value, list):
        for item in value:
            result.update(evidence_ids(item))
    return sorted(result)


def bounded_output(value, max_bytes=12000):
    """Produce bounded structured context; explicitly expose every omission."""
    for count in (25, 10, 5, 1):
        notes = set()

        def trim(item, path="result", depth=0):
            if depth > 8:
                notes.add(f"{path}: nested content omitted")
                return None
            if isinstance(item, dict):
                result = {}
                for key, val in item.items():
                    if key in ("raw", "matched_event", "password", "credentials", "cookie_value"):
                        notes.add(f"{path}.{key}: raw or sensitive content omitted")
                        continue
                    result[key] = trim(val, path + "." + key, depth + 1)
                return result
            if isinstance(item, list):
                if len(item) > count:
                    notes.add(f"{path}: showing {count} of {len(item)} records")
                return [trim(v, path + "[]", depth + 1) for v in item[:count]]
            if isinstance(item, str) and len(item) > 600:
                notes.add(f"{path}: long text shortened")
                return item[:600] + " [shortened]"
            return item

        result = trim(value)
        result["_coverage"] = sorted(notes)
        if len(json.dumps(result, ensure_ascii=False).encode()) <= max_bytes:
            return result
    return {"error": "Retrieved context exceeds the per-tool budget; narrow the query", "_coverage": ["Result omitted due to size"]}


class ToolExecutor:
    """No execution/containment backend is reachable through this allowlist."""

    def __init__(self, log_retriever: LogRetriever, incident_retriever: IncidentRetriever,
                 threat_intel_retriever: ThreatIntelRetriever, report_generator=None, history_retriever=None):
        self.log_retriever = log_retriever
        self.incident_retriever = incident_retriever
        self.threat_intel_retriever = threat_intel_retriever
        self.report_generator = report_generator
        self.history_retriever = history_retriever

    def execute_tool(self, tool_name, arguments) -> tuple[dict[str, Any], ToolCallRecord]:
        record = ToolCallRecord(tool_name=tool_name, arguments=arguments if isinstance(arguments, dict) else {})
        if tool_name not in TOOL_ARGUMENTS:
            result = {"error": f"Unknown tool '{tool_name}'"}
        else:
            try:
                args = TOOL_ARGUMENTS[tool_name].model_validate(arguments).model_dump(exclude_none=True)
                record.arguments = args
                result = bounded_output(getattr(self, "_tool_" + tool_name)(args))
            except ValidationError:
                result = {"error": "Invalid tool arguments; follow the declared schema and limits"}
            except ValueError:
                result = {"error": "Invalid indicator or query value"}
            except Exception as exc:
                logger.warning("Copilot tool %s failed (%s)", tool_name, type(exc).__name__)
                result = {"error": "Evidence source unavailable; retry or narrow the query"}
        record.success = "error" not in result
        record.error_message = result.get("error")
        record.retrieved_ids = evidence_ids(result)
        record.result_sha256 = hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()
        record.limitations = result.get("_coverage", [])
        record.result_summary = f"{len(record.retrieved_ids)} evidence references returned"
        logger.info("Copilot retrieval tool=%s success=%s ids=%s digest=%s", tool_name, record.success,
                    record.retrieved_ids, record.result_sha256)
        return result, record

    def _tool_query_logs(self, args):
        logs = self.log_retriever.query_logs(**args)
        return {"count": len(logs), "events": logs, "scope": "Returned recent records only; not a total event count"}

    def _tool_get_incident(self, args):
        return self.incident_retriever.get_incident_context(args["incident_id"]) or {"error": "Incident not found"}

    def _tool_lookup_ioc(self, args):
        return self.threat_intel_retriever.lookup_ioc(args["ioc_value"], args.get("ioc_type"))

    def _tool_list_incidents(self, args):
        incidents = self.incident_retriever.list_active_incidents()
        return {"incidents": incidents, "count": len(incidents), "scope": "Active incidents only"}

    def _tool_search_past_incidents(self, args):
        if self.history_retriever is None:
            return {"error": "Historical vector retrieval is not configured"}
        return self.history_retriever.search(args["query"], args.get("exclude_incident_id"), args.get("limit") or 5)

    def _tool_run_correlation(self, args):
        matching = self.incident_retriever.correlated_incidents(args["entity_ip"])
        return {"entity_ip": args["entity_ip"], "is_correlated": bool(matching), "matched_incidents": matching}

    def _tool_draft_report(self, args):
        inc_id = args["incident_id"]
        if self.report_generator is not None:
            report = self.report_generator.generate_report(inc_id)
            if report:
                return report.model_dump(mode="json")
        context = self.incident_retriever.get_incident_context(inc_id)
        if not context:
            return {"error": "Cannot draft report: incident not found"}
        return {"title": f"Incident Report: {context['title']}", "incident_id": inc_id,
                "risk_score": context["risk_score"], "event_count": context["event_count"],
                "summary": "Report generator unavailable; only recorded incident fields are shown"}
