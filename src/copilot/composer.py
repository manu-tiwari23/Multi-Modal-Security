"""
Response Composer with Evidence Citation Engine for AI Security Copilot.

Extracts grounding citations from retrieved data and tool outputs, attaches
traceable references to claims, and formats structured containment recommendations.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from src.copilot.models import (
    Citation,
    ContainmentRecommendation,
    CopilotResponse,
    ToolCallRecord,
)


class ResponseComposer:
    """Composes grounded Copilot responses with explicit citations and containment gates."""

    @staticmethod
    def extract_citations_from_tools(tool_records: list[ToolCallRecord], tool_outputs: list[dict[str, Any]]) -> list[Citation]:
        """Extract ground-truth citations from tool execution records and output payloads."""
        citations: list[Citation] = []
        seen_ids: set[str] = set()

        for rec, out in zip(tool_records, tool_outputs):
            if not rec.success or not isinstance(out, dict):
                continue

            tool_name = rec.tool_name

            # 1. query_logs tool output
            if tool_name == "query_logs" and "events" in out:
                for ev in out.get("events", [])[:5]:
                    eid = ev.get("event_id", "")
                    if eid and eid not in seen_ids:
                        seen_ids.add(eid)
                        entity = ev.get("entity", {})
                        ip_val = entity.get("ip", "N/A")
                        citations.append(
                            Citation(
                                id=eid,
                                type="event",
                                title=f"Event {ev.get('event_type')} from {ev.get('source')}",
                                snippet=f"Severity: {ev.get('severity')} | IP: {ip_val} | Time: {ev.get('timestamp')}",
                                source=ev.get("source"),
                                metadata={"raw": ev.get("raw")},
                            )
                        )

            # 2. get_incident tool output
            elif tool_name == "get_incident" and "incident_id" in out:
                inc_id = out.get("incident_id", "")
                if inc_id and inc_id not in seen_ids:
                    seen_ids.add(inc_id)
                    citations.append(
                        Citation(
                            id=inc_id,
                            type="incident",
                            title=f"Incident {inc_id}: {out.get('title')}",
                            snippet=f"Risk Score: {out.get('risk_score', 0):.1f} | Severity: {out.get('severity')} | Events: {out.get('event_count')}",
                            source="soc_correlation",
                            metadata={"mitre": out.get("mitre_techniques", [])},
                        )
                    )

            # 3. lookup_ioc tool output
            elif tool_name == "lookup_ioc" and "ioc" in out:
                ioc = out.get("ioc", "")
                if ioc and ioc not in seen_ids:
                    seen_ids.add(ioc)
                    citations.append(
                        Citation(
                            id=ioc,
                            type="ioc",
                            title=f"IOC {ioc} ({out.get('type')})",
                            snippet=f"Classification: {out.get('classification')} | Threat Score: {out.get('threat_score')}/100",
                            source="threat_intel",
                            metadata=out,
                        )
                    )

            # 4. draft_report tool output
            elif tool_name == "draft_report" and "incident_id" in out:
                inc_id = out.get("incident_id", "")
                if inc_id and inc_id not in seen_ids:
                    seen_ids.add(inc_id)
                    citations.append(
                        Citation(
                            id=inc_id,
                            type="incident",
                            title=f"Report Context for {inc_id}",
                            snippet=out.get("executive_summary", "")[:120],
                            source="report_generator",
                        )
                    )

        return citations

    @staticmethod
    def extract_recommendations(text: str) -> list[ContainmentRecommendation]:
        """Parse containment action recommendations from text and wrap with human-approval gates."""
        recs: list[ContainmentRecommendation] = []

        # Regex patterns for recommended actions
        ip_block_matches = re.findall(r"(?:block|isolate|blacklist)\s+(?:ip\s+)?(\b\d{1,3}(?:\.\d{1,3}){3}\b)", text, re.IGNORECASE)
        for ip in set(ip_block_matches):
            recs.append(
                ContainmentRecommendation(
                    action_type="block_ip",
                    target=ip,
                    rationale=f"Observed malicious attack traffic / brute-force activity from IP {ip}.",
                    requires_approval=True,
                    priority="high",
                )
            )

        host_iso_matches = re.findall(r"(?:isolate|quarantine)\s+(?:host\s+)?([a-zA-Z0-9_\-\.]+)", text, re.IGNORECASE)
        for host in set(host_iso_matches):
            if host.lower() not in ("ip", "host", "the", "system", "attacker", "victim"):
                recs.append(
                    ContainmentRecommendation(
                        action_type="isolate_host",
                        target=host,
                        rationale=f"Host {host} exhibited privilege escalation or high-severity intrusion indicators.",
                        requires_approval=True,
                        priority="critical",
                    )
                )

        return recs

    @classmethod
    def compose_response(
        cls,
        query: str,
        raw_answer: str,
        tool_records: list[ToolCallRecord],
        tool_outputs: list[dict[str, Any]],
        execution_time_ms: float = 0.0,
        model_name: str = "mms-copilot-gpt4",
    ) -> CopilotResponse:
        """Compose the complete CopilotResponse object with citations and recommendations."""
        citations = cls.extract_citations_from_tools(tool_records, tool_outputs)
        recommendations = cls.extract_recommendations(raw_answer)

        # Enhance markdown with grounding footer if citations exist
        answer = raw_answer
        if citations and "### Grounding Evidence & Citations" not in answer:
            footer_lines = ["\n\n---", "### 🔍 Grounding Evidence & Citations"]
            for c in citations:
                footer_lines.append(f"- **`[{c.type.upper()}: {c.id}]`** {c.title} — _{c.snippet}_")
            answer += "\n".join(footer_lines)

        return CopilotResponse(
            query=query,
            answer=answer,
            citations=citations,
            tool_calls=tool_records,
            recommendations=recommendations,
            model=model_name,
            execution_time_ms=execution_time_ms,
            created_at=datetime.now(timezone.utc),
        )
