"""Deterministic factual statements for the model to select, never invent.

The model interprets the question and retrieves/selects relevant evidence. Only
these server-rendered statements reach the analyst, so valid citation IDs cannot
be attached to a fabricated narrative or claim of executed containment.
"""

import json
import re

from src.copilot.report_generator import MITRE_DESCRIPTIONS


REVIEW_STEPS = {
    "review_detection": "Review the recorded detections and source events; a detection match alone does not prove compromise.",
    "verify_identity": "Verify the associated account, host and IP with the asset owner before proposing containment.",
    "collect_evidence": "Collect additional relevant logs or evidence to resolve gaps in the retrieved records.",
    "review_reputation": "Review provider coverage and timestamps. Unknown reputation or no known flags does not prove safety.",
    "request_approval": "If the investigation supports containment, use Incident Response to request explicit analyst approval. The Copilot cannot execute it.",
}


def safe(value):
    text = str(value if value is not None else "unknown").replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_<>\[\]])", r"\\\1", text)


def build_facts(records, outputs):
    facts = []
    seen = set()

    def add(text, refs=()):
        if text in seen:
            return
        seen.add(text)
        facts.append({"id": f"F{len(facts) + 1}", "text": text, "references": list(refs)})

    def event(ev):
        eid = ev.get("event_id")
        if not eid:
            return
        ref = f"EVENT:{eid}"
        entity = ", ".join(f"{key}={safe(val)}" for key, val in ev.get("entity", {}).items() if val)
        add(f"Recorded event {safe(eid)}: type {safe(ev.get('event_type'))}; source {safe(ev.get('source'))}; "
            f"severity {safe(ev.get('severity'))}; time {safe(ev.get('timestamp'))}. "
            f"Associated entities: {entity or 'none recorded'}.", [ref])

    def incident(inc):
        ident = inc.get("incident_id")
        if not ident:
            return
        ref = f"INCIDENT:{ident}"
        add(f"Incident {safe(ident)} — recorded title: {safe(inc.get('title'))}; "
            f"severity {safe(inc.get('severity'))}; risk score {safe(inc.get('risk_score'))}/100; "
            f"recorded events {safe(inc.get('event_count'))}.", [ref])
        if inc.get("primary_entity"):
            entity = ", ".join(f"{key}={safe(val)}" for key, val in inc["primary_entity"].items() if val)
            add(f"Primary associated entities: {entity or 'none recorded'}. Association does not establish attacker identity.", [ref])
        techniques = inc.get("mitre_techniques", [])
        if techniques:
            mapped = "; ".join(f"{safe(t)} ({safe(MITRE_DESCRIPTIONS.get(t, 'recorded technique mapping'))})" for t in techniques)
            add(f"Recorded detection annotations: {mapped}. These are detection mappings, not confirmed attack stages.", [ref])
        for rule in inc.get("rule_matches", []):
            add(f"Recorded detection: {safe(rule.get('rule_title'))} ({safe(rule.get('rule_id'))}), "
                f"severity {safe(rule.get('severity'))}.", [ref])
        for ev in inc.get("timeline", []):
            event(ev)

    for record, out in zip(records, outputs):
        if not record.success:
            add(f"{safe(record.tool_name)} could not retrieve evidence: {safe(out.get('error'))}.")
            continue
        if record.tool_name == "query_logs":
            add(f"The query returned {len(out.get('events', []))} recent matching records. This is a bounded sample, not the total volume of activity.")
            for ev in out.get("events", []):
                event(ev)
        elif record.tool_name == "get_incident":
            incident(out)
        elif record.tool_name == "search_past_incidents":
            add("Historical similarity uses shared recorded terms, not proof of a shared cause or current compromise.")
            for item in out.get("incidents", []):
                add(f"Historical reference {safe(item.get('incident_id'))}: {safe(item.get('title'))}; "
                    f"recorded status {safe(item.get('status'))}; lexical similarity {safe(item.get('similarity'))}. "
                    "This record is contextual and is not evidence for the current incident.", [f"INCIDENT:{item['incident_id']}"])
        elif record.tool_name in ("list_incidents", "run_correlation"):
            items = out.get("incidents", out.get("matched_incidents", []))
            add(f"Returned {len(items)} active incident summaries within this query's scope.")
            for inc in items:
                incident(inc)
        elif record.tool_name == "lookup_ioc":
            value = out.get("ioc")
            ref = f"IOC:{value}"
            score = out.get("threat_score")
            add(f"Indicator {safe(value)}: classification {safe(out.get('classification', 'unknown'))}; "
                f"Threat Score: {str(score) + '/100' if score is not None else 'Unavailable'}. "
                "Reputation does not prove compromise or safety.", [ref])
            for provider in out.get("providers", []):
                add(f"Provider {safe(provider.get('provider'))}: status {safe(provider.get('status'))}; "
                    f"recorded result: {safe(provider.get('explanation'))}; checked {safe(provider.get('observed_at'))}.", [ref])
            if out.get("honeypot_interactions"):
                add(f"Local honeypot telemetry contains {out['honeypot_interactions']} matching sessions, "
                    f"{out.get('honeypot_commands_seen', 0)} commands and {out.get('honeypot_files_dropped', 0)} artifacts. "
                    "These local observations are separate from reputation.", [ref])
        elif record.tool_name == "draft_report":
            ref = f"INCIDENT:{out['incident_id']}"
            add(f"Incident Report for {safe(out['incident_id'])}: {safe(out.get('executive_summary', out.get('summary', '')))}", [ref])
            for ev in out.get("attack_timeline", []):
                event(ev)
            for action in out.get("containment_actions", []):
                add(f"Conditional recommendation for analyst review: {safe(action['action_type'])} on "
                    f"{safe(action['target'])}. {safe(action['rationale'])} Human approval is required; no action was executed.", [ref])
    return facts


def selection_schema(facts):
    return {"type": "json_schema", "json_schema": {"name": "evidence_selection", "strict": True,
        "schema": {"type": "object", "additionalProperties": False,
            "properties": {
                "fact_ids": {"type": "array", "items": {"type": "string", "enum": [f["id"] for f in facts]}},
                "review_steps": {"type": "array", "items": {"type": "string", "enum": list(REVIEW_STEPS)}},
            }, "required": ["fact_ids", "review_steps"]}}}


def validate_selection(content, facts):
    data = json.loads(content)
    if not isinstance(data, dict) or set(data) != {"fact_ids", "review_steps"}:
        raise ValueError("Invalid evidence selection")
    for key, allowed, maximum in (("fact_ids", {f["id"] for f in facts}, 25),
                                  ("review_steps", set(REVIEW_STEPS), 5)):
        items = data[key]
        if not isinstance(items, list) or len(items) > maximum or any(not isinstance(v, str) or v not in allowed for v in items):
            raise ValueError("Unknown evidence reference or review step")
    if facts and not data["fact_ids"]:
        raise ValueError("No evidence selected")
    return data


def render_facts(facts, selected=None, steps=()):
    selected = set(selected) if selected is not None else {f["id"] for f in facts[:20]}
    lines = []
    for fact in facts:
        if fact["id"] in selected:
            refs = " ".join(f"[{safe(ref)}]" for ref in fact["references"])
            lines.append(f"- {fact['text']} {refs}".rstrip())
    if not lines:
        lines.append("No supporting evidence was retrieved for this question.")
    if steps:
        lines.append("\nSuggested review steps:")
        lines.extend(f"- {REVIEW_STEPS[step]}" for step in dict.fromkeys(steps))
    return "\n".join(lines)
