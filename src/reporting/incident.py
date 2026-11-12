"""Build reports from incident and response API snapshots without inference."""

from datetime import datetime, timezone
from typing import Any

from .models import Report, ReportSection


def timestamp_key(value: Any) -> datetime:
    """Compare offsets correctly; missing/invalid timestamps sort last."""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except (ValueError, TypeError):
        return datetime.max.replace(tzinfo=timezone.utc)


def build_incident_report(incident: dict, response_state: dict | None = None) -> Report:
    incident_id = incident["incident_id"]
    timeline = sorted(incident.get("timeline", []), key=lambda entry: timestamp_key(entry.get("timestamp")))
    event_ids = sorted(set(incident.get("event_ids", [])) | {e["event_id"] for e in timeline if e.get("event_id")})
    sources = sorted({e.get("source", "unknown") for e in timeline})
    types = sorted({e.get("event_type", "unknown") for e in timeline})
    state = response_state.get("phase") if response_state else incident.get("status", "unknown")
    limitations = ["Automated evidence summary; an observed indicator does not establish compromise or attribution.",
                   "This report is a snapshot. It does not execute or approve containment actions."]
    if not timeline:
        limitations.append("No event timeline is available for this incident.")
    count = incident.get("event_count", len(event_ids))
    if count != len(event_ids):
        limitations.append(f"Recorded event count ({count}) differs from available unique source IDs ({len(event_ids)}).")
    summary = (f"Incident {incident_id} has recorded severity {incident.get('severity', 'unknown')}, "
               f"risk score {incident.get('risk_score', 0):g}/100 and status {state}. "
               f"The snapshot records {count} events. Observed event types: {', '.join(types) or 'none recorded'}. "
               f"Sources: {', '.join(sources) or 'none recorded'}.")

    indicators: dict[tuple[str, str], set[str]] = {}
    def add_entity(entity: dict, reference: str) -> None:
        for kind in ("ip", "user", "host", "hash"):
            if entity.get(kind):
                indicators.setdefault((kind, str(entity[kind])), set()).add(reference)
    add_entity(incident.get("primary_entity", {}), f"incident:{incident_id}")
    for entity in incident.get("linked_entities", []):
        add_entity(entity, f"incident:{incident_id}")
    for entry in timeline:
        add_entity(entry.get("entity", {}), f"event:{entry.get('event_id', 'unavailable')}")

    sections = [
        ReportSection(title="Incident facts", columns=["Field", "Recorded value"], rows=[
            ["Created", str(incident.get("created_at", "unknown"))],
            ["Updated", str(incident.get("updated_at", "unknown"))],
            ["Status", str(state)], ["Description", incident.get("description") or "No description recorded"],
        ]),
        ReportSection(title="Event timeline", columns=["Timestamp", "Source", "Event / severity", "Observation", "Event ID"], rows=[
            [str(e.get("timestamp", "unknown")), e.get("source", "unknown"),
             f"{e.get('event_type', 'unknown')} / {e.get('severity', 'unknown')}",
             e.get("description", ""), e.get("event_id", "unavailable")] for e in timeline
        ]),
        ReportSection(title="Observed indicators and entities", columns=["Type", "Value", "Evidence references"], rows=[
            [kind, value, ", ".join(sorted(refs))] for (kind, value), refs in sorted(indicators.items())
        ]),
        ReportSection(title="Detection evidence", columns=["Rule", "Title", "Severity", "Event ID"], rows=[
            [r.get("rule_id", ""), r.get("rule_title", ""), r.get("severity", ""),
             r.get("matched_event", {}).get("event_id", "unavailable")] for r in incident.get("rule_matches", [])
        ]),
        ReportSection(title="Recorded MITRE ATT&CK mappings", paragraphs=[
            "Techniques: " + (", ".join(sorted(set(incident.get("mitre_techniques", [])))) or "none recorded"),
            "Tactics: " + (", ".join(sorted(set(incident.get("mitre_tactics", [])))) or "none recorded"),
            f"Mapping source: incident:{incident_id}; mappings are detection annotations, not independent proof of attacker intent.",
        ]),
    ]
    if response_state:
        sections.append(ReportSection(title="Response audit", columns=["Timestamp", "Transition", "Actor", "Reason"], rows=[
            [str(t.get("transitioned_at", "unknown")), f"{t.get('from_phase', '')} → {t.get('to_phase', '')}",
             t.get("transitioned_by", "unknown"), t.get("reason", "")] for t in response_state.get("transitions", [])
        ]))
    else:
        limitations.append("No incident response audit is available in this snapshot.")
    return Report(kind="incident", subject_id=incident_id, title=incident.get("title", incident_id),
                  summary=summary, sections=sections,
                  source_ids=[f"incident:{incident_id}", *[f"event:{e}" for e in event_ids]], limitations=limitations)
