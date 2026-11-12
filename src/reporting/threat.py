"""Aggregate observed telemetry without inventing external threat reputation."""

from collections import Counter

from .incident import timestamp_key
from .models import Report, ReportSection


def build_threat_report(incidents: list[dict], events: list[dict], buffer_limit: int) -> Report:
    incident_map = {i["incident_id"]: i for i in incidents}
    event_map = {}
    for incident in incident_map.values():
        for event in incident.get("timeline", []):
            event_map[event["event_id"]] = event
    # The original event has richer fields than a timeline projection.
    event_map.update({e["event_id"]: e for e in events})
    ordered = sorted(event_map.values(), key=lambda e: timestamp_key(e.get("timestamp")))
    sources = Counter(e.get("source", "unknown") for e in ordered)
    types = Counter(e.get("event_type", "unknown") for e in ordered)
    severity = Counter(i.get("severity", "unknown") for i in incident_map.values())
    techniques: dict[str, set[str]] = {}
    entities: dict[tuple[str, str], set[str]] = {}
    for incident in incident_map.values():
        for technique in set(incident.get("mitre_techniques", [])):
            techniques.setdefault(technique, set()).add(incident["incident_id"])
    for event in ordered:
        for kind in ("ip", "user", "host", "hash"):
            value = (event.get("entity") or {}).get(kind)
            if value:
                entities.setdefault((kind, value), set()).add(event["event_id"])
    sections = [
        ReportSection(title="Coverage", paragraphs=[
            f"{len(events)} recent buffer entries (configured capacity {buffer_limit}), plus available incident timeline entries; {len(event_map)} unique events after deduplication.",
            f"Available event timestamps: {ordered[0].get('timestamp', 'unknown')} to {ordered[-1].get('timestamp', 'unknown')}." if ordered else "No telemetry is available in this snapshot.",
        ]),
        ReportSection(title="Incident severity distribution", columns=["Recorded severity", "Incidents"],
                      rows=[[s, str(severity[s])] for s in ("critical", "high", "medium", "low", "unknown") if severity[s]]),
        ReportSection(title="Telemetry sources", columns=["Source", "Unique events"], rows=[[s, str(n)] for s, n in sorted(sources.items())]),
        ReportSection(title="Observed event types", columns=["Event type", "Unique events"], rows=[[s, str(n)] for s, n in sorted(types.items())]),
        ReportSection(title="Incidents by recorded risk", columns=["Incident ID", "Title", "Severity", "Risk / 100", "Status"], rows=[
            [i["incident_id"], i.get("title", ""), i.get("severity", "unknown"), str(i.get("risk_score", 0)), i.get("status", "unknown")]
            for i in sorted(incident_map.values(), key=lambda i: (-i.get("risk_score", 0), i["incident_id"]))
        ]),
        ReportSection(title="Recorded technique annotations", columns=["MITRE technique", "Incident count", "Source incidents"], rows=[
            [technique, str(len(refs)), ", ".join(sorted(refs))] for technique, refs in sorted(techniques.items())
        ]),
        ReportSection(title="Observed entities", columns=["Type", "Value", "Unique event count", "Source events"], rows=[
            [kind, value, str(len(refs)), ", ".join(sorted(refs))] for (kind, value), refs in sorted(entities.items())
        ]),
    ]
    return Report(kind="threat", subject_id="telemetry-snapshot", title="Threat activity analysis",
        summary=f"The available snapshot contains {len(incident_map)} incidents and {len(event_map)} unique events across {len(sources)} telemetry sources. {severity['critical'] + severity['high']} incidents have recorded high or critical severity.",
        sections=sections, source_ids=[*[f"incident:{i}" for i in sorted(incident_map)], *[f"event:{e}" for e in sorted(event_map)]],
        limitations=[
            "Coverage is limited to incidents retained by the running gateway and recent buffered events; this is not an exhaustive historical search.",
            "Counts describe observed telemetry, not confirmed compromises or attack attribution. Synthetic simulations are included if present.",
            "External threat feeds were not queried for this report. No observed entity is classified as clean or malicious by absence of reputation data.",
            "Incident risk scores and MITRE annotations are reported as stored; no additional inference or paid AI generation is performed.",
        ])
