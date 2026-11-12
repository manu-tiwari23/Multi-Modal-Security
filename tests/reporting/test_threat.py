from src.reporting.threat import build_threat_report


def test_deduplicates_events_and_techniques_and_preserves_source_ids():
    event = {"event_id": "evt", "timestamp": "2026-11-12T10:00:00Z", "source": "soc",
             "event_type": "auth_failure", "entity": {"ip": "203.0.113.1"}}
    incident = {"incident_id": "inc", "severity": "high", "risk_score": 70,
                "timeline": [event, event], "mitre_techniques": ["T1110", "T1110"]}
    report = build_threat_report([incident, incident], [event, event], 500)
    assert "1 incidents and 1 unique events" in report.summary
    assert report.source_ids == ["incident:inc", "event:evt"]
    techniques = next(s for s in report.sections if s.title == "Recorded technique annotations")
    assert techniques.rows == [["T1110", "1", "inc"]]
    entities = next(s for s in report.sections if s.title == "Observed entities")
    assert entities.rows == [["ip", "203.0.113.1", "1", "evt"]]


def test_empty_snapshot_and_unavailable_feeds_do_not_claim_safety():
    report = build_threat_report([], [], 500)
    assert "0 incidents and 0 unique events" in report.summary
    assert any("not queried" in limitation for limitation in report.limitations)
    assert "No telemetry is available" in report.to_html()


def test_report_ranks_incidents_and_counts_sources_from_timeline():
    report = build_threat_report([
        {"incident_id": "low", "severity": "low", "risk_score": 10},
        {"incident_id": "high", "severity": "critical", "risk_score": 90, "timeline": [
            {"event_id": "honeypot-1", "source": "honeypot", "event_type": "command", "timestamp": "2026-11-12T10:00:00Z"}]}], [], 500)
    rows = next(s.rows for s in report.sections if s.title == "Incidents by recorded risk")
    assert [r[0] for r in rows] == ["high", "low"]
    assert "honeypot" in report.to_html()
    assert "event:honeypot-1" in report.source_ids
