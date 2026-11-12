from copy import deepcopy

from src.reporting import build_incident_report


def snapshot():
    return {
        "incident_id": "inc-report-test", "title": "Suspicious email", "severity": "medium",
        "risk_score": 42.0, "event_count": 2, "status": "open",
        "event_ids": ["evt-1", "evt-2"], "primary_entity": {"ip": "203.0.113.19"},
        "timeline": [
            {"timestamp": "2026-11-12T10:30:00+01:00", "event_id": "evt-2", "source": "phishing",
             "event_type": "phishing_email_detected", "severity": "medium", "description": "Later email",
             "entity": {"ip": "203.0.113.19"}},
            {"timestamp": "2026-11-12T09:00:00Z", "event_id": "evt-1", "source": "phishing",
             "event_type": "phishing_email_detected", "severity": "low", "description": "Earlier email"},
        ],
    }


def test_report_is_grounded_chronological_and_does_not_mutate_source():
    data = snapshot()
    before = deepcopy(data)
    report = build_incident_report(data)
    assert data == before
    assert "phishing_email_detected" in report.summary
    for invented in ("brute force", "escalation", "honeypot", "compromised"):
        assert invented not in report.summary.lower()
    timeline = next(s for s in report.sections if s.title == "Event timeline")
    assert [row[-1] for row in timeline.rows] == ["evt-1", "evt-2"]
    indicators = next(s for s in report.sections if s.title.startswith("Observed indicators"))
    assert len(indicators.rows) == 1
    assert "event:evt-2" in indicators.rows[0][-1]
    assert report.source_ids == ["incident:inc-report-test", "event:evt-1", "event:evt-2"]


def test_no_evidence_is_explicit_and_counts_are_not_invented():
    report = build_incident_report({"incident_id": "empty", "event_count": 5})
    assert "none recorded" in report.summary
    assert any("No event timeline" in value for value in report.limitations)
    assert any("differs" in value for value in report.limitations)


def test_untrusted_values_cannot_inject_html_or_markdown():
    data = snapshot()
    data["title"] = '<script>alert(1)</script>'
    data["timeline"][0]["description"] = '[click](javascript:alert(1))\n| injected | <img src=x onerror=alert(1)>'
    report = build_incident_report(data)
    html = report.to_html()
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html
    md = report.to_markdown()
    assert "[click](javascript:" not in md
    assert "\\| injected \\|" in md


def test_response_status_and_audit_are_reported():
    report = build_incident_report(snapshot(), {"phase": "contained", "transitions": [{
        "transitioned_at": "2026-11-12T12:00:00Z", "from_phase": "containing", "to_phase": "contained",
        "transitioned_by": "analyst", "reason": "Reviewed containment",
    }]})
    assert "status contained" in report.summary
    assert "analyst" in report.to_html()
    assert "Reviewed containment" in report.to_markdown()
    assert "2026-11-12T12:00:00Z" in report.to_html()
