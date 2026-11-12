"""
API integration tests for Phishing detection endpoints using FastAPI TestClient.
"""

from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def test_api_phishing_scan_clean_url():
    res = client.post(
        "/api/phishing/scan/url",
        json={"url": "https://google.com", "publish_to_pipeline": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert "verdict" in data
    assert data["verdict"]["is_phishing"] is False
    assert data["verdict"]["severity"] == "safe"
    assert data["verdict"]["score"] == 0.0
    assert data["pipeline"] is not None
    assert "event_id" in data["pipeline"]


def test_api_phishing_scan_malicious_url():
    res = client.post(
        "/api/phishing/scan/url",
        json={
            "url": "http://xn--pypal-4ve.com/login/update-password.exe",
            "source_user": "victim_user",
            "publish_to_pipeline": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "verdict" in data
    assert data["verdict"]["is_phishing"] is True
    assert data["verdict"]["score"] >= 80.0
    assert len(data["verdict"]["signals"]) >= 2
    assert "pipeline" in data
    assert data["pipeline"]["event_id"] is not None


def test_api_phishing_scan_email_fields():
    res = client.post(
        "/api/phishing/scan/email",
        json={
            "sender": "security-alerts@paypal.com.account-verification.xyz",
            "recipient": "employee@target.corp",
            "subject": "URGENT: Verify your account within 24 hours or face suspension!",
            "body": "Click here to login: http://xn--pypal-4ve.com/auth/login.exe",
            "publish_to_pipeline": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "verdict" in data
    assert data["verdict"]["is_phishing"] is True
    assert data["verdict"]["score"] >= 70.0
    assert len(data["verdict"]["signals"]) >= 3
    assert data["pipeline"] is not None
    assert "event_id" in data["pipeline"]


def test_api_phishing_scan_email_raw():
    raw_email = (
        "From: admin@trusted.org\r\n"
        "To: user@target.corp\r\n"
        "Subject: Weekly Sync Notes\r\n\r\n"
        "Here are the notes from today's meeting. Thanks!\r\n"
    )
    res = client.post(
        "/api/phishing/scan/email",
        json={"raw_email": raw_email, "publish_to_pipeline": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert "verdict" in data
    assert data["verdict"]["is_phishing"] is False
    assert data["pipeline"] is None


def test_api_phishing_stats():
    res = client.get("/api/phishing/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_emails_scanned" in data
    assert "total_urls_scanned" in data
    assert "phishing_detected_count" in data
    assert "threat_intel_providers" in data
    assert data["total_urls_scanned"] >= 1


def test_api_simulate_phishing_attack():
    res = client.post(
        "/api/simulate/attack",
        json={"scenario": "phishing", "attacker_ip": "198.51.100.99"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "phishing"
    assert data["attacker_ip"] == "198.51.100.99"
    assert data["events_ingested"] >= 1
    assert data["total_active_alerts"] >= 1
    assert data["top_alert"] is not None
