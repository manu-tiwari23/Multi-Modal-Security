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


def test_api_phishing_scan_clean_attachment():
    res = client.post(
        "/api/phishing/scan/attachment",
        json={
            "filename": "notes.txt",
            "content_text": "Meeting notes for Friday review.",
            "content_type": "text/plain",
            "publish_to_pipeline": False,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"]["analysis_type"] == "attachment"
    assert data["verdict"]["is_phishing"] is False
    assert data["verdict"]["severity"] == "safe"
    assert data["features"]["detected_file_type"] == "plain_text"
    assert data["pipeline"] is None


def test_api_phishing_scan_malicious_attachment():
    import base64

    spoofed_pe = base64.b64encode(b"MZ\x90\x00SYNTHETIC_PE_PAYLOAD").decode("ascii")
    res = client.post(
        "/api/phishing/scan/attachment",
        json={
            "filename": "invoice.pdf",
            "content_base64": spoofed_pe,
            "content_type": "application/pdf",
            "source_user": "finance_user",
            "publish_to_pipeline": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"]["is_phishing"] is True
    assert data["verdict"]["severity"] == "critical"
    assert data["verdict"]["score"] >= 80.0
    assert data["features"]["is_extension_spoofed"] is True
    assert "structured_explanation" in data
    assert data["structured_explanation"]["score"] >= 80.0
    assert len(data["structured_explanation"]["top_factors"]) >= 1
    assert data["pipeline"] is not None
    assert data["pipeline"]["event_id"] is not None


def test_api_phishing_explain_endpoint():
    scan_res = client.post(
        "/api/phishing/scan/url",
        json={"url": "http://xn--pypal-4ve.com/login", "publish_to_pipeline": False},
    )
    assert scan_res.status_code == 200
    verdict_dict = scan_res.json()["verdict"]

    exp_res = client.post(
        "/api/phishing/explain",
        json={"verdict": verdict_dict, "target": "suspicious-login-link"},
    )
    assert exp_res.status_code == 200
    exp = exp_res.json()["structured_explanation"]
    assert exp["target_summary"] == "suspicious-login-link"
    assert exp["is_phishing"] is True
    assert len(exp["category_breakdown"]) >= 1
    assert len(exp["recommended_actions"]) >= 1


def test_api_phishing_scan_composite():
    import base64

    pe_b64 = base64.b64encode(b"MZ\x90\x00SYNTHETIC").decode("ascii")
    res = client.post(
        "/api/phishing/scan/composite",
        json={
            "sender": "alerts@paypal.com.verify-account.xyz",
            "recipient": "employee@target.corp",
            "subject": "URGENT: Account Suspended within 24 hours!",
            "body": "Login immediately: http://xn--pypal-4ve.com/login",
            "attachments": [
                {
                    "filename": "statement.pdf",
                    "content_base64": pe_b64,
                    "content_type": "application/pdf",
                }
            ],
            "publish_to_pipeline": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["email_verdict"]["is_phishing"] is True
    assert len(data["url_verdicts"]) == 1
    assert len(data["attachment_verdicts"]) == 1
    exp = data["structured_explanation"]
    assert exp["analysis_type"] == "composite"
    assert exp["is_phishing"] is True
    assert exp["score"] >= 85.0
    assert data["pipeline"] is not None
