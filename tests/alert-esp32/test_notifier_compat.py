import json
from unittest.mock import MagicMock
import pytest

from src.alert_esp32.models import AlertNotification, AlertAcknowledgeMessage
from src.alert_esp32.service import AlertNotifierService, TOPIC_STATUS, TOPIC_ACK


def test_notification_model_strict_sanitization():
    """Verify ethical guardrail: raw logs, credentials, and IOCs are never included in the MQTT payload."""
    raw_alert = {
        "alert_id": "alt-test-999",
        "severity": "critical",
        "title": "SSH Brute Force from 203.0.113.88 on prod-web-01",
        "source": "honeypot",
        "primary_entity": {"ip": "203.0.113.88", "user": "root", "password": "supersecretpassword"},
        "raw": {"command": "cat /etc/shadow", "evidence": "sensitive credentials"},
        "ioc": ["203.0.113.88", "evil.com"],
    }

    notification = AlertNotification.from_alert(raw_alert)
    payload_dict = notification.model_dump()

    # Must only contain the 4 sanctioned keys
    assert set(payload_dict.keys()) == {"severity", "incident_type", "source", "timestamp"}
    assert payload_dict["severity"] == "critical"
    assert payload_dict["source"] == "honeypot"
    assert "203.0.113.88" not in payload_dict["incident_type"]
    assert "password" not in json.dumps(payload_dict)
    assert "shadow" not in json.dumps(payload_dict)


def test_notification_severity_mapping():
    """Verify mapping of various SOC priorities and severities to the 5 ESP32 states."""
    test_cases = [
        ({"priority": "P1-critical"}, "critical"),
        ({"severity": "CRITICAL"}, "critical"),
        ({"priority": "P2-high"}, "high"),
        ({"severity": "HIGH"}, "high"),
        ({"priority": "P3-medium"}, "medium"),
        ({"severity": "LOW"}, "low"),
        ({"severity": "informational"}, "normal"),
    ]

    for data, expected in test_cases:
        notif = AlertNotification.from_alert(data)
        assert notif.severity == expected


def test_notifier_service_publish_mock():
    """Verify AlertNotifierService serializes and publishes payload correctly over MQTT."""
    service = AlertNotifierService(broker_host="localhost", broker_port=1883)
    mock_client = MagicMock()
    mock_res = MagicMock()
    mock_res.rc = 0
    mock_client.publish.return_value = mock_res

    service._client = mock_client
    service._connected = True

    notif = AlertNotification(
        severity="critical",
        incident_type="brute_force",
        source="soc",
        timestamp="2026-11-14T01:00:00Z"
    )

    success = service.notify(notif)
    assert success is True
    mock_client.publish.assert_called_once()
    topic, published_str = mock_client.publish.call_args[0][:2]
    assert topic == TOPIC_STATUS
    parsed = json.loads(published_str)
    assert parsed["severity"] == "critical"
    assert parsed["incident_type"] == "brute_force"


def test_notifier_service_handles_ack_message():
    """Verify AlertNotifierService processes incoming physical acknowledge messages."""
    received_acks = []

    def on_ack(msg: AlertAcknowledgeMessage):
        received_acks.append(msg)

    service = AlertNotifierService(on_ack_received=on_ack)

    # Simulate incoming message on alerts/ack
    mock_msg = MagicMock()
    mock_msg.topic = TOPIC_ACK
    mock_msg.payload = json.dumps({
        "acknowledged": True,
        "device_id": "esp32-desk-01",
        "timestamp": "2026-11-14T01:05:00Z"
    }).encode("utf-8")

    service._on_message(None, None, mock_msg)

    assert len(received_acks) == 1
    assert received_acks[0].acknowledged is True
    assert received_acks[0].device_id == "esp32-desk-01"
    assert service.last_ack == received_acks[0]

