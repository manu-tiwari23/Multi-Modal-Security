"""Unit tests for the common event schema."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.shared.event_schema import Entity, SecurityEvent


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestSecurityEventCreation:
    """Test that SecurityEvent can be created with valid data."""

    def test_minimal_event(self):
        """Only required fields provided — defaults fill the rest."""
        event = SecurityEvent(source="soc", event_type="test_event")

        assert event.source == "soc"
        assert event.event_type == "test_event"
        assert event.severity == "low"
        assert event.entity.ip is None
        assert event.raw == {}
        assert event.enrichment == {}
        assert event.event_id  # auto-generated UUID

    def test_full_event(self):
        """All fields explicitly set."""
        ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
        event = SecurityEvent(
            event_id="custom-id-123",
            timestamp=ts,
            source="honeypot",
            entity=Entity(ip="10.0.1.5", user="attacker", host="honeypot-ssh"),
            event_type="ssh_brute_force",
            severity="critical",
            raw={"line": "some raw log"},
            enrichment={"threat_score": 95},
        )

        assert event.event_id == "custom-id-123"
        assert event.timestamp == ts
        assert event.source == "honeypot"
        assert event.entity.ip == "10.0.1.5"
        assert event.entity.user == "attacker"
        assert event.severity == "critical"
        assert event.raw["line"] == "some raw log"
        assert event.enrichment["threat_score"] == 95

    def test_auto_generated_id_is_unique(self):
        """Each event gets a different UUID."""
        e1 = SecurityEvent(source="soc", event_type="a")
        e2 = SecurityEvent(source="soc", event_type="b")
        assert e1.event_id != e2.event_id


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestSecurityEventValidation:
    """Test that invalid data is rejected."""

    def test_invalid_source(self):
        with pytest.raises(ValidationError):
            SecurityEvent(source="unknown_module", event_type="test")

    def test_invalid_severity(self):
        with pytest.raises(ValidationError):
            SecurityEvent(source="soc", event_type="test", severity="extreme")

    def test_missing_required_source(self):
        with pytest.raises(ValidationError):
            SecurityEvent(event_type="test")

    def test_missing_required_event_type(self):
        with pytest.raises(ValidationError):
            SecurityEvent(source="soc")


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------


class TestSecurityEventSerialisation:
    """Test JSON serialisation / deserialisation."""

    def test_json_round_trip(self):
        original = SecurityEvent(
            source="phishing",
            event_type="suspicious_url",
            severity="high",
            entity=Entity(ip="1.2.3.4"),
            raw={"url": "http://evil.example.com"},
        )

        json_str = original.to_json()
        restored = SecurityEvent.from_json(json_str)

        assert restored.event_id == original.event_id
        assert restored.source == original.source
        assert restored.event_type == original.event_type
        assert restored.severity == original.severity
        assert restored.entity.ip == "1.2.3.4"
        assert restored.raw["url"] == "http://evil.example.com"

    def test_to_opensearch_doc(self):
        event = SecurityEvent(
            source="forensics",
            event_type="usb_insertion",
            severity="medium",
        )
        doc = event.to_opensearch_doc()

        assert isinstance(doc, dict)
        assert isinstance(doc["timestamp"], str)  # ISO string, not datetime
        assert doc["source"] == "forensics"
        assert doc["event_type"] == "usb_insertion"

    def test_from_json_invalid_raises(self):
        with pytest.raises(Exception):
            SecurityEvent.from_json("this is not json")

    def test_from_json_missing_fields_raises(self):
        with pytest.raises(Exception):
            SecurityEvent.from_json('{"source": "soc"}')  # missing event_type
