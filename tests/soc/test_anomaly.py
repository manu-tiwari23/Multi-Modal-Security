from datetime import datetime, timedelta, timezone

from src.shared.event_schema import Entity, SecurityEvent
from src.soc.detection.anomaly import RateAnomalyConfig, RateAnomalyDetector
from src.soc.detection.matcher import DetectionEngine

BASE = datetime(2026, 11, 13, tzinfo=timezone.utc)


def event(minute, number=0):
    return SecurityEvent(event_id=f"event-{minute}-{number}", source="soc", event_type="connection",
        severity="low", timestamp=BASE + timedelta(minutes=minute, seconds=number), entity=Entity(host="synthetic-host"))


def config():
    return RateAnomalyConfig(warmup_buckets=5, history_buckets=10, minimum_rate=5, deviation_multiplier=3)


def test_warmup_then_explainable_spike_emits_once():
    detector = RateAnomalyDetector(config())
    for minute in range(5):
        assert detector.evaluate(event(minute)) == []
    matches = []
    for number in range(10):
        matches.extend(detector.evaluate(event(5, number)))
    assert len(matches) == 1
    assert matches[0].context["baseline_median"] == 1
    assert matches[0].context["threshold"] == 5
    assert matches[0].context["observed_count"] == 6


def test_anomaly_state_recovers_and_duplicate_or_late_events_do_not_count():
    first = DetectionEngine([], config())
    for minute in range(5):
        first.evaluate(event(minute))
    second = DetectionEngine([], config())
    second.restore_state(first.export_state())
    for _ in range(20):
        assert second.evaluate(event(5, 0)) == []
    assert second.evaluate(event(1, 30)) == []
    matches = []
    for number in range(1, 6):
        matches.extend(second.evaluate(event(5, number)))
    assert len(matches) == 1


def test_long_idle_interval_requires_new_warmup():
    detector = RateAnomalyDetector(config())
    for minute in range(5):
        detector.evaluate(event(minute))
    for number in range(30):
        assert detector.evaluate(event(60, number)) == []
