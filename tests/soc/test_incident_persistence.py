"""Durable correlation cases for the consolidated verification pass."""
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg2
from psycopg2 import sql
import pytest

from src.shared.config import settings
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.correlation.durable import DurableCorrelationEngine
from src.soc.correlation.repository import PostgresIncidentRepository

pytestmark = pytest.mark.integration


@pytest.fixture
def durable_incidents():
    schema = "mms_incident_test_" + uuid4().hex
    repository = PostgresIncidentRepository(settings.postgres_url, schema)
    repository.list_incidents()
    try:
        yield repository, schema
    finally:
        assert schema.startswith("mms_incident_test_") and len(schema) == len("mms_incident_test_") + 32
        connection = psycopg2.connect(settings.postgres_url, connect_timeout=5)
        try:
            with connection, connection.cursor() as cursor:
                cursor.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        finally:
            connection.close()


def event(identifier):
    return SecurityEvent(event_id=identifier, source="soc", event_type="auth_failure", severity="high",
                         entity=Entity(ip="192.0.2.50"))


def test_recreated_engine_recovers_timeline_and_deduplicates(durable_incidents):
    repository, schema = durable_incidents
    first = DurableCorrelationEngine(repository)
    original = event("first-persistent-event")
    incident = first.process_event(original)
    second = DurableCorrelationEngine(PostgresIncidentRepository(settings.postgres_url, schema))
    recovered = second.get_incident(incident.incident_id)
    assert recovered.timeline[0].event_id == original.event_id
    assert recovered.risk_score > 0
    duplicate = second.process_event(original)
    assert duplicate.event_count == 1
    assert len(duplicate.timeline) == 1
    next_incident = second.process_event(event("second-persistent-event"))
    assert next_incident.incident_id == incident.incident_id
    assert next_incident.event_count == 2


def test_workers_share_entity_correlation_without_lost_events(durable_incidents):
    repository, schema = durable_incidents
    workers = [DurableCorrelationEngine(PostgresIncidentRepository(settings.postgres_url, schema)) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda index: workers[index % 2].process_event(event(f"parallel-{index}")), range(12)))
    assert len({item.incident_id for item in results}) == 1
    stored = repository.get(results[0].incident_id)
    assert stored.event_count == 12
    assert len(stored.timeline) == 12


def test_closed_response_is_projected_and_not_reused(durable_incidents):
    repository, _ = durable_incidents
    phases = {}
    engine = DurableCorrelationEngine(repository, status_provider=lambda: phases)
    incident = engine.process_event(event("before-closure"))
    phases[incident.incident_id] = "closed"
    assert not engine.active_incidents
    assert engine.get_incident(incident.incident_id).status == "closed"
    later = engine.process_event(event("after-closure"))
    assert later.incident_id != incident.incident_id
    assert len(engine.list_incidents()) == 2


def test_detection_threshold_survives_worker_change_and_replay(durable_incidents):
    from src.soc.detection.durable import DurableDetectionEngine
    from src.soc.detection.rule_model import DetectionRule
    repository, schema = durable_incidents
    rule = DetectionRule(id="test-threshold", title="Synthetic threshold", detection={
        "selection": {"event_type": "auth_failure"}, "threshold": {"count": 3, "timeframe": 60, "by": ["entity.ip"]}})
    first = DurableDetectionEngine([rule], repository)
    initial = event("threshold-one")
    assert first.evaluate(initial) == []
    assert first.evaluate(initial) == []
    second = DurableDetectionEngine([rule], PostgresIncidentRepository(settings.postgres_url, schema))
    assert second.evaluate(event("threshold-two")) == []
    last = event("threshold-three")
    matches = second.evaluate(last)
    assert len(matches) == 1
    assert set(matches[0].matched_event_ids) == {"threshold-one", "threshold-two", "threshold-three"}
    assert first.evaluate(last)[0].match_id == matches[0].match_id
