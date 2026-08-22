"""
Integration tests for the SOC ingestion pipeline.

These tests require Docker services (Redis + OpenSearch) to be running::

    docker compose up -d redis opensearch
    pytest tests/soc/test_ingestion_integration.py -v

Marked with ``@pytest.mark.integration`` so they can be skipped in CI
without Docker.
"""

from __future__ import annotations

import time

import pytest
import redis
from opensearchpy import OpenSearch

from src.shared.config import settings
from src.shared.event_bus import EventBusPublisher, EventBusConsumer
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.ingestion.opensearch_sink import OpenSearchSink

# Mark the entire module as integration tests
pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_STREAM = "events:test"
TEST_INDEX = "mms-events-test"


def _redis_available() -> bool:
    try:
        r = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2)
        r.ping()
        r.close()
        return True
    except Exception:
        return False


def _opensearch_available() -> bool:
    try:
        client = OpenSearch(hosts=[settings.opensearch_url], timeout=5)
        client.cluster.health()
        client.close()
        return True
    except Exception:
        return False


skip_no_redis = pytest.mark.skipif(
    not _redis_available(),
    reason="Redis not available — start with: docker compose up -d redis",
)

skip_no_opensearch = pytest.mark.skipif(
    not _opensearch_available(),
    reason="OpenSearch not available — start with: docker compose up -d opensearch",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_event() -> SecurityEvent:
    return SecurityEvent(
        source="soc",
        event_type="ssh_auth_failure",
        severity="medium",
        entity=Entity(ip="10.0.0.1", user="testuser", host="testhost"),
        raw={"line": "Aug 16 14:22:01 testhost sshd[1]: Failed password for testuser from 10.0.0.1"},
    )


@pytest.fixture
def clean_test_stream():
    """Delete the test stream before and after each test."""
    r = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    r.delete(TEST_STREAM)
    yield
    r.delete(TEST_STREAM)
    r.close()


@pytest.fixture
def clean_test_index():
    """Delete the test index before and after each test."""
    client = OpenSearch(hosts=[settings.opensearch_url], use_ssl=False, verify_certs=False)
    if client.indices.exists(index=TEST_INDEX):
        client.indices.delete(index=TEST_INDEX)
    yield
    if client.indices.exists(index=TEST_INDEX):
        client.indices.delete(index=TEST_INDEX)
    client.close()


# ---------------------------------------------------------------------------
# Redis Streams tests
# ---------------------------------------------------------------------------


@skip_no_redis
class TestEventBusIntegration:
    """Verify that events can be published to and consumed from Redis Streams."""

    def test_publish_and_consume(self, sample_event, clean_test_stream):
        """Publish an event → consume it back → verify fields match."""
        publisher = EventBusPublisher(redis_url=settings.redis_url)
        publisher.publish(TEST_STREAM, sample_event)
        publisher.close()

        consumer = EventBusConsumer(
            stream=TEST_STREAM,
            group="test-group",
            consumer="test-consumer-1",
            redis_url=settings.redis_url,
            block_ms=1000,
        )

        received = []
        for event in consumer.listen():
            received.append(event)
            break  # only read one

        consumer.close()

        assert len(received) == 1
        assert received[0].event_id == sample_event.event_id
        assert received[0].source == "soc"
        assert received[0].entity.ip == "10.0.0.1"

    def test_multiple_events(self, clean_test_stream):
        """Publish 5 events → consume them all."""
        publisher = EventBusPublisher(redis_url=settings.redis_url)
        event_ids = []
        for i in range(5):
            event = SecurityEvent(source="soc", event_type=f"test_{i}", severity="low")
            publisher.publish(TEST_STREAM, event)
            event_ids.append(event.event_id)
        publisher.close()

        consumer = EventBusConsumer(
            stream=TEST_STREAM,
            group="test-group-multi",
            consumer="test-consumer-multi",
            redis_url=settings.redis_url,
            block_ms=1000,
        )

        received_ids = []
        for event in consumer.listen():
            received_ids.append(event.event_id)
            if len(received_ids) == 5:
                break

        consumer.close()
        assert received_ids == event_ids


# ---------------------------------------------------------------------------
# OpenSearch tests
# ---------------------------------------------------------------------------


@skip_no_opensearch
class TestOpenSearchSinkIntegration:
    """Verify that events are correctly indexed into OpenSearch."""

    def test_index_single_event(self, sample_event, clean_test_index):
        """Index one event → retrieve it → verify fields."""
        sink = OpenSearchSink(
            opensearch_url=settings.opensearch_url,
            index_name=TEST_INDEX,
        )
        sink.index_event(sample_event)

        # OpenSearch needs a moment to make the doc searchable
        time.sleep(1.5)

        client = OpenSearch(hosts=[settings.opensearch_url], use_ssl=False, verify_certs=False)
        result = client.search(
            index=TEST_INDEX,
            body={"query": {"match_all": {}}},
        )
        client.close()
        sink.close()

        hits = result["hits"]["hits"]
        assert len(hits) == 1
        doc = hits[0]["_source"]
        assert doc["event_id"] == sample_event.event_id
        assert doc["source"] == "soc"
        assert doc["entity"]["ip"] == "10.0.0.1"

    def test_bulk_index(self, clean_test_index):
        """Bulk-index 10 events → verify count."""
        events = [
            SecurityEvent(source="soc", event_type=f"bulk_{i}", severity="low")
            for i in range(10)
        ]

        sink = OpenSearchSink(
            opensearch_url=settings.opensearch_url,
            index_name=TEST_INDEX,
        )
        count = sink.bulk_index(events)
        sink.close()

        assert count == 10

        time.sleep(1.5)

        client = OpenSearch(hosts=[settings.opensearch_url], use_ssl=False, verify_certs=False)
        result = client.count(index=TEST_INDEX)
        client.close()

        assert result["count"] == 10
