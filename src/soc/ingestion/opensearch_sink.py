"""
OpenSearch sink for the SOC ingestion pipeline.

Handles index creation (with a proper mapping) and bulk/single document
indexing.  All events stored in OpenSearch go through this sink, guaranteeing
consistent field mappings across the ``mms-events`` index.
"""

from __future__ import annotations

import logging
from typing import Optional

from opensearchpy import OpenSearch, helpers as os_helpers

from src.shared.config import settings
from src.shared.event_schema import SecurityEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Index mapping — defines how OpenSearch stores and indexes each field
# ---------------------------------------------------------------------------

_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "event_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "source": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "entity": {
                "properties": {
                    "ip": {"type": "ip"},
                    "user": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "hash": {"type": "keyword"},
                },
            },
            "raw": {"type": "object", "enabled": True},
            "enrichment": {"type": "object", "enabled": True},
        },
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}


class OpenSearchSink:
    """Indexes ``SecurityEvent`` documents into OpenSearch."""

    def __init__(self, opensearch_url: Optional[str] = None, index_name: Optional[str] = None) -> None:
        self._url = opensearch_url or settings.opensearch_url
        self._index = index_name or settings.opensearch_events_index
        self._client = OpenSearch(
            hosts=[self._url],
            use_ssl=False,
            verify_certs=False,
            timeout=30,
        )
        self._ensure_index()

    def _ensure_index(self) -> None:
        """Create the events index if it doesn't already exist."""
        if not self._client.indices.exists(index=self._index):
            self._client.indices.create(index=self._index, body=_INDEX_MAPPING)
            logger.info("Created OpenSearch index '%s'", self._index)
        else:
            logger.debug("OpenSearch index '%s' already exists", self._index)

    def index_event(self, event: SecurityEvent) -> None:
        """Index a single event."""
        doc = event.to_opensearch_doc()
        self._client.index(
            index=self._index,
            id=event.event_id,
            body=doc,
        )
        logger.debug("Indexed event %s", event.event_id)

    def bulk_index(self, events: list[SecurityEvent]) -> int:
        """Bulk-index a list of events.  Returns the number indexed."""
        if not events:
            return 0

        actions = [
            {
                "_index": self._index,
                "_id": event.event_id,
                "_source": event.to_opensearch_doc(),
            }
            for event in events
        ]

        success, errors = os_helpers.bulk(self._client, actions, raise_on_error=False)
        if errors:
            logger.error("Bulk index errors: %s", errors)
        return success

    def close(self) -> None:
        self._client.close()
