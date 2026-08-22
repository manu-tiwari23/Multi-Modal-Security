"""
FastAPI gateway for Multi Modal Security.

Provides REST endpoints for querying ingested events and a WebSocket endpoint
for streaming live events to the dashboard.

Run from the project root::

    uvicorn src.api.main:app --reload
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from opensearchpy import OpenSearch

from src.shared.config import settings
from src.shared.event_schema import SecurityEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------


class ConnectionManager:
    """Manages active WebSocket connections for live event streaming."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info("WebSocket client connected (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.remove(ws)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._connections))

    async def broadcast(self, message: str) -> None:
        """Send *message* to all connected clients."""
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)


manager = ConnectionManager()

# ---------------------------------------------------------------------------
# Background task: poll Redis Streams and relay to WebSocket clients
# ---------------------------------------------------------------------------

_relay_task: Optional[asyncio.Task] = None


async def _redis_to_websocket_relay() -> None:
    """Background coroutine that reads new events from Redis Streams and
    broadcasts them to all connected WebSocket clients.

    Uses a dedicated Redis connection with blocking XREAD (no consumer group
    needed — this is a fan-out relay, not a durable consumer).
    """
    import redis.asyncio as aioredis

    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    last_id = "$"  # only new messages from now on

    logger.info("Redis → WebSocket relay started")
    try:
        while True:
            try:
                results = await r.xread(
                    streams={"events:raw": last_id},
                    count=20,
                    block=2000,
                )
            except Exception:
                logger.exception("Redis relay error, retrying in 2s")
                await asyncio.sleep(2)
                continue

            if not results:
                continue

            for _stream, messages in results:
                for message_id, fields in messages:
                    last_id = message_id
                    await manager.broadcast(fields.get("data", "{}"))
    finally:
        await r.aclose()


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the Redis relay on startup, cancel it on shutdown."""
    global _relay_task
    _relay_task = asyncio.create_task(_redis_to_websocket_relay())
    yield
    if _relay_task:
        _relay_task.cancel()


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Multi Modal Security — API Gateway",
    version="0.1.0",
    description="REST + WebSocket API for the MMS platform.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# OpenSearch client (lazy singleton)
# ---------------------------------------------------------------------------

_os_client: Optional[OpenSearch] = None


def _get_os() -> OpenSearch:
    global _os_client
    if _os_client is None:
        _os_client = OpenSearch(
            hosts=[settings.opensearch_url],
            use_ssl=False,
            verify_certs=False,
        )
    return _os_client


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
async def health():
    """Liveness check."""
    return {"status": "ok", "service": "mms-api-gateway"}


@app.get("/api/events")
async def get_events(
    size: int = Query(default=50, ge=1, le=500, description="Number of events to return"),
    source: Optional[str] = Query(default=None, description="Filter by source module"),
    severity: Optional[str] = Query(default=None, description="Filter by severity level"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    search: Optional[str] = Query(default=None, description="Full-text search across raw data"),
):
    """Query recent security events from OpenSearch."""
    os_client = _get_os()
    index = settings.opensearch_events_index

    # Build the query
    must_clauses: list[dict] = []
    if source:
        must_clauses.append({"term": {"source": source}})
    if severity:
        must_clauses.append({"term": {"severity": severity}})
    if event_type:
        must_clauses.append({"term": {"event_type": event_type}})
    if search:
        must_clauses.append({"query_string": {"query": search}})

    body = {
        "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": size,
    }

    try:
        result = os_client.search(index=index, body=body)
        hits = result.get("hits", {}).get("hits", [])
        events = [hit["_source"] for hit in hits]
        return {
            "total": result["hits"]["total"]["value"],
            "count": len(events),
            "events": events,
        }
    except Exception as exc:
        logger.error("OpenSearch query failed: %s", exc)
        return {"total": 0, "count": 0, "events": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@app.websocket("/api/events/live")
async def websocket_events(ws: WebSocket):
    """Stream live events to connected dashboard clients."""
    await manager.connect(ws)
    try:
        while True:
            # Keep the connection alive; ignore any client messages
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
