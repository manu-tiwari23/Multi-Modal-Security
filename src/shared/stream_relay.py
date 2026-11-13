"""Acknowledged Redis ingestion with backlog recovery and invalid-event quarantine."""
import asyncio
import logging
from uuid import uuid4

import redis.asyncio as redis
from redis.exceptions import ResponseError
from pydantic import ValidationError

from .event_schema import SecurityEvent

logger = logging.getLogger(__name__)


class ReliableStreamRelay:
    def __init__(self, client, handler, stream="events:raw", group="mms-gateway", consumer=None,
                 reclaim_ms=60000, dead_stream="events:invalid"):
        self.client, self.handler = client, handler
        self.stream, self.group = stream, group
        self.consumer = consumer or f"gateway-{uuid4().hex}"
        self.reclaim_ms, self.dead_stream = reclaim_ms, dead_stream
        self.claim_cursor = "0-0"

    async def ensure_group(self):
        try:
            await self.client.xgroup_create(self.stream, self.group, id="0-0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def process(self, message_id, fields):
        try:
            event = SecurityEvent.from_json(fields.get("data", ""))
        except (ValueError, TypeError, ValidationError):
            # Quarantine and acknowledgement are atomic. Invalid content never reaches
            # a WebSocket client as an apparently valid security event.
            async with self.client.pipeline(transaction=True) as pipeline:
                pipeline.xadd(self.dead_stream, {"source_stream": self.stream, "source_id": message_id,
                    "reason": "invalid_security_event", "data": fields.get("data", "")})
                pipeline.xack(self.stream, self.group, message_id)
                await pipeline.execute()
            return
        await self.handler(event)
        await self.client.xack(self.stream, self.group, message_id)

    async def cycle(self):
        # Retry this worker's unacknowledged batch before reading newer entries.
        batches = await self.client.xreadgroup(self.group, self.consumer, {self.stream: "0-0"}, count=20)
        messages = [entry for _, entries in batches for entry in entries]
        if not messages:
            claimed = await self.client.xautoclaim(self.stream, self.group, self.consumer,
                min_idle_time=self.reclaim_ms, start_id=self.claim_cursor, count=20)
            self.claim_cursor, messages = claimed[0], claimed[1]
        if not messages:
            batches = await self.client.xreadgroup(self.group, self.consumer, {self.stream: ">"}, count=20, block=2000)
            messages = [entry for _, entries in batches for entry in entries]
        for message_id, fields in messages:
            await self.process(message_id, fields)

    async def run(self):
        while True:
            try:
                await self.ensure_group()
                await self.cycle()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Event relay processing unavailable; retaining pending messages for retry")
                await asyncio.sleep(2)


async def run_gateway_relay(url, handler):
    client = redis.from_url(url, decode_responses=True, socket_connect_timeout=5, socket_timeout=10)
    try:
        await ReliableStreamRelay(client, handler).run()
    finally:
        await client.aclose()
