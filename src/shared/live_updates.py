"""Fan out processed telemetry to every gateway worker's authenticated sockets."""
import asyncio
import json
import logging
from uuid import uuid4

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class LiveUpdates:
    def __init__(self, url, broadcast, channel="mms:live:processed"):
        self.client = redis.from_url(url, decode_responses=True, socket_connect_timeout=5, socket_timeout=10)
        self.broadcast = broadcast
        self.channel = channel
        self.worker = uuid4().hex

    async def publish(self, payload):
        await self.broadcast(json.dumps(payload))
        try:
            await self.client.publish(self.channel, json.dumps({"worker": self.worker, "payload": payload}))
        except Exception:
            logger.debug("Redis live fan-out publish skipped (Redis offline)")

    async def listen(self):
        while True:
            try:
                async with self.client.pubsub() as subscriber:
                    await subscriber.subscribe(self.channel)
                    async for message in subscriber.listen():
                        if message["type"] != "message":
                            continue
                        envelope = json.loads(message["data"])
                        if envelope.get("worker") != self.worker and isinstance(envelope.get("payload"), dict):
                            await self.broadcast(json.dumps(envelope["payload"]))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Live fan-out unavailable; retrying subscription")
                await asyncio.sleep(2)

    async def close(self):
        await self.client.aclose()
