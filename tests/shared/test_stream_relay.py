import asyncio
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import redis.asyncio as redis

from src.shared.config import settings
from src.shared.event_schema import SecurityEvent
from src.shared.stream_relay import ReliableStreamRelay


def test_processing_failure_does_not_acknowledge():
    async def scenario():
        client = AsyncMock()
        handler = AsyncMock(side_effect=RuntimeError("temporary failure"))
        relay = ReliableStreamRelay(client, handler)
        event = SecurityEvent(source="soc", event_type="synthetic", severity="low")
        with pytest.raises(RuntimeError):
            await relay.process("1-0", {"data": event.to_json()})
        client.xack.assert_not_called()
        handler.side_effect = None
        await relay.process("1-0", {"data": event.to_json()})
        client.xack.assert_awaited_once_with("events:raw", "mms-gateway", "1-0")
    asyncio.run(scenario())


@pytest.mark.integration
def test_backlog_reclaim_and_quarantine():
    async def scenario():
        client = redis.from_url(settings.redis_url, decode_responses=True)
        stream = "mms-test-relay:" + uuid4().hex
        dead = stream + ":invalid"
        event = SecurityEvent(source="soc", event_type="synthetic", severity="low")
        seen = []
        async def handler(item):
            seen.append(item.event_id)
        first = ReliableStreamRelay(client, handler, stream=stream, group="test", consumer="abandoned", dead_stream=dead, reclaim_ms=0)
        try:
            # This event predates group creation and must not be skipped.
            await client.xadd(stream, {"data": event.to_json()})
            await first.ensure_group()
            delivered = await client.xreadgroup("test", "abandoned", {stream: ">"}, count=1)
            assert delivered
            recovered = ReliableStreamRelay(client, handler, stream=stream, group="test", consumer="replacement", dead_stream=dead, reclaim_ms=0)
            await recovered.cycle()
            assert seen == [event.event_id]
            assert (await client.xpending(stream, "test"))["pending"] == 0
            await client.xadd(stream, {"data": "not a security event"})
            await recovered.cycle()
            assert seen == [event.event_id]
            quarantined = await client.xrange(dead)
            assert len(quarantined) == 1
            assert quarantined[0][1]["reason"] == "invalid_security_event"
            assert (await client.xpending(stream, "test"))["pending"] == 0
        finally:
            assert stream.startswith("mms-test-relay:")
            await client.delete(stream, dead)
            await client.aclose()
    asyncio.run(scenario())
