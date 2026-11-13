import asyncio
from unittest.mock import AsyncMock

from src.shared.live_updates import LiveUpdates


def test_publish_delivers_locally_and_tags_fanout_origin():
    async def scenario():
        import json
        broadcast = AsyncMock()
        updates = LiveUpdates("redis://localhost:6379/0", broadcast)
        original_client = updates.client
        updates.client = AsyncMock()
        try:
            payload = {"type": "event", "event": {"event_id": "synthetic"}}
            await updates.publish(payload)
            broadcast.assert_awaited_once_with(json.dumps(payload))
            envelope = json.loads(updates.client.publish.await_args.args[1])
            assert envelope == {"worker": updates.worker, "payload": payload}
        finally:
            await original_client.aclose()
    asyncio.run(scenario())
