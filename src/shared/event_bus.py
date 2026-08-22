"""
Redis Streams event bus client for Multi Modal Security.

Provides a thin publish/subscribe layer over Redis Streams so that every
module uses the same conventions for stream names, consumer groups, and
serialisation.

Usage
-----
Publishing::

    publisher = EventBusPublisher()
    publisher.publish("events:raw", event)

Consuming::

    consumer = EventBusConsumer("events:raw", group="soc-engine", consumer="soc-1")
    for event in consumer.listen():
        process(event)
"""

from __future__ import annotations

import logging
import time
from typing import Generator, Optional

import redis

from src.shared.event_schema import SecurityEvent

logger = logging.getLogger(__name__)


def _connect(redis_url: str) -> redis.Redis:
    """Create a Redis client with sane defaults."""
    return redis.Redis.from_url(
        redis_url,
        decode_responses=True,
        socket_connect_timeout=5,
        retry_on_timeout=True,
    )


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------

class EventBusPublisher:
    """Publishes ``SecurityEvent`` objects to a Redis Stream."""

    def __init__(self, redis_url: Optional[str] = None) -> None:
        if redis_url is None:
            from src.shared.config import settings
            redis_url = settings.redis_url
        self._redis = _connect(redis_url)

    def publish(self, stream: str, event: SecurityEvent) -> str:
        """Publish *event* to *stream*.

        Returns the Redis message ID assigned by the server.
        """
        message_id = self._redis.xadd(stream, {"data": event.to_json()})
        logger.debug("Published %s to %s (msg_id=%s)", event.event_id, stream, message_id)
        return message_id

    def close(self) -> None:
        self._redis.close()


# ---------------------------------------------------------------------------
# Consumer
# ---------------------------------------------------------------------------

class EventBusConsumer:
    """Consumes ``SecurityEvent`` objects from a Redis Stream consumer group.

    Creates the consumer group automatically if it doesn't exist yet (using
    ``MKSTREAM`` so the stream is also created if needed).
    """

    def __init__(
        self,
        stream: str,
        group: str,
        consumer: str,
        redis_url: Optional[str] = None,
        batch_size: int = 10,
        block_ms: int = 2000,
    ) -> None:
        if redis_url is None:
            from src.shared.config import settings
            redis_url = settings.redis_url

        self._redis = _connect(redis_url)
        self._stream = stream
        self._group = group
        self._consumer = consumer
        self._batch_size = batch_size
        self._block_ms = block_ms

        self._ensure_group()

    def _ensure_group(self) -> None:
        """Create the consumer group (and the stream) if they don't exist."""
        try:
            self._redis.xgroup_create(
                self._stream,
                self._group,
                id="0",
                mkstream=True,
            )
            logger.info(
                "Created consumer group '%s' on stream '%s'",
                self._group,
                self._stream,
            )
        except redis.ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                # Group already exists — that's fine.
                pass
            else:
                raise

    def listen(self) -> Generator[SecurityEvent, None, None]:
        """Yield ``SecurityEvent`` objects as they arrive on the stream.

        Blocks up to ``block_ms`` per iteration; loops indefinitely.
        Automatically acknowledges each message after yielding it.
        """
        while True:
            try:
                results = self._redis.xreadgroup(
                    groupname=self._group,
                    consumername=self._consumer,
                    streams={self._stream: ">"},
                    count=self._batch_size,
                    block=self._block_ms,
                )
            except redis.ConnectionError:
                logger.warning("Redis connection lost, retrying in 2s…")
                time.sleep(2)
                continue

            if not results:
                continue

            for _stream_name, messages in results:
                for message_id, fields in messages:
                    try:
                        event = SecurityEvent.from_json(fields["data"])
                        yield event
                        self._redis.xack(self._stream, self._group, message_id)
                    except Exception:
                        logger.exception(
                            "Failed to process message %s from %s",
                            message_id,
                            self._stream,
                        )

    def close(self) -> None:
        self._redis.close()
