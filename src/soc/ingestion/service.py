"""
SOC log ingestion service.

Watches a directory for new/changed log files, normalises each line into a
``SecurityEvent``, publishes it to Redis Streams, and indexes it into
OpenSearch.

Run from the project root::

    python -m src.soc.ingestion.service
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from src.shared.config import settings
from src.shared.event_bus import EventBusPublisher
from src.soc.ingestion.normalizer import normalise_syslog_line
from src.soc.ingestion.opensearch_sink import OpenSearchSink

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
)
logger = logging.getLogger(__name__)

STREAM_NAME = "events:raw"


def _process_file(
    filepath: Path,
    publisher: EventBusPublisher,
    sink: OpenSearchSink,
    *,
    offset: int = 0,
) -> int:
    """Read *filepath* from *offset*, normalise and publish each new line.

    Returns the new byte offset (so we can resume on the next pass).
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        count = 0
        for line in fh:
            event = normalise_syslog_line(line)
            if event is None:
                continue
            publisher.publish(STREAM_NAME, event)
            sink.index_event(event)
            count += 1
        new_offset = fh.tell()

    if count:
        logger.info("Ingested %d events from %s", count, filepath.name)
    return new_offset


def run(logs_dir: str | None = None, *, poll_interval: float = 2.0, once: bool = False) -> None:
    """Main ingestion loop.

    Args:
        logs_dir:       Directory to watch for ``.log`` files.
        poll_interval:  Seconds between directory scans.
        once:           If ``True``, process all files once then exit
                        (useful for tests / scripted runs).
    """
    logs_path = Path(logs_dir or settings.raw_logs_dir)
    logs_path.mkdir(parents=True, exist_ok=True)

    logger.info("Ingestion service starting — watching %s", logs_path.resolve())

    publisher = EventBusPublisher()
    sink = OpenSearchSink()

    # Track byte offsets per file so we only read new content
    offsets: dict[str, int] = {}

    try:
        while True:
            for entry in sorted(logs_path.glob("*.log")):
                key = str(entry)
                current_size = entry.stat().st_size
                last_offset = offsets.get(key, 0)

                if current_size > last_offset:
                    offsets[key] = _process_file(entry, publisher, sink, offset=last_offset)

            if once:
                break
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("Ingestion service shutting down")
    finally:
        publisher.close()
        sink.close()


# ---------------------------------------------------------------------------
# Entry-point:  python -m src.soc.ingestion.service
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run()
