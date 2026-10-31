"""Redis Stream-dən oxuyur, pipeline-ı çağırır, xətaları idarə edir.

İşə sal: python -m app.worker
"""

import asyncio
import logging
import os
import socket
from datetime import datetime

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app import queue
from app.errors import PermanentError
from app.pipeline import process
from app.enrich import reenrich

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("worker")

CONSUMER = f"{socket.gethostname()}-{os.getpid()}"
MAX_ATTEMPTS = 3
CONCURRENCY = 4
_tasks: set[asyncio.Task] = set()  # işləyən task-lara istinad: garbage collector onları silməsin


async def handle(msg_id: str, fields: dict) -> None:
    r = queue.get_redis()
    try:
        await process(fields["source"], fields["body"], datetime.fromisoformat(fields["received_at"]))
        await r.xack(queue.STREAM_IN, queue.GROUP, msg_id)
    except PermanentError as e:
        log.warning("daimi xəta %s: %s", msg_id, e)
        await queue.to_dlq(fields, "normalize", str(e))
        await r.xack(queue.STREAM_IN, queue.GROUP, msg_id)
    except Exception as e:
        info = await r.xpending_range(queue.STREAM_IN, queue.GROUP, min=msg_id, max=msg_id, count=1)
        attempts = info[0]["times_delivered"] if info else 1
        log.exception("xəta %s (cəhd %s/%s)", msg_id, attempts, MAX_ATTEMPTS)
        if attempts >= MAX_ATTEMPTS:
            await queue.to_dlq(fields, "pipeline", repr(e))
            await r.xack(queue.STREAM_IN, queue.GROUP, msg_id)
        # əks halda ACK etmirik: reclaim_loop mesajı yenidən götürəcək


async def reclaim_loop() -> None:
    """ACK olunmamış, 60 s-dən çox gözləyən mesajları yenidən emal edir."""
    r = queue.get_redis()
    while True:
        await asyncio.sleep(30)
        try:
            res = await r.xautoclaim(
                queue.STREAM_IN, queue.GROUP, CONSUMER, min_idle_time=60_000, start_id="0-0", count=50
            )
        except (RedisConnectionError, RedisTimeoutError) as e:
            log.warning("reclaim: Redis əlçatmazdır: %s", e)
            continue
        for msg_id, fields in res[1]:
            if fields:
                await handle(msg_id, fields)


async def main() -> None:
    await queue.ensure_group()
    sem = asyncio.Semaphore(CONCURRENCY)
    reclaim = asyncio.create_task(reclaim_loop())
    asyncio.create_task(reenrich.loop())
    _tasks.add(reclaim)
    log.info("worker %s başladı", CONSUMER)

    async def run(msg_id: str, fields: dict) -> None:
        async with sem:
            await handle(msg_id, fields)

    r = queue.get_redis()
    while True:
        try:
            resp = await r.xreadgroup(queue.GROUP, CONSUMER, {queue.STREAM_IN: ">"}, count=10, block=2000)
        except (RedisConnectionError, RedisTimeoutError) as e:
            log.warning("Redis əlçatmazdır (%s), 2 s sonra təkrar", e)  # worker çökmür
            await asyncio.sleep(2)
            continue
        for _stream, messages in resp or []:
            for msg_id, fields in messages:
                t = asyncio.create_task(run(msg_id, fields))
                _tasks.add(t)
                t.add_done_callback(_tasks.discard)


if __name__ == "__main__":
    asyncio.run(main())
