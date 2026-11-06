"""Redis Stream-dən oxuyur, pipeline-ı çağırır, xətaları idarə edir.

İşə sal: python -m app.worker
"""

from app.audit.logging_setup import setup_logging
from app import pipeline
from prometheus_client import start_http_server
from app.audit.metrics import DLQ_DEPTH
import asyncio
import logging
import os
import socket
from datetime import datetime

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app import queue
from app.errors import PermanentError
from app.pipeline import process
from app.enrich import reenrich

setup_logging()
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


def _stream_gone(e: Exception) -> bool:
    """Stream və ya consumer group silinib (FLUSHDB, AOF-suz restart).
    NOGROUP: qrup yoxdur. UNBLOCKED: Redis 7 bloklanmış XREADGROUP-u stream silinəndə belə kəsir."""
    return "NOGROUP" in str(e) or "UNBLOCKED" in str(e)


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
        except ResponseError as e:
            if not _stream_gone(e):
                raise
            continue  # əsas döngü qrupu yenidən yaradır
        for msg_id, fields in res[1]:
            if fields:
                await handle(msg_id, fields)


async def housekeeping_loop() -> None:
    """Hər 2 dəqiqədə: gözləyən case-ləri yenidən sına, DLQ ölçüsünü metrikaya yaz."""
    r = queue.get_redis()
    while True:
        await asyncio.sleep(120)
        try:
            n = await pipeline.retry_pending_cases()
            if n:
                log.info("%s gözləyən case yaradıldı", n)
            for stream in (queue.STREAM_DLQ, pipeline.CASES_DLQ):
                DLQ_DEPTH.labels(stream).set(await r.xlen(stream))
        except Exception:  # noqa: BLE001
            log.exception("housekeeping xətası")


async def main() -> None:
    start_http_server(9100)  # Prometheus /metrics
    await queue.ensure_group()
    sem = asyncio.Semaphore(CONCURRENCY)
    reclaim = asyncio.create_task(reclaim_loop())
    _tasks.add(asyncio.create_task(reenrich.loop()))
    _tasks.add(asyncio.create_task(housekeeping_loop()))
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
        except ResponseError as e:
            if not _stream_gone(e):
                raise
            # Redis təmizlənib (FLUSHDB, AOF-suz restart): qrupu yenidən yarat, worker çökmür
            log.warning("consumer group yoxdur, yenidən yaradılır: %s", e)
            await queue.ensure_group()
            continue
        for _stream, messages in resp or []:
            for msg_id, fields in messages:
                t = asyncio.create_task(run(msg_id, fields))
                _tasks.add(t)
                t.add_done_callback(_tasks.discard)


if __name__ == "__main__":
    asyncio.run(main())
