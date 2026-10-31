import redis.asyncio as redis

from app.config import settings

STREAM_IN = "alerts.in"
STREAM_DLQ = "alerts.dlq"
GROUP = "pipeline"

_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        # socket_timeout blok edən oxumadan (block=2000 ms) uzun olmalıdır
        _client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_timeout=10,
            socket_connect_timeout=5,
            health_check_interval=30,
        )
    return _client


async def ensure_group() -> None:
    try:
        await get_redis().xgroup_create(STREAM_IN, GROUP, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):  # qrup artıq var: normaldır
            raise


async def enqueue(source: str, body: str, received_at: str) -> str:
    return await get_redis().xadd(
        STREAM_IN,
        {"source": source, "body": body, "received_at": received_at},
        maxlen=100_000,
        approximate=True,
    )


async def to_dlq(fields: dict, stage: str, error: str) -> str:
    return await get_redis().xadd(STREAM_DLQ, {**fields, "stage": stage, "error": error[:1000]})
