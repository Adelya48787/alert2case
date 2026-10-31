"""Redis cache; Redis əlçatmaz olduqda proses yaddaşından istifadə edir."""

import hashlib
import logging
import time

import redis.asyncio as redis

from app.enrich.base import ProviderResult
from app.queue import get_redis

log = logging.getLogger("enrich.cache")

TTL = {
    "malicious": 24 * 3600,
    "suspicious": 3600,
    "clean": 6 * 3600,
    "unknown": 3600,
}
NOT_FOUND_TTL = 3600
_memory: dict[str, tuple[float, str]] = {}


def key(provider: str, ioc_type: str, value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"intel:v1:{provider}:{ioc_type}:{digest}"


def ttl_for(res: ProviderResult) -> int | None:
    if res.status == "not_found":
        return NOT_FOUND_TTL
    if res.status == "ok":
        return TTL[res.verdict]
    return None


async def get(provider: str, ioc_type: str, value: str) -> ProviderResult | None:
    k = key(provider, ioc_type, value)
    try:
        raw = await get_redis().get(k)
    except (redis.RedisError, OSError) as e:
        log.warning("Redis cache əlçatmazdır, yaddaşdan oxuyuram: %s", e)
        exp, raw = _memory.get(k, (0.0, None))
        raw = raw if exp > time.time() else None

    if not raw:
        return None

    res = ProviderResult.model_validate_json(raw)
    res.cached = True
    return res


async def put(res: ProviderResult) -> None:
    ttl = ttl_for(res)
    if ttl is None:
        return

    k = key(res.provider, res.ioc_type, res.ioc)
    raw = res.model_copy(update={"cached": False, "latency_ms": 0}).model_dump_json()

    try:
        await get_redis().set(k, raw, ex=ttl)
    except (redis.RedisError, OSError):
        _memory[k] = (time.time() + ttl, raw)
