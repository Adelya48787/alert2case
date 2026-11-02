"""Cache TTL, Redis roundtrip və yaddaş fallback testləri."""

from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest
from redis.exceptions import ConnectionError

from app.enrich import cache
from app.enrich.base import ProviderResult


def result(status="ok", verdict="malicious"):
    return ProviderResult(
        provider="virustotal",
        ioc_type="hash_sha256",
        ioc="a" * 64,
        status=status,
        verdict=verdict,
        latency_ms=125,
    )


@pytest.mark.parametrize(
    ("status", "verdict", "expected"),
    [
        ("ok", "malicious", 86400),
        ("ok", "clean", 21600),
        ("ok", "suspicious", 3600),
        ("ok", "unknown", 3600),
        ("not_found", "unknown", 3600),
    ],
)
@pytest.mark.asyncio
async def test_cache_roundtrip_and_ttl(monkeypatch, status, verdict, expected):
    redis = fakeredis.aioredis.FakeRedis()
    monkeypatch.setattr(cache, "get_redis", lambda: redis)
    res = result(status, verdict)

    try:
        assert await cache.get(res.provider, res.ioc_type, res.ioc) is None

        await cache.put(res)
        hit = await cache.get(res.provider, res.ioc_type, res.ioc)

        assert hit is not None
        assert hit.cached is True
        assert hit.status == status
        assert hit.verdict == verdict
        assert hit.latency_ms == 0
        assert res.latency_ms == 125

        k = cache.key(res.provider, res.ioc_type, res.ioc)
        ttl = await redis.ttl(k)
        assert expected - 5 <= ttl <= expected
        assert res.ioc not in k
        assert k != cache.key("otx", res.ioc_type, res.ioc)
    finally:
        await redis.aclose()


@pytest.mark.parametrize(
    "status",
    ["timeout", "error", "rate_limited", "auth_error", "skipped"],
)
@pytest.mark.asyncio
async def test_error_results_are_not_cached(monkeypatch, status):
    redis = AsyncMock()
    monkeypatch.setattr(cache, "get_redis", lambda: redis)

    await cache.put(result(status=status, verdict="unknown"))

    redis.set.assert_not_awaited()


@pytest.mark.asyncio
async def test_memory_fallback_and_expiry(monkeypatch):
    redis = AsyncMock()
    redis.get.side_effect = ConnectionError("Redis unavailable")
    redis.set.side_effect = ConnectionError("Redis unavailable")
    monkeypatch.setattr(cache, "get_redis", lambda: redis)
    monkeypatch.setattr(cache, "_memory", {})

    now = [100.0]
    monkeypatch.setattr(cache.time, "time", lambda: now[0])
    res = result(verdict="unknown")

    assert await cache.get(res.provider, res.ioc_type, res.ioc) is None

    await cache.put(res)
    hit = await cache.get(res.provider, res.ioc_type, res.ioc)
    assert hit is not None
    assert hit.cached is True

    now[0] += 3601
    assert await cache.get(res.provider, res.ioc_type, res.ioc) is None
