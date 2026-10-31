"""3.4: token bucket (Lua) və gündəlik kvota. Real Redis və real gözləmə yoxdur."""

import logging
from types import SimpleNamespace

import fakeredis.aioredis
import pytest

from app.enrich import ratelimit


@pytest.fixture
def clock(monkeypatch):
    """Saxta saat və saxta Redis: testlər bir anda bitir."""
    now = {"t": 1_000.0}
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)
        now["t"] += s

    monkeypatch.setattr(ratelimit, "get_redis", lambda: redis)
    monkeypatch.setattr(ratelimit, "_script", None)
    monkeypatch.setattr(ratelimit, "time", SimpleNamespace(time=lambda: now["t"], monotonic=lambda: now["t"]))
    monkeypatch.setattr(ratelimit, "asyncio", SimpleNamespace(sleep=fake_sleep))
    return SimpleNamespace(now=now, redis=redis, sleeps=sleeps)


async def test_vt_burst_one_second_request_must_wait(clock):
    # VT: dəqiqədə 4, burst 1 → ikinci sorğu dərhal getmir
    assert await ratelimit.acquire("virustotal", 4, 500, burst=1, max_wait=0)
    assert not await ratelimit.acquire("virustotal", 4, 500, burst=1, max_wait=0)


async def test_vt_rhythm_is_about_16_7_seconds(clock):
    assert await ratelimit.acquire("virustotal", 4, 500, burst=1)
    assert await ratelimit.acquire("virustotal", 4, 500, burst=1)
    # 4/dəq × 0.9 ehtiyat = 0.06 token/s → 1 token üçün 16.67 s gözləmə
    assert clock.sleeps == [pytest.approx(16.667, abs=0.01)]


async def test_bucket_refills_with_time(clock):
    assert await ratelimit.acquire("virustotal", 4, 500, burst=1, max_wait=0)
    clock.now["t"] += 17
    assert await ratelimit.acquire("virustotal", 4, 500, burst=1, max_wait=0)


async def test_abuseipdb_burst_five(clock):
    results = [await ratelimit.acquire("abuseipdb", 30, 1000, burst=5, max_wait=0) for _ in range(6)]
    assert results == [True] * 5 + [False]


async def test_providers_have_separate_buckets(clock):
    assert await ratelimit.acquire("virustotal", 4, 500, burst=1, max_wait=0)
    assert await ratelimit.acquire("otx", 60, 10000, burst=10, max_wait=0)


async def test_daily_quota_counts_and_expires(clock):
    for _ in range(3):
        clock.now["t"] += 20
        assert await ratelimit.acquire("virustotal", 4, 500, burst=1, max_wait=0)
    key = ratelimit.day_key("virustotal")
    assert await clock.redis.get(key) == "3"
    assert 0 < await clock.redis.ttl(key) <= 2 * 86400


async def test_daily_quota_exhausted_returns_false(clock):
    await clock.redis.set(ratelimit.day_key("virustotal"), 500)
    assert not await ratelimit.acquire("virustotal", 4, 500, burst=1, max_wait=60)
    assert clock.sleeps == []  # kvota bitibsə gözləmir də


async def test_warns_at_80_percent(clock, caplog):
    caplog.set_level(logging.WARNING, logger="enrich.ratelimit")
    for _ in range(4):
        assert await ratelimit.acquire("otx", 60, 5, burst=10, max_wait=0)
    assert "80%" in caplog.text
