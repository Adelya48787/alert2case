"""Enrichment orkestrasiyası: cache → breaker → rate limit → provider → fallback."""

import asyncio
import logging
import time

import httpx

from app.enrich import cache, ratelimit
from app.enrich.aggregate import aggregate
from app.enrich.base import IntelProvider, ProviderResult
from app.enrich.breaker import CircuitBreaker
from app.enrich.http import AuthError, RateLimited
from app.enrich.providers import PROVIDERS
from app.schemas.alert import Enrichment, NormalizedAlert

log = logging.getLogger("enrich")

BREAKERS = {p.name: CircuitBreaker(p.name) for p in PROVIDERS}
LOOKUP_TIMEOUT = 30.0  # retry-lar daxil, bir sorğu üçün maksimum
RATE_WAIT = 60.0  # token üçün maksimum gözləmə
_inflight: dict[str, asyncio.Future] = {}


async def lookup_one(p: IntelProvider, ioc_type: str, value: str) -> ProviderResult:
    if not p.enabled():
        return p.result(ioc_type, value, "skipped", p.disabled_reason or "API açarı yoxdur")
    hit = await cache.get(p.name, ioc_type, value)
    if hit:
        return hit
    breaker = BREAKERS[p.name]
    if not breaker.allow():
        return p.result(ioc_type, value, "skipped", "circuit open")
    if not await ratelimit.acquire(p.name, p.per_minute, p.per_day, p.burst, max_wait=RATE_WAIT):
        return p.result(ioc_type, value, "rate_limited", "token gözləmə müddəti bitdi")
    t0 = time.monotonic()
    try:
        res = await asyncio.wait_for(p.lookup(ioc_type, value), timeout=LOOKUP_TIMEOUT)
        breaker.success()
    except AuthError as e:
        p.disabled_reason = f"auth: {e}"  # açar özü düzəlməyəcək
        log.critical("%s söndürüldü: %s", p.name, e)
        res = p.result(ioc_type, value, "auth_error", str(e))
    except RateLimited as e:
        res = p.result(ioc_type, value, "rate_limited", str(e))
    except (asyncio.TimeoutError, httpx.TimeoutException):
        breaker.failure()
        res = p.result(ioc_type, value, "timeout")
    except Exception as e:  # noqa: BLE001
        breaker.failure()
        log.warning("%s xəta: %r", p.name, e)
        res = p.result(ioc_type, value, "error", type(e).__name__)
    res.latency_ms = int((time.monotonic() - t0) * 1000)
    await cache.put(res)
    return res


async def _single_flight(p: IntelProvider, ioc_type: str, value: str) -> ProviderResult:
    """Eyni IOC eyni anda iki alert-də gəlsə provider-ə bir sorğu gedir."""
    k = cache.key(p.name, ioc_type, value)
    if k in _inflight:
        return await asyncio.shield(_inflight[k])
    fut = asyncio.get_running_loop().create_future()
    _inflight[k] = fut
    try:
        res = await lookup_one(p, ioc_type, value)
        fut.set_result(res)
        return res
    except Exception as e:
        fut.set_exception(e)
        raise
    finally:
        _inflight.pop(k, None)


async def enrich(alert: NormalizedAlert) -> Enrichment:
    tasks = [
        _single_flight(p, o.type, o.value)
        for o in alert.external_iocs()
        for p in PROVIDERS
        if p.supports(o.type)
    ]
    results = list(await asyncio.gather(*tasks))
    return aggregate(results)
