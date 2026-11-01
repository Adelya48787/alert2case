"""3.6: enrichment servisi və yenidən enrichment. Şəbəkə, Redis və baza yoxdur."""

import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from app.enrich import reenrich, service
from app.enrich.base import IntelProvider, ProviderResult
from app.enrich.breaker import CircuitBreaker
from app.enrich.http import AuthError, RateLimited
from app.schemas.alert import Enrichment, NormalizedAlert, Observable


class Fake(IntelProvider):
    """Davranışı testdən idarə olunan provider."""

    name = "fake"
    supported = frozenset({"ip", "hash_sha256"})
    per_minute, per_day, burst = 60, 1000, 10

    def __init__(self, behaviour=100, key="k") -> None:
        super().__init__()
        self.behaviour, self.key, self.calls = behaviour, key, 0

    def api_key(self) -> str:
        return self.key

    async def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        self.calls += 1
        await asyncio.sleep(0)
        if isinstance(self.behaviour, Exception):
            raise self.behaviour
        return self.ok(ioc_type, value, self.behaviour, {})


@pytest.fixture
def env(monkeypatch):
    """Cache, rate limit və breaker saxtası."""
    state = {"cache": {}, "puts": [], "allow_rate": True}

    async def get(provider, ioc_type, value):
        return state["cache"].get((provider, ioc_type, value))

    async def put(res):
        state["puts"].append(res)

    async def acquire(*a, **kw):
        return state["allow_rate"]

    monkeypatch.setattr(service.cache, "get", get)
    monkeypatch.setattr(service.cache, "put", put)
    monkeypatch.setattr(service.ratelimit, "acquire", acquire)
    monkeypatch.setattr(service, "BREAKERS", {"fake": CircuitBreaker("fake")})
    return state


async def test_no_key_is_skipped(env):
    p = Fake(key="")
    r = await service.lookup_one(p, "ip", "1.2.3.4")
    assert r.status == "skipped" and p.calls == 0


async def test_cache_hit_does_not_call_provider(env):
    p = Fake()
    cached = p.ok("ip", "1.2.3.4", 100, {}).model_copy(update={"cached": True})
    env["cache"][("fake", "ip", "1.2.3.4")] = cached
    r = await service.lookup_one(p, "ip", "1.2.3.4")
    assert r.cached and p.calls == 0


async def test_open_breaker_skips_without_waiting(env):
    for _ in range(5):
        service.BREAKERS["fake"].failure()
    p = Fake()
    r = await service.lookup_one(p, "ip", "1.2.3.4")
    assert (r.status, r.note, p.calls) == ("skipped", "circuit open", 0)


async def test_no_token_is_rate_limited(env):
    env["allow_rate"] = False
    r = await service.lookup_one(Fake(), "ip", "1.2.3.4")
    assert r.status == "rate_limited"


async def test_success_is_cached_and_resets_breaker(env):
    service.BREAKERS["fake"].failure()
    r = await service.lookup_one(Fake(100), "ip", "1.2.3.4")
    assert (r.status, r.score) == ("ok", 100)
    assert env["puts"] == [r]
    assert service.BREAKERS["fake"].failures == 0


async def test_auth_error_disables_provider(env):
    p = Fake(AuthError("fake: HTTP 401"))
    r = await service.lookup_one(p, "ip", "1.2.3.4")
    assert r.status == "auth_error" and not p.enabled()
    assert (await service.lookup_one(p, "ip", "5.6.7.8")).status == "skipped"  # artıq sorğu atılmır
    assert p.calls == 1


@pytest.mark.parametrize(
    "exc,status",
    [(httpx.ReadTimeout("slow"), "timeout"), (asyncio.TimeoutError(), "timeout"), (ValueError("x"), "error")],
)
async def test_failures_become_status_and_count_for_breaker(env, exc, status):
    r = await service.lookup_one(Fake(exc), "ip", "1.2.3.4")
    assert r.status == status and r.score is None
    assert service.BREAKERS["fake"].failures == 1


async def test_rate_limited_by_provider_does_not_open_breaker(env):
    r = await service.lookup_one(Fake(RateLimited(5.0)), "ip", "1.2.3.4")
    assert r.status == "rate_limited" and service.BREAKERS["fake"].failures == 0


async def test_single_flight_one_request_for_same_ioc(env):
    p = Fake(100)
    a, b = await asyncio.gather(
        service._single_flight(p, "ip", "1.2.3.4"), service._single_flight(p, "ip", "1.2.3.4")
    )
    assert a.score == b.score == 100 and p.calls == 1


def alert(*obs: Observable) -> NormalizedAlert:
    now = datetime.now(timezone.utc)
    return NormalizedAlert(
        source_system="edr",
        source_ref="T-1",
        alert_type="malicious_hash",
        title="t",
        time=now,
        received_at=now,
        severity_id=4,
        observables=list(obs),
        raw={},
    )


async def test_enrich_queries_only_external_iocs(env, monkeypatch):
    p = Fake(100)
    monkeypatch.setattr(service, "PROVIDERS", [p])
    a = alert(
        Observable(type="hash_sha256", value="a" * 64, role="artifact"),
        Observable(type="ip", value="10.0.0.5", role="src", internal=True),
        Observable(type="user", value="adile", role="actor"),
    )
    e = await service.enrich(a)
    assert p.calls == 1  # daxili IP və user intel-ə getmir
    assert e.verdict == "malicious" and e.status == "ok"


async def test_all_providers_down_is_failed_unknown(env, monkeypatch):
    monkeypatch.setattr(service, "PROVIDERS", [Fake(ValueError("down"))])
    e = await service.enrich(alert(Observable(type="ip", value="1.2.3.4", role="src")))
    assert (e.status, e.verdict) == ("failed", "unknown")


async def test_reenrich_updates_audits_and_keeps_status(monkeypatch):
    a = alert(Observable(type="ip", value="1.2.3.4", role="src"))
    a.enrichment = Enrichment(status="partial", verdict="unknown")
    calls = {"audit": [], "saved": []}

    async def rows(hours, limit):
        return [{"doc": a.model_dump(mode="json"), "status": "enriched"}]

    async def new_enrich(alert):
        return Enrichment(status="ok", reputation_score=90, confidence=1.0, verdict="malicious")

    async def audit(cid, stage, event, payload=None, actor="system"):
        calls["audit"].append((stage, event, payload))

    async def save(alert, status):
        calls["saved"].append((alert.enrichment.verdict, status))

    monkeypatch.setattr(reenrich.db, "alerts_needing_reenrich", rows)
    monkeypatch.setattr(reenrich.db, "save_alert", save)
    monkeypatch.setattr(reenrich, "enrich", new_enrich)
    monkeypatch.setattr(reenrich, "audit", audit)

    assert await reenrich.run_once() == 1
    stage, event, payload = calls["audit"][0]
    assert (stage, event) == ("enrich", "re_enriched")
    assert (payload["old_verdict"], payload["new_verdict"]) == ("unknown", "malicious")
    assert calls["saved"] == [("malicious", "enriched")]  # alert-in öz statusu dəyişmir
