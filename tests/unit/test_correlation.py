"""T5.4: korrelyasiya qaydaları C1–C4 (app/correlation/engine.py). Redis yaddaşdadır (fakeredis)."""

import fakeredis
import pytest

from app import queue
from app.case.base import CaseRef
from app.correlation import engine as corr
from app.rules.engine import decide
from app.schemas.alert import Observable
from tests.unit.factories import make


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    monkeypatch.setattr(queue, "_client", fakeredis.FakeAsyncRedis(decode_responses=True))
    events = []

    async def audit(cid, stage, event, payload=None, actor="system"):
        events.append((stage, event))

    monkeypatch.setattr(corr, "audit", audit)
    corr.load_cfg.cache_clear()
    return events


def decided(**kw):
    a = make(**kw)
    a.decision = decide(a)
    return a


def ref(cid):
    return CaseRef(backend="file", case_id=cid, url=f"/{cid}")


async def test_c1_same_ioc_links_to_existing_case(fake_redis):
    first = decided(alert_type="suspicious_url", verdict="malicious", score=80)
    await corr.index_case(first, ref("C-1"))
    second = decided(alert_type="suspicious_url", verdict="malicious", score=80, user="elvin")
    linked = await corr.correlate(second)
    assert linked and linked.case_id == "C-1"
    assert "C1" in second.decision.reasons[-1] and ("correlate", "same_ioc") in fake_redis


async def test_c1_forces_case_even_if_rule_says_close():
    first = decided(alert_type="suspicious_url", verdict="malicious", score=80)
    await corr.index_case(first, ref("C-1b"))
    clean = decided(alert_type="suspicious_url", verdict="clean", score=0)
    assert clean.decision.action == "auto_close"
    await corr.correlate(clean)
    assert clean.decision.action == "create_case"  # IOC araşdırılır, səssiz bağlanmır


async def test_c2_same_user_other_type_bumps_severity():
    login = decided(alert_type="suspicious_login", verdict="suspicious", score=40, user="adile")
    await corr.index_case(login, ref("C-2"))
    h = decided(verdict="suspicious", score=40, user="adile")
    before = int(h.decision.severity_id)
    assert await corr.correlate(h) is None
    assert int(h.decision.severity_id) == before + 1 and "C-2" in h.context["related_cases"]


async def test_c2_same_type_is_not_bumped():
    first = decided(verdict="suspicious", score=40, user="teymur", host="WS-1")
    await corr.index_case(first, ref("C-2b"))
    other = decided(
        verdict="suspicious",
        score=40,
        user="teymur",
        host="WS-2",
        ioc=Observable(type="hash_sha256", value="c" * 64),
    )
    before = int(other.decision.severity_id)
    await corr.correlate(other)
    assert int(other.decision.severity_id) == before and other.context["related_cases"] == []


async def test_c3_hash_and_url_on_same_host_is_p1():
    url = decided(alert_type="suspicious_url", verdict="suspicious", score=40, host="WS-099", user="u1")
    await corr.index_case(url, ref("C-3"))
    h = decided(
        verdict="suspicious",
        score=40,
        host="WS-099",
        user="u2",
        ioc=Observable(type="hash_sha256", value="b" * 64),
    )
    await corr.correlate(h)
    assert h.decision.priority == "P1" and "C3" in h.decision.reasons[-1]


async def test_c3_clean_url_does_not_start_chain():
    url = decided(alert_type="suspicious_url", verdict="clean", score=0, host="WS-098", user="u1")
    await corr.index_case(url, ref("C-3b"))
    h = decided(
        verdict="suspicious",
        score=40,
        host="WS-098",
        user="u2",
        ioc=Observable(type="hash_sha256", value="d" * 64),
    )
    await corr.correlate(h)
    assert h.decision.priority != "P1"


async def test_c4_bruteforce_campaign_then_link():
    refs = []
    for i in range(6):
        a = decided(
            alert_type="suspicious_login",
            verdict="suspicious",
            score=40,
            user=f"user{i}",
            ioc=Observable(type="ip", value=f"203.0.113.{10 + i}"),
        )
        r = await corr.correlate(a)
        if a.context.get("campaign_subnet"):
            assert a.context["campaign_subnet"] == "203.0.113.0/24" and int(a.decision.severity_id) >= 4
            await corr.index_case(a, ref("CAMP-1"))
        refs.append(r)
    assert refs[:5] == [None] * 5 and refs[5].case_id == "CAMP-1"


async def test_c4_other_subnet_not_linked():
    for i in range(5):
        a = decided(
            alert_type="suspicious_login",
            verdict="suspicious",
            score=40,
            user=f"x{i}",
            ioc=Observable(type="ip", value=f"198.51.100.{i + 1}"),
        )
        await corr.correlate(a)
    other = decided(
        alert_type="suspicious_login",
        verdict="suspicious",
        score=40,
        user="y",
        ioc=Observable(type="ip", value="192.0.2.7"),
    )
    assert await corr.correlate(other) is None and "campaign_subnet" not in other.context


async def test_old_cases_not_correlated():
    first = decided(alert_type="suspicious_url", verdict="malicious", score=80)
    await corr.index_case(first, ref("OLD"))
    await queue.get_redis().hset(corr.case_key("OLD"), "created", "2020-01-01T00:00:00+00:00")
    assert await corr.correlate(decided(alert_type="suspicious_url", verdict="malicious", score=80)) is None


async def test_internal_ioc_never_correlates():
    a = decided(
        alert_type="suspicious_login",
        verdict="suspicious",
        score=40,
        ioc=Observable(type="ip", value="10.0.4.21", internal=True),
    )
    await corr.index_case(a, ref("INT"))
    b = decided(
        alert_type="suspicious_login",
        verdict="suspicious",
        score=40,
        user="other",
        ioc=Observable(type="ip", value="10.0.4.21", internal=True),
    )
    assert await corr.correlate(b) is None


async def test_index_keys_hide_raw_values():
    a = decided(alert_type="suspicious_url", verdict="malicious", score=80, user="elcin.admin")
    await corr.index_case(a, ref("C-H"))
    keys = [k async for k in queue.get_redis().scan_iter("corr:*")]
    assert keys and not any("elcin" in k or "example" in k for k in keys)


async def test_disabled_rules_do_nothing(monkeypatch):
    cfg = corr.load_cfg()
    off = {**cfg, "rules": {k: {**v, "enabled": False} for k, v in cfg["rules"].items()}}
    monkeypatch.setattr(corr, "load_cfg", lambda: off)
    first = decided(alert_type="suspicious_url", verdict="malicious", score=80)
    await corr.index_case(first, ref("C-OFF"))
    second = decided(alert_type="suspicious_url", verdict="malicious", score=80)
    assert await corr.correlate(second) is None
