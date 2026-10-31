"""3.1c: OTX adapteri. Şəbəkəsiz."""

import pytest

from app.config import settings
from app.enrich import providers as prov
from app.enrich.providers import OTX

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture
def fake_get(monkeypatch):
    box = {"data": None, "calls": []}

    async def _get(provider, url, headers, params=None):
        box["calls"].append({"url": url, "headers": headers, "params": params})
        return box["data"]

    monkeypatch.setattr(prov, "get_json", _get)
    return box


def test_supports():
    p = OTX()
    assert all(p.supports(t) for t in ("ip", "domain", "url", "hash_md5", "hash_sha256"))
    assert not p.supports("user")


def test_enabled_depends_on_key(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", "")
    assert not OTX().enabled()
    monkeypatch.setattr(settings, "otx_api_key", "k")
    assert OTX().enabled()


@pytest.mark.parametrize(
    "pulses,score,verdict", [(0, 0, "clean"), (2, 20, "clean"), (5, 50, "suspicious"), (50, 60, "suspicious")]
)
async def test_score_capped_at_60(fake_get, pulses, score, verdict):
    fake_get["data"] = {"pulse_info": {"count": pulses}}
    r = await OTX().lookup("ip", "1.0.0.1")
    assert r.score == score and r.verdict == verdict and r.evidence == {"pulses": pulses}


async def test_never_malicious_alone(fake_get):
    fake_get["data"] = {"pulse_info": {"count": 1000}}
    assert (await OTX().lookup("ip", "1.0.0.1")).verdict != "malicious"


@pytest.mark.parametrize(
    "ioc_type,value,section",
    [
        ("ip", "1.1.1.1", "/indicators/IPv4/1.1.1.1/general"),
        ("ip", "2001:db8::1", "/indicators/IPv6/2001%3Adb8%3A%3A1/general"),
        ("domain", "example.com", "/indicators/domain/example.com/general"),
        ("hash_sha256", EICAR, f"/indicators/file/{EICAR}/general"),
        ("url", "http://a.b/c?d=1", "/indicators/url/http%3A%2F%2Fa.b%2Fc%3Fd%3D1/general"),
    ],
)
async def test_url_building(fake_get, ioc_type, value, section):
    fake_get["data"] = {"pulse_info": {"count": 0}}
    await OTX().lookup(ioc_type, value)
    c = fake_get["calls"][0]
    assert c["url"].endswith(section) and "X-OTX-API-KEY" in c["headers"]


async def test_missing_pulse_info_is_zero(fake_get):
    fake_get["data"] = {}
    assert (await OTX().lookup("domain", "x.example")).score == 0


async def test_not_found(fake_get):
    r = await OTX().lookup("domain", "x.example")
    assert r.status == "not_found" and r.score is None


def test_registered():
    assert "otx" in [p.name for p in prov.PROVIDERS]
