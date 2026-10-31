"""3.1b: AbuseIPDB adapteri. Şəbəkəsiz."""

import pytest

from app.config import settings
from app.enrich import providers as prov
from app.enrich.providers import AbuseIPDB


@pytest.fixture
def fake_get(monkeypatch):
    box = {"data": None, "calls": []}

    async def _get(provider, url, headers, params=None):
        box["calls"].append({"url": url, "headers": headers, "params": params})
        return box["data"]

    monkeypatch.setattr(prov, "get_json", _get)
    return box


def test_supports_only_ip():
    p = AbuseIPDB()
    assert p.supports("ip") and not p.supports("hash_sha256") and not p.supports("url")


def test_enabled_depends_on_key(monkeypatch):
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    assert not AbuseIPDB().enabled()
    monkeypatch.setattr(settings, "abuseipdb_api_key", "k")
    assert AbuseIPDB().enabled()


async def test_score_evidence_and_request(fake_get):
    fake_get["data"] = {
        "data": {
            "abuseConfidenceScore": 100,
            "totalReports": 15922,
            "isWhitelisted": False,
            "isTor": False,
            "countryCode": "BG",
        }
    }
    r = await AbuseIPDB().lookup("ip", "78.128.114.174")
    assert r.score == 100 and r.verdict == "malicious"
    assert r.evidence == {
        "confidence": 100,
        "reports": 15922,
        "whitelisted": False,
        "tor": False,
        "country": "BG",
    }
    c = fake_get["calls"][0]
    assert c["url"].endswith("/check")
    assert c["params"] == {"ipAddress": "78.128.114.174", "maxAgeInDays": 90}
    assert "Key" in c["headers"] and c["headers"]["Accept"] == "application/json"


@pytest.mark.parametrize("conf,verdict", [(0, "clean"), (23, "clean"), (50, "suspicious")])
async def test_verdict_by_confidence(fake_get, conf, verdict):
    fake_get["data"] = {"data": {"abuseConfidenceScore": conf, "isWhitelisted": False}}
    assert (await AbuseIPDB().lookup("ip", "1.2.3.4")).verdict == verdict


async def test_whitelisted_is_zero(fake_get):
    fake_get["data"] = {"data": {"abuseConfidenceScore": 80, "isWhitelisted": True}}
    r = await AbuseIPDB().lookup("ip", "8.8.8.8")
    assert r.score == 0 and r.verdict == "clean"


async def test_not_found(fake_get):
    r = await AbuseIPDB().lookup("ip", "8.8.8.8")
    assert r.status == "not_found" and r.score is None


def test_registered():
    assert "abuseipdb" in [p.name for p in prov.PROVIDERS]
