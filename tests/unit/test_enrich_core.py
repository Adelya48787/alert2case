"""3.1a: provider interfeysi, ortaq HTTP client və VirusTotal adapteri. Şəbəkəsiz."""

import httpx
import pytest

from app.config import settings
from app.enrich import http
from app.enrich import providers as prov
from app.enrich.base import score_to_verdict
from app.enrich.providers import VirusTotal

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture
def fake_get(monkeypatch):
    """get_json-u saxtası ilə əvəz edir: real API-yə sorğu getmir."""
    box = {"data": None, "calls": []}

    async def _get(provider, url, headers, params=None):
        box["calls"].append({"url": url, "headers": headers, "params": params})
        return box["data"]

    monkeypatch.setattr(prov, "get_json", _get)
    return box


@pytest.mark.parametrize(
    "score,verdict",
    [
        (0, "clean"),
        (29, "clean"),
        (30, "suspicious"),
        (69, "suspicious"),
        (70, "malicious"),
        (100, "malicious"),
    ],
)
def test_score_to_verdict(score, verdict):
    assert score_to_verdict(score) == verdict


def test_ok_clamps_score_and_sets_verdict():
    r = VirusTotal().ok("ip", "1.2.3.4", 250, {"x": 1})
    assert r.status == "ok" and r.score == 100 and r.verdict == "malicious"
    assert VirusTotal().ok("ip", "1.2.3.4", -5, {}).score == 0


def test_result_has_no_score():
    r = VirusTotal().result("ip", "1.2.3.4", "timeout", "yavaş")
    assert r.status == "timeout" and r.score is None and r.verdict == "unknown" and r.note == "yavaş"


def test_enabled_depends_on_key(monkeypatch):
    p = VirusTotal()
    monkeypatch.setattr(settings, "vt_api_key", "")
    assert not p.enabled()
    monkeypatch.setattr(settings, "vt_api_key", "k")
    assert p.enabled()
    p.disabled_reason = "auth_error"
    assert not p.enabled()


def test_vt_supports():
    vt = VirusTotal()
    assert all(vt.supports(t) for t in ("ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"))
    assert not vt.supports("user")


@pytest.mark.parametrize(
    "ioc_type,value,path",
    [
        ("hash_sha256", EICAR, f"/files/{EICAR}"),
        ("domain", "example.com", "/domains/example.com"),
        ("ip", "8.8.8.8", "/ip_addresses/8.8.8.8"),
        ("url", "http://a.b/c", "/urls/aHR0cDovL2EuYi9j"),
    ],
)
def test_vt_path(ioc_type, value, path):
    assert VirusTotal.path(ioc_type, value) == path


async def test_vt_scores_engines(fake_get):
    fake_get["data"] = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "undetected": 70}}}
    }
    r = await VirusTotal().lookup("hash_sha256", EICAR)
    assert r.score == 50 and r.verdict == "suspicious"
    assert r.evidence == {"malicious": 2, "suspicious": 1, "engines": 73}
    assert "x-apikey" in fake_get["calls"][0]["headers"]


async def test_vt_many_engines_is_100(fake_get):
    fake_get["data"] = {"data": {"attributes": {"last_analysis_stats": {"malicious": 66}}}}
    r = await VirusTotal().lookup("hash_sha256", EICAR)
    assert r.score == 100 and r.verdict == "malicious"


async def test_vt_not_found(fake_get):
    r = await VirusTotal().lookup("hash_sha256", "0" * 64)
    assert r.status == "not_found" and r.score is None


def test_vt_registered():
    assert "virustotal" in [p.name for p in prov.PROVIDERS]


@pytest.fixture
def mock_http(monkeypatch):
    """Real şəbəkə əvəzinə ardıcıl cavablar qaytaran saxta transport. Retry fasiləsi 0."""
    box = {"responses": [], "seen": 0}

    def handler(request):
        box["seen"] += 1
        return box["responses"].pop(0)

    monkeypatch.setattr(http, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(http, "_backoff", lambda state: 0)
    return box


async def test_http_200(mock_http):
    mock_http["responses"] = [httpx.Response(200, json={"a": 1})]
    assert await http.get_json("t", "http://x/", {}) == {"a": 1}


async def test_http_404_returns_none_without_retry(mock_http):
    mock_http["responses"] = [httpx.Response(404)]
    assert await http.get_json("t", "http://x/", {}) is None and mock_http["seen"] == 1


@pytest.mark.parametrize("code", [401, 403])
async def test_http_auth_error_not_retried(mock_http, code):
    mock_http["responses"] = [httpx.Response(code)]
    with pytest.raises(http.AuthError):
        await http.get_json("t", "http://x/", {})
    assert mock_http["seen"] == 1


async def test_http_5xx_retried_then_ok(mock_http):
    mock_http["responses"] = [httpx.Response(503), httpx.Response(200, json={"ok": True})]
    assert await http.get_json("t", "http://x/", {}) == {"ok": True} and mock_http["seen"] == 2


async def test_http_5xx_gives_up_after_3(mock_http):
    mock_http["responses"] = [httpx.Response(500)] * 3
    with pytest.raises(http.ServerError):
        await http.get_json("t", "http://x/", {})
    assert mock_http["seen"] == http.ATTEMPTS


async def test_http_429_uses_retry_after(mock_http):
    mock_http["responses"] = [httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json={})]
    assert await http.get_json("t", "http://x/", {}) == {} and mock_http["seen"] == 2


async def test_http_429_without_header(mock_http):
    mock_http["responses"] = [httpx.Response(429)] * 3
    with pytest.raises(http.RateLimited) as e:
        await http.get_json("t", "http://x/", {})
    assert e.value.retry_after is None


async def test_http_unexpected_status(mock_http):
    mock_http["responses"] = [httpx.Response(418)]
    with pytest.raises(http.ProviderError):
        await http.get_json("t", "http://x/", {})


def test_client_is_reused(monkeypatch):
    monkeypatch.setattr(http, "_client", None)
    assert http.client() is http.client()
