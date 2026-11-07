"""Analitik paneli: giriş, API forması, təhlükəsizlik başlıqları və XSS qoruması."""

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app import main
from app.panel import queries

ADMIN = {"X-Admin-Token": "test-admin"}
STATIC = Path("app/panel/static")


@pytest.fixture
def client(monkeypatch):
    calls = {}

    async def fake_list(view, limit, filters=None):
        calls["list"] = (view, limit)
        calls["filters"] = filters
        return [{"alert_id": "a1", "priority": "P1", "verdict": "malicious", "title": "hxxp://bad[.]example"}]

    async def fake_stats():
        return {"open": 3, "reviewed": 1, "would_close": 1, "agree": 1}

    async def fake_detail(alert_id):
        return None

    monkeypatch.setattr(queries, "list_alerts", fake_list)
    monkeypatch.setattr(queries, "stats", fake_stats)
    monkeypatch.setattr(queries, "detail", fake_detail)
    c = TestClient(main.app)
    c.calls = calls
    return c


@pytest.mark.parametrize(
    "path",
    [
        "/api/panel/alerts",
        "/api/panel/stats",
        f"/api/panel/alerts/{uuid4()}",
        "/api/panel/health",
        "/api/panel/rules",
    ],
)
@pytest.mark.parametrize("headers", [{}, {"X-Admin-Token": "wrong"}])
def test_api_requires_admin_token(client, path, headers):
    assert client.get(path, headers=headers).status_code == 403


def test_list_and_stats(client):
    r = client.get("/api/panel/alerts?view=reviewed&limit=20", headers=ADMIN)
    assert r.status_code == 200 and r.json()[0]["priority"] == "P1"
    assert client.calls["list"] == ("reviewed", 20)
    assert client.get("/api/panel/stats", headers=ADMIN).json()["open"] == 3


def test_unknown_view_rejected(client):
    assert client.get("/api/panel/alerts?view=drop", headers=ADMIN).status_code == 400


@pytest.mark.parametrize(
    "query",
    ["priority=P9", "alert_type=x';drop table alerts;--", "verdict=evil", "q=" + "a" * 101],
)
def test_bad_filters_rejected(client, query):
    """Filtr dəyərləri bağlı siyahıdan kənara çıxa bilməz, axtarış mətni 100 simvolla məhduddur."""
    assert client.get(f"/api/panel/alerts?{query}", headers=ADMIN).status_code in (400, 422)


def test_filters_passed_through(client):
    r = client.get(
        "/api/panel/alerts?priority=P1&alert_type=suspicious_url&verdict=malicious&q=duckdns",
        headers=ADMIN,
    )
    assert r.status_code == 200
    assert client.calls["filters"] == {
        "priority": "P1",
        "alert_type": "suspicious_url",
        "verdict": "malicious",
        "q": "duckdns",
    }


@pytest.mark.parametrize(
    "q, expected",
    [
        (None, None),
        ("   ", None),
        ("hxxps://bad[.]example", "%https://bad.example%"),
        ("50%_off\\", "%50\\%\\_off\\\\%"),
    ],
)
def test_search_pattern_refangs_and_escapes(q, expected):
    """Analitik defang formanı yapışdıra bilər; LIKE simvolları literal axtarılır."""
    assert queries.search_pattern(q) == expected


def test_missing_alert_404(client):
    assert client.get(f"/api/panel/alerts/{uuid4()}", headers=ADMIN).status_code == 404


@pytest.mark.parametrize("path", ["/panel/", "/panel/app.js", "/panel/style.css"])
def test_static_served_with_security_headers(client, path):
    r = client.get(path)
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_static_has_no_secrets_or_inline_code():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "<script>" not in html and "style=" not in html  # CSP inline-ı bloklayır
    assert (
        ".innerHTML" not in js and "insertAdjacentHTML" not in js
    )  # alert mətni xarici mənbədəndir: yalnız textContent
    assert "localStorage" not in js  # token sekmə bağlananda silinməlidir


def test_detail_defangs_iocs(monkeypatch):
    """detail() IOC-ları və başlığı defang edir: panelin heç yerində kliklənən zərərli link olmur."""
    import asyncio

    from app import db

    doc = {
        "title": "Suspicious URL http://evil.example/x",
        "observables": [
            {"type": "url", "value": "http://evil.example/x"},
            {"type": "domain", "value": "evil.example"},
        ],
        "enrichment": {
            "status": "ok",
            "providers": [
                {
                    "provider": "virustotal",
                    "ioc_type": "url",
                    "status": "ok",
                    "score": 0,
                    "evidence": {"x": 1},
                }
            ],
        },
    }

    class FakePool:
        async def fetchrow(self, q, *a):
            if "FROM alerts" in q:
                return {
                    "alert_id": a[0],
                    "source_ref": "URL-01",
                    "alert_type": "suspicious_url",
                    "status": "case_created",
                    "received_at": None,
                    "occurrence_count": 1,
                    "doc": doc,
                }
            return None

        async def fetch(self, q, *a):
            return []

    async def fake_pool():
        return FakePool()

    async def fake_timeline(alert_id):
        return []

    monkeypatch.setattr(db, "pool", fake_pool)
    monkeypatch.setattr(db, "timeline", fake_timeline)
    d = asyncio.run(queries.detail(uuid4()))
    assert "http://" not in d["title"] and "evil.example" not in d["title"]
    assert all("evil.example" not in o["value"] for o in d["observables"])
    assert "evidence" not in d["enrichment"]["providers"][0]  # xam intel cavabı panelə çıxmır


@pytest.mark.parametrize(
    "counts, expected",
    [
        ({}, "idle"),
        ({"cached": 4}, "idle"),
        ({"ok": 10}, "ok"),
        ({"ok": 6, "rate_limited": 4}, "degraded"),
        ({"error": 5}, "down"),
        ({"not_found": 3, "error": 1}, "ok"),
        ({"circuit_open": 6, "error": 5}, "down"),
        ({"ok": 2, "circuit_open": 4}, "degraded"),
    ],
)
def test_provider_state(counts, expected):
    assert queries.provider_state(counts) == expected


def test_case_link_only_for_thehive_internal_url(monkeypatch):
    """Brauzer üçün link yalnız TheHive case-inə və gözlənilən daxili ünvana görə qurulur."""
    from app.config import settings

    monkeypatch.setattr(settings, "thehive_url", "http://thehive:9000")
    monkeypatch.setattr(settings, "thehive_public_url", "http://localhost:9000")
    th = {"backend": "thehive", "case_url": "http://thehive:9000/cases/~123/details"}
    assert queries.case_link(th) == "http://localhost:9000/cases/~123/details"
    assert queries.case_link(None) is None
    assert queries.case_link({"backend": "file", "case_url": "var/cases/FILE-1.json"}) is None
    evil = {"backend": "thehive", "case_url": "javascript:alert(1)"}
    assert queries.case_link(evil) is None
    other = {"backend": "thehive", "case_url": "http://thehive:9000.evil.example/x"}
    assert queries.case_link(other) is None


def test_health_reports_no_secrets(monkeypatch):
    """Health cavabında yalnız "açar var/yox" olur, açarın özü və ya URL olmur."""
    import asyncio

    from app.config import settings
    from app.panel import health

    monkeypatch.setattr(settings, "vt_api_key", "SECRET-VT-KEY-123")

    async def fake_recent():
        return {"virustotal": {"hour": {"ok": 3, "cached": 1}, "recent": {"ok": 1}}}

    async def fake_shadow():
        return {"shadow": 2, "decided": 5}

    async def fake_queue():
        return {"available": True, "alerts_dlq": 0, "cases_dlq": 0, "pending": 0, "lag": 0}

    async def fake_quotas():
        return {"virustotal": 7, "abuseipdb": 0, "otx": 0}

    monkeypatch.setattr(queries, "intel_recent", fake_recent)
    monkeypatch.setattr(queries, "shadow_24h", fake_shadow)
    monkeypatch.setattr(health, "_queue", fake_queue)
    monkeypatch.setattr(health, "_quotas", fake_quotas)
    h = asyncio.run(health.snapshot())
    vt = next(p for p in h["providers"] if p["provider"] == "virustotal")
    assert vt["configured"] is True and vt["state"] == "ok" and vt["quota_used"] == 7
    assert "SECRET-VT-KEY-123" not in str(h)
    assert "base_url" not in str(h) and "http" not in str(h)
