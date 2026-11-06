"""Uçdan-uca test (6.4): işləyən stekə (api + worker + postgres + redis) real alert göndərir
və layihənin əsas invariantlarını real bazada yoxlayır.

    make reset-data && make e2e          # və ya: E2E=1 pytest -q tests/e2e

Stek qalxmış olmalıdır (dev: make up; prod: make up-prod). Unit testlərdən fərqli olaraq
Redis, PostgreSQL, worker və intel mənbələri realdır. E2E=1 olmadan testlər atlanır (CI-da da).

Bazaya host-dan qoşulur: E2E_DATABASE_URL və ya .env-dəki POSTGRES_PASSWORD ilə localhost:5432.
Tətbiqin app.db modulundan istifadə etmir: .env-dəki DATABASE_URL container üçündür (host "postgres").
Sirlər yalnız .env-dən oxunur və heç yerdə çap olunmur.
"""

import asyncio
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import asyncpg
import httpx
import pytest
import pytest_asyncio
from dotenv import dotenv_values

from app.audit.log import GENESIS, row_hash
from app.db import _init as jsonb_codec  # tətbiqlə eyni jsonb codec: audit hash-ı eyni hesablansın

pytestmark = [
    pytest.mark.skipif(os.environ.get("E2E") != "1", reason="E2E=1 olmadan işləmir"),
    pytest.mark.asyncio(loop_scope="module"),  # baza pool-u bütün testlər üçün bir event loop-da
]

API = os.environ.get("E2E_API", "http://localhost:8000")
SAMPLE = ["HASH-01", "HASH-02", "URL-01", "URL-03", "LOGIN-01", "LOGIN-09"]
TIMEOUT_S = int(os.environ.get("E2E_TIMEOUT", "600"))
FINAL = ("case_created", "case_pending", "closed_auto")
STAGES = ("ingest", "normalize", "enrich", "decide", "act", "notify")

# tests/conftest.py unit testlər üçün saxta secret qoyur; e2e isə işləyən API-nin real .env dəyərləri ilə işləyir
ENV = dotenv_values(".env")
SECRET = ENV.get("WEBHOOK_HMAC_SECRET") or ""
ADMIN = ENV.get("ADMIN_TOKEN") or ""
DSN = os.environ.get("E2E_DATABASE_URL") or (
    f"postgresql://soc:{ENV.get('POSTGRES_PASSWORD') or ''}@localhost:5432/alert2case"
)


def send(name: str) -> datetime:
    """Dataset alert-ini imzalı göndərir, API-nin qəbul anını qaytarır."""
    doc = json.loads((Path("dataset/raw") / f"{name}.json").read_text(encoding="utf-8"))
    body = json.dumps(doc["payload"], separators=(",", ":")).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    r = httpx.post(
        f"{API}/ingest/{doc['source']}",
        content=body,
        timeout=10,
        headers={"Content-Type": "application/json", "X-Signature": sig},
    )
    assert r.status_code == 202, f"{name}: {r.status_code} {r.text[:200]}"
    return datetime.fromisoformat(r.json()["received_at"])


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pg():
    if not SECRET or not ADMIN:
        pytest.fail(".env-də WEBHOOK_HMAC_SECRET və ya ADMIN_TOKEN boşdur")
    try:
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2, init=jsonb_codec)
    except (OSError, asyncpg.PostgresError) as e:
        pytest.fail(
            f"Bazaya qoşulmaq olmadı ({type(e).__name__}): stek qalxıbmı (make up), .env-də POSTGRES_PASSWORD düzgündürmü? Lazım olsa E2E_DATABASE_URL verin"
        )
    yield pool
    await pool.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def run(pg):
    # Nümunə alert-ləri son 15 dəqiqədə göndərilibsə, dublikat sayılar və yeni sətir yaranmaz
    recent = await pg.fetchval(
        "SELECT count(*) FROM alerts WHERE source_ref = ANY($1) AND last_seen > now() - interval '15 minutes'",
        SAMPLE,
    )
    if recent:
        pytest.fail(f"{recent} nümunə alert son 15 dəqiqədə göndərilib (dedup): əvvəlcə make reset-data")
    since = send(SAMPLE[0]) - timedelta(seconds=1)
    for name in SAMPLE[1:]:
        send(name)
    return since


async def wait_done(pg, since: datetime) -> list[dict]:
    """Nümunənin bütün alert-ləri son vəziyyətə çatana qədər bazanı yoxlayır (polling)."""
    deadline = time.monotonic() + TIMEOUT_S
    rows: list = []
    while time.monotonic() < deadline:
        rows = await pg.fetch(
            """SELECT a.alert_id, a.source_ref, a.status, d.verdict, d.action, d.shadow
               FROM alerts a LEFT JOIN decisions d USING (alert_id)
               WHERE a.received_at >= $1 AND a.source_ref = ANY($2)""",
            since,
            SAMPLE,
        )
        if len(rows) >= len(SAMPLE) and all(r["status"] in FINAL for r in rows):
            return [dict(r) for r in rows]
        await asyncio.sleep(3)
    stuck = sorted(f"{r['source_ref']}={r['status']}" for r in rows if r["status"] not in FINAL)
    if not rows:
        pytest.fail(
            f"{TIMEOUT_S} s-də heç bir alert bazaya yazılmadı: worker işləyirmi? docker compose ps worker"
        )
    pytest.fail(f"{TIMEOUT_S} s-də emal bitmədi: {len(rows)}/{len(SAMPLE)} alert, ilişən: {stuck}")


async def test_every_alert_reaches_a_final_state(pg, run):
    rows = await wait_done(pg, run)
    assert {r["source_ref"] for r in rows} == set(SAMPLE)
    assert all(r["verdict"] for r in rows), "qərarsız alert var"


async def test_malicious_never_closed(pg, run):
    rows = await wait_done(pg, run)
    assert not [r for r in rows if r["verdict"] == "malicious" and r["status"] == "closed_auto"]


async def test_case_or_pending_for_every_create_case(pg, run):
    rows = await wait_done(pg, run)
    for r in rows:
        if r["action"] == "create_case":
            assert r["status"] in ("case_created", "case_pending"), r


async def test_duplicate_is_merged(pg, run):
    await wait_done(pg, run)
    q = "SELECT occurrence_count FROM alerts WHERE source_ref = 'HASH-01' ORDER BY received_at DESC LIMIT 1"
    before = await pg.fetchval(q)
    send("HASH-01")
    after = before
    for _ in range(10):  # worker dublikatı bir neçə saniyəyə emal edir
        await asyncio.sleep(2)
        after = await pg.fetchval(q)
        if after == before + 1:
            break
    assert after == before + 1


async def test_timeline_has_all_stages(pg, run):
    rows = await wait_done(pg, run)
    alert_id = next(r["alert_id"] for r in rows if r["source_ref"] == "HASH-01")
    r = httpx.get(f"{API}/alerts/{alert_id}/timeline", headers={"X-Admin-Token": ADMIN}, timeout=10)
    assert r.status_code == 200, r.status_code
    stages = {e["stage"] for e in r.json()}
    assert set(STAGES) <= stages, f"çatışmır: {set(STAGES) - stages}"


async def test_bad_signature_rejected():
    r = httpx.post(
        f"{API}/ingest/edr", content=b"{}", headers={"X-Signature": "sha256=" + "0" * 64}, timeout=10
    )
    assert r.status_code == 401


async def test_dlq_empty_and_audit_chain_intact(pg, run):
    await wait_done(pg, run)
    r = httpx.get(f"{API}/dlq", headers={"X-Admin-Token": ADMIN}, timeout=10)
    assert r.status_code == 200 and r.json() == [], "DLQ boş deyil"
    # tools.verify_audit ilə eyni yoxlama: hər sətir əvvəlkinin hash-ını saxlayır, öz hash-ı yenidən hesablanır
    prev = GENESIS
    for row in await pg.fetch("SELECT * FROM audit_log ORDER BY id"):
        assert row["prev_hash"] == prev, f"zəncir qırılıb: id={row['id']}"
        expected = row_hash(
            prev, row["ts"], row["correlation_id"], row["stage"], row["event"], row["actor"], row["payload"]
        )
        assert row["row_hash"] == expected, f"sətir dəyişdirilib: id={row['id']}"
        prev = row["row_hash"]
