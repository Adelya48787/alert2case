"""Pipeline-ın mərhələləri birlikdə: baza, audit və intel saxtalaşdırılır."""

import json
from datetime import datetime, timezone
from uuid import uuid4

import fakeredis
import pytest

from app import db, pipeline, queue
from app.audit.log import GENESIS, row_hash
from app.case import file_backend
from app.config import settings
from app.errors import PermanentError
from app.schemas.alert import Enrichment

AUDIT: list[tuple] = []
CASES: dict[str, dict] = {}


@pytest.fixture(autouse=True)
def fakes(monkeypatch, tmp_path):
    AUDIT.clear()
    CASES.clear()
    monkeypatch.setattr(queue, "_client", fakeredis.FakeAsyncRedis(decode_responses=True))
    monkeypatch.setattr(file_backend, "CASE_DIR", tmp_path)
    monkeypatch.setattr(settings, "case_backend", "file")
    monkeypatch.setattr(settings, "shadow_mode", False)
    monkeypatch.setattr(settings, "auto_close_enabled", True)
    monkeypatch.setattr(settings, "slack_webhook_url", "")
    monkeypatch.setattr(pipeline, "QA_SAMPLE_RATE", 0.0)

    async def audit(cid, stage, event, payload=None, actor="system"):
        AUDIT.append((stage, event))

    async def upsert(a, w):
        return a.alert_id, False

    async def save_case(a, ref):
        CASES[a.fingerprint] = {"backend": ref.backend, "case_id": ref.case_id, "url": ref.url}

    async def find_case(fp, hours=24):
        return CASES.get(fp)

    async def noop(*a, **k):
        return None

    for mod in (pipeline, __import__("app.correlation.engine", fromlist=["x"])):
        monkeypatch.setattr(mod, "audit", audit)
    monkeypatch.setattr(db, "upsert_alert", upsert)
    monkeypatch.setattr(db, "save_case", save_case)
    monkeypatch.setattr(db, "find_recent_case", find_case)
    for name in ("save_alert", "save_decision", "save_link"):
        monkeypatch.setattr(db, name, noop, raising=False)

    async def no_mail(subject, text):
        return None

    monkeypatch.setattr("app.notify.service._email", no_mail)


def fake_enrich(verdict, score, status="ok"):
    async def _enrich(alert):
        return Enrichment(status=status, verdict=verdict, reputation_score=score, confidence=1.0)

    return _enrich


async def run(raw_doc, name, monkeypatch, verdict, score, status="ok"):
    monkeypatch.setattr(pipeline, "enrich", fake_enrich(verdict, score, status))
    doc = raw_doc(name)
    await pipeline.process(doc["source"], json.dumps(doc["payload"]), datetime.now(timezone.utc))


async def test_malicious_hash_creates_case_and_notifies(raw_doc, monkeypatch):
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    stages = [s for s, _ in AUDIT]
    assert stages == ["ingest", "normalize", "enrich", "decide", "act", "notify"]
    assert ("act", "case_created") in AUDIT and ("notify", "sent") in AUDIT


async def test_clean_alert_closed_without_case(raw_doc, monkeypatch):
    await run(raw_doc, "URL-03", monkeypatch, "clean", 1)
    assert ("act", "closed_auto") in AUDIT and not CASES


async def test_failed_enrichment_never_closed(raw_doc, monkeypatch):
    await run(raw_doc, "URL-04", monkeypatch, "unknown", None, status="failed")
    assert ("decide", "create_case") in AUDIT and ("act", "case_created") in AUDIT


async def test_same_fingerprint_reuses_case(raw_doc, monkeypatch):
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    first = dict(CASES)
    AUDIT.clear()
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    assert CASES == first


async def test_case_backend_down_goes_to_case_dlq(raw_doc, monkeypatch):
    from app.case.base import CaseError

    async def boom(self, a, d):
        raise CaseError("TheHive down")

    monkeypatch.setattr(file_backend.FileBackend, "create", boom)
    await run(raw_doc, "HASH-03", monkeypatch, "malicious", 89)
    assert ("act", "case_failed") in AUDIT
    assert await queue.get_redis().xlen(pipeline.CASES_DLQ) == 1


async def test_duplicate_is_not_processed_again(raw_doc, monkeypatch):
    async def dup(a, w):
        return a.alert_id, True

    monkeypatch.setattr(db, "upsert_alert", dup)
    doc = raw_doc("HASH-01")
    await pipeline.process(doc["source"], json.dumps(doc["payload"]), datetime.now(timezone.utc))
    assert AUDIT == [("normalize", "duplicate")]


async def test_non_json_is_permanent():
    with pytest.raises(PermanentError, match="JSON deyil"):
        await pipeline.process("edr", "not-json", datetime.now(timezone.utc))
    assert AUDIT == []


def test_audit_chain_detects_tampering(now):
    cid = uuid4()
    h1 = row_hash(GENESIS, now, cid, "ingest", "received", "system", {"a": 1})
    h2 = row_hash(h1, now, cid, "normalize", "ok", "system", {"b": 2})
    assert len(h1) == 64 and h1 != h2
    # birinci sətrin payload-ı dəyişdirilsə, onun hash-ı və zəncir dəyişir
    assert row_hash(GENESIS, now, cid, "ingest", "received", "system", {"a": 999}) != h1
    # payload açarlarının sırası hash-a təsir etmir
    assert row_hash(GENESIS, now, cid, "s", "e", "system", {"x": 1, "y": 2}) == row_hash(
        GENESIS, now, cid, "s", "e", "system", {"y": 2, "x": 1}
    )


# ---------- 4.8: QA nümunəsi, korrelyasiya, case DLQ retry, bildiriş xətası ----------
async def test_qa_sample_sends_closed_alert_to_human(raw_doc, monkeypatch):
    monkeypatch.setattr(pipeline, "QA_SAMPLE_RATE", 1.0)
    await run(raw_doc, "URL-03", monkeypatch, "clean", 1)
    assert ("act", "closed_auto") in AUDIT and ("act", "qa_sampled") in AUDIT
    assert len(CASES) == 1  # QA case-i yaranıb


async def test_correlated_alert_is_linked_not_new_case(raw_doc, monkeypatch):
    from app.case.base import CaseRef

    comments = []

    async def correlate(alert):
        return CaseRef(backend="file", case_id="C-OLD", url="/x")

    async def comment(self, ref, text):
        comments.append((ref.case_id, text))

    monkeypatch.setattr(pipeline, "correlate", correlate)
    monkeypatch.setattr(file_backend.FileBackend, "comment", comment)
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    assert ("act", "case_linked") in AUDIT and ("act", "case_created") not in AUDIT
    assert comments[0][0] == "C-OLD" and "Korrelyasiya" in comments[0][1]


async def test_related_cases_are_commented_and_linked(raw_doc, monkeypatch):
    links = []

    async def correlate(alert):
        alert.context["related_cases"] = ["C-9"]
        return None

    async def save_link(alert_id, case_id, related):
        links.append((case_id, related))

    monkeypatch.setattr(pipeline, "correlate", correlate)
    monkeypatch.setattr(db, "save_link", save_link, raising=False)
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    assert links and links[0][1] == "C-9"


async def _pending_alert(raw_doc, monkeypatch):
    """Case backend çökür → alert cases.dlq-ya düşür; sənədini qaytarır."""
    from app.case.base import CaseError

    docs = {}
    orig = file_backend.FileBackend.create

    async def boom(self, a, d):
        raise CaseError("down")

    async def save_alert(a, status):
        docs[str(a.alert_id)] = a.model_dump(mode="json")

    async def load_alert(alert_id):
        return docs.get(str(alert_id))

    monkeypatch.setattr(db, "save_alert", save_alert)
    monkeypatch.setattr(db, "load_alert", load_alert, raising=False)
    monkeypatch.setattr(file_backend.FileBackend, "create", boom)
    await run(raw_doc, "HASH-03", monkeypatch, "malicious", 89)
    return docs, orig


async def test_retry_pending_cases_creates_case_when_backend_is_back(raw_doc, monkeypatch):
    docs, orig = await _pending_alert(raw_doc, monkeypatch)
    assert await pipeline.retry_pending_cases() == 0  # backend hələ də işləmir
    assert await queue.get_redis().xlen(pipeline.CASES_DLQ) == 1

    monkeypatch.setattr(file_backend.FileBackend, "create", orig)
    AUDIT.clear()
    assert await pipeline.retry_pending_cases() == 1
    assert await queue.get_redis().xlen(pipeline.CASES_DLQ) == 0
    assert ("act", "case_created") in AUDIT


async def test_retry_pending_drops_unknown_alert(monkeypatch):
    async def load_alert(alert_id):
        return None

    monkeypatch.setattr(db, "load_alert", load_alert, raising=False)
    await queue.get_redis().xadd(pipeline.CASES_DLQ, {"alert_id": str(uuid4()), "error": "x"})
    assert await pipeline.retry_pending_cases() == 0
    assert await queue.get_redis().xlen(pipeline.CASES_DLQ) == 0


async def test_p1_with_no_working_channel_is_audited_as_failed(raw_doc, monkeypatch):
    async def mail_down(subject, text):
        raise OSError("smtp down")

    monkeypatch.setattr("app.notify.service._email", mail_down)
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    assert ("notify", "failed") in AUDIT


# ---------- 4.8: n8n /stage/* yolu worker ilə eyni qərarı verir ----------
async def _client():
    import httpx

    from app import main

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://t")


@pytest.fixture
def admin(monkeypatch):
    monkeypatch.setattr(settings, "admin_token", "test-admin")
    return {"X-Admin-Token": "test-admin"}


async def test_n8n_stages_give_same_decision_as_worker(raw_doc, monkeypatch, admin):
    decisions = []

    async def save_decision(a, d):
        decisions.append((d.rule_id, d.verdict, d.action, d.priority))

    monkeypatch.setattr(db, "save_decision", save_decision)
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)  # worker yolu

    doc = raw_doc("HASH-01")
    async with await _client() as c:
        r = await c.post(
            "/stage/normalize", json={"source": doc["source"], "payload": doc["payload"]}, headers=admin
        )
        assert r.status_code == 200 and r.json()["duplicate"] is False
        alert = r.json()["alert"]
        for step in ("enrich", "decide"):
            r = await c.post(f"/stage/{step}", json=alert, headers=admin)
            assert r.status_code == 200, r.text
            alert = r.json()
        r = await c.post("/stage/act", json=alert, headers=admin)
        assert r.status_code == 200 and r.json()["case"] is not None
        r = await c.post("/stage/notify", json=r.json(), headers=admin)
        assert r.status_code == 200 and "channels" in r.json()

    assert len(decisions) == 2 and decisions[0] == decisions[1]


async def test_stages_require_admin_token(admin):
    async with await _client() as c:
        r = await c.post("/stage/normalize", json={"source": "edr", "payload": {}})
    assert r.status_code == 403


async def test_stage_normalize_bad_payload_is_422(admin):
    async with await _client() as c:
        r = await c.post("/stage/normalize", json={"source": "splunk", "payload": {}}, headers=admin)
    assert r.status_code == 422


async def test_stage_normalize_duplicate(raw_doc, monkeypatch, admin):
    async def dup(a, w):
        return a.alert_id, True

    monkeypatch.setattr(db, "upsert_alert", dup)
    doc = raw_doc("HASH-01")
    async with await _client() as c:
        r = await c.post(
            "/stage/normalize", json={"source": doc["source"], "payload": doc["payload"]}, headers=admin
        )
    assert r.json() == {"duplicate": True, "alert": None}


async def test_timeline_endpoint(monkeypatch, admin):
    from datetime import timedelta

    t0 = datetime.now(timezone.utc)
    rows = [
        {"ts": t0, "stage": "ingest", "event": "received", "actor": "system", "payload": {}},
        {
            "ts": t0 + timedelta(seconds=1.5),
            "stage": "act",
            "event": "case_created",
            "actor": "system",
            "payload": {},
        },
    ]

    async def timeline(alert_id):
        return rows if str(alert_id).endswith("1") else []

    monkeypatch.setattr(db, "timeline", timeline, raising=False)
    async with await _client() as c:
        ok = await c.get("/alerts/00000000-0000-4000-8000-000000000001/timeline", headers=admin)
        missing = await c.get("/alerts/00000000-0000-4000-8000-000000000002/timeline", headers=admin)
    assert [e["t_plus_s"] for e in ok.json()] == [0.0, 1.5]
    assert missing.status_code == 404


async def test_cases_replay_endpoint(monkeypatch, admin):
    async def retry():
        return 2

    monkeypatch.setattr(pipeline, "retry_pending_cases", retry)
    async with await _client() as c:
        r = await c.post("/dlq/cases/replay", headers=admin)
    assert r.json() == {"created": 2}


# ---------- case şərhi: case-in öz backend-i, xəta alert-i dayandırmır ----------
async def test_comment_failure_on_linked_case_does_not_fail_alert(raw_doc, monkeypatch):
    # Real hal: korrelyasiya köhnə case-ə bağladı, amma şərh yazıla bilmədi (backend əlçatmaz)
    from app.case.base import CaseError, CaseRef

    async def correlate(alert):
        return CaseRef(backend="file", case_id="C-OLD", url="/yoxdur.json")

    async def boom(self, ref, text):
        raise CaseError("backend əlçatmaz")

    monkeypatch.setattr(pipeline, "correlate", correlate)
    monkeypatch.setattr(file_backend.FileBackend, "comment", boom)
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)  # exception olmamalıdır
    assert ("act", "comment_failed") in AUDIT and ("act", "case_linked") in AUDIT
    assert ("notify", "sent") in AUDIT or ("notify", "throttled") in AUDIT


async def test_comment_uses_the_backend_of_the_existing_case(raw_doc, monkeypatch):
    # cari backend thehive, amma bağlanan case fayl case-idir → şərh fayl backend-i ilə yazılır
    from app.case.base import CaseRef
    from app.case.thehive import TheHiveBackend

    used = []

    async def correlate(alert):
        return CaseRef(backend="file", case_id="C-FILE", url="/x.json")

    async def file_comment(self, ref, text):
        used.append("file")

    async def hive_comment(self, ref, text):
        used.append("thehive")

    monkeypatch.setattr(settings, "case_backend", "thehive")
    monkeypatch.setattr(pipeline, "correlate", correlate)
    monkeypatch.setattr(file_backend.FileBackend, "comment", file_comment)
    monkeypatch.setattr(TheHiveBackend, "comment", hive_comment)
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    assert used == ["file"]


async def test_duplicate_case_comment_failure_keeps_existing_case(raw_doc, monkeypatch):
    from app.case.base import CaseError

    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    first = dict(CASES)

    async def boom(self, ref, text):
        raise CaseError("down")

    monkeypatch.setattr(file_backend.FileBackend, "comment", boom)
    AUDIT.clear()
    await run(raw_doc, "HASH-01", monkeypatch, "malicious", 89)
    assert CASES == first and ("act", "comment_failed") in AUDIT
    assert await queue.get_redis().xlen(pipeline.CASES_DLQ) == 0  # case var, DLQ-ya getmir


def test_get_backend_by_name(monkeypatch):
    from app.case.base import get_backend

    monkeypatch.setattr(settings, "case_backend", "file")
    assert get_backend().name == "file" and get_backend("thehive").name == "thehive"
