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
