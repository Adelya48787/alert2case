"""Pipeline məntiqi: baza və audit saxtası ilə (real baza 6.4-də)."""

import json
from uuid import uuid4

import pytest

from app import db, pipeline
from app.audit.log import GENESIS, row_hash
from app.errors import PermanentError


@pytest.fixture
def fake(monkeypatch):
    calls = {"audit": [], "saved": [], "dup": False}

    async def upsert(alert, window_s):
        return (uuid4() if calls["dup"] else alert.alert_id), calls["dup"]

    async def save(alert, status):
        calls["saved"].append(status)

    async def audit(cid, stage, event, payload=None, actor="system"):
        calls["audit"].append((stage, event))

    monkeypatch.setattr(db, "upsert_alert", upsert)
    monkeypatch.setattr(db, "save_alert", save)
    monkeypatch.setattr(pipeline, "audit", audit)
    return calls


async def test_new_alert_is_audited_and_saved(fake, raw_doc, now):
    doc = raw_doc("HASH-01")
    await pipeline.process("edr", json.dumps(doc["payload"]), now)
    assert fake["audit"] == [("ingest", "received"), ("normalize", "ok")]
    assert fake["saved"] == ["normalized"]


async def test_duplicate_is_not_saved_again(fake, raw_doc, now):
    fake["dup"] = True
    await pipeline.process("edr", json.dumps(raw_doc("HASH-01")["payload"]), now)
    assert fake["audit"] == [("normalize", "duplicate")] and fake["saved"] == []


async def test_non_json_is_permanent(fake, now):
    with pytest.raises(PermanentError, match="JSON deyil"):
        await pipeline.process("edr", "not-json", now)
    assert fake["audit"] == []


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
