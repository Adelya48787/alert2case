"""Phase 4 testləri: case backend-ləri və bildirişlər (şəbəkə yoxdur, respx ilə)."""

import json

import fakeredis
import httpx
import pytest
import respx

from app import queue
from app.case import file_backend
from app.case.base import CaseError, CaseRef, defang
from app.case.thehive import TheHiveBackend
from app.config import settings
from app.notify import service as notify
from app.rules.engine import decide
from tests.unit.factories import make

TH = "http://thehive.test:9000"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(queue, "_client", fakeredis.FakeAsyncRedis(decode_responses=True))
    monkeypatch.setattr(file_backend, "CASE_DIR", tmp_path / "cases")
    monkeypatch.setattr(settings, "thehive_url", TH)
    monkeypatch.setattr(settings, "thehive_api_key", "k")
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.slack.test/x")
    monkeypatch.setattr(settings, "telegram_bot_token", "")
    sent_mail = []

    async def fake_email(subject, text):
        sent_mail.append(subject)

    monkeypatch.setattr(notify, "_email", fake_email)
    return sent_mail


def mal():
    a = make(verdict="malicious", score=89)
    return a, decide(a)


def test_defang():
    assert defang("http://a.b/c") == "hxxp://a[.]b/c"


async def test_file_backend_create_and_comment():
    a, d = mal()
    b = file_backend.FileBackend()
    ref = await b.create(a, d)
    await b.comment(ref, "salam")
    doc = json.loads(open(ref.url, encoding="utf-8").read())
    assert doc["priority"] == "P1" and doc["comments"][0]["text"] == "salam"
    assert f"fp:{a.fingerprint}" in doc["tags"] and len(doc["tasks"]) == 3


@respx.mock
async def test_thehive_creates_case_observables_tasks():
    a, d = mal()
    case = respx.post(f"{TH}/api/v1/case").respond(201, json={"_id": "~42", "number": 7})
    obs = respx.post(f"{TH}/api/v1/case/~42/observable").respond(201, json=[{"_id": "~1"}])
    task = respx.post(f"{TH}/api/v1/case/~42/task").respond(201, json={"_id": "~2"})
    ref = await TheHiveBackend().create(a, d)
    body = json.loads(case.calls[0].request.content)
    assert ref.case_id == "~42" and body["severity"] == 4 and "rule:R03-HASH-MALICIOUS" in body["tags"]
    assert case.calls[0].request.headers["Authorization"] == "Bearer k"
    assert obs.call_count == len(a.observables) and task.call_count == 3
    assert json.loads(obs.calls[0].request.content)["ioc"] is True


@respx.mock
async def test_thehive_down_raises_case_error():
    respx.post(f"{TH}/api/v1/case").mock(side_effect=httpx.ConnectError("down"))
    a, d = mal()
    with pytest.raises(CaseError):
        await TheHiveBackend().create(a, d)


@respx.mock
async def test_thehive_observable_failure_keeps_case():
    a, d = mal()
    respx.post(f"{TH}/api/v1/case").respond(201, json={"_id": "~43"})
    respx.post(f"{TH}/api/v1/case/~43/observable").respond(500)
    respx.post(f"{TH}/api/v1/case/~43/task").respond(201, json={})
    ref = await TheHiveBackend().create(a, d)
    assert ref.case_id == "~43"


@respx.mock
async def test_notify_p1_slack_and_email(isolated):
    route = respx.post("https://hooks.slack.test/x").respond(200, text="ok")
    a, d = mal()
    sent = await notify.notify(a, d, CaseRef(backend="file", case_id="F1", url="/tmp/F1.json"))
    assert sent == ["slack", "email"] and route.call_count == 1
    text = json.loads(route.calls[0].request.content)["text"]
    assert "[P1]" in text and "SLA" in text


@respx.mock
async def test_notify_throttles_same_fingerprint():
    respx.post("https://hooks.slack.test/x").respond(200, text="ok")
    a, d = mal()
    await notify.notify(a, d, None)
    assert await notify.notify(a, d, None) == ["throttled"]


@respx.mock
async def test_slack_down_falls_back_to_email(isolated):
    respx.post("https://hooks.slack.test/x").respond(500)
    a = make(alert_type="suspicious_url", verdict="malicious", score=80)
    d = decide(a)  # P2: normalda email yoxdur
    assert await notify.notify(a, d, None) == ["email"]


async def test_p3_p4_not_notified():
    a = make(verdict="suspicious", score=35)
    assert await notify.notify(a, decide(a), None) == []


def test_secrets_masked_in_logs(monkeypatch, caplog):
    import logging
    from app.audit import logging_setup

    monkeypatch.setattr(settings, "vt_api_key", "SECRETKEY1234567890")
    f = logging_setup.SecretMaskFilter()
    rec = logging.LogRecord("t", logging.INFO, "", 0, "url ?apikey=%s", ("SECRETKEY1234567890",), None)
    f.filter(rec)
    assert "SECRETKEY1234567890" not in rec.getMessage() and "SECR***" in rec.getMessage()


# ---------- 4.8: Telegram, email xətası, Redis-siz throttle ----------
@respx.mock
async def test_telegram_html_escaped(monkeypatch):
    monkeypatch.setattr(settings, "slack_webhook_url", "")
    monkeypatch.setattr(settings, "telegram_bot_token", "123:abc")
    monkeypatch.setattr(settings, "telegram_chat_id", "-100")
    monkeypatch.setattr(settings, "telegram_api_base", "https://tg.test")
    route = respx.post("https://tg.test/bot123:abc/sendMessage").respond(200, json={"ok": True})
    a, d = mal()
    d = d.model_copy(update={"reasons": ["<script>&"]})
    assert await notify.notify(a, d, None) == ["telegram", "email"]
    body = json.loads(route.calls[0].request.content)
    assert body["parse_mode"] == "HTML" and body["chat_id"] == "-100"
    assert "&lt;script&gt;&amp;" in body["text"] and "<script>" not in body["text"]


@respx.mock
async def test_all_channels_down_returns_empty(monkeypatch):
    respx.post("https://hooks.slack.test/x").respond(500)

    async def mail_down(subject, text):
        raise OSError("smtp down")

    monkeypatch.setattr(notify, "_email", mail_down)
    a, d = mal()
    assert await notify.notify(a, d, None) == []


@respx.mock
async def test_redis_down_disables_throttle(monkeypatch):
    class DeadRedis:
        async def set(self, *a, **k):
            raise ConnectionError("redis down")

    monkeypatch.setattr(queue, "_client", DeadRedis())
    respx.post("https://hooks.slack.test/x").respond(200, text="ok")
    a, d = mal()
    assert await notify.notify(a, d, None) == ["slack", "email"]
    assert await notify.notify(a, d, None) == ["slack", "email"]  # çox mesaj > heç mesaj
