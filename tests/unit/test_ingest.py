import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient

from app import main, queue

SECRET = b"test-secret"


def sig(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()


@pytest.fixture
def client(monkeypatch):
    sent = []

    async def fake_enqueue(source, body, received_at):
        sent.append((source, body))
        return "1-0"

    monkeypatch.setattr(queue, "enqueue", fake_enqueue)
    c = TestClient(main.app)
    c.sent = sent
    return c


def test_valid_signature_accepted(client):
    body = b'{"a":1}'
    r = client.post("/ingest/edr", content=body, headers={"X-Signature": sig(body)})
    assert r.status_code == 202 and client.sent == [("edr", '{"a":1}')]
    assert r.json()["queued"] == "1-0"


@pytest.mark.parametrize("header", [None, "sha256=" + "0" * 64, "garbage"])
def test_bad_signature_rejected(client, header):
    headers = {"X-Signature": header} if header else {}
    r = client.post("/ingest/edr", content=b"{}", headers=headers)
    assert r.status_code == 401 and client.sent == []


def test_signature_of_other_body_rejected(client):
    r = client.post("/ingest/edr", content=b'{"a":2}', headers={"X-Signature": sig(b'{"a":1}')})
    assert r.status_code == 401


def test_unknown_source(client):
    assert client.post("/ingest/splunk", content=b"{}").status_code == 404


def test_body_too_large(client):
    body = b"x" * (main.MAX_BODY + 1)
    assert client.post("/ingest/edr", content=body, headers={"X-Signature": sig(body)}).status_code == 413


@pytest.mark.parametrize("token", [None, "wrong"])
def test_dlq_requires_admin(client, token):
    headers = {"X-Admin-Token": token} if token else {}
    assert client.get("/dlq", headers=headers).status_code == 403
    assert client.post("/dlq/replay", headers=headers).status_code == 403
