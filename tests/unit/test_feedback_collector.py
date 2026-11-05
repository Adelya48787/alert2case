"""T5.1: analitik rəyinin toplanması (TheHive webhook və əl ilə endpoint). Baza saxtalaşdırılır."""

from uuid import UUID

import httpx
import pytest

from app import db, main
from app.config import settings
from app.feedback import collector
from app.feedback.collector import FeedbackIn, from_thehive, record

AID = UUID("6f1c2a8e-0000-4000-8000-000000000001")
SAVED: list = []
AUDIT: list = []


@pytest.fixture(autouse=True)
def fake_db(monkeypatch):
    SAVED.clear()
    AUDIT.clear()

    async def alert_for_case(case_id):
        return AID if case_id == "~42" else None

    async def last_decision(alert_id):
        return {"verdict": "suspicious", "severity_id": 3, "rule_id": "R06-SUSPICIOUS", "rule_version": "v1"}

    async def save_feedback(fb, dec):
        SAVED.append((fb, dec))

    async def audit(cid, stage, event, payload=None, actor="system"):
        AUDIT.append((stage, event, payload, actor))

    monkeypatch.setattr(db, "alert_for_case", alert_for_case)
    monkeypatch.setattr(db, "last_decision", last_decision)
    monkeypatch.setattr(db, "save_feedback", save_feedback)
    monkeypatch.setattr(collector, "audit", audit)
    monkeypatch.setattr(settings, "admin_token", "test-admin")
    monkeypatch.setattr(settings, "feedback_token", "fb-token")


def closed(resolution="FalsePositive", **extra):
    return {
        "operation": "update",
        "objectType": "Case",
        "object": {"_id": "~42", "status": "Resolved", "resolutionStatus": resolution, **extra},
    }


# ---------- TheHive payload ----------
@pytest.mark.parametrize(
    "resolution,verdict",
    [
        ("TruePositive", "malicious"),
        ("FalsePositive", "clean"),
        ("Indeterminate", "suspicious"),
        ("Other", "suspicious"),
    ],
)
async def test_resolution_mapping(resolution, verdict):
    fb = await from_thehive(closed(resolution, severity=3, assignee="adile", summary="test"))
    assert (fb.alert_id, fb.human_verdict, fb.human_severity, fb.analyst, fb.source, fb.comment) == (
        AID,
        verdict,
        4,
        "adile",
        "thehive",
        "test",
    )


@pytest.mark.parametrize(
    "body",
    [
        {"object": {"_id": "~42", "status": "Open"}},  # case açıqdır
        closed("Duplicated"),  # rəy sayılmır
        {"operation": "update", "object": {}},  # case ID yoxdur
        closed(_id="~999"),  # alert2case case-i deyil
    ],
    ids=["open", "duplicated", "no-id", "foreign-case"],
)
async def test_not_feedback_is_ignored(body):
    assert await from_thehive(body) is None


async def test_details_format_and_fallbacks():
    body = {
        "objectId": "~42",
        "details": {
            "resolutionStatus": "TruePositive",
            "severity": "high",
            "_updatedBy": "elvin",
            "summary": "x" * 900,
        },
    }
    fb = await from_thehive(body)
    assert fb.human_severity is None and fb.analyst == "elvin" and len(fb.comment) == 500


# ---------- record ----------
@pytest.mark.parametrize(
    "auto,human,agree",
    [
        ("suspicious", "suspicious", True),
        ("suspicious", "clean", False),
        ("unknown", "suspicious", True),
        ("unknown", "clean", False),
    ],
)
async def test_record_agreement(monkeypatch, auto, human, agree):
    async def last_decision(alert_id):
        return {"verdict": auto, "severity_id": 3, "rule_id": "R99-DEFAULT", "rule_version": "v1"}

    monkeypatch.setattr(db, "last_decision", last_decision)
    res = await record(FeedbackIn(alert_id=AID, human_verdict=human, analyst="adile"))
    assert res == {"saved": True, "agree": agree, "rule": "R99-DEFAULT"}
    stage, event, payload, actor = AUDIT[0]
    assert (stage, event, actor) == ("feedback", "agree" if agree else "disagree", "adile")
    assert payload["auto"] == auto and payload["human"] == human and len(SAVED) == 1


async def test_record_without_decision(monkeypatch):
    async def none(alert_id):
        return None

    monkeypatch.setattr(db, "last_decision", none)
    assert "error" in await record(FeedbackIn(alert_id=AID, human_verdict="clean"))
    assert SAVED == [] and AUDIT == []


def test_bad_verdict_rejected():
    with pytest.raises(ValueError):
        FeedbackIn(alert_id=AID, human_verdict="unknown")


# ---------- endpoint-lər ----------
def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://t")


async def test_manual_feedback_requires_admin():
    body = {"alert_id": str(AID), "human_verdict": "clean"}
    async with client() as c:
        no = await c.post("/feedback", json=body)
        yes = await c.post("/feedback", json=body, headers={"X-Admin-Token": "test-admin"})
    assert no.status_code == 403 and yes.json()["saved"] is True


@pytest.mark.parametrize(
    "headers,code",
    [
        ({}, 403),
        ({"X-Feedback-Token": "wrong"}, 403),
        ({"X-Admin-Token": "test-admin"}, 403),  # admin token rəy endpoint-ini açmır
        ({"X-Feedback-Token": "fb-token"}, 200),
        ({"Authorization": "Bearer fb-token"}, 200),  # TheHive belə göndərir
    ],
)
async def test_thehive_webhook_auth(headers, code):
    async with client() as c:
        r = await c.post("/feedback/thehive", json=closed(), headers=headers)
    assert r.status_code == code
    if code == 200:
        assert r.json()["agree"] is False and SAVED[0][0].human_verdict == "clean"


async def test_thehive_webhook_disabled_without_token(monkeypatch):
    monkeypatch.setattr(settings, "feedback_token", "")
    async with client() as c:
        r = await c.post("/feedback/thehive", json=closed(), headers={"X-Feedback-Token": ""})
    assert r.status_code == 403


async def test_thehive_webhook_ignores_non_closing_update():
    async with client() as c:
        r = await c.post(
            "/feedback/thehive",
            json={"object": {"_id": "~42", "status": "Open"}},
            headers={"X-Feedback-Token": "fb-token"},
        )
    assert r.json() == {"ignored": True} and SAVED == []


# ---------- TheHive 5.8 real formatı: status + stage, resolutionStatus boş ----------
@pytest.mark.parametrize(
    "status,verdict",
    [
        ("TruePositive", "malicious"),
        ("FalsePositive", "clean"),
        ("Indeterminate", "suspicious"),
        ("Other", "suspicious"),
    ],
)
async def test_thehive5_status_field(status, verdict):
    body = {
        "operation": "update",
        "objectType": "case",
        "object": {
            "_id": "~42",
            "status": status,
            "stage": "Closed",
            "resolutionStatus": None,
            "severity": 4,
            "assignee": "svc-alert2case@soc.lab",
            "summary": "real 5.8 payload",
        },
    }
    fb = await from_thehive(body)
    assert (fb.human_verdict, fb.human_severity, fb.analyst) == (verdict, 5, "svc-alert2case@soc.lab")


@pytest.mark.parametrize("status", ["New", "InProgress", "Open", "Duplicated"])
async def test_thehive5_open_or_duplicate_is_ignored(status):
    body = {
        "object": {"_id": "~42", "status": status, "stage": "Open" if status != "Duplicated" else "Closed"}
    }
    assert await from_thehive(body) is None


async def test_real_thehive58_webhook_v0_payload():
    # TheHive 5.8.1 webhook (version 0) case bağlananda real göndərdiyi forma
    body = {
        "operation": "update",
        "objectType": "Case",
        "objectId": "~42",
        "details": {"status": "FalsePositive", "stage": "Closed", "resolutionStatus": None},
        "object": {
            "_id": "~42",
            "status": "Resolved",
            "stage": "Closed",
            "extendedStatus": "FalsePositive",
            "resolutionStatus": None,
            "severity": 4,
            "assignee": "svc-alert2case@soc.lab",
            "summary": "real payload",
        },
    }
    fb = await from_thehive(body)
    assert (fb.human_verdict, fb.analyst, fb.comment) == ("clean", "svc-alert2case@soc.lab", "real payload")


async def test_resolved_without_known_result_is_ignored():
    assert (
        await from_thehive({"object": {"_id": "~42", "status": "Resolved", "extendedStatus": None}}) is None
    )
