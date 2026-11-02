"""4.2a: deklarativ qayda mühərriki və rules/severity.yaml. Baza və şəbəkə istifadə olunmur."""

import os
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.rules import engine
from app.rules.engine import RuleSet, decide, get_path, load_rules, matches, priority_for
from app.schemas.alert import Enrichment, NormalizedAlert, Observable


def make(
    alert_type="malicious_hash",
    verdict="unknown",
    score=None,
    status="ok",
    ctx=None,
    providers=None,
    conflict=False,
    user="kamran",
    host="WS-033",
):
    now = datetime.now(timezone.utc)
    a = NormalizedAlert(
        source_system="edr",
        alert_type=alert_type,
        title="t",
        time=now,
        received_at=now,
        user=user,
        host=host,
        raw={},
        observables=[Observable(type="hash_sha256", value="ab" * 32)],
    )
    a.enrichment = Enrichment(
        status=status,
        verdict=verdict,
        reputation_score=score,
        conflict=conflict,
        confidence=1.0,
        providers=providers or [],
    )
    a.context = {
        "asset_criticality": "medium",
        "user_privileged": False,
        "user_vip": False,
        "allowlisted": False,
        "allowlist_reason": "",
        **(ctx or {}),
    }
    return a


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.setattr(engine, "_loaded", {"mtime": None, "rules": None})


def test_real_rules_file_is_valid():
    rs = load_rules()
    assert rs.version and rs.rules[-1].id == "R99-DEFAULT" and rs.rules[-1].when == {}


@pytest.mark.parametrize(
    "kw,rule,verdict,sev,prio,action",
    [
        ({"verdict": "malicious", "score": 89}, "R03-HASH-MALICIOUS", "malicious", 5, "P1", "create_case"),
        ({"verdict": "clean", "score": 0}, "R07-CLEAN", "clean", 1, "P4", "auto_close"),
        ({"verdict": "unknown", "status": "failed"}, "R01-ENRICH-FAILED", "unknown", 4, "P2", "create_case"),
        (
            {"alert_type": "suspicious_login", "verdict": "malicious", "score": 100},
            "R04-MALICIOUS",
            "malicious",
            4,
            "P2",
            "create_case",
        ),
        (
            {
                "alert_type": "suspicious_login",
                "verdict": "suspicious",
                "score": 50,
                "ctx": {"user_privileged": True},
            },
            "R05-PRIV-LOGIN",
            "suspicious",
            4,
            "P1",
            "create_case",
        ),
        (
            {"alert_type": "suspicious_url", "verdict": "suspicious", "score": 40},
            "R06-SUSPICIOUS",
            "suspicious",
            3,
            "P3",
            "create_case",
        ),
        (
            {"verdict": "clean", "score": 10, "ctx": {"allowlisted": True, "allowlist_reason": "VPN"}},
            "R02-ALLOWLIST",
            "clean",
            1,
            "P4",
            "auto_close",
        ),
        ({"verdict": "unknown", "status": "partial"}, "R99-DEFAULT", "unknown", 3, "P3", "create_case"),
    ],
)
def test_decision_table(kw, rule, verdict, sev, prio, action):
    d = decide(make(**kw))
    got = (d.rule_id, d.verdict, int(d.severity_id), d.priority, d.action)
    assert got == (rule, verdict, sev, prio, action)
    assert d.rule_version == load_rules().version
    assert d.reasons[0].startswith(f"qayda {rule}")


def test_allowlisted_but_malicious_is_not_closed():
    d = decide(make(verdict="malicious", score=90, ctx={"allowlisted": True}))
    assert d.rule_id == "R03-HASH-MALICIOUS" and d.action == "create_case"


def test_failed_enrichment_beats_allowlist():
    d = decide(make(status="failed", ctx={"allowlisted": True}))
    assert d.rule_id == "R01-ENRICH-FAILED"


def test_allowlist_without_score_does_not_match():
    d = decide(make(verdict="clean", score=None, ctx={"allowlisted": True}))
    assert d.rule_id == "R07-CLEAN"


@pytest.mark.parametrize(
    "sev,ctx,prio",
    [
        (6, {}, "P1"),
        (5, {}, "P1"),
        (4, {}, "P2"),
        (4, {"user_privileged": True}, "P1"),
        (4, {"user_vip": True}, "P1"),
        (4, {"asset_criticality": "crown_jewel"}, "P1"),
        (4, {"asset_criticality": "high"}, "P1"),
        (3, {}, "P3"),
        (3, {"asset_criticality": "high"}, "P2"),
        (2, {"user_privileged": True}, "P4"),
        (1, {}, "P4"),
        (0, {}, "P4"),
    ],
)
def test_priority_matrix(sev, ctx, prio):
    assert priority_for(sev, ctx) == prio


def test_get_path():
    doc = {"a": {"b": {"c": 1}}, "x": 5}
    assert get_path(doc, "a.b.c") == 1
    assert get_path(doc, "a.z") is None and get_path(doc, "x.y") is None


@pytest.mark.parametrize(
    "when,ok",
    [
        ({"s": {"gt": 10}}, True),
        ({"s": {"gte": 20}}, True),
        ({"s": {"lt": 20}}, False),
        ({"s": {"lte": 20}}, True),
        ({"s": {"ne": 3}}, True),
        ({"v": {"in": ["a", "b"]}}, True),
        ({"v": {"in": ["x"]}}, False),
        ({"missing": {"lt": 5}}, False),
        ({"missing": {"exists": False}}, True),
        ({"s": {"exists": True}}, True),
        ({"missing": {"eq": None}}, True),
        ({"s": {"gt": 10}, "v": {"eq": "z"}}, False),
        ({}, True),
    ],
)
def test_matches(when, ok):
    assert matches(when, {"s": 20, "v": "a"}) is ok


def _rs(rules, version="t"):
    return RuleSet.model_validate({"version": version, "rules": rules})


DEFAULT = {"id": "R99", "when": {}, "then": {"verdict": "unknown", "severity_id": 3, "action": "create_case"}}


def test_unknown_operator_rejected():
    with pytest.raises(ValidationError):
        _rs([{"id": "R1", "when": {"x": {"regex": "a"}}, "then": DEFAULT["then"]}, DEFAULT])


def test_last_rule_must_be_default():
    with pytest.raises(ValidationError):
        _rs([{"id": "R1", "when": {"x": {"eq": 1}}, "then": DEFAULT["then"]}])


def test_duplicate_ids_rejected():
    with pytest.raises(ValidationError):
        _rs([{**DEFAULT, "when": {"x": {"eq": 1}}}, DEFAULT])


@pytest.mark.parametrize("bad", [{"severity_id": 7}, {"verdict": "evil"}, {"action": "delete"}])
def test_then_validated(bad):
    with pytest.raises(ValidationError):
        _rs([{**DEFAULT, "then": {**DEFAULT["then"], **bad}}])


def test_bad_file_keeps_previous_version(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text(
        'version: "v1"\nrules:\n  - {id: R99, when: {}, then: {verdict: unknown, severity_id: 3, '
        "action: create_case}}\n",
        encoding="utf-8",
    )
    assert load_rules(p).version == "v1"
    p.write_text("version: [broken\n", encoding="utf-8")
    st = p.stat()
    os.utime(p, (st.st_atime, st.st_mtime + 5))
    assert load_rules(p).version == "v1"  # köhnə işlək versiya qaldı


def test_bad_file_on_first_load_raises(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text('version: "v1"\nrules: []\n', encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rules(p)


def test_reasons_explain_decision():
    providers = [
        {
            "provider": "virustotal",
            "ioc_type": "hash_sha256",
            "status": "ok",
            "score": 100,
            "evidence": {"malicious": 66, "suspicious": 0, "engines": 75},
        },
        {"provider": "otx", "ioc_type": "hash_sha256", "status": "timeout", "score": None, "evidence": {}},
    ]
    d = decide(
        make(
            verdict="malicious",
            score=89,
            providers=providers,
            conflict=True,
            host="DC-01",
            ctx={
                "user_privileged": True,
                "asset_criticality": "crown_jewel",
                "allowlisted": True,
                "allowlist_reason": "x",
            },
        )
    )
    text = "\n".join(d.reasons)
    for part in (
        "intel: malicious, skor 89",
        "ziddir",
        "virustotal (hash_sha256): skor 100; malicious=66",
        "otx (hash_sha256): timeout",
        "imtiyazlıdır: kamran",
        "crown_jewel (DC-01)",
        "allowlist: x",
    ):
        assert part in text
