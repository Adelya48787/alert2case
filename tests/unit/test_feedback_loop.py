"""T5.4: rəy dövrəsinin bütövlüyü — real aggregate + decide + blockers ilə safety gate,
və expected.csv-dən süni rəy yaradan alət."""

import copy

import pytest

from app.config import settings
from app.enrich.aggregate import load_weights
from app.rules.engine import decide, load_rules
from tests.unit.factories import make
from tools import feedback_from_expected as ffe
from tools import tuner
from tools.replay import evaluate


@pytest.fixture(autouse=True)
def live_mode(monkeypatch):
    monkeypatch.setattr(settings, "shadow_mode", False)
    monkeypatch.setattr(settings, "auto_close_enabled", True)


def login_with_scores(vt, ab):
    a = make(alert_type="suspicious_login", verdict="suspicious", score=46)
    a.enrichment.providers = [
        {"provider": "virustotal", "ioc_type": "ip", "status": "ok", "score": vt},
        {"provider": "abuseipdb", "ioc_type": "ip", "status": "ok", "score": ab},
    ]
    return a


def test_replay_counts_false_negative():
    clean_but_bad = make(verdict="clean", score=0)
    clean_but_bad.decision = decide(clean_but_bad)
    res = evaluate([(clean_but_bad, "malicious")], load_weights(), load_rules())
    assert res["fn"] == 1 and res["recall"] == 0.0 and res["fn_alerts"]


def test_safety_gate_rejects_proposal_that_creates_false_negative():
    # "pis" təklif: suspicious həddi 90, zəif siqnal qaydası yox → zərərli login təmiz sayılır
    a = login_with_scores(50, 40)
    w = load_weights()
    bad = copy.deepcopy(w)
    bad["thresholds"]["suspicious"] = 90
    for p in bad["providers"].values():
        p.pop("weak_signal", None)
    before = evaluate([(a, "malicious")], w, load_rules())
    after = evaluate([(a, "malicious")], bad, load_rules())
    assert (before["fn"], after["fn"]) == (0, 1)
    assert tuner.is_safe(before, after) is False and tuner.is_safe(before, before) is True


def test_safe_proposal_passes_gate():
    a = login_with_scores(50, 40)
    w = load_weights()
    small = copy.deepcopy(w)
    small["providers"]["virustotal"]["weight"] = round(w["providers"]["virustotal"]["weight"] + 0.05, 2)
    assert tuner.is_safe(
        evaluate([(a, "malicious")], w, load_rules()), evaluate([(a, "malicious")], small, load_rules())
    )


def test_replay_does_not_mutate_stored_alerts():
    a = login_with_scores(50, 40)
    snapshot = a.model_dump()
    evaluate([(a, "malicious")], load_weights(), load_rules())
    assert a.model_dump() == snapshot


# ---------- tools/feedback_from_expected.py ----------
@pytest.mark.parametrize(
    "label,human",
    [
        ("malicious", "malicious"),
        ("clean", "clean"),
        ("uncertain", "suspicious"),
        ("suspicious", "suspicious"),
        ("unknown", "suspicious"),
        (" Clean ", "clean"),
    ],
)
def test_label_mapping(label, human):
    assert ffe.to_human(label) == human


def test_real_expected_csv_maps_to_valid_feedback():
    labels = ffe.load_labels()
    assert len(labels) == 36
    assert {ffe.to_human(v) for v in labels.values()} <= {"malicious", "suspicious", "clean"}


async def test_generator_records_feedback_for_latest_alerts(monkeypatch):
    sent = []

    async def latest():
        return [
            {"alert_id": "6f1c2a8e-0000-4000-8000-000000000001", "source_ref": "HASH-01"},
            {"alert_id": "6f1c2a8e-0000-4000-8000-000000000002", "source_ref": "NOPE-99"},
        ]

    async def record(fb):
        sent.append(fb)
        return {"saved": True, "agree": fb.human_verdict == "malicious"}

    monkeypatch.setattr(ffe, "latest_decided_alerts", latest)
    monkeypatch.setattr(ffe, "record", record)
    stats = await ffe.run(limit=0)
    assert stats == {"agree": 1} and len(sent) == 1
    assert (sent[0].analyst, sent[0].source, sent[0].comment) == ("demo", "manual", "expected.csv")
