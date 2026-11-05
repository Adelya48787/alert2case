"""5.2a: replay — confusion matrix və həqiqət mənbəyi. Baza və şəbəkə istifadə olunmur."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.schemas.alert import Enrichment, NormalizedAlert, Observable
from tools import replay


def alert(ref, providers=None):
    now = datetime.now(timezone.utc)
    a = NormalizedAlert(
        source_system="edr",
        alert_type="malicious_hash",
        title="t",
        time=now,
        received_at=now,
        source_ref=ref,
        raw={},
        observables=[Observable(type="hash_sha256", value="ab" * 32)],
    )
    a.enrichment = Enrichment(status="ok", providers=providers or [])
    return a


@pytest.fixture
def fake(monkeypatch):
    """decide() alert-in source_ref-inə görə action qaytarır; blockers boşdur."""
    plan = {"action": {}, "blocked": set(), "agg_calls": []}

    def decide(a, rules):
        return SimpleNamespace(action=plan["action"].get(a.source_ref, "create_case"))

    def aggregate(results, weights):
        plan["agg_calls"].append((len(results), weights))
        return Enrichment(status="ok", verdict="clean", reputation_score=0)

    monkeypatch.setattr(replay, "decide", decide)
    monkeypatch.setattr(replay, "aggregate", aggregate)
    monkeypatch.setattr(replay, "blockers", lambda a: ["x"] if a.source_ref in plan["blocked"] else [])
    return plan


@pytest.mark.parametrize(
    "v,human",
    [
        ("malicious", True),
        ("uncertain", True),
        ("suspicious", True),
        ("unknown", True),
        ("clean", False),
        (" Clean ", False),
    ],
)
def test_needs_human(v, human):
    assert replay.needs_human(v) is human


def test_confusion_matrix(fake):
    fake["action"] = {"TN": "auto_close", "FN": "auto_close"}
    cases = [
        (alert("TP"), "malicious"),
        (alert("FP"), "clean"),
        (alert("TN"), "clean"),
        (alert("FN"), "uncertain"),
    ]
    r = replay.evaluate(cases, {}, None)
    assert (r["n"], r["tp"], r["fp"], r["fn"], r["tn"]) == (4, 1, 1, 1, 1)
    assert r["fn_alerts"] == ["FN"]
    assert r["precision"] == 0.5 and r["recall"] == 0.5 and r["auto_close_rate"] == 0.5


def test_guard_blocks_auto_close(fake):
    fake["action"] = {"A": "auto_close"}
    fake["blocked"] = {"A"}
    r = replay.evaluate([(alert("A"), "malicious")], {}, None)
    assert r["fn"] == 0 and r["tp"] == 1


def test_recomputes_with_stored_provider_scores(fake):
    prov = [{"provider": "virustotal", "ioc_type": "hash_sha256", "status": "ok", "score": 100}]
    replay.evaluate([(alert("A", prov), "malicious"), (alert("B"), "clean")], {"w": 1}, None)
    assert fake["agg_calls"] == [(1, {"w": 1})]  # yalnız provider-i olan alert yenidən hesablanır


def test_original_alert_not_mutated(fake):
    prov = [{"provider": "otx", "ioc_type": "ip", "status": "ok", "score": 60}]
    a = alert("A", prov)
    replay.evaluate([(a, "clean")], {}, None)
    assert a.enrichment.verdict == "unknown"


def test_empty_cases():
    r = replay.evaluate([], {}, None)
    assert r["n"] == 0 and r["recall"] == 0.0 and r["fn_alerts"] == []


@pytest.mark.parametrize("header", ["alert_id,verdict,reason", "alert_id,alert_type,expected_verdict,x"])
def test_load_expected_both_formats(tmp_path, header):
    p = tmp_path / "e.csv"
    cols = header.split(",")
    row = {"alert_id": "HASH-01", "verdict": "malicious", "expected_verdict": "malicious"}
    p.write_text(header + "\n" + ",".join(row.get(c, "z") for c in cols) + "\n", encoding="utf-8")
    assert replay.load_expected(p) == {"HASH-01": "malicious"}


def test_load_expected_missing_file(tmp_path):
    assert replay.load_expected(tmp_path / "yox.csv") == {}


def test_real_expected_csv_has_36_labels():
    exp = replay.load_expected()
    if not exp:
        pytest.skip("dataset/expected.csv bu mühitdə yoxdur")
    assert len(exp) == 36 and set(exp.values()) <= {
        "malicious",
        "clean",
        "uncertain",
        "suspicious",
        "unknown",
    }
