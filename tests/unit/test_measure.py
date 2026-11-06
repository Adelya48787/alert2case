"""6.1: manual ölçmə nümunəsi, bölgü, kartlar və xülasə. Fayl sistemi və şəbəkə istifadə olunmur."""

import json
from collections import Counter
from pathlib import Path

from tools import measure

ROOT = Path(__file__).resolve().parents[2]


def dataset():
    labels = {}
    for line in (ROOT / "dataset/expected.csv").read_text(encoding="utf-8").splitlines()[1:]:
        aid, verdict = line.split(",")[:2]
        labels[aid] = verdict
    ids = {}
    for aid in labels:
        ids.setdefault(aid.split("-")[0], []).append(aid)
    return ids, labels


def test_sample_is_stratified_and_covers_all_verdicts():
    ids, labels = dataset()
    s = measure.pick_sample(ids, labels)
    assert len(s) == len(set(s)) == 20
    assert Counter(a.split("-")[0] for a in s) == Counter(measure.PER_TYPE)
    for t in measure.PER_TYPE:
        assert measure.VERDICTS_REQUIRED <= {labels[a] for a in s if a.startswith(t + "-")}


def test_sample_and_assignment_are_reproducible():
    ids, labels = dataset()
    assert measure.pick_sample(ids, labels) == measure.pick_sample(ids, labels)
    s = measure.pick_sample(ids, labels)
    assert measure.assign(s) == measure.assign(s)
    assert measure.pick_sample(ids, labels, seed=7) != s


def test_each_alert_measured_by_two_different_analysts():
    ids, labels = dataset()
    rows = measure.assign(measure.pick_sample(ids, labels))
    by_alert = {}
    for r in rows:
        by_alert.setdefault(r["alert_id"], []).append(r["analyst"])
    assert len(by_alert) == 20
    assert all(len(v) == 2 and len(set(v)) == 2 for v in by_alert.values())


def test_load_is_balanced_and_sessions_are_small():
    ids, labels = dataset()
    rows = measure.assign(measure.pick_sample(ids, labels))
    load = Counter(r["analyst"] for r in rows)
    assert sum(load.values()) == 40 and max(load.values()) - min(load.values()) <= 1
    per_session = Counter((r["analyst"], r["session"]) for r in rows)
    assert max(per_session.values()) <= measure.MAX_PER_SESSION


def test_order_differs_between_analysts():
    ids, labels = dataset()
    rows = measure.assign(measure.pick_sample(ids, labels))
    orders = {a: [r["alert_id"] for r in rows if r["analyst"] == a] for a in measure.ANALYSTS}
    assert len({tuple(o) for o in orders.values()}) == len(measure.ANALYSTS)


def test_cards_show_source_fields_but_no_answers():
    _, labels = dataset()
    for f in sorted((ROOT / "dataset/raw").glob("*.json")):
        text = measure.card(f.stem, json.loads(f.read_text(encoding="utf-8")))
        assert text.startswith(f"# {f.stem} · ")
        low = text.lower()
        for word in ("malicious", "uncertain", "verdict", "expected", "clean"):
            assert word not in low, (f.stem, word)


def _rows(alert, analyst, total=80.0, note=""):
    return [
        {"alert_id": alert, "analyst": analyst, "step": f"S{i}", "duration_s": str(total / 8), "note": note}
        for i in range(1, 9)
    ]


def test_summarize_counts_complete_and_drops_outliers():
    sample = ["HASH-01", "URL-01"]
    rows = _rows("HASH-01", "elcin", 120) + _rows("HASH-01", "elvin", 60) + _rows("URL-01", "elcin", 90)
    rows += _rows("URL-01", "teymur", 900, note="outlier")
    rows += _rows("URL-01", "elvin")[:5]  # yarımçıq
    s = measure.summarize(rows, sample)
    assert s["measurements"] == 3
    assert s["outliers"] == 1
    assert s["alerts_ok"] == 1 and s["alerts_short"] == ["URL-01"]
    assert s["incomplete"] == ["URL-01/elvin"]
    assert s["median_s"] == 90
    assert s["by_type"] == {"HASH": 90, "URL": 90}


def test_summarize_flags_alerts_outside_sample():
    s = measure.summarize(_rows("NET-01", "elcin"), ["HASH-01"])
    assert s["unknown"] == ["NET-01"]


def test_p90():
    assert measure.p90([10]) == 10
    assert measure.p90(list(range(1, 11))) == 9.1


def test_merge_combines_analyst_files_in_time_order(tmp_path, monkeypatch):
    monkeypatch.setattr(measure, "OUT", tmp_path)
    (tmp_path / "raw").mkdir()
    head = "alert_id,analyst,step,t_start,t_end,duration_s,verdict,priority,note\n"
    (tmp_path / "raw/elvin.csv").write_text(head + "URL-01,elvin,S1,2026-11-07T10:00:00,x,5,,,\n")
    (tmp_path / "raw/elcin.csv").write_text(head + "HASH-01,elcin,S1,2026-11-07T09:00:00,x,4,,,\n")
    rows = measure.merge()
    assert [r["analyst"] for r in rows] == ["elcin", "elvin"]
    merged = (tmp_path / "manual_raw.csv").read_text().splitlines()
    assert merged[0] == head.strip() and len(merged) == 3


def test_merge_without_files_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(measure, "OUT", tmp_path)
    assert measure.merge() == []
    assert not (tmp_path / "manual_raw.csv").exists()
