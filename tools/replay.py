"""Qayda və çəkiləri keçmiş alert-lər üzərində yenidən işlədir və nəticəni həqiqətlə müqayisə edir.
Həqiqət: analitik rəyi (feedback), yoxdursa dataset/expected.csv.
  python -m tools.replay                                   # cari fayllar
  python -m tools.replay --weights cand/weights.yaml --rules cand/severity.yaml
"""

import argparse
import asyncio
import csv
from pathlib import Path

import yaml

from app import db
from app.enrich.aggregate import aggregate
from app.enrich.base import ProviderResult
from app.rules.engine import RuleSet, decide
from app.rules.guards import blockers
from app.schemas.alert import NormalizedAlert

EXPECTED = Path("dataset/expected.csv")


def needs_human(verdict: str) -> bool:
    """clean-dən başqa hər hökm (malicious, suspicious, uncertain, unknown) insana getməlidir."""
    return verdict.strip().lower() != "clean"


def load_expected(path: Path = EXPECTED) -> dict[str, str]:
    """dataset/expected.csv → {alert_id: verdict}. 'expected_verdict' və 'verdict' sütunları tanınır."""
    if not path.exists():
        return {}
    with open(path, encoding="utf-8", newline="") as f:
        out = {}
        for r in csv.DictReader(f):
            v = r.get("expected_verdict") or r.get("verdict")
            if r.get("alert_id") and v:
                out[r["alert_id"].strip()] = v.strip()
        return out


async def load_cases() -> list[tuple[NormalizedAlert, str]]:
    expected = load_expected()
    p = await db.pool()
    rows = await p.fetch(
        """SELECT a.doc, a.source_ref,
                  (SELECT human_verdict FROM feedback f WHERE f.alert_id = a.alert_id
                   ORDER BY created_at DESC LIMIT 1) AS human
           FROM alerts a WHERE a.doc->'decision' IS NOT NULL AND a.doc->'decision' != 'null'::jsonb"""
    )
    out = []
    for r in rows:
        truth = r["human"] or expected.get(r["source_ref"])
        if truth:
            out.append((NormalizedAlert.model_validate(r["doc"]), truth))
    return out


def evaluate(cases: list, weights: dict, rules: RuleSet) -> dict:
    tp = fp = fn = tn = 0
    misses = []
    for alert, truth in cases:
        a = alert.model_copy(deep=True)
        results = [
            ProviderResult(ioc="?", **{k: p.get(k) for k in ("provider", "ioc_type", "status", "score")})
            for p in a.enrichment.providers
        ]
        if results:
            a.enrichment = aggregate(results, weights)
        d = decide(a, rules)
        closes = d.action == "auto_close" and not blockers(a)
        pred_human = not closes
        if needs_human(truth) and pred_human:
            tp += 1
        elif needs_human(truth) and not pred_human:
            fn += 1
            misses.append(alert.source_ref or str(alert.alert_id))
        elif not needs_human(truth) and pred_human:
            fp += 1
        else:
            tn += 1
    n = max(1, tp + fp + fn + tn)
    return {
        "n": tp + fp + fn + tn,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(tp / max(1, tp + fp), 3),
        "recall": round(tp / max(1, tp + fn), 3),
        "auto_close_rate": round((fn + tn) / n, 3),
        "fn_alerts": misses,
    }


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--weights", default="rules/weights.yaml")
    ap.add_argument("--rules", default="rules/severity.yaml")
    a = ap.parse_args()
    weights = yaml.safe_load(Path(a.weights).read_text(encoding="utf-8"))
    rules = RuleSet.model_validate(yaml.safe_load(Path(a.rules).read_text(encoding="utf-8")))
    res = evaluate(await load_cases(), weights, rules)
    print(res)


if __name__ == "__main__":
    asyncio.run(main())
