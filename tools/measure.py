#!/usr/bin/env python3
"""6.1 manual ölçmə: nümunə, analitik bölgüsü, alert kartları və nəticənin yoxlanması.

  python -m tools.measure plan     # sample.txt, assignment.csv, alerts/*.md (yalnız hazırlayan işlədir)
  python -m tools.measure check    # raw/<analitik>.csv → manual_raw.csv, yoxlama və xülasə

Seçim sabit toxumla edilir: eyni dataset → eyni nümunə və eyni bölgü.
Analitiklər expected.csv-ni görmür: plan yalnız sayları çap edir, alert_id ilə verdict-i yox.
"""

import argparse
import csv
import json
import math
import random
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEED = 42
PER_TYPE = {"HASH": 7, "URL": 7, "LOGIN": 6}
ANALYSTS = ["elcin", "teymur", "elvin"]
MAX_PER_SESSION = 10
VERDICTS_REQUIRED = {"malicious", "clean", "uncertain"}

RAW = Path("dataset/raw")
EXPECTED = Path("dataset/expected.csv")
OUT = Path("docs/measure")
BASELINE = Path("docs/baseline/baseline_raw.csv")


# ---------------------------------------------------------------- plan
def pick_sample(ids_by_type: dict[str, list[str]], labels: dict[str, str], seed: int = SEED) -> list[str]:
    """Hər tipdən PER_TYPE qədər alert. Hər tipdə üç verdict-in hamısı olmalıdır."""
    rng = random.Random(seed)
    sample: list[str] = []
    for t, n in PER_TYPE.items():
        pool = sorted(ids_by_type[t])
        for _ in range(1000):
            pick = sorted(rng.sample(pool, n))
            if VERDICTS_REQUIRED <= {labels[a] for a in pick}:
                break
        else:  # pragma: no cover - dataset dəyişsə
            raise SystemExit(f"{t}: üç verdict-i əhatə edən nümunə tapılmadı")
        sample += pick
    return sample


def assign(sample: list[str], analysts: list[str] = ANALYSTS, seed: int = SEED) -> list[dict]:
    """Hər alert iki fərqli analitikə düşür, yük bərabər paylanır, sıra hər analitikdə fərqlidir."""
    rng = random.Random(seed + 1)
    order = sample[:]
    rng.shuffle(order)
    pairs = [(analysts[i], analysts[(i + 1) % len(analysts)]) for i in range(len(analysts))]
    per: dict[str, list[str]] = defaultdict(list)
    for i, aid in enumerate(order):
        for a in pairs[i % len(pairs)]:
            per[a].append(aid)
    rows = []
    for a in analysts:
        mine = per[a][:]
        rng.shuffle(mine)
        sessions = math.ceil(len(mine) / MAX_PER_SESSION)
        size = math.ceil(len(mine) / sessions)
        for pos, aid in enumerate(mine):
            rows.append({"analyst": a, "session": pos // size + 1, "pos": pos + 1, "alert_id": aid})
    return rows


def card(alert_id: str, doc: dict) -> str:
    """Alert kartı baseline-dakı formatda. Yalnız mənbənin göndərdiyi sahələr, cavab yoxdur."""
    src, p = doc["source"], doc["payload"]
    if src == "edr":
        f = p["file"]
        lines = [
            f"# {alert_id} · {p['detection']['name']}",
            "- Mənbə: EDR",
            f"- Vaxt: {p['event_time'][:16].replace('T', ' ')} UTC",
            f"- Host: {p['device']['hostname']} · İstifadəçi: {p['user']}",
            f"- Fayl: {f['name']}",
            f"- SHA256: {f['sha256']}",
            f"- Yol: {f['path']}",
            f"- EDR severity: {p['detection']['severity']}",
        ]
    elif src == "proxy":
        lines = [
            f"# {alert_id} · Web request via proxy",
            "- Mənbə: WebProxy",
            f"- Vaxt: {p['@timestamp'][:16].replace('T', ' ')} UTC",
            f"- Mənbə IP: {p['source']['ip']} · İstifadəçi: {p['user']['name']}",
            f"- URL: {p['url']['full']}",
            f"- Proxy qərarı: {p['event']['action']}",
            f"- Status kodu: {p['http']['response']['status_code']}",
        ]
    elif src == "wazuh":
        d = p["data"]
        lines = [
            f"# {alert_id} · {p['rule']['description']}",
            "- Mənbə: Wazuh",
            f"- Vaxt: {p['timestamp'][:16].replace('T', ' ')} UTC",
            f"- Agent: {p['agent']['name']} · İstifadəçi: {d['dstuser']}",
            f"- Mənbə IP: {d['srcip']}",
            f"- Qayda: {p['rule']['id']} (level {p['rule']['level']})",
            f"- Log: {p['full_log']}",
        ]
    else:
        raise ValueError(f"naməlum mənbə: {src}")
    return "\n".join(lines) + "\n"


def plan() -> None:
    labels = {r["alert_id"]: r["verdict"] for r in csv.DictReader(EXPECTED.open(encoding="utf-8"))}
    ids_by_type: dict[str, list[str]] = defaultdict(list)
    for f in RAW.glob("*.json"):
        ids_by_type[f.stem.split("-")[0]].append(f.stem)
    sample = pick_sample(ids_by_type, labels)
    rows = assign(sample)

    (OUT / "alerts").mkdir(parents=True, exist_ok=True)
    (OUT / "sample.txt").write_text("\n".join(sample) + "\n", encoding="utf-8")
    with (OUT / "assignment.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["analyst", "session", "pos", "alert_id"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    for old in (OUT / "alerts").glob("*.md"):
        old.unlink()
    for aid in sample:
        doc = json.loads((RAW / f"{aid}.json").read_text(encoding="utf-8"))
        (OUT / "alerts" / f"{aid}.md").write_text(card(aid, doc), encoding="utf-8")

    types = Counter(a.split("-")[0] for a in sample)
    print(f"Nümunə: {len(sample)} alert · " + ", ".join(f"{t} {n}" for t, n in types.items()))
    print("Hər tipdə malicious, clean və uncertain var (ID-lər çap olunmur)")
    for a in ANALYSTS:
        mine = [r for r in rows if r["analyst"] == a]
        s = Counter(r["session"] for r in mine)
        print(
            f"  {a}: {len(mine)} alert · oturumlar: " + ", ".join(f"{k}: {v}" for k, v in sorted(s.items()))
        )
    print(f"Yazıldı: {OUT}/sample.txt, assignment.csv, alerts/ ({len(sample)} kart)")


# ---------------------------------------------------------------- check
def p90(xs: list[float]) -> float:
    xs = sorted(xs)
    k = (len(xs) - 1) * 0.9
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def summarize(rows: list[dict], sample: list[str]) -> dict:
    """Hər (alert, analitik) üçün S1–S8 cəmi. Outlier qeydli addımı olan ölçmə çıxarılır."""
    steps: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)
    outlier: set[tuple[str, str]] = set()
    for r in rows:
        key = (r["alert_id"], r["analyst"])
        steps[key][r["step"]] = steps[key].get(r["step"], 0.0) + float(r["duration_s"])
        if "outlier" in (r.get("note") or ""):
            outlier.add(key)
    complete = {k: sum(v.values()) for k, v in steps.items() if len(v) == 8 and k not in outlier}
    per_alert = Counter(a for a, _ in complete)
    totals = list(complete.values())
    by_type: dict[str, list[float]] = defaultdict(list)
    for (a, _), t in complete.items():
        by_type[a.split("-")[0]].append(t)
    return {
        "measurements": len(complete),
        "incomplete": sorted(f"{a}/{n}" for (a, n), v in steps.items() if len(v) != 8),
        "outliers": len(outlier),
        "alerts_ok": sum(1 for a in sample if per_alert[a] >= 2),
        "alerts_short": sorted(a for a in sample if per_alert[a] < 2),
        "types_ok": {
            t: sum(1 for a in sample if a.startswith(t + "-") and per_alert[a] >= 2) for t in PER_TYPE
        },
        "unknown": sorted({a for a, _ in steps} - set(sample)),
        "median_s": statistics.median(totals) if totals else None,
        "p90_s": p90(totals) if totals else None,
        "by_type": {t: statistics.median(v) for t, v in sorted(by_type.items())},
    }


def baseline_unchanged() -> bool | None:
    try:
        r = subprocess.run(
            ["git", "diff", "--quiet", "origin/main", "--", str(BASELINE)], capture_output=True
        )
    except FileNotFoundError:  # pragma: no cover
        return None
    return {0: True, 1: False}.get(r.returncode)  # 128: origin/main yoxdur → bilinmir


def merge() -> list[dict]:
    """Hər analitik öz faylına yazır (PR konflikti olmasın). 6.2 birləşmiş manual_raw.csv-ni oxuyur."""
    rows: list[dict] = []
    fields: list[str] = []
    for f in sorted((OUT / "raw").glob("*.csv")):
        with f.open(encoding="utf-8") as fh:
            r = csv.DictReader(fh)
            fields = fields or list(r.fieldnames or [])
            rows += list(r)
    if rows:
        rows.sort(key=lambda r: r["t_start"])
        with (OUT / "manual_raw.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
    return rows


def check() -> int:
    sample = (OUT / "sample.txt").read_text(encoding="utf-8").split()
    rows = merge()
    s = summarize(rows, sample)
    ok = True

    def line(good: bool, text: str) -> None:
        nonlocal ok
        ok &= good
        print(f"  {'OK  ' if good else 'FAIL'} {text}")

    print("6.1 manual ölçmə · yoxlama")
    line(s["alerts_ok"] == len(sample), f"ən azı 2 tam ölçmə: {s['alerts_ok']}/{len(sample)} alert")
    if s["alerts_short"]:
        print(f"       çatmayan: {' '.join(s['alerts_short'])}")
    line(
        all(n >= 6 for n in s["types_ok"].values()),
        "hər tipdən ən azı 6: " + ", ".join(f"{t} {n}" for t, n in s["types_ok"].items()),
    )
    line(
        not s["unknown"],
        f"nümunədən kənar alert yoxdur{': ' + ' '.join(s['unknown']) if s['unknown'] else ''}",
    )
    bu = baseline_unchanged()
    line(
        bu is not False,
        "docs/baseline/baseline_raw.csv dəyişməyib"
        if bu is not False
        else "baseline faylı dəyişib → git checkout origin/main -- docs/baseline/baseline_raw.csv",
    )
    if s["incomplete"]:
        print(f"  WARN yarımçıq ölçmə (8 addım yoxdur): {' '.join(s['incomplete'])}")
    print(f"\nTam ölçmə: {s['measurements']} · outlier kimi çıxarılan: {s['outliers']}")
    if s["median_s"] is not None:
        print(f"Median {s['median_s'] / 60:.1f} dəq · P90 {s['p90_s'] / 60:.1f} dəq")
        print("Tip üzrə median: " + ", ".join(f"{t} {v / 60:.1f} dəq" for t, v in s["by_type"].items()))
    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["plan", "check"])
    a = ap.parse_args()
    if a.action == "plan":
        plan()
    else:
        sys.exit(check())


if __name__ == "__main__":
    main()
