"""6.3 dəqiqlik: sistemin qərarlarını dataset/expected.csv ilə müqayisə edir və auto-close təhlükəsizliyini ölçür.

    python -m tools.accuracy --label cold     # bazadakı son qaçış → decisions_cold.csv, accuracy_cold.md
    python -m tools.accuracy summary          # bütün ssenarilər + manual (6.1) → accuracy.md

expected.csv üç sinif işlədir: malicious, clean, uncertain. Sistem dörd: malicious, suspicious, clean, unknown.
Müqayisədə sistemin suspicious və unknown cavabları "uncertain" sayılır (hər ikisi "insan baxmalıdır" deməkdir).

Auto-close təhlükəsizliyi (shadow qərarları daxil, çünki shadow=true "sistem bunu bağlayardı" deməkdir):
  FN = insan baxmalı olan (malicious və ya uncertain) alert-i sistem bağlayardı  → 0 olmalıdır
  FP = təmiz alert-i sistem insana göndərdi                                       → analitikin vaxtı
Bazaya host-dan qoşulur: MEASURE_DATABASE_URL və ya .env-dəki POSTGRES_PASSWORD ilə localhost:5432.
"""

import argparse
import asyncio
import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from tools.compute_mttr import SCENARIOS, dsn, table

EXPECTED = Path("dataset/expected.csv")
OUT = Path("docs/measure")
MANUAL = OUT / "manual_raw.csv"
CLASSES = ["malicious", "uncertain", "clean"]
SYSTEM = {"malicious": "malicious", "suspicious": "uncertain", "unknown": "uncertain", "clean": "clean"}
MANUAL_MAP = {"malicious": "malicious", "suspicious": "uncertain", "clean": "clean"}

SQL = """
SELECT DISTINCT ON (a.source_ref) a.source_ref, d.verdict, d.severity_id, d.priority, d.action,
       d.rule_id, d.shadow
FROM decisions d JOIN alerts a USING (alert_id)
ORDER BY a.source_ref, d.decided_at DESC
"""


# ---------------------------------------------------------------- metrikalar
def kappa(a: list[str], b: list[str]) -> float | None:
    """Cohen's kappa: təsadüfi razılaşmanı çıxdıqdan sonra iki qiymətləndiricinin razılaşması."""
    n = len(a)
    if n == 0:
        return None
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def matrix(truth: list[str], pred: list[str]) -> list[list[str]]:
    c = Counter(zip(truth, pred))
    return [[f"həqiqət: {t}"] + [str(c[(t, p)]) for p in CLASSES] for t in CLASSES]


def safety(rows: list[dict]) -> dict:
    tp = fn = fp = tn = 0
    for r in rows:
        human = r["expected"] != "clean"
        close = r["would_close"]
        tp += human and not close
        fn += human and close
        fp += (not human) and not close
        tn += (not human) and close
    n = max(1, len(rows))
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "recall": tp / max(1, tp + fn),
        "close_share": (tn + fn) / n,
    }


def load_expected() -> dict[str, str]:
    with EXPECTED.open(encoding="utf-8") as f:
        return {r["alert_id"]: r["verdict"] for r in csv.DictReader(f)}


# ---------------------------------------------------------------- bir qaçış
async def fetch() -> list[dict]:
    import asyncpg

    conn = await asyncpg.connect(dsn())
    try:
        return [dict(r) for r in await conn.fetch(SQL)]
    finally:
        await conn.close()


def evaluate(decs: list[dict], expected: dict[str, str]) -> list[dict]:
    out = []
    for d in decs:
        if d["source_ref"] not in expected:
            continue
        out.append(
            {
                "alert_id": d["source_ref"],
                "expected": expected[d["source_ref"]],
                "system_verdict": d["verdict"],
                "system": SYSTEM.get(d["verdict"], "uncertain"),
                "priority": d["priority"],
                "action": d["action"],
                "rule_id": d["rule_id"],
                "shadow": bool(d["shadow"]),
                "would_close": d["action"] == "auto_close" or bool(d["shadow"]),
            }
        )
    return out


def report(label: str, rows: list[dict]) -> str:
    truth = [r["expected"] for r in rows]
    pred = [r["system"] for r in rows]
    s = safety(rows)
    acc = sum(t == p for t, p in zip(truth, pred)) / max(1, len(rows))
    k = kappa(truth, pred)
    lines = [
        f"# Dəqiqlik · {label}",
        "",
        f"Tarix: {datetime.now().astimezone():%Y-%m-%d %H:%M} · Müqayisə olunan alert: {len(rows)}",
        "",
        "## Verdict (sətir: expected.csv, sütun: sistem; suspicious və unknown = uncertain)",
        "",
    ]
    lines += table([""] + [f"sistem: {c}" for c in CLASSES], matrix(truth, pred))
    raw = Counter(r["system_verdict"] for r in rows)
    lines += [
        "",
        f"Sistemin xam cavabları: {', '.join(f'{k} {v}' for k, v in sorted(raw.items()))}",
        "",
        f"- Verdict dəqiqliyi: {acc:.1%}",
        f"- Cohen's kappa (sistem vs həqiqət): {k:.2f}" if k is not None else "- Cohen's kappa: —",
        "",
        "## Auto-close təhlükəsizliyi (shadow qərarları daxil)",
        "",
        f"- TP {s['tp']} · **FN {s['fn']}** · FP {s['fp']} · TN {s['tn']}",
        f"- Recall (insana çatmalı olanlardan çatanlar): {s['recall']:.1%}",
        f"- Auto-close payı (sistemin bağlayacağı alert-lər): {s['close_share']:.1%}",
    ]
    if s["fn"]:
        bad = [r for r in rows if r["expected"] != "clean" and r["would_close"]]
        lines += ["", "**DİQQƏT: FN var. Auto-close açılmamalıdır.**", ""]
        lines += table(
            ["Alert", "Həqiqət", "Sistem", "Qayda"],
            [[r["alert_id"], r["expected"], r["system_verdict"], r["rule_id"]] for r in bad],
        )
    wrong = [r for r in rows if r["expected"] != r["system"]]
    lines += ["", "## Uyğun gəlməyən alert-lər", ""]
    lines += (
        table(
            ["Alert", "Həqiqət", "Sistem", "Qayda", "Bağlayardı"],
            [
                [
                    r["alert_id"],
                    r["expected"],
                    r["system_verdict"],
                    r["rule_id"],
                    "bəli" if r["would_close"] else "xeyr",
                ]
                for r in wrong
            ],
        )
        if wrong
        else ["yoxdur"]
    )
    return "\n".join(lines) + "\n"


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------- xülasə
def load_decisions(label: str) -> list[dict] | None:
    p = OUT / f"decisions_{label}.csv"
    if not p.exists():
        return None
    with p.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["would_close"] = r["would_close"] == "True"
    return rows


def manual_verdicts(path: Path) -> dict[tuple[str, str], str]:
    out = {}
    with path.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["step"] == "S8" and r.get("verdict"):
                out[(r["alert_id"], r["analyst"])] = MANUAL_MAP.get(r["verdict"], "uncertain")
    return out


def summary(expected: dict[str, str]) -> str:
    lines = ["# 6.3 · Dəqiqlik: xülasə", "", f"Yeniləndi: {datetime.now().astimezone():%Y-%m-%d %H:%M}", ""]
    rows = []
    for sc in SCENARIOS:
        d = load_decisions(sc)
        if d is None:
            rows.append([sc, "—", "—", "—", "—", "—", "—"])
            continue
        s = safety(d)
        acc = sum(r["expected"] == r["system"] for r in d) / max(1, len(d))
        k = kappa([r["expected"] for r in d], [r["system"] for r in d])
        rows.append(
            [
                sc,
                str(len(d)),
                f"**{s['fn']}**",
                str(s["fp"]),
                f"{acc:.1%}",
                f"{k:.2f}",
                f"{s['close_share']:.1%}",
            ]
        )
    lines += ["## Sistem: ssenarilər üzrə", ""]
    lines += table(["Ssenari", "Alert", "FN", "FP", "Dəqiqlik", "Kappa", "Auto-close payı"], rows)
    lines += [
        "",
        'Chaos-da intel mənbələri WireMock-dur (hamısına "zərərli" cavab verir): orada verdict dəqiqliyi məna daşımır, '
        "yalnız FN (heç nə səhvən bağlanmırmı) vacibdir.",
    ]

    if MANUAL.exists():
        mv = manual_verdicts(MANUAL)
        by_an: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for (aid, an), v in mv.items():
            if aid in expected:
                by_an[an].append((expected[aid], v))
        lines += ["", "## Manual (6.1): analitiklər həqiqətə qarşı", ""]
        mrows = []
        for an, pairs in sorted(by_an.items()):
            t, p = [x for x, _ in pairs], [y for _, y in pairs]
            acc = sum(a == b for a, b in pairs) / len(pairs)
            fn = sum(a != "clean" and b == "clean" for a, b in pairs)
            mrows.append([an, str(len(pairs)), f"{acc:.1%}", f"{kappa(t, p):.2f}", str(fn)])
        lines += table(["Analitik", "Alert", "Dəqiqlik", "Kappa", "Zərərli/şübhəli → clean"], mrows)
        ans = sorted(by_an)
        if len(ans) == 2:
            both = sorted({a for a, n in mv if n == ans[0]} & {a for a, n in mv if n == ans[1]})
            a1 = [mv[(a, ans[0])] for a in both]
            a2 = [mv[(a, ans[1])] for a in both]
            agree = sum(x == y for x, y in zip(a1, a2)) / max(1, len(both))
            k = kappa(a1, a2)
            lines += [
                "",
                f"Analitiklər arası razılaşma ({len(both)} alert): {agree:.1%}, kappa {k:.2f}"
                if k is not None
                else "",
            ]
        cold = load_decisions("cold")
        if cold:
            sample = {a for a, _ in mv}
            same = [r for r in cold if r["alert_id"] in sample]
            if same:
                acc = sum(r["expected"] == r["system"] for r in same) / len(same)
                k = kappa([r["expected"] for r in same], [r["system"] for r in same])
                lines += [
                    "",
                    f"Sistem (cold) eyni {len(same)} alert-də: dəqiqlik {acc:.1%}, kappa {k:.2f}, FN {safety(same)['fn']}",
                ]
    lines += [
        "",
        "## Auto-close qərarı üçün şərtlər (runbook 6.3)",
        "",
        "| Şərt | Hədd |",
        "|---|---|",
        "| FN (shadow daxil), bütün ssenarilərdə | 0 |",
        "| QA nümunəsində səhv bağlama | 0 |",
        '| Rəy dövrəsində "sistem bağlayardı, analitik malicious dedi" | 0 |',
        "| Kill switch: AUTO_CLOSE_ENABLED=false 1 dəqiqədə dayandırır | test olunub |",
        "",
        '36 alert-lik testdə "FN 0" FN-in heç vaxt olmayacağı demək deyil: qoruyucular və QA nümunəsi qalıq riski azaldır.',
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", nargs="?", default="measure", choices=["measure", "summary"])
    ap.add_argument("--label", choices=SCENARIOS)
    a = ap.parse_args()
    expected = load_expected()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.action == "summary":
        text = summary(expected)
        (OUT / "accuracy.md").write_text(text, encoding="utf-8")
        print(text)
        return 0
    if not a.label:
        ap.error("--label lazımdır: cold, warm, burst və ya chaos")
    rows = evaluate(asyncio.run(fetch()), expected)
    if not rows:
        print("qərar tapılmadı (alert-lər emal olunubmu?)")
        return 1
    write_csv(OUT / f"decisions_{a.label}.csv", rows)
    text = report(a.label, rows)
    (OUT / f"accuracy_{a.label}.md").write_text(text, encoding="utf-8")
    print(text)
    return 0 if safety(rows)["fn"] == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
