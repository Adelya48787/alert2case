"""6.2 avtomatik MTTR: hər alert üçün "qəbul → hərəkət" və "qəbul → bildiriş" müddəti, manual ölçmə (6.1) ilə müqayisə.

    python -m tools.compute_mttr --label cold                # bitməsini gözləyir, auto_cold.csv və mttr_cold.md yazır
    python -m tools.compute_mttr --label warm --wait 0       # gözləmədən, olduğu kimi
    python -m tools.compute_mttr summary                     # mövcud auto_*.csv-lərdən summary.md

Başlanğıc: API-nin alert-i qəbul etdiyi an (alerts.received_at). Növbədə gözləmə də MTTR-ə daxildir.
Son: audit-də ilk "act" hadisəsi (case_created, case_linked, closed_auto).
Bazaya host-dan qoşulur: MEASURE_DATABASE_URL və ya .env-dəki POSTGRES_PASSWORD ilə localhost:5432.
Yalnız standart kitabxana və asyncpg istifadə edir (pandas lazım deyil).
"""

import argparse
import asyncio
import csv
import math
import os
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ACTIONS = ("case_created", "case_linked", "closed_auto")
OPEN_STATUSES = ("new", "enriched", "decided")
SCENARIOS = ("cold", "warm", "burst", "chaos")
OUT = Path("docs/measure")
MANUAL = OUT / "manual_raw.csv"

SQL = """
SELECT a.source_ref, a.alert_type, a.status, a.received_at AS t_received,
       (SELECT min(l.ts) FROM audit_log l
         WHERE l.correlation_id = a.alert_id AND l.stage = 'act' AND l.event = ANY($2::text[])) AS t_action,
       (SELECT min(l.ts) FROM audit_log l
         WHERE l.correlation_id = a.alert_id AND l.stage = 'notify') AS t_notify
FROM alerts a WHERE a.received_at >= $1
ORDER BY a.received_at
"""


# ---------------------------------------------------------------- statistika
def p90(xs: list[float]) -> float:
    s = sorted(xs)
    k = (len(s) - 1) * 0.9
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def stats(xs: list[float]) -> dict:
    if not xs:
        return {"n": 0, "median": None, "p90": None, "mean": None, "max": None}
    return {
        "n": len(xs),
        "median": statistics.median(xs),
        "p90": p90(xs),
        "mean": statistics.fmean(xs),
        "max": max(xs),
    }


def fmt(v: float | None, nd: int = 2) -> str:
    return "—" if v is None else f"{v:.{nd}f}"


def table(head: list[str], rows: list[list[str]]) -> list[str]:
    out = [
        "| " + " | ".join(head) + " |",
        "|" + "|".join("---:" if i else "---" for i in range(len(head))) + "|",
    ]
    return out + ["| " + " | ".join(r) + " |" for r in rows]


def reduction(manual: float | None, auto: float | None) -> str:
    if not manual or auto is None:
        return "—"
    return f"{(1 - auto / manual) * 100:.1f}%"


# ---------------------------------------------------------------- məlumat
def dsn() -> str:
    if os.environ.get("MEASURE_DATABASE_URL"):
        return os.environ["MEASURE_DATABASE_URL"]
    from dotenv import dotenv_values

    pw = dotenv_values(".env").get("POSTGRES_PASSWORD") or ""
    return f"postgresql://soc:{pw}@localhost:5432/alert2case"


async def fetch(since: datetime, wait_s: int) -> list[dict]:
    import asyncpg

    conn = await asyncpg.connect(dsn())
    try:
        deadline = time.monotonic() + wait_s
        while True:
            rows = [dict(r) for r in await conn.fetch(SQL, since, list(ACTIONS))]
            open_ = [r for r in rows if r["status"] in OPEN_STATUSES]
            if rows and not open_:
                return rows
            if time.monotonic() >= deadline:
                if open_:
                    print(
                        f"DİQQƏT: {len(open_)} alert hələ emal olunur, olduğu kimi hesablanır",
                        file=sys.stderr,
                    )
                return rows
            print(f"  gözlənilir: {len(rows)} alert, emalda {len(open_)}", file=sys.stderr)
            await asyncio.sleep(10)
    finally:
        await conn.close()


def durations(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        t0 = r["t_received"]
        out.append(
            {
                "source_ref": r["source_ref"],
                "alert_type": r["alert_type"],
                "prefix": r["source_ref"].split("-")[0],
                "status": r["status"],
                "action_s": (r["t_action"] - t0).total_seconds() if r["t_action"] else None,
                "notify_s": (r["t_notify"] - t0).total_seconds() if r["t_notify"] else None,
            }
        )
    return out


def manual_totals(path: Path) -> list[dict]:
    """Hər (alert, analitik) üçün S1–S8 cəmi. Outlier qeydli addımı olan ölçmə çıxarılır."""
    steps: dict[tuple[str, str], float] = defaultdict(float)
    count: dict[tuple[str, str], int] = defaultdict(int)
    outlier: set[tuple[str, str]] = set()
    with path.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            k = (r["alert_id"], r["analyst"])
            steps[k] += float(r["duration_s"])
            count[k] += 1
            if "outlier" in (r.get("note") or ""):
                outlier.add(k)
    return [
        {"alert_id": a, "analyst": n, "prefix": a.split("-")[0], "total_s": t}
        for (a, n), t in steps.items()
        if count[(a, n)] == 8 and (a, n) not in outlier
    ]


# ---------------------------------------------------------------- hesabat
def report(label: str, d: list[dict], manual: list[dict] | None) -> str:
    done = [x for x in d if x["action_s"] is not None]
    lines = [
        f"# Avtomatik MTTR · {label}",
        "",
        f"Tarix: {datetime.now().astimezone():%Y-%m-%d %H:%M} · "
        f"Alert: {len(d)}, hərəkətə çatan: {len(done)}, çatmayan: {len(d) - len(done)}",
        "",
        "## Qəbul → hərəkət (saniyə)",
        "",
    ]
    rows = []
    for p in sorted({x["prefix"] for x in done}):
        s = stats([x["action_s"] for x in done if x["prefix"] == p])
        rows.append([p, str(s["n"]), fmt(s["median"]), fmt(s["p90"]), fmt(s["mean"]), fmt(s["max"])])
    s = stats([x["action_s"] for x in done])
    rows.append(["**Hamısı**", str(s["n"]), fmt(s["median"]), fmt(s["p90"]), fmt(s["mean"]), fmt(s["max"])])
    lines += table(["Tip", "n", "Median", "P90", "Orta", "Max"], rows)
    n = stats([x["notify_s"] for x in d if x["notify_s"] is not None])
    lines += [
        "",
        f"Qəbul → bildiriş (bütün prioritetlər): median {fmt(n['median'])} s, P90 {fmt(n['p90'])} s",
    ]

    if manual:
        sample = {m["alert_id"] for m in manual}
        auto_s = [x for x in done if x["source_ref"] in sample]
        lines += [
            "",
            "## Manual ilə müqayisə (eyni alert-lər, median)",
            "",
            f"Manual: {len(manual)} ölçmə, {len(sample)} alert. Avtomatik: həmin alert-lərdən {len(auto_s)}.",
            "",
        ]
        rows = []
        for p in sorted({m["prefix"] for m in manual}):
            mm = stats([m["total_s"] for m in manual if m["prefix"] == p])["median"]
            aa = stats([x["action_s"] for x in auto_s if x["prefix"] == p])["median"]
            rows.append([p, fmt(mm, 0), fmt(aa), reduction(mm, aa)])
        mm = stats([m["total_s"] for m in manual])["median"]
        aa = stats([x["action_s"] for x in auto_s])["median"]
        rows.append(["**Hamısı**", fmt(mm, 0), fmt(aa), reduction(mm, aa)])
        lines += table(["Tip", "Manual median (s)", "Avtomatik median (s)", "Azalma"], rows)
        lines += [
            "",
            'Qeyd: avtomatik vaxt "case hazırdır" anına qədərdir. Analitik P1/P2 case-i yenə oxuyur və araşdırır.',
        ]
    return "\n".join(lines) + "\n"


def write_csv(path: Path, d: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(d[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(d)


def load_auto(label: str) -> list[dict] | None:
    p = OUT / f"auto_{label}.csv"
    if not p.exists():
        return None
    with p.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["action_s"] = float(r["action_s"]) if r["action_s"] else None
    return rows


def summary(manual: list[dict] | None) -> str:
    sample = {m["alert_id"] for m in manual} if manual else set()
    mm = stats([m["total_s"] for m in manual])["median"] if manual else None
    lines = [
        "# 6.2 · Avtomatik ölçmə: xülasə",
        "",
        f"Yeniləndi: {datetime.now().astimezone():%Y-%m-%d %H:%M}",
        "",
    ]
    rows = []
    for sc in SCENARIOS:
        d = load_auto(sc)
        if d is None:
            rows.append([sc, "—", "—", "—", "—", fmt(mm, 0), "—", "—"])
            continue
        done = [x["action_s"] for x in d if x["action_s"] is not None]
        s = stats(done)
        same = stats([x["action_s"] for x in d if x["action_s"] is not None and x["source_ref"] in sample])
        rows.append(
            [
                sc,
                str(len(d)),
                str(len(d) - len(done)),
                fmt(s["median"]),
                fmt(s["p90"]),
                fmt(mm, 0),
                fmt(same["median"]),
                reduction(mm, same["median"]),
            ]
        )
    lines += table(
        [
            "Ssenari",
            "Alert",
            "Çatmayan",
            "Median (s)",
            "P90 (s)",
            "Manual median (s)",
            "Eyni 20 alert median (s)",
            "Azalma",
        ],
        rows,
    )
    lines += [
        "",
        "- **cold:** boş cache, 10 saniyədə bir alert (real SOC tempi).",
        "- **warm:** eyni alert-lər, intel cache dolu.",
        "- **burst:** 36 alert bir anda; vaxtın çoxu VirusTotal limitinin (dəqiqədə 4) növbəsindədir.",
        "- **chaos:** intel mənbələri test stekində 3 s (±1 s) gecikmə ilə.",
        "",
        'Avtomatik vaxt "case hazırdır" anına qədərdir. Dürüst müqayisə: analitikin triaja sərf etdiyi vaxt '
        "manual median-dan avtomatik median-a düşdü; analitik P1/P2 case-i yenə araşdırır.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", nargs="?", default="measure", choices=["measure", "summary"])
    ap.add_argument("--label", choices=SCENARIOS)
    ap.add_argument("--since", default="1970-01-01T00:00:00+00:00", help="ISO tarix; default: hamısı")
    ap.add_argument("--wait", type=int, default=1200, help="emalın bitməsini neçə saniyə gözləmək")
    ap.add_argument("--manual", default=str(MANUAL))
    a = ap.parse_args()
    manual = manual_totals(Path(a.manual)) if Path(a.manual).exists() else None
    OUT.mkdir(parents=True, exist_ok=True)

    if a.action == "summary":
        text = summary(manual)
        (OUT / "summary.md").write_text(text, encoding="utf-8")
        print(text)
        return 0

    if not a.label:
        ap.error("--label lazımdır: cold, warm, burst və ya chaos")
    since = datetime.fromisoformat(a.since)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    d = durations(asyncio.run(fetch(since, a.wait)))
    if not d:
        print("alert tapılmadı (make reset-data-dan sonra alert göndərilibmi?)")
        return 1
    write_csv(OUT / f"auto_{a.label}.csv", d)
    text = report(a.label, d, manual)
    (OUT / f"mttr_{a.label}.md").write_text(text, encoding="utf-8")
    print(text)
    missing = sum(1 for x in d if x["action_s"] is None)
    return 0 if missing == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
