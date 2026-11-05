"""Analitik rəyindən qayda təklifləri hazırlayır. Heç vaxt production-u özü dəyişmir:
təklifi yeni git branch-ına commit edir, PR-ı insan açır və təsdiqləyir.
  python -m tools.tuner              # yalnız hesabat: docs/feedback/proposal-<tarix>.md
  python -m tools.tuner --apply      # + tuner/<tarix> branch-ı və commit
"""

import argparse
import asyncio
import copy
import subprocess
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path
import yaml
from app import db
from app.rules.engine import RuleSet
from tools.replay import evaluate, load_cases

WEIGHTS, RULES, ALLOW = (
    Path("rules/weights.yaml"),
    Path("rules/severity.yaml"),
    Path("context/allowlist.yaml"),
)
MIN_SAMPLES, FP_LIMIT, STEP, W_MIN, W_MAX = 10, 0.30, 0.05, 0.1, 0.6


def is_safe(before: dict, after: dict) -> bool:
    """Safety gate: false negative sayını artıran təklif heç vaxt keçmir."""
    return after["fn"] <= before["fn"]


async def feedback_rows() -> list[dict]:
    p = await db.pool()
    rows = await p.fetch(
        """SELECT f.*, a.doc FROM feedback f JOIN alerts a USING (alert_id)
           ORDER BY f.created_at"""
    )
    return [dict(r) for r in rows]


def rule_stats(rows: list[dict]) -> dict:
    s = defaultdict(Counter)
    for r in rows:
        s[r["rule_id"]]["n"] += 1
        auto_h, human_h = r["auto_verdict"] != "clean", r["human_verdict"] != "clean"
        s[r["rule_id"]]["fp"] += auto_h and not human_h
        s[r["rule_id"]]["fn"] += human_h and not auto_h
        s[r["rule_id"]]["sev_diff"] += (
            r["human_severity"] is not None and r["human_severity"] != r["auto_severity"]
        )
    return s


def propose_weights(rows: list[dict], weights: dict) -> tuple[dict, list[str]]:
    """Analitiklə daha çox razılaşan provider-in çəkisi artır, az razılaşanınkı azalır."""
    agree, total = Counter(), Counter()
    for r in rows:
        for p in r["doc"]["enrichment"]["providers"]:
            if p["status"] != "ok":
                continue
            prov_h = (p["score"] or 0) >= weights["thresholds"]["suspicious"]
            total[p["provider"]] += 1
            agree[p["provider"]] += prov_h == (r["human_verdict"] != "clean")
    new, notes = copy.deepcopy(weights), []
    for prov, n in total.items():
        if n < MIN_SAMPLES or prov not in new["providers"]:
            continue
        rate = agree[prov] / n
        w = new["providers"][prov]["weight"]
        if rate < 0.6:
            w = max(W_MIN, round(w - STEP, 2))
        elif rate > 0.85:
            w = min(W_MAX, round(w + STEP, 2))
        if w != new["providers"][prov]["weight"]:
            notes.append(
                f"{prov}: razılaşma {rate:.0%} ({n} rəy) → çəki {new['providers'][prov]['weight']} → {w}"
            )
            new["providers"][prov]["weight"] = w
    return new, notes


def propose_thresholds(stats: dict, weights: dict) -> tuple[dict, list[str]]:
    new, notes = copy.deepcopy(weights), []
    noisy = [rid for rid, c in stats.items() if c["n"] >= MIN_SAMPLES and c["fp"] / c["n"] > FP_LIMIT]
    if noisy:
        new["thresholds"]["suspicious"] = min(60, weights["thresholds"]["suspicious"] + 5)
        notes.append(
            f"FP payı > {FP_LIMIT:.0%} olan qaydalar {noisy}: suspicious həddi "
            f"{weights['thresholds']['suspicious']} → {new['thresholds']['suspicious']}"
        )
    return new, notes


def propose_allowlist(rows: list[dict]) -> list[dict]:
    fp_iocs = Counter()
    for r in rows:
        if r["human_verdict"] == "clean" and r["auto_verdict"] != "clean":
            for o in r["doc"]["observables"]:
                if not o["internal"] and o["type"] in ("ip", "domain"):
                    fp_iocs[(o["type"], o["value"])] += 1
    until = (date.today() + timedelta(days=30)).isoformat()
    return [
        {
            "type": "ip_cidr" if t == "ip" else "domain",
            "value": f"{v}/32" if t == "ip" else v,
            "owner": "tuner",
            "reason": f"{n} dəfə FP kimi qiymətləndirilib",
            "expires_at": until,
        }
        for (t, v), n in fp_iocs.items()
        if n >= 3
    ]


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    rows = await feedback_rows()
    weights = yaml.safe_load(WEIGHTS.read_text(encoding="utf-8"))
    rules = RuleSet.model_validate(yaml.safe_load(RULES.read_text(encoding="utf-8")))
    stats = rule_stats(rows)
    cand, notes_w = propose_weights(rows, weights)
    cand, notes_t = propose_thresholds(stats, cand)
    allow = propose_allowlist(rows)
    cases = await load_cases()
    before, after = evaluate(cases, weights, rules), evaluate(cases, cand, rules)
    safe = is_safe(before, after)
    today = date.today().isoformat()
    lines = [
        f"# Tuner təklifi · {today}",
        "",
        f"Rəy sayı: {len(rows)}",
        "",
        "| Qayda | n | FP | FN | severity fərqi |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| {rid} | {c['n']} | {c['fp']} | {c['fn']} | {c['sev_diff']} |" for rid, c in sorted(stats.items())
    ]
    proposals = [f"- {n}" for n in notes_w + notes_t] or ["- dəyişiklik yoxdur"]
    lines += ["", "## Təkliflər", *proposals]
    lines += [f"- allowlist təklifi: {a['type']} {a['value']} ({a['reason']})" for a in allow]
    lines += [
        "",
        "## Replay",
        f"- indi: {before}",
        f"- təkliflə: {after}",
        f"- qərar: {'TƏHLÜKƏSİZ' if safe else 'RƏDD: FN sayı artır'}",
    ]
    out = Path(f"docs/feedback/proposal-{today}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if args.apply and safe and (notes_w or notes_t or allow):
        branch = f"tuner/{today}"
        subprocess.run(["git", "switch", "-c", branch], check=True)
        cand["version"] = f"{today}.tuner"
        WEIGHTS.write_text(yaml.safe_dump(cand, sort_keys=False, allow_unicode=True), encoding="utf-8")
        if allow:
            doc = yaml.safe_load(ALLOW.read_text(encoding="utf-8")) or {"entries": []}
            doc["entries"] += allow
            ALLOW.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
        subprocess.run(["git", "add", str(WEIGHTS), str(ALLOW), str(out)], check=True)
        subprocess.run(["git", "commit", "-m", f"chore(tuner): feedback-based proposal {today}"], check=True)
        print(f"\nBranch {branch} hazırdır: git push -u origin {branch} və GitHub-da PR açın.")
    elif args.apply:
        print("\nTətbiq olunmadı: ya dəyişiklik yoxdur, ya da replay FN artımı göstərir.")


if __name__ == "__main__":
    asyncio.run(main())
