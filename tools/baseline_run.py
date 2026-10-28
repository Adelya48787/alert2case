#!/usr/bin/env python3
"""Baseline ölçməsi üçün köməkçi: əmr yazmadan, Enter ilə addım-addım.

İşlətmək (repo qovluğunda, venv aktiv):
    python tools/baseline_run.py --analyst adile NET-03 NET-04 NET-01 ...
Alert sırası verilməsə, təsadüfi sıra yaradılır və .baseline_order_<analyst>.txt-də saxlanılır.

Vaxtı tools/timer.py yazır, bu skript yalnız onu sizin yerinizə çağırır.
Bitmiş alert-lər (S8 sətri olanlar) yenidən başladanda avtomatik keçilir.
"""

import argparse
import csv
import random
import subprocess
import sys
from pathlib import Path

ALERTS = Path("docs/baseline/alerts")
RAW = Path("docs/baseline/baseline_raw.csv")
TIMER = [sys.executable, "tools/timer.py"]

STEPS = [
    ("S1", "Kartı oxu", "alert-i başa düşəndə"),
    ("S2", "IOC-ları qeydinə köçür ([.] → .)", "köçürüləndə"),
    ("S3", "VirusTotal tab-ını aç, IOC-u yoxla", "nəticəni oxuyanda"),
    ("S4", "IP → AbuseIPDB · hash/URL → OTX", "nəticəni oxuyanda"),
    ("S5", "Nəticəni şərh et, verdict-ə qərar ver", "verdict qərara alınanda"),
    ("S6", "Priority seç (P1–P4)", "seçiləndə"),
    ("S7", "GitHub → New issue, şablonla doldur", "issue saxlananda"),
    ("S8", "WhatsApp qrupuna şablonla yaz", "mesaj göndəriləndə"),
]
VERDICTS = {"m": "malicious", "s": "suspicious", "c": "clean"}

B, D, G, Y, R, X = "\033[1m", "\033[2m", "\033[32m", "\033[33m", "\033[31m", "\033[0m"


def timer(*args: str) -> None:
    r = subprocess.run([*TIMER, *args], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"{R}timer xətası:{X} {r.stderr.strip() or r.stdout.strip()}")
        sys.exit(1)


def done_steps(analyst: str) -> dict[str, set[str]]:
    if not RAW.exists():
        return {}
    out: dict[str, set[str]] = {}
    with RAW.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["analyst"] == analyst:
                out.setdefault(r["alert_id"], set()).add(r["step"])
    return out


def ask(prompt: str, valid: dict[str, str]) -> str:
    while True:
        v = input(prompt).strip().lower()
        if v in valid:
            return valid[v]
        print(f"{Y}  Seçimlər: {', '.join(valid)}{X}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--analyst", required=True)
    p.add_argument("order", nargs="*", help="alert sırası, məs. NET-03 NET-04 ...")
    a = p.parse_args()

    if not ALERTS.is_dir():
        sys.exit("Repo qovluğunda deyilsiniz: cd ~/projects/alert2case")
    all_ids = sorted(f.stem for f in ALERTS.glob("*.md"))
    order_file = Path(f".baseline_order_{a.analyst}.txt")
    if a.order:
        order = [x.upper() for x in a.order]
    elif order_file.exists():
        order = order_file.read_text().split()
    else:
        order = all_ids[:]
        random.shuffle(order)
    bad = [x for x in order if x not in all_ids]
    if bad or len(set(order)) != len(all_ids):
        sys.exit(f"Sıra səhvdir. 12 kartın hamısı bir dəfə olmalıdır. Tanınmayan: {bad}")
    order_file.write_text(" ".join(order) + "\n")

    status = subprocess.run([*TIMER, "status", "--analyst", a.analyst], capture_output=True, text=True).stdout
    if "yoxdur" not in status:
        sys.exit(
            f"Açıq timer var: {status.strip()}\nƏvvəlcə: python tools/timer.py stop --analyst {a.analyst} --note outlier"
        )

    progress = done_steps(a.analyst)
    finished = {k for k, v in progress.items() if "S8" in v}
    todo = [x for x in order if x not in finished]
    print(f"{B}Baseline ölçməsi · {a.analyst}{X}  ({len(finished)}/12 bitib)")
    print(f"{D}Sıra: {' → '.join(order)}{X}")
    print(f"{D}Hər addım: Enter = addımı bitir və növbətisi başlasın · o + Enter = outlier qeydi{X}\n")

    for n, aid in enumerate(todo, start=len(finished) + 1):
        have = progress.get(aid, set())
        first = next(c for c, _, _ in STEPS if c not in have)
        input(f"{B}[{n}/12] {aid}{X} hazırsan? Tab-ları bağla, Enter basanda {first} başlayır… ")
        for i, (code, what, until) in enumerate(STEPS):
            if code in have:
                continue
            timer("start", aid, code, "--analyst", a.analyst)
            if code == "S1":
                print(f"{D}{'─' * 50}{X}")
                print((ALERTS / f"{aid}.md").read_text(encoding="utf-8").rstrip())
                print(f"{D}{'─' * 50}{X}")
            nxt = f" → sonra {STEPS[i + 1][0]}" if i < 7 else ""
            key = input(f"  {G}▶ {code}{X} {what}  {D}(Enter: {until}{nxt}){X} ").strip().lower()
            note = ["--note", "outlier"] if key == "o" else []
            if code == "S8":
                v = ask("    verdict  m=malicious s=suspicious c=clean: ", VERDICTS)
                pr = ask("    priority 1-4: ", {str(k): f"P{k}" for k in range(1, 5)})
                timer("stop", "--analyst", a.analyst, "--verdict", v, "--priority", pr, *note)
            else:
                timer("stop", "--analyst", a.analyst, *note)
        print(
            f"  {G}✓ {aid} bitdi{X}  {D}(fasilə lazımdırsa, indi ver: Ctrl+C ilə çıx, sonra eyni əmrlə davam et){X}\n"
        )

    print(f"{G}{B}12/12 bitdi.{X} Yoxlama:")
    rows = [r for r in csv.DictReader(RAW.open(encoding="utf-8")) if r["analyst"] == a.analyst]
    s8 = [r for r in rows if r["step"] == "S8"]
    print(f"  sətir: {len(rows)} (96 olmalıdır) · S8: {len(s8)} (12 olmalıdır)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}Dayandırıldı.{X} Açıq addım varsa, eyni əmrlə yenidən başlayanda xəbər veriləcək.")
