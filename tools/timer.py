#!/usr/bin/env python3
"""Manual baseline timer.
python tools/timer.py start HASH-03 S3 --analyst adile
python tools/timer.py stop --analyst adile [--verdict malicious --priority P2]
python tools/timer.py status --analyst adile
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STATE = Path(".timer_state.json")
OUT = Path("docs/baseline/baseline_raw.csv")
FIELDS = ["alert_id", "analyst", "step", "t_start", "t_end", "duration_s", "verdict", "priority", "note"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["start", "stop", "status"])
    p.add_argument("alert_id", nargs="?")
    p.add_argument("step", nargs="?", choices=[f"S{i}" for i in range(1, 9)])
    p.add_argument("--analyst", required=True)
    p.add_argument("--verdict", default="", choices=["", "malicious", "suspicious", "clean"])
    p.add_argument("--priority", default="", choices=["", "P1", "P2", "P3", "P4"])
    p.add_argument("--note", default="")
    a = p.parse_args()

    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    if a.action == "status":
        print(state.get(a.analyst, "açıq timer yoxdur"))
        return
    if a.action == "start":
        if not (a.alert_id and a.step):
            sys.exit("start üçün alert_id və step lazımdır")
        if a.analyst in state:
            sys.exit(f"Əvvəlcə açıq timer-i bağla: {state[a.analyst]}")
        state[a.analyst] = {"alert_id": a.alert_id, "step": a.step, "t0": time.time(), "t_start": now_iso()}
    else:
        cur = state.pop(a.analyst, None)
        if not cur:
            sys.exit("Açıq timer yoxdur")
        OUT.parent.mkdir(parents=True, exist_ok=True)
        new_file = not OUT.exists()
        with OUT.open("a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            if new_file:
                w.writeheader()
            w.writerow(
                {
                    "alert_id": cur["alert_id"],
                    "analyst": a.analyst,
                    "step": cur["step"],
                    "t_start": cur["t_start"],
                    "t_end": now_iso(),
                    "duration_s": round(time.time() - cur["t0"], 2),
                    "verdict": a.verdict,
                    "priority": a.priority,
                    "note": a.note,
                }
            )
    STATE.write_text(json.dumps(state))


if __name__ == "__main__":
    main()
