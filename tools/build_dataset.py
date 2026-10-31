"""dataset/iocs_*.csv → dataset/raw/*.json. Hər tip öz mənbəsinin formatında yazılır.

python -m tools.build_dataset
"""

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)  # hər dəfə eyni vaxt damğaları
SRC = Path("dataset")
OUT = SRC / "raw"
BASE = datetime(2026, 11, 2, 8, 0, tzinfo=timezone.utc)


def ts(i: int) -> str:
    return (BASE + timedelta(minutes=7 * i + random.randint(0, 5))).isoformat()


def wazuh(r: dict, i: int) -> dict:  # suspicious_login
    return {
        "id": r["alert_id"],
        "timestamp": ts(i),
        "rule": {
            "id": "5715",
            "level": 10,
            "description": "sshd: authentication success from unusual location",
        },
        "agent": {"name": r["host"]},
        "data": {"srcip": r["ioc"], "dstuser": r["user"]},
        "full_log": f"Accepted password for {r['user']} from {r['ioc']} port 52144 ssh2",
    }


def edr(r: dict, i: int) -> dict:  # malicious_hash
    return {
        "detection_id": r["alert_id"],
        "event_time": ts(i),
        "detection": {"name": "Suspicious executable", "severity": "high"},
        "device": {"hostname": r["host"]},
        "user": r["user"],
        "file": {
            "name": r["file_name"] or "unknown.exe",
            "path": f"C:\\Users\\{r['user']}\\Downloads\\",
            "sha256": r["ioc"],
        },
    }


def proxy(r: dict, i: int) -> dict:  # suspicious_url
    return {
        "@timestamp": ts(i),
        "event": {"id": r["alert_id"], "category": "web", "action": "allowed"},
        "url": {"full": r["ioc"]},  # defang saxlanılır: repo-da klik edilə bilən zərərli link olmasın
        "source": {"ip": r["src_ip"] or "10.0.4.21"},
        "user": {"name": r["user"]},
        "http": {"response": {"status_code": 200}},
    }


RENDER = {
    "suspicious_login": ("wazuh", wazuh),
    "malicious_hash": ("edr", edr),
    "suspicious_url": ("proxy", proxy),
}
FILES = ("iocs_hash.csv", "iocs_url.csv", "iocs_login.csv")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in FILES:
        rows += list(csv.DictReader(open(SRC / name, encoding="utf-8")))
    for i, r in enumerate(rows):
        source, fn = RENDER[r["alert_type"]]
        doc = {"source": source, "payload": fn(r, i)}
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        (OUT / f"{r['alert_id']}.json").write_text(text, encoding="utf-8")
    print(f"{len(rows)} alert yazıldı → {OUT}/")


if __name__ == "__main__":
    main()
