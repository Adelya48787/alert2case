"""dataset/raw/*.json → dataset/normalized/*.json (vahid schema).

python -m tools.normalize_dataset
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from app.normalize import normalize

RECEIVED_AT = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)  # sabit: fayllar hər dəfə eyni çıxır


def main() -> None:
    out = Path("dataset/normalized")
    out.mkdir(parents=True, exist_ok=True)
    ok = 0
    for f in sorted(Path("dataset/raw").glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        a = normalize(doc["source"], doc["payload"], RECEIVED_AT)
        (out / f.name).write_text(a.model_dump_json(indent=2) + "\n", encoding="utf-8")
        print(f"{f.stem:10s} {a.alert_type:17s} obs={len(a.observables)} fp={a.fingerprint[:8]}")
        ok += 1
    print(f"{ok} alert normalizə olundu")


if __name__ == "__main__":
    main()
