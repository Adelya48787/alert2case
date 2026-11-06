"""Demo və test üçün: analitik rəyini dataset/expected.csv-dən yaradır (hər alert-in son versiyası üçün).
Real rəy TheHive-dan gəlir (5.1). Bu alət yalnız rəy dövrəsini kiçik dataset-də göstərmək üçündür:
rəylər analyst=demo, comment=expected.csv ilə yazılır, hesabatda süni olduqları görünür.

  python -m tools.feedback_from_expected               # bütün alert-lər
  python -m tools.feedback_from_expected --limit 10
"""

import argparse
import asyncio
from collections import Counter

from app import db
from app.feedback.collector import FeedbackIn, record
from tools.replay import load_expected

# expected.csv etiketi → FeedbackIn (yalnız 3 dəyər qəbul edir). "uncertain" və "unknown" insan
# baxmalı olan haldır, yəni suspicious (replay.needs_human ilə eyni məntiq).
HUMAN = {"malicious": "malicious", "clean": "clean", "suspicious": "suspicious"}


def to_human(label: str) -> str:
    return HUMAN.get(label.strip().lower(), "suspicious")


def load_labels() -> dict[str, str]:
    return load_expected()


async def latest_decided_alerts() -> list[dict]:
    p = await db.pool()
    rows = await p.fetch(
        """SELECT DISTINCT ON (a.source_ref) a.alert_id, a.source_ref FROM alerts a
           JOIN decisions d USING (alert_id) ORDER BY a.source_ref, a.received_at DESC"""
    )
    return [dict(r) for r in rows]


async def run(limit: int = 0) -> dict:
    labels = load_labels()
    stats: Counter = Counter()
    for r in (await latest_decided_alerts())[: limit or None]:
        label = labels.get(r["source_ref"])
        if not label:
            continue
        res = await record(
            FeedbackIn(
                alert_id=r["alert_id"],
                human_verdict=to_human(label),
                analyst="demo",
                source="manual",
                comment="expected.csv",
            )
        )
        if "error" not in res:
            stats["agree" if res.get("agree") else "disagree"] += 1
    return dict(stats)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    print(await run(args.limit))


if __name__ == "__main__":
    asyncio.run(main())
