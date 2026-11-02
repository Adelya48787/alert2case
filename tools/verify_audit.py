"""audit_log hash zəncirini yoxlayır. İşə sal: python -m tools.verify_audit"""

import asyncio
import sys

from app import db
from app.audit.log import GENESIS, row_hash


async def main() -> int:
    p = await db.pool()
    rows = await p.fetch("SELECT * FROM audit_log ORDER BY id")
    prev = GENESIS
    for r in rows:
        if r["prev_hash"] != prev:
            print(f"ZƏNCİR QIRILIB: id={r['id']} prev_hash əvvəlki sətrə uyğun deyil")
            return 1
        expected = row_hash(
            prev, r["ts"], r["correlation_id"], r["stage"], r["event"], r["actor"], r["payload"]
        )
        if r["row_hash"] != expected:
            print(f"SƏTİR DƏYİŞDİRİLİB: id={r['id']} stage={r['stage']} event={r['event']}")
            return 1
        prev = r["row_hash"]
    print(f"OK: {len(rows)} sətir, zəncir bütövdür")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
