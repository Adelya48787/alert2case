"""Audit log: hash zənciri ilə dəyişdirilə bilməyən jurnal."""

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

from app import db

GENESIS = "0" * 64


def row_hash(prev: str, ts: datetime, cid: UUID, stage: str, event: str, actor: str, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, default=str)
    raw = f"{prev}|{ts.isoformat()}|{cid}|{stage}|{event}|{actor}|{body}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def audit(
    cid: UUID, stage: str, event: str, payload: dict | None = None, actor: str = "system"
) -> None:
    payload = payload or {}
    p = await db.pool()
    async with p.acquire() as c, c.transaction():
        await c.execute("SELECT pg_advisory_xact_lock(4242)")  # zəncir ardıcıl yazılır
        prev = await c.fetchval("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1") or GENESIS
        ts = datetime.now(timezone.utc)
        h = row_hash(prev, ts, cid, stage, event, actor, payload)
        await c.execute(
            """INSERT INTO audit_log (ts, correlation_id, stage, event, actor, payload, prev_hash, row_hash)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
            ts,
            cid,
            stage,
            event,
            actor,
            payload,
            prev,
            h,
        )
