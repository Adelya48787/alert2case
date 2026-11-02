"""PostgreSQL: bağlantı pool-u, alert-in yazılması və dedup."""

import json
from uuid import UUID

import asyncpg

from app.config import settings
from app.schemas.alert import NormalizedAlert

_pool: asyncpg.Pool | None = None


async def _init(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb", schema="pg_catalog", encoder=lambda v: json.dumps(v, default=str), decoder=json.loads
    )


async def pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=10, init=_init)
    return _pool


async def upsert_alert(a: NormalizedAlert, window_s: int) -> tuple[UUID, bool]:
    """Yeni alert-i yazır. Pəncərə daxilində eyni fingerprint varsa (id, True) qaytarır."""
    p = await pool()
    async with p.acquire() as c, c.transaction():
        # eyni fingerprint-i iki worker eyni anda yazmasın
        await c.execute("SELECT pg_advisory_xact_lock(hashtext($1))", a.fingerprint)
        row = await c.fetchrow(
            """SELECT alert_id FROM alerts
               WHERE fingerprint = $1 AND last_seen > now() - make_interval(secs => $2)
               ORDER BY last_seen DESC LIMIT 1""",
            a.fingerprint,
            float(window_s),
        )
        if row:
            await c.execute(
                """UPDATE alerts SET occurrence_count = occurrence_count + 1,
                   last_seen = now() WHERE alert_id = $1""",
                row["alert_id"],
            )
            return row["alert_id"], True
        await c.execute(
            """INSERT INTO alerts (alert_id, source_ref, source_system, alert_type,
                                   fingerprint, received_at, doc)
               VALUES ($1, $2, $3, $4, $5, $6, $7)""",
            a.alert_id,
            a.source_ref,
            a.source_system,
            a.alert_type,
            a.fingerprint,
            a.received_at,
            a.model_dump(mode="json"),
        )
        return a.alert_id, False


async def save_alert(a: NormalizedAlert, status: str) -> None:
    p = await pool()
    await p.execute(
        "UPDATE alerts SET doc = $2, status = $3 WHERE alert_id = $1",
        a.alert_id,
        a.model_dump(mode="json"),
        status,
    )


async def alerts_needing_reenrich(hours: int = 24, limit: int = 50) -> list:
    p = await pool()
    return await p.fetch(
        """SELECT doc, status FROM alerts
           WHERE doc->'enrichment'->>'status' IN ('partial', 'failed')
             AND status NOT IN ('closed_auto', 'closed')
             AND received_at > now() - make_interval(hours => $1)
           ORDER BY received_at LIMIT $2""",
        hours,
        limit,
    )


# ---------- Phase 4: qərarlar və case-lər ----------
async def save_decision(a: NormalizedAlert, d) -> None:
    p = await pool()
    await p.execute(
        """INSERT INTO decisions (alert_id, verdict, severity_id, priority, action, rule_id,
                                  rule_version, reasons, shadow, decided_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
        a.alert_id,
        d.verdict,
        int(d.severity_id),
        d.priority,
        d.action,
        d.rule_id,
        d.rule_version,
        d.reasons,
        d.shadow,
        d.decided_at,
    )


async def save_case(a: NormalizedAlert, ref) -> None:
    p = await pool()
    await p.execute(
        """INSERT INTO cases (alert_id, fingerprint, backend, case_id, case_url)
           VALUES ($1, $2, $3, $4, $5) ON CONFLICT (alert_id) DO NOTHING""",
        a.alert_id,
        a.fingerprint,
        ref.backend,
        ref.case_id,
        ref.url,
    )


async def find_recent_case(fingerprint: str, hours: int = 24) -> dict | None:
    p = await pool()
    row = await p.fetchrow(
        """SELECT backend, case_id, case_url AS url FROM cases
           WHERE fingerprint = $1 AND created_at > now() - make_interval(hours => $2)
           ORDER BY created_at DESC LIMIT 1""",
        fingerprint,
        hours,
    )
    return dict(row) if row else None


async def load_alert(alert_id) -> dict | None:
    p = await pool()
    return await p.fetchval("SELECT doc FROM alerts WHERE alert_id = $1::uuid", str(alert_id))


async def timeline(alert_id) -> list[dict]:
    p = await pool()
    rows = await p.fetch(
        """SELECT ts, stage, event, actor, payload FROM audit_log
           WHERE correlation_id = $1::uuid ORDER BY id""",
        str(alert_id),
    )
    return [dict(r) for r in rows]
