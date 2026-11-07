"""Panel üçün oxuma sorğuları. Heç nə yazmır: rəy mövcud /feedback endpoint-i ilə yazılır."""

from uuid import UUID

from app import db
from app.case.base import defang

VIEWS = {"open", "reviewed", "all"}

# Hər alert üçün son qərar, case və son rəy (LATERAL: alert başına bir sətir)
_LIST = """
SELECT a.alert_id, a.source_ref, a.alert_type, a.status, a.received_at, a.occurrence_count,
       a.doc->>'title' AS title, a.doc->>'host' AS host, a.doc->>'user' AS "user",
       d.verdict, d.priority, d.action, d.rule_id, d.shadow,
       c.backend AS case_backend, c.case_id,
       f.human_verdict, f.analyst, f.created_at AS reviewed_at
FROM alerts a
LEFT JOIN LATERAL (SELECT verdict, priority, action, rule_id, shadow FROM decisions
                   WHERE alert_id = a.alert_id ORDER BY decided_at DESC LIMIT 1) d ON true
LEFT JOIN cases c ON c.alert_id = a.alert_id
LEFT JOIN LATERAL (SELECT human_verdict, analyst, created_at FROM feedback
                   WHERE alert_id = a.alert_id ORDER BY created_at DESC LIMIT 1) f ON true
WHERE d.verdict IS NOT NULL
  AND ($1 = 'all'
       OR ($1 = 'open' AND f.human_verdict IS NULL AND a.status <> 'closed_auto')
       OR ($1 = 'reviewed' AND f.human_verdict IS NOT NULL))
ORDER BY d.priority, a.received_at DESC
LIMIT $2
"""

_STATS = """
SELECT
  count(*) FILTER (WHERE f.alert_id IS NULL AND a.status <> 'closed_auto') AS open,
  count(*) FILTER (WHERE f.alert_id IS NOT NULL) AS reviewed,
  count(*) FILTER (WHERE d.shadow AND f.alert_id IS NULL) AS would_close,
  count(*) FILTER (WHERE f.alert_id IS NOT NULL AND (f.auto_verdict = f.human_verdict
                   OR (f.auto_verdict = 'unknown' AND f.human_verdict = 'suspicious'))) AS agree
FROM alerts a
JOIN LATERAL (SELECT shadow FROM decisions WHERE alert_id = a.alert_id
              ORDER BY decided_at DESC LIMIT 1) d ON true
LEFT JOIN LATERAL (SELECT alert_id, auto_verdict, human_verdict FROM feedback
                   WHERE alert_id = a.alert_id ORDER BY created_at DESC LIMIT 1) f ON true
"""


async def list_alerts(view: str = "open", limit: int = 100) -> list[dict]:
    p = await db.pool()
    rows = await p.fetch(_LIST, view, limit)
    return [{**dict(r), "title": defang(r["title"] or "")} for r in rows]


async def stats() -> dict:
    p = await db.pool()
    row = await p.fetchrow(_STATS)
    return dict(row) if row else {}


async def detail(alert_id: UUID) -> dict | None:
    p = await db.pool()
    a = await p.fetchrow(
        "SELECT alert_id, source_ref, alert_type, status, received_at, occurrence_count, doc FROM alerts WHERE alert_id = $1",
        alert_id,
    )
    if a is None:
        return None
    doc = a["doc"] or {}
    dec = await p.fetchrow(
        """SELECT verdict, severity_id, priority, action, rule_id, rule_version, reasons, shadow, decided_at
           FROM decisions WHERE alert_id = $1 ORDER BY decided_at DESC LIMIT 1""",
        alert_id,
    )
    case = await p.fetchrow("SELECT backend, case_id, case_url FROM cases WHERE alert_id = $1", alert_id)
    fbs = await p.fetch(
        """SELECT human_verdict, analyst, source, comment, created_at FROM feedback
           WHERE alert_id = $1 ORDER BY created_at""",
        alert_id,
    )
    enr = doc.get("enrichment") or {}
    return {
        "alert_id": a["alert_id"],
        "source_ref": a["source_ref"],
        "alert_type": a["alert_type"],
        "status": a["status"],
        "received_at": a["received_at"],
        "occurrence_count": a["occurrence_count"],
        "title": defang(doc.get("title") or ""),
        "host": doc.get("host"),
        "user": doc.get("user"),
        # IOC-lar yalnız defang formada göstərilir: panelin heç bir yerində kliklənən zərərli link olmur
        "observables": [
            {
                "type": o.get("type"),
                "value": defang(str(o.get("value", ""))),
                "internal": o.get("internal", False),
            }
            for o in doc.get("observables") or []
        ],
        "enrichment": {
            "status": enr.get("status"),
            "verdict": enr.get("verdict"),
            "score": enr.get("score"),
            "confidence": enr.get("confidence"),
            "providers": [
                {k: pr.get(k) for k in ("provider", "ioc_type", "status", "score", "cached", "note")}
                for pr in enr.get("providers") or []
            ],
        },
        "decision": dict(dec) if dec else None,
        "case": dict(case) if case else None,
        "feedback": [dict(f) for f in fbs],
        "timeline": await db.timeline(alert_id),
    }
