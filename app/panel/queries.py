"""Panel üçün oxuma sorğuları. Heç nə yazmır: rəy mövcud /feedback endpoint-i ilə yazılır.

Bütün istifadəçi girişi (filtr, axtarış) sorğuya parametr kimi ötürülür, SQL mətninə heç vaxt qoşulmur.
"""

from uuid import UUID

from app import db
from app.case.base import defang

VIEWS = {"open", "reviewed", "all"}
PRIORITIES = {"P1", "P2", "P3", "P4"}
TYPES = {"malicious_hash", "suspicious_url", "suspicious_login"}
VERDICTS = {"malicious", "suspicious", "unknown", "clean"}

# Hər alert üçün son qərar, case və son rəy (LATERAL: alert başına bir sətir).
# $3..$6 boş ola bilər: NULL olanda həmin filtr tətbiq olunmur.
_LIST = """
SELECT a.alert_id, a.source_ref, a.alert_type, a.status, a.received_at, a.occurrence_count,
       a.doc->>'title' AS title, a.doc->>'host' AS host, a.doc->>'user' AS "user",
       jsonb_array_length(COALESCE(a.doc->'observables', '[]'::jsonb)) AS ioc_count,
       d.verdict, d.priority, d.action, d.rule_id, d.shadow,
       c.backend AS case_backend, c.case_id,
       EXTRACT(EPOCH FROM (c.created_at - a.received_at)) AS case_seconds,
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
  AND ($3::text IS NULL OR d.priority = $3)
  AND ($4::text IS NULL OR a.alert_type = $4)
  AND ($5::text IS NULL OR d.verdict = $5)
  AND ($6::text IS NULL
       OR a.source_ref ILIKE $6 ESCAPE '\\'
       OR a.doc->>'title' ILIKE $6 ESCAPE '\\'
       OR a.doc->>'host' ILIKE $6 ESCAPE '\\'
       OR a.doc->>'user' ILIKE $6 ESCAPE '\\'
       OR d.rule_id ILIKE $6 ESCAPE '\\'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(a.doc->'observables', '[]'::jsonb)) o
                  WHERE o->>'value' ILIKE $6 ESCAPE '\\'))
ORDER BY d.priority, a.received_at DESC
LIMIT $2
"""

_STATS = """
SELECT
  count(*) FILTER (WHERE f.alert_id IS NULL AND a.status <> 'closed_auto') AS open,
  count(*) FILTER (WHERE f.alert_id IS NOT NULL) AS reviewed,
  count(*) FILTER (WHERE d.shadow AND f.alert_id IS NULL) AS would_close,
  count(*) FILTER (WHERE f.alert_id IS NOT NULL AND (f.auto_verdict = f.human_verdict
                   OR (f.auto_verdict = 'unknown' AND f.human_verdict = 'suspicious'))) AS agree,
  count(*) FILTER (WHERE a.received_at > now() - interval '24 hours') AS last_24h,
  count(*) AS total
FROM alerts a
JOIN LATERAL (SELECT shadow FROM decisions WHERE alert_id = a.alert_id
              ORDER BY decided_at DESC LIMIT 1) d ON true
LEFT JOIN LATERAL (SELECT alert_id, auto_verdict, human_verdict FROM feedback
                   WHERE alert_id = a.alert_id ORDER BY created_at DESC LIMIT 1) f ON true
"""

# Açıq alert-lər prioritetə, bütün alert-lər son verdict-ə və tipə görə
_BREAKDOWN = """
SELECT d.priority, d.verdict, a.alert_type,
       (f.alert_id IS NULL AND a.status <> 'closed_auto') AS is_open, count(*) AS n
FROM alerts a
JOIN LATERAL (SELECT priority, verdict FROM decisions WHERE alert_id = a.alert_id
              ORDER BY decided_at DESC LIMIT 1) d ON true
LEFT JOIN LATERAL (SELECT alert_id FROM feedback WHERE alert_id = a.alert_id LIMIT 1) f ON true
GROUP BY 1, 2, 3, 4
"""

# Qəbul → case vaxtı: median və p90 (saniyə)
_CASE_TIME = """
SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY s) AS median_s,
       percentile_cont(0.9) WITHIN GROUP (ORDER BY s) AS p90_s,
       count(*) AS n
FROM (SELECT EXTRACT(EPOCH FROM (c.created_at - a.received_at)) AS s
      FROM cases c JOIN alerts a USING (alert_id)) t
WHERE s >= 0
"""

# Son 24 saat, saatlıq: hər saatda gələn alert sayı (boş saatlar 0)
_HOURLY = """
SELECT h AS hour, count(a.alert_id) AS n
FROM generate_series(date_trunc('hour', now()) - interval '23 hours', date_trunc('hour', now()),
                     interval '1 hour') h
LEFT JOIN alerts a ON date_trunc('hour', a.received_at) = h
GROUP BY h ORDER BY h
"""

# Eyni xarici IOC, host və ya istifadəçi ilə başqa alert-lər (son 7 gün)
_RELATED = """
WITH me AS (
  SELECT a.alert_id, a.doc->>'host' AS host, a.doc->>'user' AS usr,
         ARRAY(SELECT o->>'value' FROM jsonb_array_elements(COALESCE(a.doc->'observables', '[]'::jsonb)) o
               WHERE NOT COALESCE((o->>'internal')::boolean, false)
                 AND o->>'type' NOT IN ('user', 'host')) AS iocs
  FROM alerts a WHERE a.alert_id = $1
)
SELECT a.alert_id, a.source_ref, a.alert_type, a.received_at, a.doc->>'title' AS title,
       d.priority, d.verdict,
       CASE WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(a.doc->'observables', '[]'::jsonb)) o
                         WHERE o->>'value' = ANY(me.iocs)) THEN 'ioc'
            WHEN a.doc->>'host' = me.host THEN 'host'
            ELSE 'user' END AS reason
FROM alerts a CROSS JOIN me
LEFT JOIN LATERAL (SELECT priority, verdict FROM decisions WHERE alert_id = a.alert_id
                   ORDER BY decided_at DESC LIMIT 1) d ON true
WHERE a.alert_id <> me.alert_id
  AND a.received_at > now() - interval '7 days'
  AND (EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(a.doc->'observables', '[]'::jsonb)) o
               WHERE o->>'value' = ANY(me.iocs))
       OR (me.host IS NOT NULL AND a.doc->>'host' = me.host)
       OR (me.usr IS NOT NULL AND a.doc->>'user' = me.usr))
ORDER BY a.received_at DESC
LIMIT 10
"""


def search_pattern(q: str | None) -> str | None:
    """Axtarış mətnini ILIKE nümunəsinə çevirir.

    Analitik paneldə gördüyü defang formanı (hxxp, [.]) yapışdıra bilər: bazada IOC refang saxlanılır,
    ona görə axtarışdan əvvəl geri çevrilir. %, _ və \\ simvolları literal axtarılır.
    """
    if q is None:
        return None
    q = q.strip()[:100]
    if not q:
        return None
    q = q.replace("[.]", ".").replace("[:]", ":").replace("hxxps", "https").replace("hxxp", "http")
    q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{q}%"


async def list_alerts(view: str = "open", limit: int = 100, filters: dict | None = None) -> list[dict]:
    f = filters or {}
    p = await db.pool()
    rows = await p.fetch(
        _LIST,
        view,
        limit,
        f.get("priority"),
        f.get("alert_type"),
        f.get("verdict"),
        search_pattern(f.get("q")),
    )
    return [{**dict(r), "title": defang(r["title"] or "")} for r in rows]


async def stats() -> dict:
    p = await db.pool()
    row = await p.fetchrow(_STATS)
    out = dict(row) if row else {}
    by_priority = {k: 0 for k in sorted(PRIORITIES)}
    by_verdict = {k: 0 for k in ("malicious", "suspicious", "unknown", "clean")}
    by_type: dict[str, int] = {}
    for r in await p.fetch(_BREAKDOWN):
        if r["is_open"] and r["priority"] in by_priority:
            by_priority[r["priority"]] += r["n"]
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + r["n"]
        by_type[r["alert_type"]] = by_type.get(r["alert_type"], 0) + r["n"]
    ct = await p.fetchrow(_CASE_TIME)
    out.update(
        open_by_priority=by_priority,
        by_verdict=by_verdict,
        by_type=by_type,
        case_median_s=ct["median_s"] if ct else None,
        case_p90_s=ct["p90_s"] if ct else None,
        cases=ct["n"] if ct else 0,
        hourly=[{"hour": r["hour"], "n": r["n"]} for r in await p.fetch(_HOURLY)],
    )
    return out


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
    case = await p.fetchrow(
        "SELECT backend, case_id, case_url, created_at FROM cases WHERE alert_id = $1", alert_id
    )
    fbs = await p.fetch(
        """SELECT human_verdict, analyst, source, comment, created_at FROM feedback
           WHERE alert_id = $1 ORDER BY created_at""",
        alert_id,
    )
    related = await p.fetch(_RELATED, alert_id)
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
            # aggregate.py sahəni reputation_score adı ilə yazır (0–100)
            "score": enr.get("reputation_score", enr.get("score")),
            "confidence": enr.get("confidence"),
            "conflict": enr.get("conflict"),
            "providers": [
                {k: pr.get(k) for k in ("provider", "ioc_type", "status", "score", "cached", "note")}
                for pr in enr.get("providers") or []
            ],
        },
        "decision": dict(dec) if dec else None,
        "case": dict(case) if case else None,
        "feedback": [dict(f) for f in fbs],
        "related": [{**dict(r), "title": defang(r["title"] or "")} for r in related],
        "timeline": await db.timeline(alert_id),
    }
