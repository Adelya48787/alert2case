"""Panel üçün oxuma sorğuları. Heç nə yazmır: rəy mövcud /feedback endpoint-i ilə yazılır.

Bütün istifadəçi girişi (filtr, axtarış) sorğuya parametr kimi ötürülür, SQL mətninə heç vaxt qoşulmur.
"""

from uuid import UUID

from app import db
from app.case.base import defang
from app.config import settings

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
       (a.doc->'enrichment'->>'reputation_score')::numeric AS score,
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
  AND ($7::text IS NULL OR a.doc->>'host' = $7)
  AND ($8::text IS NULL OR a.doc->>'user' = $8)
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


# Incident: son 7 gündə eyni host-a (host yoxdursa, istifadəçiyə) aid ən azı 2 alert
_INCIDENTS = """
WITH x AS (
  SELECT a.alert_id, a.alert_type, a.received_at,
         CASE WHEN COALESCE(a.doc->>'host', '') <> '' THEN 'host' ELSE 'user' END AS kind,
         COALESCE(NULLIF(a.doc->>'host', ''), a.doc->>'user') AS entity,
         d.priority, d.verdict, (f.alert_id IS NULL AND a.status <> 'closed_auto') AS is_open
  FROM alerts a
  JOIN LATERAL (SELECT priority, verdict FROM decisions WHERE alert_id = a.alert_id
                ORDER BY decided_at DESC LIMIT 1) d ON true
  LEFT JOIN LATERAL (SELECT alert_id FROM feedback WHERE alert_id = a.alert_id LIMIT 1) f ON true
  WHERE a.received_at > now() - interval '7 days'
)
SELECT kind, entity, count(*) AS alerts, count(*) FILTER (WHERE is_open) AS open,
       min(priority) AS priority,
       min(priority) FILTER (WHERE is_open) AS open_priority,
       count(*) FILTER (WHERE priority = 'P1') AS p1,
       count(*) FILTER (WHERE verdict = 'malicious') AS malicious,
       count(*) FILTER (WHERE verdict = 'suspicious') AS suspicious,
       count(*) FILTER (WHERE verdict = 'unknown') AS unknown,
       count(*) FILTER (WHERE verdict = 'clean') AS clean,
       array_agg(DISTINCT alert_type) AS types,
       min(received_at) AS first_seen, max(received_at) AS last_seen
FROM x
WHERE entity IS NOT NULL
GROUP BY kind, entity
HAVING count(*) >= 2 AND ($1 = 'all' OR count(*) FILTER (WHERE is_open) > 0)
ORDER BY COALESCE(min(priority) FILTER (WHERE is_open), min(priority)), count(*) DESC
LIMIT 100
"""

INCIDENT_VIEWS = {"open", "all"}


async def incidents(view: str = "open") -> list[dict]:
    p = await db.pool()
    return [{**dict(r), "types": sorted(r["types"] or [])} for r in await p.fetch(_INCIDENTS, view)]


# Xülasə üçün provider sübutundan yalnız bu rəqəmlər çıxır (xam cavab panelə getmir)
FACT_KEYS = {
    "virustotal": ("malicious", "suspicious", "engines"),
    "abuseipdb": ("confidence", "reports"),
    "otx": ("pulses",),
}


def provider_facts(pr: dict) -> dict:
    ev = pr.get("evidence") or {}
    keys = FACT_KEYS.get(pr.get("provider"), ())
    return {k: ev[k] for k in keys if isinstance(ev.get(k), (int, float)) and not isinstance(ev.get(k), bool)}


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


def case_link(case) -> str | None:
    """TheHive case-i üçün brauzerdə açılan link. Fayl backend-i və ya gözlənilməz URL → None."""
    if not case or case["backend"] != "thehive":
        return None
    url = str(case["case_url"] or "")
    internal = settings.thehive_url.rstrip("/")
    public = settings.thehive_public_url.rstrip("/")
    if not url.startswith(internal + "/") or not public.startswith(("http://", "https://")):
        return None
    return public + url[len(internal) :]


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
        f.get("host"),
        f.get("user"),
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
                {
                    **{k: pr.get(k) for k in ("provider", "ioc_type", "status", "score", "cached", "note")},
                    "facts": provider_facts(pr),
                }
                for pr in enr.get("providers") or []
            ],
        },
        "decision": dict(dec) if dec else None,
        "case": dict(case) if case else None,
        "case_link": case_link(case),
        "feedback": [dict(f) for f in fbs],
        "related": [{**dict(r), "title": defang(r["title"] or "")} for r in related],
        "context": {
            k: (doc.get("context") or {}).get(k)
            for k in ("asset_criticality", "user_privileged", "user_vip", "allowlisted")
        },
        "timeline": await db.timeline(alert_id),
    }


# ---------- System health ----------
# Son 1 saatda hər intel mənbəyinin cavab statusları (worker-in breaker-i prosesin yaddaşındadır,
# API onu görmür: vəziyyət real nəticələrdən hesablanır)
_INTEL_RECENT = """
SELECT p->>'provider' AS provider,
       CASE WHEN p->>'note' = 'circuit open' THEN 'circuit_open' ELSE p->>'status' END AS status,
       COALESCE((p->>'cached')::boolean, false) AS cached,
       a.received_at > now() - interval '15 minutes' AS recent,
       count(*) AS n
FROM alerts a, jsonb_array_elements(COALESCE(a.doc->'enrichment'->'providers', '[]'::jsonb)) p
WHERE a.received_at > now() - interval '1 hour'
GROUP BY 1, 2, 3, 4
"""

_SHADOW_24H = """
SELECT count(*) FILTER (WHERE d.shadow) AS shadow, count(*) AS decided
FROM decisions d WHERE d.decided_at > now() - interval '24 hours'
"""


BAD = ("error", "failed", "rate_limited", "disabled", "skipped", "circuit_open")


def provider_state(counts: dict) -> str:
    """ok / degraded / down / idle: son 15 dəqiqənin cavablarına görə."""
    live = {k: v for k, v in counts.items() if k != "cached"}
    total = sum(live.values())
    if total == 0:
        return "idle"
    bad = sum(v for k, v in live.items() if k in BAD)
    if live.get("ok", 0) + live.get("not_found", 0) == 0 and bad:
        return "down"
    return "degraded" if bad / total >= 0.3 else "ok"


async def intel_recent() -> dict[str, dict]:
    """provider → {"hour": {status: n}, "recent": {status: n}} (son 1 saat və son 15 dəqiqə)."""
    p = await db.pool()
    out: dict[str, dict] = {}
    for r in await p.fetch(_INTEL_RECENT):
        e = out.setdefault(r["provider"], {"hour": {}, "recent": {}})
        for win in ("hour", "recent") if r["recent"] else ("hour",):
            c = e[win]
            c[r["status"]] = c.get(r["status"], 0) + r["n"]
            if r["cached"]:
                c["cached"] = c.get("cached", 0) + r["n"]
    return out


async def shadow_24h() -> dict:
    p = await db.pool()
    r = await p.fetchrow(_SHADOW_24H)
    return dict(r) if r else {"shadow": 0, "decided": 0}


# ---------- Rule performance ----------
_RULES = """
SELECT d.rule_id, count(*) AS alerts,
       count(*) FILTER (WHERE d.shadow) AS shadow,
       count(f.alert_id) AS reviewed,
       count(*) FILTER (WHERE f.alert_id IS NOT NULL AND (f.auto_verdict = f.human_verdict
                        OR (f.auto_verdict = 'unknown' AND f.human_verdict = 'suspicious'))) AS agree,
       mode() WITHIN GROUP (ORDER BY d.verdict) AS top_verdict,
       max(a.received_at) AS last_seen
FROM alerts a
JOIN LATERAL (SELECT rule_id, verdict, shadow FROM decisions WHERE alert_id = a.alert_id
              ORDER BY decided_at DESC LIMIT 1) d ON true
LEFT JOIN LATERAL (SELECT alert_id, auto_verdict, human_verdict FROM feedback
                   WHERE alert_id = a.alert_id ORDER BY created_at DESC LIMIT 1) f ON true
GROUP BY d.rule_id
ORDER BY alerts DESC
"""

# ADR-0003 şərtləri: shadow mode-da "sistem bağlayardı" deyilən və analitikin baxdığı alert-lər.
# Simulyator dataset-i (HASH-/URL-/LOGIN-NN) "dataset-dən kənar" sayılmır.
_SHADOW_PROGRESS = """
SELECT count(*) AS reviewed,
       count(*) FILTER (WHERE f.human_verdict IN ('malicious', 'suspicious')) AS would_miss,
       count(*) FILTER (WHERE a.source_ref !~ '^(HASH|URL|LOGIN)-[0-9]+$') AS reviewed_real,
       count(*) FILTER (WHERE a.source_ref !~ '^(HASH|URL|LOGIN)-[0-9]+$'
                        AND f.human_verdict IN ('malicious', 'suspicious')) AS would_miss_real
FROM alerts a
JOIN LATERAL (SELECT shadow FROM decisions WHERE alert_id = a.alert_id
              ORDER BY decided_at DESC LIMIT 1) d ON d.shadow
JOIN LATERAL (SELECT human_verdict FROM feedback WHERE alert_id = a.alert_id
              ORDER BY created_at DESC LIMIT 1) f ON true
"""

SHADOW_TARGET = 30  # ADR-0003: ən azı 30 görülməmiş alert


async def rules() -> dict:
    p = await db.pool()
    rows = [dict(r) for r in await p.fetch(_RULES)]
    sp = await p.fetchrow(_SHADOW_PROGRESS)
    progress = dict(sp) if sp else {}
    progress["target"] = SHADOW_TARGET
    return {"rules": rows, "shadow_progress": progress}
