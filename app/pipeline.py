"""Alert-in tam yolu. Hər mərhələ ayrıca funksiyadır: worker hamısını ardıcıl çağırır,
n8n isə eyni funksiyaları HTTP ilə tək-tək çağırır (app/stages.py)."""

import json
import logging
import random
from datetime import datetime, timezone

from app import db, queue
from app.audit.log import audit
from app.audit.metrics import ALERTS, DUPLICATES, INTEL, NOTIFY, TIME_TO_ACTION, timed
from app.case.base import CaseError, CaseRef, get_backend
from app.config import settings
from app.context.loader import apply_context
from app.correlation.engine import correlate, index_case
from app.enrich.service import enrich
from app.errors import PermanentError
from app.normalize import normalize
from app.notify.service import notify
from app.rules.engine import decide
from app.rules.guards import apply_guards
from app.schemas.alert import NormalizedAlert

log = logging.getLogger("pipeline")
CASES_DLQ = "cases.dlq"
QA_SAMPLE_RATE = 0.10


async def stage_normalize(source: str, payload: dict, received_at: datetime) -> NormalizedAlert | None:
    """None qaytarırsa alert təkrardır və emal dayanır."""
    with timed("normalize"):
        alert = normalize(source, payload, received_at)
        alert_id, duplicate = await db.upsert_alert(alert, settings.dedup_window_s)
    if duplicate:
        DUPLICATES.labels(alert.alert_type).inc()
        await audit(alert_id, "normalize", "duplicate", {"fingerprint": alert.fingerprint})
        return None
    await audit(
        alert.alert_id,
        "ingest",
        "received",
        {"source": source, "source_ref": alert.source_ref, "received_at": received_at.isoformat()},
    )
    await audit(
        alert.alert_id,
        "normalize",
        "ok",
        {"alert_type": alert.alert_type, "observables": len(alert.observables)},
    )
    return alert


async def stage_enrich(alert: NormalizedAlert) -> NormalizedAlert:
    with timed("enrich"):
        alert.enrichment = await enrich(alert)
    e = alert.enrichment
    for p in e.providers:
        INTEL.labels(p["provider"], p["status"], str(p["cached"])).inc()
    await audit(
        alert.alert_id,
        "enrich",
        e.status,
        {
            "score": e.reputation_score,
            "confidence": e.confidence,
            "conflict": e.conflict,
            "verdict": e.verdict,
            "providers": [
                {k: p.get(k) for k in ("provider", "ioc_type", "status", "score", "cached", "latency_ms")}
                for p in e.providers
            ],
        },
    )
    await db.save_alert(alert, "enriched")
    return alert


async def stage_decide(alert: NormalizedAlert) -> NormalizedAlert:
    with timed("decide"):
        apply_context(alert)
        d = apply_guards(alert, decide(alert))
        alert.decision = d
    await db.save_decision(alert, d)
    await audit(
        alert.alert_id,
        "decide",
        d.action,
        {
            "verdict": d.verdict,
            "severity": int(d.severity_id),
            "priority": d.priority,
            "rule": d.rule_id,
            "rule_version": d.rule_version,
            "shadow": d.shadow,
            "reasons": d.reasons,
            "context": alert.context,
        },
    )
    await db.save_alert(alert, "decided")
    return alert


async def stage_correlate(alert: NormalizedAlert) -> CaseRef | None:
    """Phase 5: oxşar açıq case varsa onu qaytarır və alert onun altına düşür."""
    with timed("correlate"):
        return await correlate(alert)


async def _comment(alert: NormalizedAlert, ref: CaseRef, text: str) -> bool:
    """Mövcud case-ə şərh: case-in öz backend-i ilə. Alınmasa alert emalı dayanmır, audit-ə yazılır."""
    try:
        await get_backend(ref.backend).comment(ref, text)
        return True
    except (CaseError, OSError, ValueError) as e:
        log.warning("case %s-ə şərh yazılmadı: %s", ref.case_id, e)
        await audit(
            alert.alert_id,
            "act",
            "comment_failed",
            {"case_id": ref.case_id, "backend": ref.backend, "error": str(e)[:300]},
        )
        return False


async def _create_case(alert: NormalizedAlert, to_dlq: bool = True) -> CaseRef | None:
    existing = await db.find_recent_case(alert.fingerprint, hours=24)
    if existing:  # idempotentlik: eyni hadisə, eyni case
        ref = CaseRef(**existing)
        await _comment(alert, ref, f"Təkrar alert {alert.alert_id} ({alert.received_at.isoformat()})")
        return ref
    try:
        ref = await get_backend().create(alert, alert.decision)
        await db.save_case(alert, ref)
        return ref
    except CaseError as e:
        log.error("case yaradılmadı: %s", e)
        if to_dlq:
            await queue.get_redis().xadd(CASES_DLQ, {"alert_id": str(alert.alert_id), "error": str(e)[:500]})
            await audit(alert.alert_id, "act", "case_failed", {"error": str(e)[:500]})
        return None


async def stage_act(alert: NormalizedAlert, related: CaseRef | None = None) -> CaseRef | None:
    d = alert.decision
    with timed("act"):
        if d.action == "auto_close":
            await db.save_alert(alert, "closed_auto")
            await audit(alert.alert_id, "act", "closed_auto", {"rule": d.rule_id})
            if random.random() < QA_SAMPLE_RATE:  # 10% QA nümunəsi insana gedir
                qa = alert.model_copy(
                    update={
                        "decision": d.model_copy(
                            update={
                                "priority": "P4",
                                "reasons": [*d.reasons, "QA nümunəsi: avtomatik bağlanıb, yoxlayın"],
                            }
                        )
                    }
                )
                await _create_case(qa)
                await audit(alert.alert_id, "act", "qa_sampled", {})
            ref = None
        elif related:
            await _comment(alert, related, f"Korrelyasiya: alert {alert.alert_id} bu case-ə əlavə olundu")
            await db.save_case(alert, related)
            await audit(alert.alert_id, "act", "case_linked", {"case_id": related.case_id})
            ref = related
        else:
            ref = await _create_case(alert)
            if ref:
                await audit(
                    alert.alert_id,
                    "act",
                    "case_created",
                    {"case_id": ref.case_id, "backend": ref.backend, "url": ref.url},
                )
        if ref:
            await index_case(alert, ref)  # Phase 5: korrelyasiya indeksi
            for cid in alert.context.get("related_cases", []):
                await _comment(alert, ref, f"Əlaqəli case: {cid}")
                await db.save_link(alert.alert_id, ref.case_id, cid)
        await db.save_alert(
            alert, "closed_auto" if d.action == "auto_close" else ("case_created" if ref else "case_pending")
        )
    ALERTS.labels(alert.alert_type, d.action, d.priority, str(d.shadow)).inc()
    return ref


async def stage_notify(alert: NormalizedAlert, ref: CaseRef | None) -> list[str]:
    with timed("notify"):
        sent = await notify(alert, alert.decision, ref)
    for ch in sent:
        NOTIFY.labels(ch).inc()
    if sent == ["throttled"]:
        event = "throttled"
    elif sent:
        event = "sent"
    elif alert.decision.priority in ("P1", "P2"):
        event = "failed"  # P1/P2, amma heç bir kanal işləmədi
    else:
        event = "skipped"  # P3/P4 bildiriş tələb etmir
    await audit(alert.alert_id, "notify", event, {"channels": sent})
    TIME_TO_ACTION.labels(alert.alert_type).observe(
        (datetime.now(timezone.utc) - alert.received_at).total_seconds()
    )
    return sent


async def process(source: str, body: str, received_at: datetime) -> None:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise PermanentError(f"JSON deyil: {e}") from e
    alert = await stage_normalize(source, payload, received_at)
    if alert is None:
        return
    await stage_enrich(alert)
    await stage_decide(alert)
    related = await stage_correlate(alert)
    ref = await stage_act(alert, related)
    await stage_notify(alert, ref)


async def retry_pending_cases(limit: int = 20) -> int:
    """cases.dlq-dakı alert-lər üçün case yaratmağı yenidən sınayır."""
    r = queue.get_redis()
    done = 0
    for msg_id, f in await r.xrange(CASES_DLQ, count=limit):
        doc = await db.load_alert(f["alert_id"])
        if doc is None:
            await r.xdel(CASES_DLQ, msg_id)
            continue
        alert = NormalizedAlert.model_validate(doc)
        ref = await _create_case(alert, to_dlq=False)
        if ref:
            await r.xdel(CASES_DLQ, msg_id)
            await db.save_alert(alert, "case_created")
            await audit(alert.alert_id, "act", "case_created", {"case_id": ref.case_id, "retry": True})
            done += 1
        else:
            break  # backend hələ də işləmir
    return done
