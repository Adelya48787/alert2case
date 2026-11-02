"""partial/failed statuslu alert-ləri 15 dəqiqədən bir yenidən enrich edir."""

import asyncio
import logging

from app import db
from app.audit.log import audit
from app.enrich.service import enrich
from app.schemas.alert import NormalizedAlert

log = logging.getLogger("enrich.reenrich")
INTERVAL_S = 15 * 60


async def on_verdict_change(alert: NormalizedAlert, old_verdict: str) -> None:
    """Phase 4-də case-ə şərh yazmaq üçün genişlənəcək."""
    log.info("verdict dəyişdi %s: %s → %s", alert.alert_id, old_verdict, alert.enrichment.verdict)


async def run_once(limit: int = 50) -> int:
    rows = await db.alerts_needing_reenrich(hours=24, limit=limit)
    for row in rows:
        alert = NormalizedAlert.model_validate(row["doc"])
        old = alert.enrichment
        alert.enrichment = await enrich(alert)
        await audit(
            alert.alert_id,
            "enrich",
            "re_enriched",
            {
                "old_status": old.status,
                "new_status": alert.enrichment.status,
                "old_verdict": old.verdict,
                "new_verdict": alert.enrichment.verdict,
            },
        )
        if alert.enrichment.verdict != old.verdict:
            await on_verdict_change(alert, old.verdict)
        await db.save_alert(alert, row["status"])
    return len(rows)


async def loop() -> None:
    while True:
        await asyncio.sleep(INTERVAL_S)
        try:
            n = await run_once()
            if n:
                log.info("%s alert yenidən enrich olundu", n)
        except Exception:  # noqa: BLE001
            log.exception("re-enrichment uğursuz oldu, növbəti dövrdə təkrar")
