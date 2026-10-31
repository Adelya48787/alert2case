"""Alert-in bütün yolu. Phase 3–5-də bu funksiya genişlənəcək."""

import json
import logging
from datetime import datetime

from app import db
from app.audit.log import audit
from app.config import settings
from app.errors import PermanentError
from app.normalize import normalize

log = logging.getLogger("pipeline")


async def process(source: str, body: str, received_at: datetime) -> None:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise PermanentError(f"JSON deyil: {e}") from e

    alert = normalize(source, payload, received_at)
    alert_id, duplicate = await db.upsert_alert(alert, settings.dedup_window_s)
    if duplicate:
        await audit(alert_id, "normalize", "duplicate", {"fingerprint": alert.fingerprint})
        return
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
    # Phase 3: enrich · Phase 4: decide, act, notify · Phase 5: correlate
    await db.save_alert(alert, "normalized")
