"""Panel üçün sistem vəziyyəti: kill switch/shadow mode, intel mənbələri, növbə və DLQ.

Yalnız oxuyur. Heç bir açar və ya URL qaytarmır: provider üçün yalnız "açar təyin olunub" (bool).
"""

import logging

from app.config import settings
from app.enrich.providers import PROVIDERS
from app.enrich.ratelimit import day_key
from app.panel import queries
from app.pipeline import CASES_DLQ
from app.queue import GROUP, STREAM_DLQ, STREAM_IN, get_redis

log = logging.getLogger(__name__)


async def _queue() -> dict:
    r = get_redis()
    out: dict = {"available": True}
    try:
        out["alerts_dlq"] = await r.xlen(STREAM_DLQ)
        out["cases_dlq"] = await r.xlen(CASES_DLQ)
        groups = await r.xinfo_groups(STREAM_IN)
        g = next((x for x in groups if x.get("name") == GROUP), {})
        out["pending"] = g.get("pending", 0)  # worker götürüb, hələ bitirməyib
        out["lag"] = g.get("lag") or 0  # hələ heç kim götürməyib
    except Exception as e:  # Redis yoxdursa panel yenə açılmalıdır
        log.warning("health: redis oxunmadı: %s", e)
        out = {"available": False}
    return out


async def _quotas() -> dict[str, int | None]:
    r = get_redis()
    used: dict[str, int | None] = {}
    for p in PROVIDERS:
        try:
            used[p.name] = int(await r.get(day_key(p.name)) or 0)
        except Exception:
            used[p.name] = None
    return used


async def snapshot() -> dict:
    recent = await queries.intel_recent()
    used = await _quotas()
    providers = []
    for p in PROVIDERS:
        win = recent.get(p.name, {"hour": {}, "recent": {}})
        providers.append(
            {
                "provider": p.name,
                "configured": bool(p.api_key()),
                "state": queries.provider_state(win["recent"]),
                "last_hour": win["hour"],
                "last_15m": win["recent"],
                "quota_used": used.get(p.name),
                "quota_day": p.per_day,
                "per_minute": p.per_minute,
            }
        )
    return {
        # API prosesinin konfiqurasiyası (.env); worker eyni .env-i oxuyur
        "auto_close_enabled": settings.auto_close_enabled,
        "shadow_mode": settings.shadow_mode,
        "case_backend": settings.case_backend,
        "decisions_24h": await queries.shadow_24h(),
        "providers": providers,
        "queue": await _queue(),
    }
