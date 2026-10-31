"""Provider üzrə dəqiqəlik (token bucket) və gündəlik limit. Bütün worker-lər Redis-də bölüşür."""

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from app.queue import get_redis

log = logging.getLogger("enrich.ratelimit")
_LUA = (Path(__file__).parent / "ratelimit.lua").read_text()
_script = None


def _get_script():
    global _script
    if _script is None:
        _script = get_redis().register_script(_LUA)
    return _script


def day_key(provider: str) -> str:
    return f"quota:{provider}:{datetime.now(timezone.utc).date().isoformat()}"


SAFETY = 0.9  # limitin 90%-i: provider-in pəncərəsi ilə bizim saatımız arasındakı fərqə ehtiyat


async def acquire(
    provider: str, per_minute: int, per_day: int, burst: int = 1, max_wait: float = 60.0
) -> bool:
    """Token alındı → True. max_wait saniyədə alınmadı və ya gündəlik kvota bitdi → False.
    burst: bir anda ardıcıl buraxılan sorğu sayı (vedrənin tutumu)."""
    r = get_redis()
    used = int(await r.get(day_key(provider)) or 0)
    if per_day and used >= per_day:
        log.warning("%s: gündəlik kvota bitib (%s)", provider, per_day)
        return False
    deadline = time.monotonic() + max_wait
    while True:
        allowed, wait_ms = await _get_script()(
            keys=[f"rl:{provider}"],
            args=[burst, per_minute / 60.0 * SAFETY, int(time.time() * 1000), 1],
        )
        if int(allowed) == 1:
            n = await r.incr(day_key(provider))
            if n == 1:
                await r.expire(day_key(provider), 2 * 86400)
            if per_day and n == int(per_day * 0.8):
                log.warning("%s: gündəlik kvotanın 80%%-i istifadə olunub", provider)
            return True
        if time.monotonic() + wait_ms / 1000 > deadline:
            return False
        await asyncio.sleep(wait_ms / 1000)
