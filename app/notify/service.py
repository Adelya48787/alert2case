"""P1/P2 bildirişləri: Slack və Telegram; P1 üçün və ya chat alınmayanda email."""

import html
import logging
from datetime import timedelta
from email.message import EmailMessage

import aiosmtplib
import httpx

from app.case.base import CaseRef, defang
from app.config import settings
from app.queue import get_redis
from app.schemas.alert import Decision, NormalizedAlert

log = logging.getLogger("notify")
SLA = {
    "P1": timedelta(minutes=15),
    "P2": timedelta(hours=1),
    "P3": timedelta(hours=4),
    "P4": timedelta(hours=24),
}
THROTTLE_S = 30 * 60


def render(alert: NormalizedAlert, d: Decision, case: CaseRef | None) -> str:
    iocs = (
        ", ".join(
            f"{defang(o.value) if o.type in ('url', 'domain', 'ip') else o.value[:16] + '…'} ({o.type})"
            for o in alert.external_iocs()[:3]
        )
        or "-"
    )
    deadline = (alert.received_at + SLA[d.priority]).strftime("%H:%M UTC")
    lines = [
        f"[{d.priority}] {alert.alert_type} · {d.severity_id.name} · {d.verdict}",
        f"IOC: {iocs}",
        f"Host/istifadəçi: {alert.host or '-'} / {alert.user or '-'}",
        "Səbəblər:",
        *[f"  - {r}" for r in d.reasons[:4]],
        f"Case: {case.url if case else 'yaradılmadı, case DLQ-dadır (pending)'}",
        f"SLA: {deadline}-ə qədər",
    ]
    return "\n".join(lines)


async def _slack(text: str) -> None:
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.post(settings.slack_webhook_url, json={"text": text})
        r.raise_for_status()


async def _telegram(text: str) -> None:
    url = f"{settings.telegram_api_base}/bot{settings.telegram_bot_token}/sendMessage"
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.post(
            url,
            json={
                "chat_id": settings.telegram_chat_id,
                "text": f"<pre>{html.escape(text)}</pre>",
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
        )
        r.raise_for_status()


async def _email(subject: str, text: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "alert2case@lab.local", settings.email_to, subject
    msg.set_content(text)
    await aiosmtplib.send(msg, hostname=settings.smtp_host, port=settings.smtp_port, timeout=5)


async def notify(alert: NormalizedAlert, d: Decision, case: CaseRef | None) -> list[str]:
    """Göndərilən kanalların siyahısını qaytarır."""
    if d.priority not in ("P1", "P2"):
        return []
    try:  # eyni fingerprint üçün 30 dəqiqədə bir bildiriş
        first = await get_redis().set(f"notify:{alert.fingerprint}", "1", nx=True, ex=THROTTLE_S)
    except Exception:  # noqa: BLE001  Redis yoxdursa throttle yox
        first = True
    if not first:
        return ["throttled"]
    text = render(alert, d, case)
    sent: list[str] = []
    for name, enabled, fn in (
        ("slack", bool(settings.slack_webhook_url), _slack),
        ("telegram", bool(settings.telegram_bot_token), _telegram),
    ):
        if not enabled:
            continue
        try:
            await fn(text)
            sent.append(name)
        except Exception as e:  # noqa: BLE001
            log.warning("%s bildirişi alınmadı: %r", name, e)
    if d.priority == "P1" or not sent:  # P1 həmişə, chat alınmasa fallback
        try:
            await _email(f"[{d.priority}] {alert.alert_type} {alert.host or alert.user or ''}", text)
            sent.append("email")
        except Exception as e:  # noqa: BLE001
            log.error("email də alınmadı: %r", e)
    return sent
