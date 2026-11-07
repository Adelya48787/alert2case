"""Auto-close qoruyucuları: qayda "bağla" desə də, təhlükəsizlik şərtləri ödənməlidir (ADR-0002, ADR-0003)."""

from urllib.parse import urlsplit

from app.config import settings
from app.normalize.iocs import refang
from app.rules.engine import priority_for
from app.schemas.alert import Decision, NormalizedAlert, Severity

MIN_CONFIDENCE = 0.67

# ADR-0003: dynamic DNS provayderləri. Bu domenlərin alt domenini hər kəs pulsuz və dəqiqələr içində yaradır.
# Yeni alt domeni VT-yə skan etdirmək onu "0/93 təmiz" göstərir: bu, təmizliyin sübutu deyil.
DYNAMIC_DNS = (
    "duckdns.org",
    "ddns.net",
    "hopto.org",
    "zapto.org",
    "sytes.net",
    "no-ip.org",
    "no-ip.biz",
    "no-ip.info",
    "noip.me",
    "myftp.org",
    "myftp.biz",
    "serveftp.com",
    "servebeer.com",
    "servehttp.com",
    "redirectme.net",
    "bounceme.net",
    "3utilities.com",
    "ddns.me",
    "dynu.net",
    "dynu.com",
    "freeddns.org",
    "ddnsfree.com",
    "dyndns.org",
    "dynalias.com",
    "homeip.net",
    "gotdns.ch",
    "mooo.com",
    "chickenkiller.com",
    "us.to",
    "afraid.org",
    "linkpc.net",
)


def _host(obs_type: str, value: str) -> str | None:
    if obs_type == "domain":
        return refang(value).strip().lower().rstrip(".")
    if obs_type == "url":
        try:
            return (urlsplit(refang(value)).hostname or "").rstrip(".") or None
        except ValueError:
            return None
    return None


def dynamic_dns_hosts(alert: NormalizedAlert) -> list[str]:
    """Alert-in dynamic DNS provayderinə aid host-ları (URL və domain observable-larından)."""
    out = []
    for o in alert.observables:
        h = _host(o.type, o.value)
        if h and any(h == s or h.endswith("." + s) for s in DYNAMIC_DNS) and h not in out:
            out.append(h)
    return out


def blockers(alert: NormalizedAlert) -> list[str]:
    e, c = alert.enrichment, alert.context
    approved = bool(c.get("allowlisted"))  # allowlist insan tərəfindən təsdiqlənib
    out = []
    if e.verdict == "malicious":  # qızıl qayda: qayda faylı nə desə də, zərərli alert bağlanmır
        out.append("intel verdict-i malicious-dir")
    if e.status != "ok" and not approved:
        out.append(f"enrichment natamamdır ({e.status})")
    if e.confidence < MIN_CONFIDENCE and not approved:
        out.append(f"etibarlılıq aşağıdır ({e.confidence})")
    if e.conflict:
        out.append("intel mənbələri ziddiyyətlidir")
    if c.get("user_privileged") or c.get("user_vip"):
        out.append("imtiyazlı/VIP istifadəçi")
    if c.get("asset_criticality") == "crown_jewel":
        out.append("kritik asset (crown_jewel)")
    ddns = dynamic_dns_hosts(alert)
    if ddns and not approved:  # ADR-0003: VT-də "0 zərərli" yeni alt domen üçün sübut deyil
        out.append("dynamic DNS domeni: " + ", ".join(ddns))
    return out


def apply_guards(alert: NormalizedAlert, d: Decision) -> Decision:
    if d.action != "auto_close":
        return d
    found = blockers(alert)
    if found:
        sev = max(d.severity_id, Severity.LOW)
        return d.model_copy(
            update={
                "action": "create_case",
                "severity_id": sev,
                "priority": priority_for(sev, alert.context),
                "reasons": [*d.reasons, "auto-close bloklandı: " + "; ".join(found)],
            }
        )
    if not settings.auto_close_enabled or settings.shadow_mode:
        why = "kill switch bağlıdır" if not settings.auto_close_enabled else "shadow mode"
        return d.model_copy(
            update={
                "action": "create_case",
                "shadow": True,
                "reasons": [*d.reasons, f"{why}: sistem bu alert-i bağlayardı, insan təsdiqləsin"],
            }
        )
    return d
