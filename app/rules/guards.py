"""Auto-close qoruyucuları: qayda "bağla" desə də, təhlükəsizlik şərtləri ödənməlidir (ADR-0002)."""

from app.config import settings
from app.rules.engine import priority_for
from app.schemas.alert import Decision, NormalizedAlert, Severity

MIN_CONFIDENCE = 0.67


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
