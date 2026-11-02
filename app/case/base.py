"""Case backend interfeysi, case mətni və backend seçimi."""

from abc import ABC, abstractmethod

from pydantic import BaseModel

from app.config import settings
from app.schemas.alert import Decision, NormalizedAlert


class CaseRef(BaseModel):
    backend: str
    case_id: str
    url: str


class CaseError(Exception):
    """Case yaradıla bilmədi. Pipeline bunu case DLQ-ya yazır."""


class CaseBackend(ABC):
    name: str

    @abstractmethod
    async def create(self, alert: NormalizedAlert, d: Decision) -> CaseRef: ...

    @abstractmethod
    async def comment(self, ref: CaseRef, text: str) -> None: ...


PLAYBOOK_TASKS = {
    "malicious_hash": [
        "Hostun izolyasiyası barədə qərar ver",
        "Faylın mənbəyini müəyyən et (email, yükləmə, USB)",
        "Eyni hash-ı digər hostlarda axtar",
    ],
    "suspicious_login": [
        "İstifadəçi ilə girişi təsdiqlə",
        "MFA və login tarixçəsini yoxla",
        "Hesabın bloklanması barədə qərar ver",
    ],
    "suspicious_url": [
        "Proxy loglarında digər istifadəçiləri yoxla",
        "Domenin bloklanması barədə qərar ver",
        "İstifadəçidən kontekst soruş",
    ],
}


def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")


def primary_ioc(alert: NormalizedAlert) -> str:
    iocs = alert.external_iocs() or alert.observables
    v = iocs[0].value
    return defang(v[:60]) if iocs[0].type in ("url", "domain", "ip") else v[:16] + "…"


def title(alert: NormalizedAlert, d: Decision) -> str:
    where = alert.host or alert.user or "-"
    return f"[{d.priority}][{alert.alert_type}] {primary_ioc(alert)} on {where}"


def description(alert: NormalizedAlert, d: Decision) -> str:
    lines = [
        f"**Verdict:** {d.verdict} · **Severity:** {d.severity_id.name} · **Priority:** {d.priority}",
        f"**Qayda:** {d.rule_id} (versiya {d.rule_version})",
        "",
        "### Niyə",
        *[f"- {r}" for r in d.reasons],
        "",
        "### Alert",
        f"- Mənbə: {alert.source_system} · ID: {alert.source_ref}",
        f"- Hadisə vaxtı: {alert.time.isoformat()} · Qəbul: {alert.received_at.isoformat()}",
        f"- İstifadəçi: {alert.user} · Host: {alert.host}",
        f"- alert2case ID: {alert.alert_id} · fingerprint: {alert.fingerprint}",
    ]
    if d.shadow:
        lines += [
            "",
            "> Shadow mode: sistem bu alert-i avtomatik bağlayardı. Razısınızsa bağlayın,"
            " razı deyilsinizsə FP/FN rəyi yazın.",
        ]
    return "\n".join(lines)


def get_backend() -> CaseBackend:
    if settings.case_backend == "thehive":
        from app.case.thehive import TheHiveBackend

        return TheHiveBackend()
    from app.case.file_backend import FileBackend

    return FileBackend()
