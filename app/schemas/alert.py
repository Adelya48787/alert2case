"""Vahid alert schema-sı. Sahələr OCSF Detection Finding (class_uid 2004) ilə uyğunlaşdırılıb."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(IntEnum):  # OCSF severity_id
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


AlertType = Literal["suspicious_login", "malicious_hash", "suspicious_url"]
ObsType = Literal["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "user", "host"]
Verdict = Literal["malicious", "suspicious", "clean", "unknown"]


class Observable(BaseModel):
    type: ObsType
    value: str
    role: Literal["src", "dst", "actor", "target", "artifact"] = "artifact"
    internal: bool = False  # daxili IP: xarici enrichment-ə göndərilmir


class Enrichment(BaseModel):  # Phase 3 doldurur
    status: Literal["pending", "ok", "partial", "failed", "skipped"] = "pending"
    reputation_score: int | None = None  # 0-100
    confidence: float = 0.0  # cavab verən / gözlənilən mənbə
    conflict: bool = False
    verdict: Verdict = "unknown"
    providers: list[dict[str, Any]] = Field(default_factory=list)


class Decision(BaseModel):  # Phase 4 doldurur
    verdict: Verdict
    severity_id: Severity
    priority: Literal["P1", "P2", "P3", "P4"]
    action: Literal["auto_close", "create_case"]
    rule_id: str
    rule_version: str
    reasons: list[str]
    shadow: bool = False
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NormalizedAlert(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    class_uid: int = 2004  # OCSF: Detection Finding
    alert_id: UUID = Field(default_factory=uuid4)
    source_system: Literal["wazuh", "edr", "proxy"]
    source_ref: str | None = None  # mənbədəki ID (dataset: HASH-01)
    alert_type: AlertType
    title: str
    time: datetime  # hadisənin baş verdiyi an
    received_at: datetime  # bizə çatdığı an = MTTR başlanğıcı
    severity_id: Severity = Severity.UNKNOWN
    user: str | None = None
    host: str | None = None
    observables: list[Observable] = Field(min_length=1)
    fingerprint: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    enrichment: Enrichment = Field(default_factory=Enrichment)
    decision: Decision | None = None
    raw: dict[str, Any]

    @field_validator("time", "received_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp-də saat qurşağı olmalıdır")
        return v.astimezone(timezone.utc)

    def external_iocs(self) -> list[Observable]:
        """Xarici intel-də yoxlanacaq observable-lar."""
        return [o for o in self.observables if not o.internal and o.type not in ("user", "host")]
