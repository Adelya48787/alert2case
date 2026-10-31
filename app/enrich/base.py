"""Intel provider-lərin ümumi interfeysi və nəticə modeli."""

from abc import ABC, abstractmethod
from typing import Any, Literal
from pydantic import BaseModel, Field
from app.schemas.alert import Verdict

Status = Literal["ok", "not_found", "rate_limited", "timeout", "error", "auth_error", "skipped"]


class ProviderResult(BaseModel):
    provider: str
    ioc_type: str
    ioc: str
    status: Status
    score: int | None = None  # 0–100, yalnız status=ok olanda
    verdict: Verdict = "unknown"
    evidence: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int = 0
    cached: bool = False
    note: str = ""


def score_to_verdict(score: int) -> Verdict:
    if score >= 70:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "clean"


class IntelProvider(ABC):
    name: str
    supported: frozenset[str]
    per_minute: int
    per_day: int
    burst: int = 1

    def __init__(self) -> None:
        self.disabled_reason = ""

    @abstractmethod
    def api_key(self) -> str: ...
    @abstractmethod
    async def lookup(self, ioc_type: str, value: str) -> ProviderResult: ...
    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported

    def enabled(self) -> bool:
        return bool(self.api_key()) and not self.disabled_reason

    def ok(self, ioc_type: str, value: str, score: int, evidence: dict) -> ProviderResult:
        score = max(0, min(100, int(score)))
        return ProviderResult(
            provider=self.name,
            ioc_type=ioc_type,
            ioc=value,
            status="ok",
            score=score,
            verdict=score_to_verdict(score),
            evidence=evidence,
        )

    def result(self, ioc_type: str, value: str, status: Status, note: str = "") -> ProviderResult:
        return ProviderResult(provider=self.name, ioc_type=ioc_type, ioc=value, status=status, note=note)
