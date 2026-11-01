"""Deklarativ qayda mühərriki: YAML qaydaları, eval yoxdur, hər qərarın səbəbi var."""

import logging
import operator
from pathlib import Path
from typing import Any, Literal
import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from app.schemas.alert import Decision, NormalizedAlert, Severity, Verdict

log = logging.getLogger("rules")
RULES_FILE = Path("rules/severity.yaml")
OPS = {
    "eq": operator.eq,
    "ne": operator.ne,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
    "in": lambda value, arg: value in arg,
    "exists": lambda value, arg: (value is not None) == bool(arg),
}
NULL_SAFE = {"eq", "ne", "exists"}  # None ilə müqayisə olunanlar


class Then(BaseModel):
    verdict: Verdict
    severity_id: int = Field(ge=0, le=6)
    action: Literal["auto_close", "create_case"]


class Rule(BaseModel):
    id: str
    description: str = ""
    when: dict[str, dict[str, Any]]
    then: Then

    @field_validator("when")
    @classmethod
    def _known_ops(cls, v: dict) -> dict:
        for path, cond in v.items():
            unknown = set(cond) - set(OPS)
            if unknown:
                raise ValueError(f"{path}: naməlum operator {unknown}")
        return v


class RuleSet(BaseModel):
    version: str
    rules: list[Rule] = Field(min_length=1)

    @model_validator(mode="after")
    def _has_default(self) -> "RuleSet":
        if self.rules[-1].when:
            raise ValueError("son qayda şərtsiz (default) olmalıdır")
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("qayda ID-ləri təkrarlanır")
        return self


_loaded: dict = {"mtime": None, "rules": None}


def load_rules(path: Path = RULES_FILE) -> RuleSet:
    """Fayl dəyişəndə yenidən oxuyur. Səhv faylda əvvəlki işlək versiya qalır."""
    mtime = path.stat().st_mtime
    if _loaded["mtime"] != mtime:
        try:
            _loaded["rules"] = RuleSet.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
            log.info("qaydalar yükləndi: versiya %s", _loaded["rules"].version)
        except (ValidationError, yaml.YAMLError) as e:
            if _loaded["rules"] is None:
                raise
            log.error("qayda faylı səhvdir, köhnə versiya saxlanılır: %s", e)
        _loaded["mtime"] = mtime
    return _loaded["rules"]


def get_path(doc: dict, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(doc, dict):
            return None
        doc = doc.get(part)
    return doc


def matches(when: dict, doc: dict) -> bool:
    for path, cond in when.items():
        value = get_path(doc, path)
        for op, arg in cond.items():
            if value is None and op not in NULL_SAFE:
                return False
            if not OPS[op](value, arg):
                return False
    return True


def priority_for(severity: int, ctx: dict) -> str:
    critical = (
        ctx.get("user_privileged")
        or ctx.get("user_vip")
        or ctx.get("asset_criticality") in ("high", "crown_jewel")
    )
    if severity >= Severity.CRITICAL or (severity == Severity.HIGH and critical):
        return "P1"
    if severity == Severity.HIGH or (severity == Severity.MEDIUM and critical):
        return "P2"
    if severity == Severity.MEDIUM:
        return "P3"
    return "P4"


def evidence_lines(alert: NormalizedAlert) -> list[str]:
    e = alert.enrichment
    lines = [f"intel: {e.verdict}, skor {e.reputation_score}, etibarlılıq {e.confidence}, status {e.status}"]
    if e.conflict:
        lines.append("intel mənbələri bir-birinə ziddir")
    for p in e.providers:
        if p.get("status") == "ok" and p.get("evidence"):
            ev = ", ".join(f"{k}={v}" for k, v in p["evidence"].items() if v is not None)
            lines.append(f"{p['provider']} ({p['ioc_type']}): skor {p['score']}; {ev}")
        elif p.get("status") != "ok":
            lines.append(f"{p['provider']} ({p['ioc_type']}): {p['status']}")
    c = alert.context
    if c.get("user_privileged"):
        lines.append(f"istifadəçi imtiyazlıdır: {alert.user}")
    if c.get("asset_criticality") in ("high", "crown_jewel"):
        lines.append(f"asset vacibliyi: {c['asset_criticality']} ({alert.host})")
    if c.get("allowlisted"):
        lines.append(f"allowlist: {c.get('allowlist_reason')}")
    return lines


def decide(alert: NormalizedAlert, rules: RuleSet | None = None) -> Decision:
    rules = rules or load_rules()
    doc = alert.model_dump(mode="json")
    rule = next(r for r in rules.rules if matches(r.when, doc))
    sev = rule.then.severity_id
    return Decision(
        verdict=rule.then.verdict,
        severity_id=Severity(sev),
        priority=priority_for(sev, alert.context),
        action=rule.then.action,
        rule_id=rule.id,
        rule_version=rules.version,
        reasons=[f"qayda {rule.id}: {rule.description}", *evidence_lines(alert)],
    )
