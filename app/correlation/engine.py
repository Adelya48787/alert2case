"""Oxşar case-lərin əlaqələndirilməsi. İndeks Redis-dədir: IOC/user/host → case ID-ləri."""

import hashlib
import ipaddress
import json
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import yaml

from app.audit.log import audit
from app.case.base import CaseRef
from app.queue import get_redis
from app.rules.engine import priority_for
from app.schemas.alert import NormalizedAlert, Observable, Severity

CFG_FILE = Path("rules/correlation.yaml")


@lru_cache(maxsize=1)
def load_cfg(path: str = str(CFG_FILE)) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _h(v: str) -> str:
    return hashlib.sha256(v.lower().encode()).hexdigest()[:24]


def obs_key(o: Observable) -> str:
    return f"corr:obs:{o.type}:{_h(o.value)}"


def user_key(user: str) -> str:
    return f"corr:user:{_h(user)}"


def host_key(host: str) -> str:
    return f"corr:host:{_h(host)}"


def case_key(case_id: str) -> str:
    return f"corr:case:{case_id}"


async def _fresh_cases(key: str, hours: int) -> list[tuple[str, dict]]:
    r = get_redis()
    out = []
    now = datetime.now(timezone.utc)
    for cid in await r.smembers(key):
        meta = await r.hgetall(case_key(cid))
        if meta and (now - datetime.fromisoformat(meta["created"])).total_seconds() < hours * 3600:
            out.append((cid, meta))
    return out


def _ref(cid: str, meta: dict) -> CaseRef:
    return CaseRef(backend=meta["backend"], case_id=cid, url=meta["url"])


def _bump(alert: NormalizedAlert, by: int, reason: str, min_severity: int = 0) -> None:
    d = alert.decision
    sev = Severity(min(Severity.CRITICAL, max(int(d.severity_id) + by, min_severity)))
    alert.decision = d.model_copy(
        update={
            "severity_id": sev,
            "priority": priority_for(sev, alert.context),
            "action": "create_case",
            "reasons": [*d.reasons, reason],
        }
    )


async def correlate(alert: NormalizedAlert) -> CaseRef | None:
    """Əlaqələndiriləcək case-i qaytarır (C1, C4) və ya qərarı yerində gücləndirir (C2, C3)."""
    cfg, rules = load_cfg(), load_cfg()["rules"]
    hours = cfg["window_hours"]
    related: list[str] = alert.context.setdefault("related_cases", [])

    if rules["same_ioc"]["enabled"]:  # C1
        for o in alert.external_iocs():
            for cid, meta in await _fresh_cases(obs_key(o), hours):
                d = alert.decision
                alert.decision = d.model_copy(
                    update={
                        "action": "create_case",
                        "reasons": [*d.reasons, f"korrelyasiya C1: {o.type} {cid} case-ində artıq var"],
                    }
                )
                await audit(alert.alert_id, "correlate", "same_ioc", {"case_id": cid, "ioc_type": o.type})
                return _ref(cid, meta)

    if rules["same_user_multi_type"]["enabled"] and alert.user:  # C2
        for cid, meta in await _fresh_cases(user_key(alert.user), hours):
            if meta["alert_type"] != alert.alert_type:
                _bump(
                    alert,
                    rules["same_user_multi_type"]["severity_bump"],
                    f"korrelyasiya C2: {alert.user} üçün {meta['alert_type']} case-i var ({cid})",
                )
                related.append(cid)
                await audit(alert.alert_id, "correlate", "same_user", {"case_id": cid})
                break

    if rules["same_host_chain"]["enabled"] and alert.host:  # C3
        chain = {"malicious_hash", "suspicious_url"}
        for cid, meta in await _fresh_cases(host_key(alert.host), hours):
            if {meta["alert_type"], alert.alert_type} == chain and meta.get("verdict") != "clean":
                _bump(
                    alert,
                    0,
                    f"korrelyasiya C3: {alert.host}-da hash + URL zənciri ({cid})",
                    min_severity=Severity.CRITICAL,
                )
                related.append(cid)
                await audit(alert.alert_id, "correlate", "host_chain", {"case_id": cid})
                break

    bf = rules["login_bruteforce"]  # C4
    src = [o for o in alert.external_iocs() if o.type == "ip"]
    if bf["enabled"] and alert.alert_type == "suspicious_login" and src:
        net = str(ipaddress.ip_network(f"{src[0].value}/{bf['subnet_prefix']}", strict=False))
        r, now = get_redis(), time.time()
        zkey = f"corr:bf:{net}"
        await r.zadd(zkey, {str(alert.alert_id): now})
        await r.zremrangebyscore(zkey, 0, now - bf["window_minutes"] * 60)
        await r.expire(zkey, bf["window_minutes"] * 60)
        existing = await r.get(f"corr:bf:case:{net}")
        if existing:
            await audit(alert.alert_id, "correlate", "bruteforce_link", {"subnet": net})
            return CaseRef(**json.loads(existing))
        if await r.zcard(zkey) >= bf["threshold"]:
            _bump(
                alert,
                1,
                f"korrelyasiya C4: {net} şəbəkəsindən {bf['window_minutes']} dəq-də "
                f"{bf['threshold']}+ login cəhdi (kampaniya)",
                min_severity=Severity.HIGH,
            )
            alert.context["campaign_subnet"] = net
            await audit(alert.alert_id, "correlate", "bruteforce_campaign", {"subnet": net})
    return None


async def index_case(alert: NormalizedAlert, ref: CaseRef) -> None:
    """Yaranan və ya əlaqələndirilən case-i indeksə yazır ki, sonrakı alert-lər onu tapsın."""
    cfg = load_cfg()
    r, ttl = get_redis(), cfg["index_ttl_days"] * 86400
    if not await r.exists(case_key(ref.case_id)):
        await r.hset(
            case_key(ref.case_id),
            mapping={
                "backend": ref.backend,
                "url": ref.url,
                "alert_type": alert.alert_type,
                "verdict": alert.decision.verdict,
                "created": datetime.now(timezone.utc).isoformat(),
            },
        )
        await r.expire(case_key(ref.case_id), ttl)
    keys = [obs_key(o) for o in alert.external_iocs()]
    keys += [user_key(alert.user)] if alert.user else []
    keys += [host_key(alert.host)] if alert.host else []
    for k in keys:
        await r.sadd(k, ref.case_id)
        await r.expire(k, ttl)
    net = alert.context.get("campaign_subnet")
    if net:
        bf = cfg["rules"]["login_bruteforce"]
        await r.set(f"corr:bf:case:{net}", ref.model_dump_json(), ex=bf["window_minutes"] * 60)
