"""Daxili kontekst: asset vacibliyi, istifadəçi imtiyazı, allowlist."""

import csv
import ipaddress
import logging
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit
import yaml
from app.schemas.alert import NormalizedAlert, Observable

log = logging.getLogger("context")
CTX_DIR = Path("context")
_cache: dict = {"stamp": None, "data": None}


def _stamp() -> tuple:
    return tuple(sorted((p.name, p.stat().st_mtime) for p in CTX_DIR.glob("*") if p.is_file()))


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "y")


def load() -> dict:
    """Fayllar dəyişəndə yenidən oxuyur. Restart lazım deyil."""
    stamp = _stamp()
    if _cache["stamp"] != stamp:
        assets, ids, allow = {}, {}, []
        if (CTX_DIR / "assets.csv").exists():
            with open(CTX_DIR / "assets.csv", encoding="utf-8") as f:
                assets = {r["hostname"].strip().lower(): r["criticality"].strip() for r in csv.DictReader(f)}
        if (CTX_DIR / "identities.csv").exists():
            with open(CTX_DIR / "identities.csv", encoding="utf-8") as f:
                ids = {r["user"].strip().lower(): r for r in csv.DictReader(f)}
        if (CTX_DIR / "allowlist.yaml").exists():
            allow = (yaml.safe_load((CTX_DIR / "allowlist.yaml").read_text(encoding="utf-8")) or {}).get(
                "entries", []
            )
        _cache.update(stamp=stamp, data={"assets": assets, "identities": ids, "allow": allow})
        log.info(
            "kontekst yükləndi: %s asset, %s istifadəçi, %s allowlist", len(assets), len(ids), len(allow)
        )
    return _cache["data"]


def allowlist_match(o: Observable, entries: list[dict], today: date) -> str | None:
    for e in entries:
        exp = e.get("expires_at")
        if exp and date.fromisoformat(str(exp)) < today:
            continue  # müddəti bitmiş qeyd tətbiq olunmur
        kind, value = e["type"], str(e["value"]).strip().lower()
        if kind == "ip_cidr" and o.type == "ip":
            if ipaddress.ip_address(o.value) in ipaddress.ip_network(value, strict=False):
                return e["reason"]
        elif kind == "domain" and o.type in ("domain", "url"):
            host = (urlsplit(o.value).hostname or "") if o.type == "url" else o.value
            if host == value or host.endswith("." + value):
                return e["reason"]
        elif kind == "hash" and o.type.startswith("hash_") and o.value == value:
            return e["reason"]
    return None


def apply_context(alert: NormalizedAlert, today: date | None = None) -> None:
    data = load()
    today = today or date.today()
    ident = data["identities"].get((alert.user or "").lower(), {})
    ext = alert.external_iocs()
    reasons = [r for o in ext if (r := allowlist_match(o, data["allow"], today))]
    alert.context = {
        "asset_criticality": data["assets"].get((alert.host or "").lower(), "unknown"),
        "user_privileged": _truthy(ident.get("is_privileged", "")),
        "user_vip": _truthy(ident.get("is_vip", "")),
        "allowlisted": bool(ext) and len(reasons) == len(ext),  # BÜTÜN xarici IOC-lar
        "allowlist_reason": "; ".join(sorted(set(reasons))),
    }
