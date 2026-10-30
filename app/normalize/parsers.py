"""Mənbə parser-ləri: hər mənbənin öz formatı → NormalizedAlert."""

import ipaddress
from datetime import datetime
from urllib.parse import urlsplit

from app.normalize.base import BaseParser, Severity, parse_ts, register
from app.normalize.iocs import domain_of, hash_type, is_internal_ip, normalize_url
from app.schemas.alert import NormalizedAlert, Observable


def _wazuh_level(level: int) -> Severity:
    if level >= 15:
        return Severity.CRITICAL
    if level >= 12:
        return Severity.HIGH
    if level >= 8:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFORMATIONAL


_EDR_SEV = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@register
class WazuhParser(BaseParser):
    source = "wazuh"

    def parse(self, p: dict, received_at: datetime) -> NormalizedAlert:
        ip = p["data"]["srcip"].strip()
        user = (p["data"].get("dstuser") or "").lower() or None
        obs = [Observable(type="ip", value=ip, role="src", internal=is_internal_ip(ip))]
        if user:
            obs.append(Observable(type="user", value=user, role="target"))
        return NormalizedAlert(
            source_system="wazuh",
            source_ref=p.get("id"),
            alert_type="suspicious_login",
            title=p["rule"]["description"],
            time=parse_ts(p["timestamp"]),
            received_at=received_at,
            severity_id=_wazuh_level(int(p["rule"]["level"])),
            user=user,
            host=p.get("agent", {}).get("name"),
            observables=obs,
            raw=p,
        )


@register
class EdrParser(BaseParser):
    source = "edr"

    def parse(self, p: dict, received_at: datetime) -> NormalizedAlert:
        h = p["file"]["sha256"].strip().lower()
        obs = [Observable(type=hash_type(h), value=h, role="artifact")]
        user = (p.get("user") or "").lower() or None
        if user:
            obs.append(Observable(type="user", value=user, role="actor"))
        host = p.get("device", {}).get("hostname")
        if host:
            obs.append(Observable(type="host", value=host, role="target"))
        return NormalizedAlert(
            source_system="edr",
            source_ref=p.get("detection_id"),
            alert_type="malicious_hash",
            title=f"{p['detection']['name']}: {p['file'].get('name', '?')}",
            time=parse_ts(p["event_time"]),
            received_at=received_at,
            severity_id=_EDR_SEV.get(p["detection"].get("severity", "").lower(), Severity.UNKNOWN),
            user=user,
            host=host,
            observables=obs,
            raw=p,
        )


@register
class ProxyParser(BaseParser):
    source = "proxy"

    def parse(self, p: dict, received_at: datetime) -> NormalizedAlert:
        url = normalize_url(p["url"]["full"])
        obs = [Observable(type="url", value=url, role="dst")]
        dom = domain_of(url)
        if dom:
            obs.append(Observable(type="domain", value=dom, role="dst"))
        else:  # URL-də domain yox, IP var: IP-ni ayrıca yoxlamaq üçün əlavə edirik
            host = urlsplit(url).hostname or ""
            try:
                ipaddress.ip_address(host)
                obs.append(Observable(type="ip", value=host, role="dst", internal=is_internal_ip(host)))
            except ValueError:
                pass
        src = p.get("source", {}).get("ip")
        if src:
            obs.append(Observable(type="ip", value=src, role="src", internal=is_internal_ip(src)))
        user = (p.get("user", {}).get("name") or "").lower() or None
        if user:
            obs.append(Observable(type="user", value=user, role="actor"))
        return NormalizedAlert(
            source_system="proxy",
            source_ref=p.get("event", {}).get("id"),
            alert_type="suspicious_url",
            title=f"Web request to {dom or url[:60]}",
            time=parse_ts(p["@timestamp"]),
            received_at=received_at,
            severity_id=Severity.LOW,
            user=user,
            observables=obs,
            raw=p,
        )
