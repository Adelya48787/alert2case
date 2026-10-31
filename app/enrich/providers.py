"""VirusTotal, AbuseIPDB və OTX adapterləri. Hər biri cavabı 0–100 skora çevirir."""

import base64
from urllib.parse import quote
from app.config import settings
from app.enrich.base import IntelProvider, ProviderResult
from app.enrich.http import get_json

HASHES = {"hash_md5", "hash_sha1", "hash_sha256"}


class VirusTotal(IntelProvider):
    name = "virustotal"
    supported = frozenset({"ip", "domain", "url", *HASHES})
    per_minute, per_day, burst = 4, 500, 1  # public API: 4/dəq, ardıcıl yox

    def api_key(self) -> str:
        return settings.vt_api_key

    @staticmethod
    def path(ioc_type: str, value: str) -> str:
        if ioc_type in HASHES:
            return f"/files/{value}"
        if ioc_type == "domain":
            return f"/domains/{value}"
        if ioc_type == "ip":
            return f"/ip_addresses/{value}"
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"/urls/{url_id}"  # VT URL ID formatı

    async def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        data = await get_json(
            self.name, settings.vt_base_url + self.path(ioc_type, value), headers={"x-apikey": self.api_key()}
        )
        if data is None:
            return self.result(ioc_type, value, "not_found")
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        # 5 və daha çox mühərrik "malicious" deyirsə skor 100 olur
        score = round((mal + 0.5 * sus) * 20)
        return self.ok(
            ioc_type, value, score, {"malicious": mal, "suspicious": sus, "engines": sum(stats.values())}
        )


class AbuseIPDB(IntelProvider):
    name = "abuseipdb"
    supported = frozenset({"ip"})
    per_minute, per_day, burst = 30, 1000, 5

    def api_key(self) -> str:
        return settings.abuseipdb_api_key

    async def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        data = await get_json(
            self.name,
            settings.abuseipdb_base_url + "/check",
            headers={"Key": self.api_key(), "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": 90},
        )
        if data is None:
            return self.result(ioc_type, value, "not_found")
        d = data["data"]
        score = 0 if d.get("isWhitelisted") else int(d.get("abuseConfidenceScore", 0))
        return self.ok(
            ioc_type,
            value,
            score,
            {
                "confidence": d.get("abuseConfidenceScore"),
                "reports": d.get("totalReports"),
                "whitelisted": d.get("isWhitelisted"),
                "tor": d.get("isTor"),
                "country": d.get("countryCode"),
            },
        )


class OTX(IntelProvider):
    name = "otx"
    supported = frozenset({"ip", "domain", "url", *HASHES})
    per_minute, per_day, burst = 60, 10000, 10
    SECTION = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "hash_md5": "file",
        "hash_sha1": "file",
        "hash_sha256": "file",
    }

    def api_key(self) -> str:
        return settings.otx_api_key

    async def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        section = self.SECTION[ioc_type]
        if ioc_type == "ip" and ":" in value:
            section = "IPv6"
        url = f"{settings.otx_base_url}/indicators/{section}/{quote(value, safe='')}/general"
        data = await get_json(self.name, url, headers={"X-OTX-API-KEY": self.api_key()})
        if data is None:
            return self.result(ioc_type, value, "not_found")
        pulses = int(data.get("pulse_info", {}).get("count", 0))
        # OTX səs-küylüdür: məşhur təmiz IP-lər də pulse-larda olur. Skor 60-dan yuxarı qalxmır.
        return self.ok(ioc_type, value, min(60, pulses * 10), {"pulses": pulses})


PROVIDERS: list[IntelProvider] = [VirusTotal(), AbuseIPDB(), OTX()]
