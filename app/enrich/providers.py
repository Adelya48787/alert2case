"""VirusTotal, AbuseIPDB və OTX adapterləri. Hər biri cavabı 0–100 skora çevirir."""

import base64
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


PROVIDERS: list[IntelProvider] = [VirusTotal()]
