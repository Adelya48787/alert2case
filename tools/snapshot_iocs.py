#!/usr/bin/env python3
"""IOC snapshot-ları: VirusTotal, AbuseIPDB və OTX cavablarını bu günün tarixi ilə saxlayır.

İşlətmək (repo kökündən, venv aktiv):
    python tools/snapshot_iocs.py dataset/iocs_hash.csv            # fayldakı bütün IOC-lar
    python tools/snapshot_iocs.py dataset/iocs_login.csv --only LOGIN-03,LOGIN-04
    python tools/snapshot_iocs.py --check 1.2.3.4                  # namizədi yoxla, fayla yazma
    python tools/snapshot_iocs.py --check 'hxxp://bad[.]example/x' --type url

Qaydalar:
- Yalnız mövcud reputasiya hesabatı soruşulur (lookup). Heç nə skan edilmir, heç bir URL açılmır.
- Açarlar yalnız .env-dən oxunur, ekrana və fayla yazılmır.
- Əvvəlki snapshot-un üstünə yazılmır (--force olmadan): etiketləmə günündəki vəziyyət qalmalıdır.
- AbuseIPDB yalnız IP qəbul edir; hash və URL üçün sorğu göndərilmir və fayl yaradılmır.
- Yalnız standart kitabxana: Linux, WSL və macOS-da eyni işləyir.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUT = Path("dataset/snapshots")
VT_GAP_S = 15.5  # pulsuz VirusTotal: dəqiqədə 4 sorğu
TIMEOUT_S = 25
TYPE_BY_ALERT = {"malicious_hash": "hash", "suspicious_url": "url", "suspicious_login": "ip"}
HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

_last_vt = 0.0


def load_env(path: Path = Path(".env")) -> dict[str, str]:
    env: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def refang(s: str) -> str:
    s = s.strip().replace("[.]", ".").replace("[:]", ":")
    return re.sub(r"^hxxp", "http", s, flags=re.I)


def detect_type(ioc: str) -> str:
    if HEX64.match(ioc):
        return "hash"
    if IPV4.match(ioc):
        return "ip"
    return "url"


def http_get(url: str, headers: dict[str, str]) -> tuple[int, object]:
    req = urllib.request.Request(
        url, headers={**headers, "Accept": "application/json", "User-Agent": "alert2case-snapshot"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            status, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    try:
        return status, json.loads(body.decode("utf-8") or "null")
    except (ValueError, UnicodeDecodeError):
        return status, body.decode("utf-8", "replace")[:2000]


def vt(ioc: str, typ: str, key: str) -> tuple[str, int, object]:
    global _last_vt
    if typ == "hash":
        path = f"files/{ioc.lower()}"
    elif typ == "ip":
        path = f"ip_addresses/{ioc}"
    else:  # URL id = base64url(url) padding-siz; bu, skan deyil, mövcud hesabatın oxunmasıdır
        path = "urls/" + base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
    url = f"https://www.virustotal.com/api/v3/{path}"
    for attempt in (1, 2):
        wait = VT_GAP_S - (time.monotonic() - _last_vt)
        if wait > 0:
            time.sleep(wait)
        _last_vt = time.monotonic()
        status, data = http_get(url, {"x-apikey": key})
        if status != 429 or attempt == 2:
            return url, status, data
        print("    VT 429: 60 saniyə gözləyirik…")
        time.sleep(60)
    return url, status, data


def abuseipdb(ip: str, key: str) -> tuple[str, int, object]:
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
        {"ipAddress": ip, "maxAgeInDays": 90}
    )
    status, data = http_get(url, {"Key": key})
    return url, status, data


def otx(ioc: str, typ: str, key: str) -> tuple[str, int, object]:
    kind = {"hash": "file", "ip": "IPv4", "url": "url"}[typ]
    url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{urllib.parse.quote(ioc, safe='')}/general"
    status, data = http_get(url, {"X-OTX-API-KEY": key})
    return url, status, data


def summarize(provider: str, status: int, data: object) -> str:
    try:
        if provider == "vt":
            if status == 404:
                return "VT: tapılmadı (404)"
            s = data["data"]["attributes"]["last_analysis_stats"]  # type: ignore[index]
            total = sum(v for v in s.values() if isinstance(v, int))
            return f"VT: {s.get('malicious', 0)} malicious, {s.get('suspicious', 0)} suspicious / {total}"
        if provider == "abuseipdb":
            d = data["data"]  # type: ignore[index]
            return f"AbuseIPDB: skor {d['abuseConfidenceScore']}, {d['totalReports']} şikayət, Tor={d.get('isTor')}"
        if provider == "otx":
            return f"OTX: {data['pulse_info']['count']} pulse"  # type: ignore[index]
    except (KeyError, TypeError):
        pass
    return f"{provider}: HTTP {status}"


def run_one(
    alert_id: str | None,
    ioc: str,
    typ: str,
    keys: dict[str, str],
    providers: list[str],
    save: bool,
    force: bool,
) -> int:
    errors = 0
    for p in providers:
        if p == "abuseipdb" and typ != "ip":
            continue
        target = OUT / f"{alert_id}-{p}.json" if alert_id else None
        if save and target and target.exists() and not force:
            print(f"    {p}: artıq var ({target}), keçildi")
            continue
        key = keys.get({"vt": "VT_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY", "otx": "OTX_API_KEY"}[p], "")
        if not key:
            print(f"    {p}: .env-də açar yoxdur, keçildi")
            errors += 1
            continue
        try:
            if p == "vt":
                url, status, data = vt(ioc, typ, key)
            elif p == "abuseipdb":
                url, status, data = abuseipdb(ioc, key)
            else:
                url, status, data = otx(ioc, typ, key)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"    {p}: şəbəkə xətası ({type(e).__name__}), fayl yazılmadı")
            errors += 1
            continue
        print(f"    {summarize(p, status, data)}")
        if status in (401, 403):
            print(f"    {p}: açar qəbul olunmadı, fayl yazılmadı")
            errors += 1
            continue
        if status not in (200, 404):
            print(f"    {p}: HTTP {status}, fayl yazılmadı (sonra yenidən işlədin)")
            errors += 1
            continue
        if save and target:
            OUT.mkdir(parents=True, exist_ok=True)
            doc = {
                "alert_id": alert_id,
                "ioc": ioc,
                "ioc_type": typ,
                "provider": p,
                "endpoint": url,
                "http_status": status,
                "collected_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "response": data,
            }
            text = json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
            target.write_text(text, encoding="utf-8")
            if len(text.encode()) > 450_000:
                print(
                    f"    XƏBƏRDARLIQ: {target} {len(text) // 1024} KB, pre-commit 500 KB limitinə yaxındır"
                )
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="IOC snapshot-ları (VT, AbuseIPDB, OTX)")
    ap.add_argument("csv", nargs="*", type=Path, help="dataset/iocs_*.csv faylları")
    ap.add_argument("--only", default="", help="vergüllə alert_id-lər, məs. HASH-09,HASH-10")
    ap.add_argument("--providers", default="vt,abuseipdb,otx")
    ap.add_argument("--force", action="store_true", help="mövcud snapshot-un üstünə yaz")
    ap.add_argument("--check", metavar="IOC", help="namizəd IOC-u yoxla, fayla yazma")
    ap.add_argument("--type", choices=["hash", "url", "ip"], help="--check üçün tip (avtomatik təyin olunur)")
    a = ap.parse_args()

    if not Path("dataset").is_dir() and not a.check:
        sys.exit("Repo kökündən işlədin: cd ~/projects/alert2case")
    keys = load_env()
    providers = [p.strip() for p in a.providers.split(",") if p.strip()]

    if a.check:
        ioc = refang(a.check)
        typ = a.type or detect_type(ioc)
        print(f"{ioc} ({typ}) · fayla yazılmır")
        return 1 if run_one(None, ioc, typ, keys, providers, save=False, force=False) else 0

    if not a.csv:
        ap.error("ən azı bir CSV faylı və ya --check lazımdır")
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    errors = done = skipped = 0
    for path in a.csv:
        for r in csv.DictReader(path.open(encoding="utf-8")):
            aid = r["alert_id"]
            if only and aid not in only:
                continue
            raw = (r.get("ioc") or "").strip()
            if not raw:
                print(f"{aid}: IOC boşdur (pending), keçildi")
                skipped += 1
                continue
            ioc = refang(raw)
            typ = TYPE_BY_ALERT.get(r["alert_type"]) or detect_type(ioc)
            if typ == "hash" and not HEX64.match(ioc):
                print(f"{aid}: SHA256 deyil ({len(ioc)} simvol), keçildi")
                errors += 1
                continue
            print(f"{aid} · {typ}")
            errors += run_one(aid, ioc, typ, keys, providers, save=True, force=a.force)
            done += 1
    print(f"\nHazır: {done} IOC · boş: {skipped} · xəta: {errors} · fayllar: {OUT}/")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
