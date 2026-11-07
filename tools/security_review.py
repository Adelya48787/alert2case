"""6.6b: təhlükəsizlik review-nun avtomatlaşdırıla bilən yoxlamaları (docs/security-review.md, 1–9).

    .venv/bin/python -m tools.security_review        # dev stek qalxmış olmalıdır (make up)

İşləyən steki yoxlayır və nəticəni docs/security/review_checks.md-yə yazır.
Sirlər yalnız .env-dən oxunur, heç vaxt çap olunmur: ekrana yalnız açarın ADI və sayı çıxır.
Case yoxdursa, bir neçə alert göndərir (lokal test məlumatı).
"""

from __future__ import annotations

import json
import os
import re
import subprocess  # nosec B404
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime
from pathlib import Path

import yaml
from dotenv import dotenv_values

API = os.environ.get("REVIEW_API", "http://localhost:8000")
MAILPIT = os.environ.get("REVIEW_MAILPIT", "http://localhost:8025")
OUT = Path("docs/security/review_checks.md")
ENV = dotenv_values(".env")
SECRET_KEYS = [
    "VT_API_KEY",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "THEHIVE_API_KEY",
    "THEHIVE_SECRET",
    "SLACK_WEBHOOK_URL",
    "TELEGRAM_BOT_TOKEN",
    "POSTGRES_PASSWORD",
    "WEBHOOK_HMAC_SECRET",
    "ADMIN_TOKEN",
    "FEEDBACK_TOKEN",
    "N8N_WEBHOOK_TOKEN",
    "N8N_ENCRYPTION_KEY",
    "GRAFANA_ADMIN_PASSWORD",
]
DC = ["docker", "compose"]
rows: list[tuple[int, str, str, str]] = []  # (#, nəticə, necə yoxlanıldı, sübut)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)  # nosec B603


def http(method: str, path: str, body: bytes = b"", headers: dict | None = None, base: str = API) -> int:
    req = urllib.request.Request(base + path, data=body or None, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # nosec B310
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return 0


def record(n: int, ok: bool | None, how: str, evidence: str) -> None:
    mark = "OK" if ok else ("ƏL İLƏ" if ok is None else "FAIL")
    rows.append((n, mark, how, evidence))
    color = {"OK": "32", "FAIL": "31"}.get(mark, "33")
    print(f"  \033[{color}m{mark:6}\033[0m {n}. {evidence}")


# ---------------------------------------------------------------- 1. autentifikasiya
def check_auth() -> None:
    j = {"Content-Type": "application/json"}
    bad = {"X-Admin-Token": "wrong-token", **j}
    cases = [
        ("POST", "/ingest/edr", b"{}", {"X-Signature": "sha256=" + "0" * 64}, 401),
        ("POST", "/ingest/edr", b"{}", {}, 401),
        ("GET", "/dlq", b"", {}, 403),
        ("GET", "/dlq", b"", bad, 403),
        ("POST", "/dlq/replay", b"", {}, 403),
        ("POST", "/dlq/cases/replay", b"", {}, 403),
        ("GET", "/alerts/00000000-0000-0000-0000-000000000000/timeline", b"", {}, 403),
        ("POST", "/feedback", b"{}", j, 403),
        ("POST", "/feedback/thehive", b"{}", j, 403),
        ("POST", "/feedback/thehive", b"{}", {"Authorization": "Bearer wrong", **j}, 403),
        ("POST", "/stage/act", b"{}", j, 403),
    ]
    got = [(m, p, http(m, p, b, h), exp) for m, p, b, h, exp in cases]
    wrong = [f"{m} {p} → {c} (gözlənilən {e})" for m, p, c, e in got if c != e]
    record(
        1,
        not wrong,
        "token-siz və səhv token ilə 11 sorğu",
        f"{len(got) - len(wrong)}/{len(got)} endpoint 401/403 qaytardı"
        + (f"; {'; '.join(wrong)}" if wrong else ""),
    )


# ---------------------------------------------------------------- 2. portlar
def check_ports() -> None:
    out = run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"]).stdout
    exposed, local = [], 0
    for line in out.splitlines():
        name, _, ports = line.partition("\t")
        for p in filter(None, (x.strip() for x in ports.split(","))):
            if "->" not in p:
                continue  # yalnız daxili şəbəkə portu
            if p.startswith("127.0.0.1:") or p.startswith("[::1]:"):
                local += 1
            else:
                exposed.append(f"{name} {p}")
    record(
        2,
        not exposed and local > 0,
        "`docker ps` port bağlamaları",
        f"{local} port yalnız 127.0.0.1-də" + (f"; xaricə açıq: {', '.join(exposed)}" if exposed else ""),
    )


# ---------------------------------------------------------------- 3. ölçü limiti
def check_size() -> None:
    c = http("POST", "/ingest/edr", b"a" * 300_000, {"Content-Type": "application/json"})
    record(3, c == 413, "300 KB payload → /ingest/edr", f"cavab {c} (gözlənilən 413, limit 256 KB)")


# ---------------------------------------------------------------- 4. loglarda secret
def check_logs() -> None:
    logs = run(DC + ["logs", "--no-color"]).stdout
    found, checked = [], 0
    for k in SECRET_KEYS:
        v = (ENV.get(k) or "").strip()
        if len(v) < 8:  # boş və ya çox qısa dəyər: yoxlamaq mənasızdır
            continue
        checked += 1
        n = logs.count(v)
        if n:
            found.append(f"{k} ({n} dəfə)")
    record(
        4,
        not found and checked > 0,
        "`docker compose logs` içində .env-dəki hər secret-in dəyəri axtarılır (dəyər çap olunmur)",
        f"{checked} secret yoxlandı, {len(logs.splitlines())} log sətri; tapılan: {', '.join(found) if found else '0'}",
    )


# ---------------------------------------------------------------- 5. audit
def check_audit() -> None:
    psql = DC + ["exec", "-T", "postgres", "psql", "-U", "soc", "-d", "alert2case", "-tAc"]
    v = run(DC + ["exec", "-T", "api", "python", "-m", "tools.verify_audit"])
    chain_ok = v.returncode == 0 and "OK" in v.stdout
    u = run(psql + ["UPDATE audit_log SET event = event WHERE id = (SELECT min(id) FROM audit_log)"])
    d = run(psql + ["DELETE FROM audit_log WHERE id = (SELECT min(id) FROM audit_log)"])
    blocked = all(r.returncode != 0 and "append-only" in r.stderr for r in (u, d))
    record(
        5,
        chain_ok and blocked,
        "`tools.verify_audit` + UPDATE/DELETE cəhdi",
        f"zəncir: {v.stdout.strip().splitlines()[-1] if v.stdout.strip() else 'xəta'}; "
        f"UPDATE/DELETE: {'trigger rədd etdi' if blocked else 'RƏDD EDİLMƏDİ'}",
    )


# ---------------------------------------------------------------- 6. container
def check_container() -> None:
    imgs = run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]).stdout.split()
    img = next((i for i in imgs if i.startswith("alert2case:") and i != "alert2case:<none>"), None)
    uid = run(["docker", "run", "--rm", "--entrypoint", "id", img, "-u"]).stdout.strip() if img else ""
    cfg = run(
        DC + ["-f", "docker-compose.yml", "-f", "docker-compose.prod.yml", "config", "--format", "json"]
    )
    hard = []
    try:
        svcs = json.loads(cfg.stdout)["services"]  # interpolasiya olunmuş config: çap ETMİRİK
        for s in ("api", "worker"):
            c = svcs.get(s, {})
            if c.get("read_only") and "ALL" in (c.get("cap_drop") or []):
                hard.append(s)
    except (ValueError, KeyError):
        pass
    record(
        6,
        uid == "10001" and hard == ["api", "worker"],
        "prod image-də `id -u`, prod compose config-də read_only və cap_drop",
        f"image {img or 'tapılmadı (make up-prod və ya docker build)'}: uid {uid or '?'}; "
        f"read_only + cap_drop ALL: {', '.join(hard) or 'yox'}",
    )


# ---------------------------------------------------------------- 7. defang
RAW_URL = re.compile(r"\bhttps?://|\b[a-z0-9-]+\.(?:com|org|net|ru|xyz|io|az|info|top)\b", re.I)


def ensure_cases() -> list[dict]:
    def load() -> list[dict]:
        r = run(DC + ["exec", "-T", "worker", "sh", "-c", "cat /code/var/cases/*.json 2>/dev/null"])
        docs, buf = [], r.stdout
        dec = json.JSONDecoder()
        i = 0
        while i < len(buf):
            while i < len(buf) and buf[i].isspace():
                i += 1
            if i >= len(buf):
                break
            obj, i = dec.raw_decode(buf, i)
            docs.append(obj)
        return docs

    docs = load()
    if not any("url" in str(d.get("tags")) for d in docs):
        print("  (URL case-i yoxdur: URL-01, URL-02, URL-03, HASH-01 göndərilir, ~2-3 dəq)")
        run([sys.executable, "tools/simulator.py", "--rate", "1", "--only", "URL-01,URL-02,URL-03,HASH-01"])
        for _ in range(60):
            time.sleep(5)
            docs = load()
            if sum("url" in str(d.get("tags")) for d in docs) >= 2:
                break
    return docs


def check_defang() -> None:
    docs = ensure_cases()
    titles = [d.get("title", "") for d in docs if "suspicious_url" in str(d.get("tags"))]
    raw_titles = [t for t in titles if RAW_URL.search(t)]
    mails, raw_mails = 0, 0
    try:
        with urllib.request.urlopen(MAILPIT + "/api/v1/messages?limit=50", timeout=10) as r:  # nosec B310
            msgs = json.load(r).get("messages", [])
        for m in msgs:
            with urllib.request.urlopen(f"{MAILPIT}/api/v1/message/{m['ID']}", timeout=10) as r:  # nosec B310
                text = json.load(r).get("Text", "")
            mails += 1
            raw_mails += bool(re.search(r"\bhttps?://", text))
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        pass
    record(
        7,
        bool(titles) and not raw_titles and not raw_mails,
        "URL case başlıqları (var/cases) və Mailpit bildirişləri",
        f"{len(titles)} URL case başlığı, defang olunmamış: {len(raw_titles)}; "
        f"{mails} bildiriş, defang olunmamış URL: {raw_mails}",
    )


# ---------------------------------------------------------------- 8. allowlist
def check_allowlist() -> None:
    entries = (yaml.safe_load(Path("context/allowlist.yaml").read_text(encoding="utf-8")) or {}).get(
        "entries", []
    )
    bad = []
    for e in entries:
        miss = [k for k in ("owner", "reason", "expires_at") if not e.get(k)]
        exp = e.get("expires_at")
        exp = exp if isinstance(exp, date) else (datetime.fromisoformat(str(exp)).date() if exp else None)
        if miss:
            bad.append(f"{e.get('value')}: {', '.join(miss)} yoxdur")
        elif exp and exp < date.today():
            bad.append(f"{e.get('value')}: müddəti keçib ({exp})")
    record(
        8,
        bool(entries) and not bad,
        "`context/allowlist.yaml`: owner, reason, expires_at",
        f"{len(entries)} qeyd"
        + (f"; problem: {'; '.join(bad)}" if bad else ", hamısı tam və müddəti keçməyib"),
    )


# ---------------------------------------------------------------- 9. malicious bağlanmır
def check_malicious() -> None:
    r = run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "tests/unit", "-k", "malicious"])
    last = next(
        (x.strip("= ") for x in reversed(r.stdout.splitlines()) if re.search(r"\d+ (passed|failed)", x)), "?"
    )
    record(
        9,
        r.returncode == 0,
        "unit testlər `-k malicious` (+ E2E `test_malicious_never_closed`, 6.4)",
        f"pytest: {last}",
    )


def main() -> int:
    if not ENV:
        print(".env tapılmadı: repo kökündən işə salın")
        return 1
    if http("GET", "/health") != 200:
        print("API cavab vermir: stek qalxıbmı (make up)?")
        return 1
    print("Təhlükəsizlik yoxlamaları (6.6b):")
    # 7 əvvəl: case və bildiriş yaranır, audit log dolur, loglarda real trafik olur
    checks = [
        (1, check_auth),
        (2, check_ports),
        (3, check_size),
        (7, check_defang),
        (4, check_logs),
        (5, check_audit),
        (6, check_container),
        (8, check_allowlist),
        (9, check_malicious),
    ]
    for n, f in checks:
        try:
            f()
        except Exception as e:  # bir yoxlamanın xətası digərlərini dayandırmasın
            record(n, False, f.__name__, f"yoxlama xətası: {type(e).__name__}")
    record(
        10,
        None,
        "1.5-dəki qeydiyyat",
        "VirusTotal şərtləri: komanda bir açar və qeyri-kommersiya istifadəni təsdiqləyir",
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Təhlükəsizlik yoxlamaları: avtomatik nəticələr",
        "",
        f"Tarix: {datetime.now().astimezone():%Y-%m-%d %H:%M} · Skript: `python -m tools.security_review`",
        "",
        "| # | Nəticə | Necə yoxlanıldı | Sübut |",
        "|---|---|---|---|",
        *[f"| {n} | {m} | {h} | {e} |" for n, m, h, e in sorted(rows)],
    ]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    fails = sum(m == "FAIL" for _, m, _, _ in rows)
    print(f"\nNəticə: {OUT}")
    print(
        f"SECREVIEW {'OK' if not fails else 'FAIL'} · {sum(m == 'OK' for _, m, _, _ in rows)} OK · {fails} FAIL · 1 əl ilə"
    )
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
