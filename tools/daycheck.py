"""Gündəlik / təqdimatdan əvvəl sağlamlıq yoxlaması (6.8). Yalnız oxuyur, heç nəyi dəyişmir.

    .venv/bin/python tools/daycheck.py              # bir dəfə, audit zənciri də yoxlanır
    .venv/bin/python tools/daycheck.py --no-audit   # audit zənciri olmadan (sürətli)
    .venv/bin/python tools/daycheck.py --watch 10   # hər 10 s yenilə (Ctrl+C ilə çıx)

Host-dan işləyir: Postgres localhost:5432, Redis localhost:6379, API localhost:8000.
Sirlər ekrana çıxmır: .env-dən yalnız parol (bağlantı üçün) və üç konfiq bayrağı oxunur.
"Yekun" hissəsində KRİTİK sətir varsa çıxış kodu 1-dir.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import asyncpg
import httpx
import redis
import typer
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent
STREAM_IN, STREAM_DLQ, CASES_DLQ, GROUP = "alerts.in", "alerts.dlq", "cases.dlq", "pipeline"
DEMO_CONFIG = {"AUTO_CLOSE_ENABLED": "false", "SHADOW_MODE": "true", "CASE_BACKEND": "thehive"}
CORE = ("api", "worker", "postgres", "redis")

# Profil servisləri: işləmirsə yalnız xəbərdarlıq (TheHive istisna: CASE_BACKEND=thehive olanda kritikdir)
WEB = {
    "api": "http://localhost:8000/health",
    "thehive": "http://localhost:9000/api/status",
    "mailpit": "http://localhost:8025/",
    "n8n": "http://localhost:5678/healthz",
    "grafana": "http://localhost:3000/api/health",
    "prometheus": "http://localhost:9090/-/ready",
}

app = typer.Typer(add_completion=False)


@dataclass
class Facts:
    config: dict[str, str] = field(default_factory=dict)
    containers: dict[str, str] = field(default_factory=dict)  # servis -> state (running, exited...)
    web: dict[str, bool] = field(default_factory=dict)
    db_ok: bool = False
    redis_ok: bool = False
    alerts: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    dedup_merged: int = 0
    decisions: list[tuple] = field(default_factory=list)
    intel: dict[str, dict[str, int]] = field(default_factory=dict)  # provider -> status -> say
    pending: int | None = None
    lag: int | None = None
    alerts_dlq: int | None = None
    cases_dlq: int | None = None
    audit: str | None = None  # None = yoxlanmadı
    audit_ok: bool = True


def verdicts(f: Facts) -> list[tuple[str, str]]:
    """Faktlardan (səviyyə, mesaj) siyahısı. Səviyyə: KRİTİK və ya XƏBƏRDARLIQ."""
    out: list[tuple[str, str]] = []
    crit = lambda m: out.append(("KRİTİK", m))  # noqa: E731
    warn = lambda m: out.append(("XƏBƏRDARLIQ", m))  # noqa: E731

    for svc in CORE:
        state = f.containers.get(svc)
        if state != "running":
            crit(f"{svc} konteyneri işləmir ({state or 'yoxdur'}): make up")
    if f.containers.get("api") == "running" and not f.web.get("api"):
        crit(
            "API konteyneri running, amma /health cavab vermir: docker compose up -d --force-recreate api worker"
        )
    if not f.db_ok:
        crit("Postgres-ə qoşulmaq olmur (localhost:5432)")
    if not f.redis_ok:
        crit("Redis-ə qoşulmaq olmur (localhost:6379)")
    if f.config.get("CASE_BACKEND") == "thehive" and not f.web.get("thehive"):
        crit("CASE_BACKEND=thehive, amma TheHive cavab vermir: make up-full (açılması 1–2 dəq)")
    for svc in ("mailpit", "n8n", "grafana", "prometheus"):
        if not f.web.get(svc):
            warn(f"{svc} cavab vermir")
    for key, want in DEMO_CONFIG.items():
        if f.config.get(key) != want:
            warn(f"{key}={f.config.get(key)!r}, demo üçün {want} gözlənilir")
    if f.lag and f.lag > 20:
        warn(f"alerts.in növbəsində {f.lag} emal olunmamış mesaj: worker gecikir və ya dayanıb")
    if f.alerts_dlq:
        warn(f"alerts.dlq-da {f.alerts_dlq} mesaj: GET /dlq ilə baxın")
    if f.cases_dlq:
        warn(f"cases.dlq-da {f.cases_dlq} gözləyən case: case backend əlçatmazdır?")
    for prov, counts in f.intel.items():
        if counts.get("auth_error"):
            crit(f"{prov}: auth_error, API açarı etibarsızdır")
    if not f.audit_ok:
        crit(f"audit zənciri: {f.audit}")
    return out


def _env() -> dict[str, str]:
    vals = dotenv_values(ROOT / ".env")
    return {k: (v or "") for k, v in vals.items()}


def _containers() -> dict[str, str]:
    try:
        out = subprocess.run(
            [
                "docker",
                "compose",
                "--profile",
                "thehive",
                "--profile",
                "obs",
                "ps",
                "-a",
                "--format",
                "{{.Service}} {{.State}}",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)


def _web() -> dict[str, bool]:
    res = {}
    with httpx.Client(timeout=2.0) as c:
        for name, url in WEB.items():
            try:
                res[name] = c.get(url).status_code < 500
            except httpx.HTTPError:
                res[name] = False
    return res


async def _db(f: Facts, password: str) -> None:
    try:
        conn = await asyncpg.connect(
            host="localhost", port=5432, user="soc", password=password, database="alert2case", timeout=3
        )
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        return
    f.db_ok = True
    try:
        f.alerts = await conn.fetchval("SELECT count(*) FROM alerts")
        f.by_status = dict(await conn.fetch("SELECT status, count(*) FROM alerts GROUP BY 1 ORDER BY 2 DESC"))
        f.dedup_merged = await conn.fetchval("SELECT coalesce(sum(occurrence_count - 1), 0) FROM alerts")
        f.decisions = [
            tuple(r)
            for r in await conn.fetch(
                "SELECT rule_id, priority, action, count(*) FROM decisions GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 8"
            )
        ]
        for prov, status, n in await conn.fetch(
            """SELECT p->>'provider', p->>'status', count(*) FROM alerts a,
                      jsonb_array_elements(a.doc->'enrichment'->'providers') p GROUP BY 1, 2"""
        ):
            f.intel.setdefault(prov, {})[status] = n
    finally:
        await conn.close()


def _redis(f: Facts) -> None:
    r = redis.Redis(host="localhost", port=6379, socket_timeout=2, decode_responses=True)
    try:
        r.ping()
    except redis.RedisError:
        return
    f.redis_ok = True
    try:
        for g in r.xinfo_groups(STREAM_IN):
            if g["name"] == GROUP:
                f.pending, f.lag = g.get("pending"), g.get("lag")
    except redis.ResponseError:  # stream hələ yaranmayıb
        pass
    f.alerts_dlq, f.cases_dlq = r.xlen(STREAM_DLQ), r.xlen(CASES_DLQ)


def _audit(f: Facts) -> None:
    try:
        p = subprocess.run(
            ["docker", "compose", "exec", "-T", "api", "python", "-m", "tools.verify_audit"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        f.audit, f.audit_ok = f"yoxlanmadı: {type(e).__name__}", False
        return
    f.audit = (p.stdout or p.stderr).strip().splitlines()[-1] if (p.stdout or p.stderr).strip() else "?"
    f.audit_ok = p.returncode == 0


def collect(with_audit: bool) -> Facts:
    env = _env()
    f = Facts(config={k: env.get(k, "") for k in DEMO_CONFIG})
    f.containers = _containers()
    f.web = _web()
    asyncio.run(_db(f, env.get("POSTGRES_PASSWORD", "")))
    _redis(f)
    if with_audit and f.containers.get("api") == "running":
        _audit(f)
    return f


def render(f: Facts) -> str:
    ok = lambda b: "ok" if b else "YOX"  # noqa: E731
    L = [f"alert2case · daycheck · {time.strftime('%H:%M:%S')}", ""]
    L.append("1 · Konteynerlər")
    for svc in (*CORE, "mailpit", "n8n", "thehive", "cassandra", "elasticsearch", "prometheus", "grafana"):
        L.append(f"   {svc:<14} {f.containers.get(svc, '-')}")
    L.append("2 · Endpoint-lər")
    L.append("   " + "  ".join(f"{k} {ok(v)}" for k, v in f.web.items()))
    L.append("3 · Konfiq")
    L.append("   " + "  ".join(f"{k}={v}" for k, v in f.config.items()))
    L.append("4 · Alert-lər")
    L.append(f"   cəmi {f.alerts}   " + "  ".join(f"{k}: {v}" for k, v in f.by_status.items()))
    L.append(f"   Dedup ilə birləşən təkrar: {f.dedup_merged}")
    L.append("5 · Növbələr")
    L.append(
        f"   alerts.in pending {f.pending}  lag {f.lag}   alerts.dlq {f.alerts_dlq}   cases.dlq {f.cases_dlq}"
    )
    L.append("6 · Intel provayderləri")
    for prov, counts in sorted(f.intel.items()):
        L.append(f"   {prov:<11} " + "  ".join(f"{s}: {n}" for s, n in sorted(counts.items())))
    if not f.intel:
        L.append("   (hələ enrichment yoxdur)")
    L.append("7 · Qərarlar (qayda · prioritet · action · say)")
    for row in f.decisions:
        L.append("   " + "  ".join(str(x) for x in row))
    if not f.decisions:
        L.append("   (hələ qərar yoxdur)")
    L.append("8 · Audit zənciri")
    L.append(f"   {f.audit if f.audit is not None else 'yoxlanmadı (--no-audit)'}")
    L.append("")
    L.append("Yekun")
    v = verdicts(f)
    L += [f"   {lvl}: {msg}" for lvl, msg in v] or ["   OK: kritik problem yoxdur"]
    return "\n".join(L)


@app.command()
def main(
    no_audit: bool = typer.Option(False, "--no-audit", help="audit zəncirini yoxlama"),
    watch: int = typer.Option(0, "--watch", min=0, help="hər N saniyədən bir yenilə"),
) -> None:
    os.chdir(ROOT)
    if not watch:
        f = collect(not no_audit)
        typer.echo(render(f))
        raise typer.Exit(1 if any(lvl == "KRİTİK" for lvl, _ in verdicts(f)) else 0)
    try:
        while True:
            text = render(collect(False))  # watch rejimində audit hər dövrdə yoxlanmır (yavaşdır)
            typer.echo("\033[2J\033[H" + text)
            time.sleep(watch)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    app()
