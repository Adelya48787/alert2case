# alert2case

SOC alert-lərini avtomatik zənginləşdirən, qiymətləndirən və case-ə çevirən sistem. Wazuh, EDR və proxy-dən gələn alert IOC-larına ayrılır, VirusTotal, AbuseIPDB və OTX-də yoxlanılır, qaydalar və təhlükəsizlik qoruyucuları ilə qərar verilir, case (TheHive və ya fayl) yaradılır və P1/P2 üçün bildiriş göndərilir. Hər addım dəyişdirilə bilməyən audit log-a yazılır.

## Nəticə bir baxışda

36 alert-lik dataset, 2026-11-07 ölçmələri ([`docs/measure/summary.md`](docs/measure/summary.md), [`accuracy.md`](docs/measure/accuracy.md)):

| | Manual (2 analitik, 40 ölçmə) | alert2case |
|---|---|---|
| Triaj vaxtı (median, eyni 20 alert) | 249 s | **50 s** (−80%); cache dolu: 0.07 s |
| Yük altında (36 alert bir anda) | — | 142 s (VirusTotal pulsuz limiti: dəqiqədə 4) |
| Dəqiqlik (eyni 20 alert) | 65% (kappa 0.46) | **80%** (kappa 0.69) |
| Zərərli/şübhəli alert-in səhvən bağlanması (FN) | 3 / 20 (hər analitik) | **0** (4 ssenarinin hamısında) |
| Auto-close | — | **bağlı (shadow mode)**: sistem 6–17% alert-i bağlayardı, amma insan təsdiqləyir ([ADR-0003](docs/adr/0003-auto-close-decision.md)) |

## Tez başlanğıc (10 dəqiqə)

Tələblər: Windows (WSL 2) / macOS / Linux, Docker, [uv](https://docs.astral.sh/uv/), Git. Yoxlama: `tools/doctor.sh`.

```bash
git clone git@github.com:Adelya48787/alert2case.git && cd alert2case
cp .env.example .env                        # açarları doldur: VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, ...
uv venv --python 3.12 && source .venv/bin/activate
uv pip install -r requirements-dev.txt && pre-commit install
make up && make migrate                     # PostgreSQL, Redis, n8n, Mailpit, api, worker
make simulate                               # 36 alert göndərilir
```

Nəticəyə harada baxmaq olar:

| Nə | Harada |
|---|---|
| Case-lər | `var/cases/*.json` (`CASE_BACKEND=file`) və ya TheHive (`make up-full`, `CASE_BACKEND=thehive`) |
| Bildirişlər | Mailpit: <http://localhost:8025>, Slack / Telegram (`.env`-də verilibsə) |
| Bir alert-in tarixçəsi | `curl -H "X-Admin-Token: …" localhost:8000/alerts/<alert_id>/timeline` |
| Metrikalar | `make up-obs` → Grafana <http://localhost:3000> |

Bütün portlar yalnız `127.0.0.1`-də açılır.

## Sənədlər

| Sənəd | Kim üçün |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Sistemi dəyişəcək proqramçı: komponentlər, məlumat modeli, qərar məntiqi, diaqram |
| [`docs/operations.md`](docs/operations.md) | Sistemi işlədən şəxs: simptom → əmr (DLQ, kill switch, açar sızması, ehtiyat nüsxə) |
| [`docs/adr/`](docs/adr/) | Qərarlar: platforma (0001), FN riski və fallback (0002), auto-close (0003) |
| [`docs/resilience.md`](docs/resilience.md) | Intel mənbələri çökəndə və ya yavaşlayanda nə olur (chaos testləri) |
| [`docs/security-review.md`](docs/security-review.md) | Təhlükəsizlik yoxlaması, qəbul olunan risklər, secret rotasiyası |
| [`docs/measure/`](docs/measure/) | Manual və avtomatik ölçmələr, dəqiqlik |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | TheHive inteqrasiyasında rastlaşılan problemlər |

## Testlər

```bash
pytest tests/unit                               # unit testlər (CI-da coverage ≥ 85%)
make reset-data && make e2e                     # uçdan-uca: işləyən stekə real alert-lər
make prod-check                                 # production image (make up-prod)
```

CI hər PR-da: lint, unit testlər, gitleaks (bütün tarixçə), bandit, pip-audit, trivy.

## Konfiqurasiya

Bütün sirlər yalnız `.env`-dədir (gitignore-da, pre-commit və CI gitleaks ilə qorunur). Əsas açarlar:

| Dəyişən | Mənası |
|---|---|
| `AUTO_CLOSE_ENABLED` | Kill switch. `false`: sistem heç nəyi özü bağlamır (default) |
| `SHADOW_MODE` | `true`: "bağlayardım" qərarı yazılır, alert insana gedir (default) |
| `CASE_BACKEND` | `file` və ya `thehive` |
| `WEBHOOK_HMAC_SECRET` | Ingest imzası (`X-Signature: sha256=…`) |
| `ADMIN_TOKEN` | Admin endpoint-ləri (`X-Admin-Token`) |

Qaydalar və çəkilər: `rules/severity.yaml`, `rules/weights.yaml`, `rules/correlation.yaml`; daxili kontekst: `context/` (asset, istifadəçi, allowlist). `severity.yaml` və `context/` dəyişəndə restart lazım deyil; `weights.yaml` və `correlation.yaml` üçün `make restart-worker`.

## Məhdudiyyətlər

- 36 alert-lik dataset statistik nəticə üçün kiçikdir; rəqəmlər istiqamət göstərir, ümumiləşdirmə deyil.
- Rəy dövrəsindəki rəylərin bir hissəsi `expected.csv`-dən süni yaradılıb.
- VirusTotal pulsuz planı (dəqiqədə 4 sorğu) burst zamanı triaj vaxtını artırır.
- Intel nəticələri zamanla dəyişir (IOC drift): eyni alert bir ay sonra fərqli qiymətləndirilə bilər ([ADR-0003](docs/adr/0003-auto-close-decision.md)).
- Skor düsturları evristikdir (`rules/weights.yaml`).
- E2E testlər CI-da yox, lokal stekdə işləyir.
- TheHive Community lisenziyası 2 istifadəçi ilə məhdudlaşır.

## Lisenziya

MIT, bax [`LICENSE`](LICENSE). Layihə 4 nəfərlik komanda tərəfindən təhsil məqsədilə hazırlanıb.
