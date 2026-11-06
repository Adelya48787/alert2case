# Təhlükəsizlik review · v1.0.0 · 2026-11-07

Bu sənəd təhvildən əvvəlki təhlükəsizlik yoxlamasının nəticəsidir (Task 6.6). Avtomatik yoxlamalar `python -m tools.security_review` ilə işləyən stekdə aparılıb; xam çıxış: [`security/review_checks.md`](security/review_checks.md). CI-dakı yoxlamalar: `.github/workflows/security.yml` ([ekran görüntüsü](security/security-ci-green.png)).

**Review üsulu:** avtomatik yoxlamalar (`tools/security_review.py`) və bu sənədin PR review-u. Ayrıca review iclası keçirilmədi (Team Lead qərarı, 2026-11-07): yoxlamalar sübutla birlikdə sənəddədir, ikinci göz PR review ilə təmin olunur.

## 1. Yoxlamalar

| # | Yoxlama | Necə yoxlanıldı | Nəticə |
|---|---|---|---|
| 1 | Bütün endpoint-lər autentifikasiya tələb edir (ingest HMAC, admin, feedback, n8n token) | 11 sorğu token-siz və səhv token ilə: `/ingest`, `/dlq`, `/dlq/replay`, `/dlq/cases/replay`, `/alerts/{id}/timeline`, `/feedback`, `/feedback/thehive`, `/stage/act` | ✅ 11/11 → 401/403 |
| 2 | Portlar yalnız 127.0.0.1-də | `docker ps` port bağlamaları | ✅ 8 port, hamısı 127.0.0.1 |
| 3 | Ingest ölçü limiti (256 KB) | 300 KB payload → `/ingest/edr` | ✅ 413 |
| 4 | Secret-lər loglarda yoxdur | `docker compose logs`-da `.env`-dəki hər secret-in dəyəri axtarıldı (dəyər çap olunmur) | ✅ 10 secret, 2787 log sətri, tapılan 0 |
| 5 | Audit log dəyişdirilə bilmir, zəncir bütövdür | `tools.verify_audit` + `UPDATE`/`DELETE` cəhdi | ✅ 274 sətir, zəncir bütöv; trigger UPDATE və DELETE-i rədd etdi |
| 6 | Container root deyil, fayl sistemi read-only | prod image-də `id -u`; prod compose-da `read_only`, `cap_drop: [ALL]` | ✅ uid 10001; api və worker read-only, bütün capability-lər atılıb |
| 7 | IOC-lar case başlığında və bildirişdə defang olunub | URL case başlıqları (`var/cases`) və Mailpit bildirişləri | ✅ 12 URL case başlığı, 50 bildiriş: defang olunmamış 0 |
| 8 | Allowlist qeydlərinin hamısında owner və expires_at var | `context/allowlist.yaml` | ✅ 2 qeyd, hamısı tam, müddəti keçməyib (2027-06-30) |
| 9 | Malicious heç vaxt auto-close olmur | unit testlər `-k malicious` (265 test) + E2E `test_malicious_never_closed` (6.4) + 6.3 ölçmələri | ✅ 265 passed; 4 ssenaridə FN 0 |
| 10 | VirusTotal şərtləri: bir açar, qeyri-kommersiya istifadə | 1.5-dəki qeydiyyat; əl ilə təsdiq | ✅ Team Lead təsdiqi (2026-11-07): layihə qeyri-kommersiya təhsil layihəsidir, pulsuz Public API şərtləri daxilində işləyir |

### CI (hər PR, main və həftəlik)

| Alət | Nə yoxlayır | Nəticə (2026-11-07) |
|---|---|---|
| gitleaks 8.21.2 | Bütün git tarixçəsində secret | no leaks found |
| bandit 1.9.4 (`-ll`) | Python kodunda təhlükəli pattern | Medium 0, High 0 (Low 18: aşağıda qəbul olunan risk) |
| pip-audit | `requirements.txt` CVE-ləri | No known vulnerabilities found |
| trivy 0.65.0 | prod image (Debian 13.7 + Python) CRITICAL/HIGH | 0 |

Review zamanı bir tapıntı düzəldildi: `tools/snapshot_iocs.py`-də `urlopen` istənilən sxemi (`file://` daxil) açırdı (bandit B310, Medium). İndi yalnız `https` qəbul olunur.

## 2. Qəbul olunan risklər

| Risk | Niyə qəbul olunur | Azaldan tədbir |
|---|---|---|
| bandit Low B311 (`random`, 4 yer) | QA nümunəsi (10%), dataset və ölçmə nümunəsi seçimi üçündür; kriptoqrafiya deyil | — |
| bandit Low B404/B603/B607 (`subprocess`, 13 yer) | Yalnız sabit `git`, `docker`, `pytest` əmrləri; `shell=True` yoxdur, istifadəçi girişi əmrə düşmür | Kod review |
| bandit Low B105 (`n8n_credentials.py`) | Mailpit SMTP-nin boş parolu (`""`): lokal test poçtu, parol yoxdur | — |
| `/health` və `/metrics` token-siz | Prometheus scrape və healthcheck üçündür; yalnız 127.0.0.1-də və daxili şəbəkədə əlçatandır; secret və IOC qaytarmır | Port yalnız lokal (yoxlama 2) |
| Dev stek sərtləşdirilməyib (root, yazıla bilən FS) | İnkişaf üçün kod mount olunur | Production yalnız `make up-prod` ilə (yoxlama 6, 6.5) |
| Audit trigger-i DB sahibi (`soc`) silə bilər | Trigger tətbiqin və analitikin səhvən dəyişməsindən qoruyur, DB admininə qarşı yox | Hash zənciri dəyişikliyi aşkarlayır (`tools.verify_audit`) |
| Case observable-ları defang olunmamış saxlanılır | Analitik və TheHive IOC-u axtarış və bloklama üçün orijinal formada istəyir | Başlıq və bildirişlər defang olunur (yoxlama 7) |
| Yeni qeydiyyatlı adi domen VT-də "0 zərərli" görünə bilər | Dynamic DNS qoruyucusu yalnız məlum provayderləri tutur | Auto-close bağlıdır, shadow mode (ADR-0003); kill switch 6.4 s |
| `n8n/credentials.local.json` açıq mətndə | Import üçün müvəqqəti fayldır, gitignore-dadır | Import-dan dərhal sonra silinir |
| VirusTotal pulsuz limiti (dəqiqədə 4) | Pulsuz Public API | Cache, token bucket, rate_limited → fail-safe (case açılır) |

## 3. Secret rotasiyası

| Secret | Harada yaradılır | Harada saxlanılır / istifadə olunur | Kim dəyişir | Necə yoxlanılır |
|---|---|---|---|---|
| `ADMIN_TOKEN` | `openssl rand -hex 24` | `.env`; API (`X-Admin-Token`), n8n credential | Team Lead | `tools/rotate_admin_token.sh`: köhnə 403, yeni 200 |
| `WEBHOOK_HMAC_SECRET` | `openssl rand -hex 32` | `.env`; API (ingest imzası), simulator və mənbələr | Team Lead | `make simulate`: 202; köhnə imza 401 |
| `FEEDBACK_TOKEN` | `openssl rand -hex 24` | `.env`; API, TheHive endpoint (Bearer) | Team Lead | `/feedback/thehive` köhnə token 403 |
| `N8N_WEBHOOK_TOKEN` | `openssl rand -hex 24` | `.env`; n8n credential | Team Lead | n8n workflow işləyir |
| `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | Provayderin saytında | Hər üzvün öz `.env`-i | Açarın sahibi | `make doctor`; worker logunda `rate_limited`/`401` yoxdur |
| `THEHIVE_API_KEY`, `THEHIVE_SECRET` | TheHive UI | `.env` | TheHive admini | Case yaranır (`CASE_BACKEND=thehive`) |
| `SLACK_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN` | Slack / BotFather | `.env` | Kanalın sahibi | P1/P2 bildirişi çatır |
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` | `.env`, Postgres volume | Team Lead | `ALTER USER soc PASSWORD ...` + `.env` + `docker compose up -d --force-recreate` |
| `N8N_ENCRYPTION_KEY` | `openssl rand -hex 32` | `.env`, n8n | Team Lead | **Rotasiya olunmur**: n8n credential-ları bu açarla şifrələnib; dəyişsə hamısı yenidən import olunmalıdır |
| `GRAFANA_ADMIN_PASSWORD` | `openssl rand -hex 16` | `.env` | Team Lead | Grafana girişi |

**Məşq (2026-11-07):** `ADMIN_TOKEN` rotasiya edildi (`tools/rotate_admin_token.sh`). Köhnə token 403, yeni token 200, `/health` 200, worker işləyir; api 20 s-də hazır oldu. n8n-dəki "alert2case admin token" credential-ı yeni token ilə yenidən idxal edildi (eyni ID, workflow dəyişmir; açıq mətnli nüsxələr silindi).

**Məşqdə tapılan boşluq:** `tools/n8n_credentials.py` `N8N_WEBHOOK_TOKEN`-i məcburi tələb edir, amma bu dəyişən `.env.example`-da yoxdur. Rotasiya zamanı yalnız admin token credential-ı ayrıca idxal olundu. Düzəliş: `N8N_WEBHOOK_TOKEN` `.env.example`-a əlavə olunmalı, skript isə yalnız mövcud dəyərlər üçün credential yaratmalıdır.

**Sızma halında:** açar dərhal provayderdə ləğv olunur və yenisi yaradılır. Git tarixçəsindən silmək kifayət deyil: açar klonlarda və CI loglarında qala bilər. Layihə bitəndə hər üzv öz açarlarını ləğv edir (Task 6.9).
