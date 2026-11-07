# Əməliyyat runbook-u

Problemlə üzləşən şəxs üçündür: hər bölmə **simptomla** başlayır, sonra kopyalana bilən əmrlər gəlir. Bütün əmrlər repo kökündən (`cd ~/projects/alert2case`) işlədilir. Arxitektura: [`architecture.md`](architecture.md).

Admin endpoint-ləri üçün token-i `.env`-dən dəyişənə oxuyun (ekrana çıxmır):

```bash
T=$(grep -E '^ADMIN_TOKEN=' .env | cut -d= -f2-)
```

## Başlatmaq / dayandırmaq

| Nə | Əmr |
|---|---|
| Əsas stek (PostgreSQL, Redis, n8n, Mailpit, api, worker) | `make up` |
| + TheHive | `make up-full` |
| + Prometheus və Grafana | `make up-obs` |
| Production image ilə api və worker | `make up-prod && make prod-check` |
| Dev image-ə qayıtmaq | `make down-prod` |
| Dayandırmaq (məlumat qalır) | `make down` |
| Vəziyyət | `make ps` |
| Loglar | `make logs` və ya `docker compose logs -f worker` |
| Miqrasiyalar | `make migrate` |
| Test məlumatını silmək (cədvəllər qalır) | `make reset-data` |
| **Hər şeyi silmək** (volume-lar daxil) | `make reset` |

## Sağlamlıq

```bash
curl -s localhost:8000/health                                   # {"status":"ok"}: API və Redis
docker compose ps --format '{{.Service}} {{.State}}'            # hamısı running
curl -s -H "X-Admin-Token: $T" localhost:8000/dlq | python3 -m json.tool | head   # [] olmalıdır
docker compose exec -T redis redis-cli XLEN cases.dlq           # 0 olmalıdır
docker compose exec -T redis redis-cli XPENDING alerts.in pipeline   # emalda olanlar
```

Grafana (<http://localhost:3000>, `make up-obs`): DLQ dərinliyi, mərhələ vaxtları, intel nəticələri, qəbul → hərəkət vaxtı.

## Analitik paneli

**Simptom:** analitik case-ləri nəzərdən keçirməli və ya sistemin "bağlayardım" qərarlarını yoxlamalıdır.

Brauzerdə <http://localhost:8000/panel/> açın, admin token-i və adınızı yazın. Token yalnız həmin sekmədə saxlanılır.

Yuxarıda dashboard var: açıq case-lər və P1 sayı, son 24 saatda gələn alert-lər, qəbul → case vaxtının median və p90 dəyəri, analitiklə razılaşma, saatlıq qrafik, prioritet və qərar paylanması. "Live" açıq olanda hər 30 saniyədən bir yenilənir. Siyahını prioritet, alert tipi və sistemin qərarı ilə süzmək olar. Axtarış IOC, host, istifadəçi və qayda adında işləyir, defang formanı (`hxxp`, `[.]`) da qəbul edir. Alert-in detalında bunlar var: qərarın səbəbləri, hər intel mənbəyi üçün kart (status, skor, cache), mərhələ-mərhələ vaxt zolağı, son 7 gündə eyni IOC, host və ya istifadəçi ilə gələn əlaqəli alert-lər.

| Simptom | Səbəb | Həll |
|---|---|---|
| "Token qəbul olunmadı" | Token səhvdir və ya rotasiya olunub | `.env`-dəki `ADMIN_TOKEN` |
| Siyahı boşdur | Bütün alert-lərə rəy verilib və ya alert yoxdur | "Hamısı" tabı; `make simulate` |
| Səhifə açılır, amma düymələr işləmir | Brauzer köhnə JS-i cache-dən götürür | `Ctrl+Shift+R` |

Yuxarıdakı keçidlər:

- **Alerts:** dashboard, siyahı və detal. Case TheHive-dadırsa, "Open in TheHive ↗" linki görünür. Link `THEHIVE_PUBLIC_URL` ilə qurulur, standart dəyəri `http://localhost:9000`-dır.
- **System:** auto-close və shadow mode vəziyyəti, case backend; hər intel mənbəyi üçün ok / degraded / down nişanı (son 15 dəqiqənin real cavablarına görə; "circuit open" breaker-in açıq olduğunu göstərir), gündəlik kvota; növbə və DLQ dərinliyi. Chaos testində VirusTotal burada "down" görünür. Yuxarıdakı "Auto-close: OFF" nişanı API-nin `.env` konfiqurasiyasıdır.
- **Rules:** hər qayda üçün alert sayı, feedback və analitiklə razılaşma (70%-dən aşağı → "tuning"). ADR-0003 üçün shadow review irəliləyişi: "sistem bağlayardı" deyilən və analitikin baxdığı real alert-lər (dataset alert-ləri sayılmır), hədəf 30, would-miss hədəfi 0.

Klaviatura: `j`/`k` keçid, `a` approve, `r` reject, `o` TheHive, `/` axtarış, `1`/`2`/`3` bölmələr, `?` kömək.

Panel rəyi `feedback` cədvəlinə `source=manual` ilə yazılır və audit-ə düşür: `python -m tools.tuner` onu nəzərə alır.

## Auto-close-u dərhal dayandırmaq (kill switch)

**Simptom:** sistem bağlamamalı olduğu alert-i bağlayıb və ya bağlamaya şübhə var.

```bash
sed -i 's/^AUTO_CLOSE_ENABLED=.*/AUTO_CLOSE_ENABLED=false/' .env
docker compose up -d --force-recreate api worker                 # prod: make up-prod
docker compose exec -T worker python -c 'from app.config import settings as s; print(s.auto_close_enabled, s.shadow_mode)'
```

Gözlənilən: `False …`. Ölçülmüş keçid vaxtı 6.4 s ([`measure/killswitch.md`](measure/killswitch.md)). Bundan sonra "bağla" qərarları "kill switch bağlıdır" səbəbi ilə case olur. Bağlanmış alert-ləri tapmaq:

```bash
docker compose exec -T postgres psql -U soc -d alert2case -c \
  "select source_ref, received_at from alerts where status='closed_auto' order by received_at desc limit 20;"
```

Təkrar sınaq: `tools/killswitch_test.sh` (lokal test məlumatını silir).

## DLQ-da mesaj var

**Simptom:** Grafana-da `alert2case_dlq_depth{stream="alerts.dlq"} > 0` və ya alert case-ə çevrilmədi.

```bash
curl -s -H "X-Admin-Token: $T" localhost:8000/dlq | python3 -m json.tool    # stage və error sahələri
```

1. `stage` və `error`-a baxın: hansı mərhələdə, nə səbəbdən (məs. parser xətası, DB əlçatmaz).
2. Səbəbi düzəldin (kod düzəlişi → PR; infrastruktur → servisi qaldırın).
3. Yenidən emal edin:

```bash
curl -s -X POST -H "X-Admin-Token: $T" localhost:8000/dlq/replay       # {"replayed": N}
```

Səbəb düzəlmədən replay etməyin: mesaj 3 cəhddən sonra yenə DLQ-ya düşəcək.

## Case yaranmır (`case_pending`)

**Simptom:** alert statusu `case_pending`, `cases.dlq` boş deyil, worker logunda `CaseError`.

```bash
docker compose exec -T redis redis-cli XLEN cases.dlq
docker compose --profile thehive ps                                   # thehive, cassandra, elasticsearch healthy?
curl -s -o /dev/null -w '%{http_code}\n' localhost:9000/api/status    # 200
```

TheHive qalxandan sonra housekeeping 2 dəqiqə ərzində case-ləri özü yaradır. Gözləmədən:

```bash
curl -s -X POST -H "X-Admin-Token: $T" localhost:8000/dlq/cases/replay      # {"created": N}
```

TheHive DNS-dən düşübsə (`No address associated with hostname`): [`troubleshooting.md`](troubleshooting.md).

## Intel provider işləmir

**Simptom:** çox alert `partial` / `failed` / `unknown`, worker logunda `circuit open`, `rate_limited`, `HTTP 401` və ya `söndürüldü`.

```bash
docker compose logs --since 30m worker | grep -cE 'circuit open'
docker compose logs --since 30m worker | grep -E 'söndürüldü|HTTP 401|HTTP 429' | tail -5
for k in VT_API_KEY ABUSEIPDB_API_KEY OTX_API_KEY; do [ -n "$(grep -E "^$k=" .env | cut -d= -f2-)" ] && echo "$k: dolu" || echo "$k: BOŞ"; done
```

| Səbəb | Nə etməli |
|---|---|
| `HTTP 401`, provider söndürülüb | Açar səhv və ya ləğv olunub: `.env`-i düzəldin, `make restart-worker` (söndürmə restart-a qədər qalır) |
| `circuit open` | Provider çöküb və ya çox yavaşdır: breaker 60 s sonra özü yoxlayır. Davamlıdırsa provider-in status səhifəsinə baxın |
| `rate_limited`, `HTTP 429` | VT pulsuz limiti (dəqiqədə 4) və ya gündəlik kvota dolub. Alert-lər bağlanmır, 15 dəqiqədən bir yenidən enrich olunur |

Bütün hallarda sistem fail-safe-dir: natamam enrichment heç vaxt auto-close olmur ([ADR-0002](adr/0002-fn-risk-and-fallback.md)).

## Açar sızıb

**Simptom:** gitleaks tapıntısı, açar ekran görüntüsündə/çatda paylaşılıb və ya provider-də naməlum istifadə.

1. **Dərhal provider-də ləğv edin** (VT, AbuseIPDB, OTX, Slack, Telegram, TheHive). Git tarixçəsindən silmək kifayət deyil.
2. Yeni açarı `.env`-ə yazın, `docker compose up -d --force-recreate api worker`.
3. Daxili token-lər üçün hazır skript: `tools/rotate_admin_token.sh` (ADMIN_TOKEN; ehtiyat, yoxlama, uğursuzluqda bərpa). Sonra n8n credential-ını yeniləyin (aşağıda).
4. Loglarda sızma olmadığını yoxlayın: `python -m tools.security_review` (4-cü yoxlama).

Hər açarın harada saxlandığı və necə yoxlandığı: [`security-review.md`](security-review.md), bölmə 3.

n8n admin token credential-ını yeniləmək:

```bash
python - <<'EOF'
import json; from pathlib import Path; from dotenv import dotenv_values
t = dotenv_values(".env").get("ADMIN_TOKEN") or ""; assert len(t) >= 32
Path("n8n/credentials.local.json").write_text(json.dumps([{"id": "a2cAdminToken01", "name": "alert2case admin token",
  "type": "httpHeaderAuth", "data": {"name": "X-Admin-Token", "value": t}}]), encoding="utf-8")
EOF
docker compose cp n8n/credentials.local.json n8n:/tmp/creds.json && \
docker compose exec n8n n8n import:credentials --input=/tmp/creds.json ; \
docker compose exec n8n rm -f /tmp/creds.json ; rm -f n8n/credentials.local.json ; docker compose restart n8n
```

## Qayda dəyişikliyi

**Simptom:** analitiklər eyni tip səhv qərarı təkrar-təkrar düzəldir (rəy dövrəsi) və ya yeni təhlükə növü.

```bash
git checkout -b rules/<qısa-ad>
python -m tools.tuner                      # rəylərdən təklif: docs/feedback/proposal-<tarix>.md
# rules/severity.yaml və ya rules/weights.yaml-ı redaktə edin, version sahəsini artırın
python -m tools.replay --rules rules/severity.yaml --weights rules/weights.yaml   # FN artmamalıdır
pytest tests/unit
```

PR → review → merge → serverdə `git pull`. `severity.yaml` və `context/` avtomatik yenidən oxunur; `weights.yaml` və `correlation.yaml` üçün `make restart-worker`. Qayda heç vaxt birbaşa serverdə redaktə olunmur: dəyişiklik yalnız PR ilə.

Allowlist (`context/allowlist.yaml`): hər qeyddə `owner`, `reason`, `expires_at` məcburidir, müddəti keçmiş qeyd tətbiq olunmur.

## Audit yoxlaması

**Simptom:** audit log-un dəyişdirildiyinə şübhə və ya dövri yoxlama.

```bash
docker compose exec -T api python -m tools.verify_audit       # "OK: N sətir, zəncir bütövdür"
```

`ZƏNCİR QIRILIB` və ya `SƏTİR DƏYİŞDİRİLİB` çıxsa: həmin `id`-ni qeyd edin, DB-yə kimin giriş etdiyini yoxlayın, son ehtiyat nüsxə ilə müqayisə edin. Bir alert-in tam tarixçəsi:

```bash
curl -s -H "X-Admin-Token: $T" localhost:8000/alerts/<alert_id>/timeline | python3 -m json.tool
```

## Ehtiyat nüsxə və bərpa

```bash
mkdir -p backups
docker compose exec -T postgres pg_dump -U soc -Fc alert2case > backups/alert2case-$(date +%F).dump
ls -lh backups/
```

`backups/` repo-ya commit olunmur: içində alert və IOC məlumatı var. Bərpa (boş bazaya):

```bash
make down && docker compose up -d postgres
docker compose exec -T postgres dropdb -U soc --if-exists alert2case
docker compose exec -T postgres createdb -U soc alert2case
docker compose exec -T postgres pg_restore -U soc -d alert2case < backups/alert2case-<tarix>.dump
make up
docker compose exec -T api python -m tools.verify_audit
```

Redis-də yalnız növbə, cache və korrelyasiya indeksi var: itməsi məlumat itkisi deyil (cache yenidən dolur, korrelyasiya pəncərəsi 24 saatdır).

## Layihə bitəndə

Hər üzv öz API açarlarını, Slack webhook-unu, Telegram botunu və TheHive açarlarını provider-də ləğv edir, sonra `.env`-i silir (Task 6.9).
