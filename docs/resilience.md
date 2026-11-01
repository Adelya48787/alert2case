# Dayanıqlılıq: xəta ssenariləri və müşahidə olunan davranış

Tarix: 2026-11-01 · main `d082448` (Phase 3: 3.1–3.6) + `feature/t3-7b-tests` · bir kompüterdə, Docker Compose ilə.

İddia: **nə olursa olsun, alert itmir.** Hər alert ya enrich olunur, ya da səbəbi ilə `partial` / `failed` / `skipped` statusunda bazada qalır. Worker çökmür.

## Ssenarilər

| # | Ssenari | Necə yaradıldı | Gözlənilən | Müşahidə | Status |
|---|---|---|---|---|---|
| 1 | Normal axın (real API) | `simulator --only HASH-01,LOGIN-01,URL-01` | `pending` yoxdur | 3/3 `ok`, confidence 1.0: HASH-01 malicious 91, LOGIN-01 malicious 97, URL-01 suspicious 53. Üçü də `expected.csv` ilə uyğundur | ✓ |
| 2 | VT 429 (burst) | cache silindi, `simulator --burst 30` (ilk 30 alert), 8 dəq gözləmə | 0 × 429 | 30/30 → 202 · `HTTP 429`: **0** · VT sayğacı 16 → 30 (14 sorğu ~8 dəq-yə yayıldı) · XPENDING 0 | ✓ |
| 3 | Provider yavaşdır | toxiproxy `latency 10000 ms` (read timeout 8 s) | `timeout`, `failed`, hər sorğu ≤ 30 s, worker işləyir | HASH-04, LOGIN-04: bütün provider-lər `timeout`, `failed`/`unknown`. Sorğu vaxtları 24 706–26 840 ms (3 cəhd × 8 s + backoff), hamısı < 30 000 ms. Traceback 0 | ✓ |
| 4 | Provider tam çöküb | toxiproxy `enabled:false`, 6 alert | ilk sorğular `error`, 5 xətadan sonra `circuit open` | Əvvəlcə `error: ConnectError`, sonra VT və OTX `skipped: circuit open` (gözləmədən). AbuseIPDB-də 3 xəta yığıldı, breaker açılmadı (hədd 5). VT növbəsində 60 s-dən çox gözləyənlər `rate_limited`. 6/6 `failed`, Traceback 0 | ✓ |
| 4b | Bərpa | proxy `enabled:true`, 60 s gözləmə, 2 alert | breaker yarımaçıq → normal | HASH-08: VT və OTX `ok`, malicious | ✓ |
| 5 | Hamısı çöküb | worker-in 3 base URL-i `http://127.0.0.1:9` (müvəqqəti override faylı, `.env` dəyişmədi) | `failed`/`unknown`, itki yox | HASH-05, LOGIN-05: `enriched` · `failed` · `unknown`. Traceback 0 | ✓ |
| 6 | Açar səhvdir | `VT_API_KEY=wrong-key-for-test` (override) | `auth_error`, provider söndürülür | HASH-09: VT `auth_error` (HTTP 401), OTX ok → `partial`. HASH-10: VT `skipped: auth: virustotal: HTTP 401` (sorğu getmədi), OTX ok → `partial`. Loq: `CRITICAL enrich virustotal söndürüldü: virustotal: HTTP 401` | ✓ |
| 7 | Redis restart | `docker compose restart redis`, 5 s sonra 1 alert | worker çökmür, davam edir | Worker çökmədi (Up, Traceback 0, redis-py bağlantını özü bərpa etdi). **Redis qalxana qədər gələn alert API-dən `500` aldı** (aşağıda: məhdudiyyət 1). Redis qalxandan sonra eyni alert 202 → `ok`/`clean` | ✓ / ⚠ |

## İnvariant (ssenari 1, 3, 4, 4b və 5-dən sonra)

```
 enrichment | count          status     | count
------------+-------        ------------+-------
 failed     |    10          enriched   |    15
 ok         |     4          normalized |   112   ← 3.6-dan əvvəlki qaçışlar
 skipped    |     1

XPENDING alerts.in pipeline → 0
docker compose logs worker | grep -c Traceback → 0
```

Bu mərhələdə göndərilən 15 alert-in 15-i bazadadır, `pending` yoxdur.

## Məlum məhdudiyyətlər

1. **Redis əlçatmaz olanda ingest 500 qaytarır.** API alert-i Redis-ə yaza bilmir və `500 Internal Server Error` verir. Alert səssizcə itmir: göndərən rədd cavabını görür. Amma çatdırılma göndərənin təkrar cəhdindən asılıdır, simulyator isə təkrar cəhd etmir. Təklif: Redis xətasında `503` + `Retry-After` qaytarmaq və simulyatorda 5xx üçün 2–3 təkrar cəhd.
2. **Sənədləşdirmə diapazonundakı IP intel-ə getmir.** LOGIN-08-in IP-si `203.0.113.10` (RFC 5737, TEST-NET-3). Python onu `is_private=True` sayır, `is_internal_ip()` daxili kimi işarələyir, alert `skipped`/`unknown` olur. Davranış təhlükəsizdir (avtomatik bağlanmır), amma `expected.csv`-də LOGIN-08 `clean`-dir: Phase 6 dəqiqlik ölçməsindən əvvəl IP real ictimai IP ilə əvəz olunmalıdır.
3. **Breaker vəziyyəti hər worker prosesinin yaddaşındadır.** Ssenari 3-ün VT timeout-ları ssenari 4-də də sayıldı (arada uğurlu sorğu yox idi), ona görə VT breaker-i 4 görünən xətadan sonra açıldı. Bu, gözlənilən davranışdır. 2 worker işləsə, hər birinin öz breaker-i olacaq.
4. **VT pulsuz planı yavaşdır.** Hər 16.7 s-də bir sorğu. Burst zamanı növbədə 60 s-dən çox qalan IOC-lar `rate_limited` olur, alert `partial` qalır və 15 dəqiqəlik yenidən enrichment onu tamamlayır.

## Necə təkrarlamaq

Test mühiti (WireMock + Toxiproxy, real API-yə sorğu getmir):

```bash
alias dct='docker compose -f docker-compose.yml -f docker-compose.test.yml'
dct up -d
curl -s -XPOST localhost:8474/proxies -d '{"name":"intel","listen":"0.0.0.0:8666","upstream":"wiremock:8080"}'
docker compose exec redis redis-cli --scan --pattern 'intel:v1:*' | xargs -r docker compose exec -T redis redis-cli DEL

# ssenari 3
curl -s -XPOST localhost:8474/proxies/intel/toxics -d '{"name":"slow","type":"latency","attributes":{"latency":10000}}'
python tools/simulator.py --only HASH-04,LOGIN-04 --rate 2 && sleep 90
curl -s -XDELETE localhost:8474/proxies/intel/toxics/slow

# ssenari 4 və 4b
curl -s -XPOST localhost:8474/proxies/intel -d '{"enabled":false}'
python tools/simulator.py --only HASH-06,HASH-07,LOGIN-06,LOGIN-07,URL-06,URL-07 --rate 2 && sleep 120
curl -s -XPOST localhost:8474/proxies/intel -d '{"enabled":true}' && sleep 60
python tools/simulator.py --only HASH-08 --rate 2
```

Ssenari 5 və 6 üçün `.env` dəyişdirilmir, repo-dan kənarda müvəqqəti override faylı istifadə olunur:

```bash
cat > /tmp/broken.yml <<'EOF'
services:
  worker:
    environment:
      VT_BASE_URL: http://127.0.0.1:9
      ABUSEIPDB_BASE_URL: http://127.0.0.1:9
      OTX_BASE_URL: http://127.0.0.1:9
EOF
docker compose -f docker-compose.yml -f /tmp/broken.yml up -d --force-recreate worker
```

Hər sınaqdan sonra normal rejim: `docker compose up -d --force-recreate worker` və `docker compose exec worker printenv VT_BASE_URL` boş olmalıdır.

Nəticələri oxumaq (`$[*]` bash-da genişlənməsin deyə SQL heredoc ilə):

```bash
docker compose exec -T postgres psql -U soc -d alert2case <<'SQL'
select source_ref, doc->'enrichment'->>'status' st,
       jsonb_path_query_array(doc->'enrichment'->'providers', '$[*].status') pst,
       jsonb_path_query_array(doc->'enrichment'->'providers', '$[*].latency_ms') ms
from alerts where status = 'enriched' order by received_at desc limit 20;
SQL
```

## Unit testlər

`tests/unit/test_service.py` (14 test) fallback cədvəlinin hər sətrini şəbəkəsiz yoxlayır: açar yoxdur, cache, breaker, rate limit, 401, timeout, 429, single-flight, daxili IOC, hamısı çöküb, yenidən enrichment. `tests/conftest.py` testlərdə intel açarlarını boşaldır ki, heç bir test real API-yə sorğu atmasın. Nəticə: 191 passed, coverage 96%.
