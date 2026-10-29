# Layihə 3 · alert2case · 1-ci həftə hesabatı

Komanda: Adilə (Team Lead), Elçin, Teymur, Elvin · Tarix: 29.10.2026

## 1. Manual prosesin addımları və baseline

- 8 addım (S1–S8) və sərhədləri, ölçmə metodu və bütün cədvəllər: [baseline/README.md](baseline/README.md)
- 12 alert × 2 analitik, blind test, təsadüfi sıra. Xam məlumat: [baseline/baseline_raw.csv](baseline/baseline_raw.csv)
- **Median manual MTTR (alert başına):** HASH 512 s · NET 481 s · WEB 485 s, ümumilikdə **≈ 8.3 dəqiqə**
- **Vaxtın 36%-i S3+S4-də** (intel saytları), 24%-i S7-də (ticket)
- **Manual dəqiqlik: 50%** · **Verdict uyğunsuzluğu: 100%** (12 alert-in hamısında iki analitik fərqli qərar verib)
- Zərərli alert-lərin heç biri `clean` adlandırılmayıb; səhvlərin hamısı `suspicious` ətrafındadır

| Manual addım | Pay | Avtomatlaşdıran modul (to-be) |
|---|---:|---|
| S1–S2 oxumaq, IOC çıxarmaq | 14% | Ingest API + normalizasiya (Phase 2) |
| S3–S4 VT, AbuseIPDB/OTX | 36% | Enrichment: paralel sorğu, cache, rate limit (Phase 3) |
| S5–S6 verdict, priority | 18% | Qayda mühərriki + ADR-0002 qoruyucuları (Phase 4) |
| S7–S8 ticket, mesaj | 31% | TheHive case + Slack/Telegram/e-mail bildirişi (Phase 4) |

## 2. Hazır platforma vs öz məntiqimiz

- Sınanan: Shuffle, n8n, tam Python; TheHive+Cortex resurs və vaxt səbəbindən sınanmayıb (Cortex orkestrasiya deyil, analyzer mühərrikidir)
- Eyni ssenari (webhook → VirusTotal → `malicious ≥ 5` olarsa bildiriş), 2 saatlıq time-box, meyar və çəkilər PoC-dan əvvəl razılaşdırılıb
- **Ağırlıqlı matris:** Shuffle **2.80** / n8n **3.35** / Cortex — / Python **3.80**
- **Qərar: hibrid.** Qərar məntiqi Python-da (testlə yoxlanılır, test meyarının çəkisi 20), vizual orkestrasiya n8n-də
- **n8n-də:** alert-in yolunun vizual axını, xəta workflow-u, demo. **Python-da:** qəbul, normalizasiya, enrichment, qaydalar, auto-close qoruyucuları, case və bildiriş, audit
- Əsas sübutlar: Shuffle-da API açarı export JSON-una düşür; Python PoC-da fail-open səhvi pytest ilə dəqiqələr içində tutuldu və düzəldildi; n8n açarı Credentials-də saxlayır, amma məntiqi avtomatik test etmək olmur
- [adr/0001-platform-selection.md](adr/0001-platform-selection.md) · PoC qeydləri: [poc/shuffle.md](poc/shuffle.md), [poc/n8n.md](poc/n8n.md), [poc/python.md](poc/python.md)

## 3. Avtomatik qərarın səhv olması riski (FN)

- FN (zərərlinin bağlanması) FP-dən qat-qat bahalıdır, ona görə prinsip **fail-safe**: şübhə varsa insana göndər
- **Auto-close yalnız bütün şərtlər birlikdə ödənəndə:** verdict `clean`, confidence ≥ 0.67 (mənbələrin ən az 2/3-ü cavab verib), ziddiyyət yoxdur, enrichment tam uğurlu, istifadəçi imtiyazlı deyil, asset kritik deyil
- **Qoruyucular:** shadow mode (qərar yazılır, tətbiq olunmur), auto-close-ların 10%-i QA üçün insana, kill switch `AUTO_CLOSE_ENABLED=false`
- Shadow mode-dan çıxış meyarı: dataset üzərində FN = 0 və QA-da 0 səhv
- Baseline bu yanaşmanı dəstəkləyir: insanlar əmin olmayanda da `suspicious` seçir
- [adr/0002-fn-risk-and-fallback.md](adr/0002-fn-risk-and-fallback.md)

## 4. Enrichment mənbəyi əlçatmaz olanda

- Fallback cədvəli **9 vəziyyət**: 429 (60 s token gözləməsi, sonra `skipped`), 5xx/timeout (3 retry, backoff 1–2–4 s), ardıcıl 5 xəta (circuit breaker 60 s), bütün mənbələr əlçatmaz (verdict `unknown`, severity +1, auto-close qadağan), 401/403 (provider söndürülür), Redis, TheHive və bildiriş kanalı əlçatmaz (DLQ və e-mail fallback), `partial` alert (15 dəqiqədən bir yenidən enrichment)
- Prinsiplər: alert heç vaxt itmir (`case`, `closed_auto` və ya DLQ), məlumat azaldıqca sistem daha ehtiyatlı olur
- Intel limitləri və cavab nümunələri: [intel-sources.md](intel-sources.md), fixture-lar `tests/fixtures/`

## Görülən işlər

- Phase 0: 4 kompüter hazır (WSL, Docker, Python 3.12, VS Code, GitHub 2FA + SSH, `doctor.sh`)
- Repo: qorunan `main`, PR + review, squash merge; secret qoruması üç qatda (`.env` + gitleaks pre-commit + CI), saxta açarla sınanıb
- `docker-compose`: PostgreSQL, Redis, n8n, Mailpit, TheHive profili (trial lisenziya)
- Baseline (kartlar, timer, ölçmə, analiz), 3 PoC, ADR-0001, ADR-0002
- Hər üzvün mühitini və Phase 1 nəticələrini yoxlayan skript: `tools/phase1_exit.sh`
- Phase 1 qərarları komanda razılaşması ilə Team Lead tərəfindən verilib

## Növbəti həftə: Phase 2

Dataset (36 alert, HASH/URL/LOGIN), vahid alert schema (OCSF), parser-lər, simulyator, HMAC ilə qəbul edən Ingest API, Redis Streams, PostgreSQL + audit log, DLQ.

## Risklər və bloklar

- **Kiçik nümunə:** baseline 12 alert × 2 analitikdir; rəqəmlər istiqamət göstərir. Phase 6-da 20 alert ilə təkrar ölçüləcək
- **Analitiklər arası 100% uyğunsuzluq:** manual qərarlar qeyri-sabitdir; qayda cədvəli (Phase 4) sərhəd hallarını dəqiq təyin etməlidir
- **TheHive lisenziyası:** Community lisenziyası korporativ e-mail tələb edir; trial ilə davam edirik, ehtiyat variant file backend-dir
- **Python-da inteqrasiyalar:** hazır connector yoxdur, VT/AbuseIPDB/OTX/TheHive/Slack adapterləri yazılmalıdır (Phase 3–4 iş həcmi)
- **VirusTotal limiti** (dəqiqədə 4 sorğu): cache və rate limiter məcburidir
