# alert2case · Yekun hesabat

Layihə 3 · SOC alert triajının avtomatlaşdırılması · 4 nəfərlik komanda · Noyabr 2026 · versiya v1.0.0

## Xülasə

SOC analitiki hər alert üçün eyni addımları əl ilə təkrarlayır: alert-i oxuyur, IOC-ları çıxarır, onları VirusTotal, AbuseIPDB və OTX-də yoxlayır, qərar verir, ticket açır və komandaya yazır. alert2case bu addımları avtomatlaşdırır: alert gəldiyi andan case-in yaranmasına qədər.

| Göstərici | Manual | alert2case | Mənbə |
|---|---|---|---|
| Triaj vaxtı (median, eyni 20 alert) | 249 s | 50 s (−80%) | 6.1, 6.2 |
| Intel cache dolu olanda | — | 0.07 s | 6.2 (warm) |
| 36 alert bir anda (VT limiti altında) | — | 142 s (−49%) | 6.2 (burst) |
| Dəqiqlik (eyni 20 alert) | 65% (kappa 0.46) | 80% (kappa 0.69) | 6.3 |
| Zərərli/şübhəli alert-in səhvən bağlanması (FN) | 3 / 20 (hər analitik) | 0 (4 ssenaridə) | 6.3 |
| Hərəkətə çatmayan alert | — | 0 / 144 (4 ssenari × 36) | 6.2 |

Auto-close **açılmayıb**: sistem shadow mode-da işləyir, "bağlayardım" qərarını yazır, amma alert insana gedir ([ADR-0003](adr/0003-auto-close-decision.md)). Sürət qazancı auto-close-dan yox, hər alert-in zənginləşdirilib qərar təklifi ilə hazır gəlməsindən yaranır.

---

## 1. Problem və məqsəd

Kiçik SOC komandasında eyni tip alert-lər (zərərli fayl hash-ı, şübhəli URL, şübhəli login) gündə onlarla dəfə gəlir və hər biri 5–10 dəqiqə əl işi tələb edir. Vaxtın böyük hissəsi intel saytlarında axtarışa və ticket yazmağa gedir. Nəticədə həqiqi təhlükə növbədə gözləyir, analitiklər isə eyni alert-ə fərqli qərarlar verir.

Məqsədlər:

1. Triaj vaxtını (alert-in gəlməsindən case-ə qədər) ölçülə bilən şəkildə azaltmaq.
2. Zərərli alert-i heç vaxt avtomatik bağlamamaq (FN = 0).
3. Hər qərarı izlənə bilən və yoxlanıla bilən etmək (audit).
4. Intel mənbələri çökəndə də alert itirməmək.

Həftəlik hesabat: [`week1-report.md`](week1-report.md).

## 2. Baseline: manual triaj

Manual proses 8 addıma bölündü (S1–S8: oxumaq, IOC çıxarmaq, VT, AbuseIPDB/OTX, verdict, prioritet, ticket, mesaj) və iki dəfə ölçüldü. Ölçmələr blind test kimi aparıldı: analitik doğru cavabı görmürdü, alert-lərin sırası təsadüfi idi, kartları hazırlayanlar ölçmədə analitik kimi iştirak etmədi.

| | 1-ci ölçmə (1.3) | 2-ci ölçmə (6.1) |
|---|---|---|
| Nümunə | 12 alert × 2 analitik | 20 alert × 2 analitik, 2 oturum |
| Median vaxt | ≈ 8.3 dəq | 4.2 dəq (HASH 3.4, LOGIN 4.6, URL 6.9) |
| Dəqiqlik | 50% | 65% (hər analitik), kappa 0.46 |
| Analitiklər arası razılıq | 0 / 12 eyni qərar | 80% (kappa 0.69) |

Vaxtın 36%-i intel saytlarında (S3–S4), 31%-i ticket və mesajda (S7–S8) keçdi. Bu iki pay avtomatlaşdırmanın əsas hədəfi oldu.

İkinci ölçmə birincidən təxminən iki dəfə tez çıxdı. Bunun səbəbi fərqli analitiklər, fərqli alert nümunəsi və analitiklərin layihə boyu intel alətlərini öyrənməsidir. Ona görə avtomatik vaxt **eyni alert-lər üzərində** ikinci ölçmə ilə müqayisə olunur: bu, sistemin xeyrinə olmayan, daha sərt müqayisədir.

Mənbə: [`baseline/README.md`](baseline/README.md), [`measure/README.md`](measure/README.md).

## 3. Arxitektura və platforma seçimi

Üç yanaşma eyni ssenari üzərində 2 saatlıq PoC ilə sınandı: Shuffle, n8n və təmiz Python. Çəkili matris: Shuffle 2.80, n8n 3.35, Python 3.80. Qərar hibriddir ([ADR-0001](adr/0001-platform-selection.md)):

- **Python** (FastAPI, Redis Streams, PostgreSQL, öz qayda mühərriki): qəbul, normalizasiya, enrichment, qərar, qoruyucular, case, bildiriş, audit. Səbəb: qərar məntiqi pytest ilə yoxlanılır; PoC-da fail-open səhvi test ilə dəqiqələr içində tapıldı.
- **n8n**: eyni mərhələlərin vizual axını (`/stage/*` endpoint-ləri), xəta workflow-u, demo.

Axın: ingest (HMAC) → Redis Stream → worker → normalize və dedup → enrich → decide → correlate → act → notify → audit. Ətraflı: [`architecture.md`](architecture.md).

## 4. Enrichment və dayanıqlılıq

Hər xarici IOC üç mənbədə paralel yoxlanılır. Mənbələrin xətaları alert-i itirmir, yalnız qərarı daha ehtiyatlı edir:

| Qat | Davranış |
|---|---|
| Timeout və retry | 8 s, 3 cəhd, backoff |
| Circuit breaker | 5 ardıcıl xəta → 60 s; 401-də provider söndürülür |
| Rate limit | VT pulsuz limiti (dəqiqədə 4) üçün token bucket; 60 s-dən çox gözləyən → `rate_limited` |
| Cache | verdict-ə görə 1–24 saat |
| Yenidən enrichment | `partial`/`failed` alert-lər 15 dəqiqədən bir |

Chaos testləri (WireMock + Toxiproxy): yavaş provider, tam çökmə, hamısı çöküb, səhv açar, Redis restart. Bütün ssenarilərdə alert itmədi, worker çökmədi. Bir məhdudiyyət tapıldı: Redis əlçatmaz olanda ingest `500` qaytarır və çatdırılma göndərənin təkrar cəhdindən asılıdır. Mənbə: [`resilience.md`](resilience.md).

"Clean" qərarı üçün sərt şərt qoyuldu: hər IOC güclü mənbədə (VT, AbuseIPDB) **tapılmalıdır**. Heç kimin tanımadığı IOC təmiz deyil, `unknown`-dur. Bu qayda rəy dövrəsi turunda (5.4) tapılan üç FN-dən sonra əlavə olundu.

## 5. Qərar məntiqi və təhlükəsizlik qoruyucuları

Əsas prinsip ([ADR-0002](adr/0002-fn-risk-and-fallback.md)): zərərli alert-i bağlamaq (FN) onu insana göndərməkdən (FP) qat-qat bahalıdır, ona görə şübhə varsa insana göndərilir.

Qərar üç qatdan keçir:

1. **Qaydalar** (`rules/severity.yaml`): ilk uyğun gələn qayda verdict, severity və hərəkəti təyin edir.
2. **Qoruyucular**: qayda "bağla" desə də case açılır, əgər intel `malicious`-dur, enrichment natamamdır, etibarlılıq < 0.67-dir, mənbələr ziddiyyətlidir, istifadəçi imtiyazlı/VIP-dir, asset kritikdir və ya domen dynamic DNS-dir.
3. **Kill switch və shadow mode**: `AUTO_CLOSE_ENABLED=false` və ya `SHADOW_MODE=true` olanda heç nə avtomatik bağlanmır. Kill switch 6.4 s-də işləyir ([`measure/killswitch.md`](measure/killswitch.md)).

Prioritet severity və kontekstdən (asset kritikliyi, imtiyazlı istifadəçi) hesablanır. P1 və P2 üçün Slack, Telegram və email bildirişi göndərilir. Hər addım hash zənciri ilə qorunan, dəyişdirilə bilməyən audit log-a yazılır.

## 6. Rəy dövrəsi və korrelyasiya

**Rəy dövrəsi.** Analitik TheHive-da case-i bağlayanda verdict webhook ilə sistemə qayıdır. Tuner rəylərdən qayda və çəki təklifi hazırlayır, replay təklifi keçmiş alert-lər üzərində sınayır (safety gate: FN artmamalıdır). Təklif ayrıca branch-a commit olunur və production-u yalnız insanın merge etdiyi PR dəyişir: sistem özünü özü dəyişmir.

Tam tur (5.4) dataset üzərində 5 problem tapdı: üç qayda/çəki problemi (HASH-11, HASH-12, URL-12, LOGIN-09, LOGIN-12 səhvən bağlana bilərdi), worker-in bir çöküş halı və yarımçıq qalan reset. Düzəlişlərdən sonra replay: FN 2 → 0, recall 0.92 → 1.0. Rəylər bu turda `expected.csv`-dən süni yaradılmışdı, yəni mexanizm göstərildi, dəqiqlik isə 6.3-də ayrıca ölçüldü. Mənbə: [`feedback/tour-2026-11-05.md`](feedback/tour-2026-11-05.md).

**Korrelyasiya** (C1–C4, son 24 saat): eyni IOC artıq açıq case-dədirsə yeni case açılmır (C1); eyni istifadəçidə fərqli tipli alert severity-ni artırır (C2); eyni host-da hash və URL zənciri P1 olur (C3); eyni /24 şəbəkəsindən 60 dəqiqədə 5+ login brute-force case-i kimi birləşir (C4).

## 7. Nəticələr

### 7.1 Sürət (6.2)

Vaxt alert-in API tərəfindən qəbulundan ilk hərəkətə (case yaradıldı, mövcud case-ə bağlandı və ya bağlandı) qədər ölçülür. 36 alert, dörd ssenari:

| Ssenari | Şərt | Median | P90 | Manual ilə (eyni 20 alert) |
|---|---|---|---|---|
| cold | Boş cache, 10 s-də bir alert (real SOC tempi) | 50.0 s | 69.9 s | −79.8% |
| warm | Intel cache dolu | 0.09 s | 45.3 s | ~−100% |
| burst | 36 alert bir anda | 141.6 s | 267.3 s | −49.0% |
| chaos | Intel mənbələri 3 ± 1 s gecikmə ilə | 123.0 s | 234.9 s | −52.3% |

Tiplər üzrə (cold, eyni alert-lər): HASH 206 s → 9.9 s, LOGIN 276 s → 42.3 s, URL 412 s → 66.6 s. URL ən yavaşdır, çünki hər URL alert-i üçün VT iki dəfə sorğulanır (URL və domen), VT isə dəqiqədə 4 sorğu ilə məhdudlaşır.

Dürüst qeyd: avtomatik vaxt "case hazırdır" anına qədərdir. Analitik P1/P2 case-i yenə də oxuyur və araşdırır, amma IOC-ların yoxlanması, verdict təklifi və ticket artıq hazırdır.

### 7.2 Dəqiqlik və təhlükəsizlik (6.3)

| Ssenari | FN | FP | Dəqiqlik | Kappa | "Bağlayardı" payı |
|---|---|---|---|---|---|
| cold | 0 | 8 | 72.2% | 0.57 | 8.3% |
| warm | 0 | 5 | 72.2% | 0.57 | 16.7% |
| burst | 0 | 9 | 69.4% | 0.52 | 5.6% |
| chaos | 0 | 11 | (WireMock) | — | 0.0% |

Sistemin səhvləri təhlükəsiz tərəfədir: təmiz alert-lər `suspicious`/`unknown` olub insana gedir (FP), zərərli alert heç vaxt bağlanmır. Yük altında (burst) VT cavab verə bilmədiyi üçün dəqiqlik düşür, amma sistem daha ehtiyatlı olur: "bağlayardı" payı 5.6%-ə enir.

### 7.3 Ölçmə zamanı tapılan risk: IOC drift

İlk ölçmədə dörd ssenaridən üçündə FN çıxdı: URL-11 və URL-12 (dynamic DNS domenləri: duckdns.org, ddns.net). Etiketlənəndə VT bu URL-ləri tanımırdı (`uncertain`), ölçmə zamanı isə tanıyırdı: 93 mühərrikdə 0 zərərli. Sistem bunu "təmiz" saydı və bağlayardı. Nəticə VT limitindən asılı idi: sorğu limitə düşəndə alert `unknown` olub insana gedirdi.

Ehtimal olunan səbəb: manual ölçmədə analitiklər bu URL-ləri VT-də axtarıb, VT isə tanımadığı URL-i axtarışda avtomatik skan edir. Sübut olunmayıb: sistem VT-nin ilk görülmə tarixini saxlamır. Riskin özü isə real idi: hücumçu yeni alt domeni VT-yə skan etdirsə, "0/93" alır.

Həll ([ADR-0003](adr/0003-auto-close-decision.md)): dynamic DNS provayderlərinin (31 provayder) domenləri heç vaxt avtomatik bağlanmır. Qoruyucudan sonra dörd ssenarinin hamısında FN 0 oldu. Qoruyucu olmasaydı, warm ssenarisində FN 3 olardı (URL-09 da eyni vəziyyətə keçmişdi).

### 7.4 Auto-close qərarı

Auto-close açılmadı. Səbəblər:

- Qoruyucu FN-ləri gördükdən sonra eyni 36 alert üzərində yoxlandı: işlədiyini göstərir, ümumiləşdiyini sübut etmir.
- Intel nəticələri qaçışdan qaçışa dəyişir.
- Fayda kiçikdir (36 alert-in 2–6-sı bağlanardı), bir FN-in qiyməti isə yüksəkdir.

Açılma şərtləri: 4 ssenaridə FN 0 (✓), kill switch testi (✓, 6.4 s), görülməmiş 30+ alert-də FN 0, shadow mode dövründə "sistem bağlayardı, analitik malicious dedi" halı 0, QA nümunəsində səhv 0.

### 7.5 Uçdan-uca testlər (6.4)

7 E2E test işləyən stekə real alert göndərir və invariantları real bazada yoxlayır: hər alert son vəziyyətə çatır, malicious heç vaxt bağlanmır, `create_case` → case, dublikat birləşir, timeline-da bütün mərhələlər var, səhv imza rədd edilir, DLQ boşdur, audit zənciri bütövdür. Unit testlər: 676 (CI-da coverage ≥ 85%).

## 8. Təhlükəsizlik (6.5, 6.6)

| Sahə | Nəticə |
|---|---|
| Sirlər | Yalnız `.env`-də; pre-commit və CI-da gitleaks (bütün git tarixçəsi: 0 sızma) |
| Kod | bandit: Medium/High 0 (bir Medium tapıldı və düzəldildi: `urlopen` istənilən sxemi açırdı) |
| Asılılıqlar | pip-audit: 0 məlum zəiflik |
| Production image | trivy: 0 CRITICAL/HIGH; root olmayan istifadəçi (uid 10001), read-only fayl sistemi, bütün capability-lər atılıb |
| İşləyən sistem | 10 yoxlama: autentifikasiya (11/11 endpoint), portlar yalnız 127.0.0.1, ölçü limiti, loglarda secret 0, audit dəyişdirilə bilmir, defang, allowlist, malicious bağlanmır |
| Secret rotasiyası | `ADMIN_TOKEN` məşqi: köhnə 403, yeni 200; məşq bir boşluq tapdı (`N8N_WEBHOOK_TOKEN` nümunə konfiqdə yoxdur) |

CI hər PR-da, main-də və həftəlik işləyir. Qəbul olunan risklər və rotasiya cədvəli: [`security-review.md`](security-review.md).

## 9. Məhdudiyyətlər və növbəti addımlar

**Məhdudiyyətlər:**

- 36 alert-lik dataset statistik nəticə üçün kiçikdir. Rəqəmlər istiqamət göstərir.
- Rəy dövrəsindəki rəylərin bir hissəsi `expected.csv`-dən süni yaradılıb.
- VirusTotal pulsuz limiti (dəqiqədə 4) burst zamanı triaj vaxtını artırır və dəqiqliyi azaldır.
- Intel nəticələri zamanla dəyişir (IOC drift). Etiketlər yazılan gün doğru idi, ölçmə günü isə bəziləri fərqli görünürdü.
- Skor düsturları evristikdir (`rules/weights.yaml`).
- E2E testlər CI-da yox, lokal stekdə işləyir.
- TheHive Community lisenziyası 2 istifadəçi ilə məhdudlaşır.
- Redis əlçatmaz olanda ingest `500` qaytarır, göndərən təkrar etməlidir.

**Növbəti addımlar:**

1. Shadow mode-da real alert axını ilə 30+ görülməmiş alert toplamaq və auto-close şərtlərini yoxlamaq.
2. VT-nin ilk görülmə tarixini saxlamaq: yeni (< 30 gün) qeyd "təmiz" sayılmasın (ADR-0003, variant B).
3. Redis xətasında `503` + `Retry-After` və simulyatorda təkrar cəhd.
4. VT ödənişli planı və ya əlavə güclü mənbə (burst-da dəqiqlik).
5. E2E testləri CI-a köçürmək (test steki ilə).
6. `N8N_WEBHOOK_TOKEN`-i nümunə konfiqə əlavə etmək.

## 10. Komponentlər üzrə qeydlər

Hər bölmə komponenti quran üzvün qeydidir: nə quruldu, əsas qərar, çətinlik, sübut, məhdudiyyət.

### 10.1 Mühit və infrastruktur

**docker-compose: PostgreSQL, Redis, n8n, Mailpit, Makefile (1.2a)** · ⏳ gözlənilir

**TheHive steki, lisenziya, service account (1.2b)** · ⏳ gözlənilir

**Repo, branch protection, secret qoruması (1.1a, 1.1b, 1.1c).** Qorunan `main`, hər dəyişiklik PR və review ilə, squash merge. Sirlər üç qatda qorunur: `.env` (gitignore), gitleaks pre-commit hook-u və CI. Qoruma saxta açarla sınandı: commit bloklandı. Sübut: `.pre-commit-config.yaml`, `.github/workflows/ci.yml`.

### 10.2 Tədqiqat və qərarlar

**Baseline hazırlığı və analizi (1.3a, 1.3b)** · ⏳ gözlənilir

**SOAR PoC: n8n və Python, ADR-0001 (1.4a, 1.4c).** Eyni ssenari üç platformada 2 saatlıq time-box ilə quruldu, meyar və çəkilər PoC-dan əvvəl razılaşdırıldı. Python PoC-da fail-open səhvi (mənbə cavab verməyəndə "təmiz") pytest ilə tapıldı: bu, qərar məntiqinin kodda saxlanmasının əsas səbəbi oldu. Sübut: `docs/poc/`, ADR-0001.

**SOAR PoC: Shuffle (1.4b)** · ⏳ gözlənilir

**Intel API tədqiqatı (1.5)** · ⏳ gözlənilir

**FN riski və fallback cədvəli, ADR-0002 (1.6)** · ⏳ gözlənilir

### 10.3 Məlumat və ingest

**Vahid alert schema, OCSF (2.1)** · ⏳ gözlənilir

**Dataset: HASH (2.2a-1)** · ⏳ gözlənilir

**Dataset: URL (2.2a-2)** · ⏳ gözlənilir

**Dataset: LOGIN (2.2a-3)** · ⏳ gözlənilir

**Alert JSON-ları və etiketləmə (2.2b)** · ⏳ gözlənilir (etiketləmə). Generator: dataset IOC-larından üç mənbənin (Wazuh, EDR, proxy) real formatında 36 alert JSON-u yaradır, etiketlər `expected.csv`-də saxlanılır.

**Simulyator, IOC çıxarma, parser-lər (2.3, 2.4a, 2.4b-1, 2.4b-2, 2.4b-3).** Simulyator alert-ləri HMAC imzası ilə istənilən tempdə göndərir (`--rate`, `--burst`, `--only`). Parser-lər üç mənbənin formatını `NormalizedAlert`-ə çevirir; IOC-lar refang olunur, daxili IP-lər işarələnir. Fingerprint host-suz hesablanır: eyni IOC fərqli host-larda bir alert sayılır. Sübut: `app/normalize/`, `tests/unit/test_normalize.py`, `test_iocs.py`.

**Ingest API, Redis Streams, baza, audit, worker, DLQ (2.5a, 2.5b).** API yalnız imzanı yoxlayır və alert-i stream-ə yazır (202), ağır iş worker-dədir. Mesaj emal bitəndən sonra ACK olunur, çökmüş worker-in mesajı 60 s sonra başqasına keçir, 3 uğursuz cəhddən sonra DLQ. Audit log hash zənciri ilə qorunur və `UPDATE`/`DELETE` trigger ilə qadağandır. Sübut: `app/main.py`, `app/worker.py`, `app/audit/`.

**Testlər və CI (2.6)** · ⏳ gözlənilir

### 10.4 Enrichment

**Provider interfeysi, VirusTotal, AbuseIPDB, OTX adapterləri (3.1a, 3.1b, 3.1c)** · ⏳ gözlənilir

**Timeout, retry, circuit breaker (3.2)** · ⏳ gözlənilir

**Redis cache (3.3)** · ⏳ gözlənilir

**Rate limiter, nəticələrin birləşdirilməsi, test mühiti və chaos testləri (3.4, 3.5, 3.7a, 3.7b-c).** VT limiti üçün Redis-də Lua skripti ilə atomik token bucket: bir neçə worker eyni limiti paylaşır. Birləşdirmə güclü mənbələrin maksimumunu və çəkili ortalamanı qarışdırır, çəkilər `rules/weights.yaml`-dadır. Chaos testləri WireMock və Toxiproxy ilə real API-yə sorğu göndərmədən 7 xəta ssenarisini təkrarlayır. Sübut: `app/enrich/ratelimit.py`, `aggregate.py`, `docs/resilience.md`.

**Enrichment servisi, fallback, yenidən enrichment (3.6)** · ⏳ gözlənilir

### 10.5 Qərar və hərəkət

**Daxili kontekst: asset, istifadəçi, allowlist (4.1)** · ⏳ gözlənilir

**Qayda mühərriki, severity.yaml (4.2)** · ⏳ gözlənilir

**Auto-close qoruyucuları, shadow mode, kill switch (4.3)** · ⏳ gözlənilir

**Case interfeysi, fayl və TheHive backend-ləri (4.4a, 4.4b)** · ⏳ gözlənilir

**Slack, Telegram, bildiriş servisi (4.5a, 4.5b)** · ⏳ gözlənilir

**Pipeline, case DLQ, housekeeping (4.6a)** · ⏳ gözlənilir

**n8n axını, xəta workflow-u (4.6b)** · ⏳ gözlənilir

**Log maskası, audit yoxlaması, timeline (4.7a)** · ⏳ gözlənilir

**Prometheus metrikaları, Grafana (4.7b)** · ⏳ gözlənilir

**Testlər: qaydalar, qoruyucular, case, bildiriş, pipeline (4.8a, 4.8b, 4.8c)** · ⏳ gözlənilir

### 10.6 Rəy dövrəsi və korrelyasiya

**Rəyin toplanması, TheHive webhook (5.1)** · ⏳ gözlənilir

**Replay, tuner, safety gate (5.2)** · ⏳ gözlənilir

**Korrelyasiya C1–C4 (5.3)** · ⏳ gözlənilir

**Testlər və rəy dövrəsinin tam turu (5.4)** · ⏳ gözlənilir

### 10.7 Ölçmə və təhvil

**Manual və avtomatik ölçmə, dəqiqlik, ADR-0003 (6.1, 6.2, 6.3).** Manual və avtomatik vaxt eyni alert-lər və eyni sərhədlərlə ölçüldü (başlanğıc: qəbul anı, son: ilk hərəkət). Dörd ssenari bir skriptlə təkrarlanır (`tools/measure_auto.sh`). Ölçmə URL-11/URL-12 drift-ini aşkarladı və dynamic DNS qoruyucusuna gətirdi; kill switch ayrıca test olundu. Sübut: `docs/measure/`, ADR-0003, `tools/killswitch_test.sh`.

**E2E testlər, production image, security CI və review (6.4, 6.5, 6.6a, 6.6b).** E2E testlər işləyən stekdə 7 invariantı yoxlayır. Production image multi-stage, root olmayan istifadəçi, read-only. Security CI 4 alətlə hər PR-da işləyir; review 9 yoxlamanı avtomatik aparır. Sübut: `tests/e2e/`, `Dockerfile`, `.github/workflows/security.yml`, `docs/security-review.md`.

**Sənədlər (6.7a, 6.7b, 6.7c).** README, arxitektura (Mermaid diaqramı) və simptomdan başlayan əməliyyat runbook-u. Sənədlər kodla eyni repoda saxlanılır və PR ilə dəyişir.

---

## Əlavələr

| Sənəd | Məzmun |
|---|---|
| [`architecture.md`](architecture.md) | Komponentlər, məlumat modeli, qərar məntiqi |
| [`operations.md`](operations.md) | Əməliyyat runbook-u |
| [`adr/`](adr/) | ADR-0001, ADR-0002, ADR-0003 |
| [`measure/summary.md`](measure/summary.md), [`measure/accuracy.md`](measure/accuracy.md) | Ölçmə nəticələri |
| [`resilience.md`](resilience.md) | Chaos testləri |
| [`security-review.md`](security-review.md) | Təhlükəsizlik review |
| [`feedback/tour-2026-11-05.md`](feedback/tour-2026-11-05.md) | Rəy dövrəsinin tam turu |
