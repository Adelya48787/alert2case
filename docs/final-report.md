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

Hər komponent üçün: nə quruldu, əsas qərar, çətinlik və həlli, sübut (PR, fayl, test), məhdudiyyət.

### 10.1 Mühit və infrastruktur

**docker-compose: PostgreSQL, Redis, n8n, Mailpit, Makefile (1.2a)**

- **Nə quruldu:** PostgreSQL, Redis, n8n və Mailpit üçün `docker-compose.yml` və gündəlik əmrlər üçün `Makefile` (`make up`, `migrate`, `logs`, `reset-data`). PostgreSQL və Redis-in healthcheck-i var, onlardan asılı servislər onlar hazır olandan sonra başlayır; portlar yalnız `127.0.0.1`-də açılır.
- **Əsas qərar:** Hər üzvün kompüterində eyni mühit bir əmrlə qalxsın: servis versiyaları `.env`-də sabitlənib (`POSTGRES_VERSION` və s.). Email üçün real SMTP əvəzinə Mailpit: test bildirişləri heç kimə getmir, amma brauzerdə görünür.
- **Çətinlik və həlli:** Mailpit SMTP bağlantılarında reverse DNS sorğusu edirdi və bəzi mühitlərdə gecikmə yaradırdı; söndürüldü (#24).
- **Sübut:** `docker-compose.yml`, `Makefile`, PR #4, #24.
- **Məhdudiyyət:** Dev stek sərtləşdirilməyib (root, yazıla bilən fayl sistemi); production üçün ayrıca override var (6.5).

**TheHive steki, lisenziya, service account (1.2b)**

- **Nə quruldu:** TheHive 5 steki (Cassandra, Elasticsearch, TheHive) ayrıca compose profili kimi (`make up-full`), təşkilat və case yaratmaq üçün service account.
- **Əsas qərar:** TheHive əsas steki ağırlaşdırmasın deyə profil ilə ayrıldı: TheHive olmadan sistem fayl backend-i ilə tam işləyir.
- **Çətinlik və həlli:** Üç ağır servis (Cassandra, Elasticsearch, TheHive) gec qalxır və çox yaddaş istəyir; ona görə əsas stekdən ayrıldı və yalnız lazım olanda qaldırılır. DNS və webhook problemləri `troubleshooting.md`-də yazılıb.
- **Sübut:** `docker-compose.yml` (`thehive` profili), PR #5, `docs/troubleshooting.md`.
- **Məhdudiyyət:** TheHive yalnız bir üzvün kompüterində qurulub; Community lisenziyası 2 istifadəçi ilə məhdudlaşır.

**Repo, branch protection, secret qoruması (1.1a, 1.1b, 1.1c).** Qorunan `main`, hər dəyişiklik PR və review ilə, squash merge. Sirlər üç qatda qorunur: `.env` (gitignore), gitleaks pre-commit hook-u və CI. Qoruma saxta açarla sınandı: commit bloklandı. Sübut: `.pre-commit-config.yaml`, `.github/workflows/ci.yml`.

### 10.2 Tədqiqat və qərarlar

**Baseline hazırlığı və analizi (1.3a, 1.3b)**

- **Nə quruldu:** 12 alert kartı (HASH, NET, WEB; hər növdə 2 zərərli, 1 təmiz, 1 qeyri-müəyyən), düzgün cavablar (`answers.csv`), addım-addım vaxt ölçən `timer.py` və nəticəni cədvəl və qrafikə çevirən hesabat skripti.
- **Əsas qərar:** Ölçmə blind test kimi aparıldı: kartları hazırlayanlar ölçmədə iştirak etmədi, sıra təsadüfi idi, 8 addımın (S1–S8) sərhədləri əvvəlcədən razılaşdırıldı.
- **Çətinlik və həlli:** 8 addımın hər birini əl ilə qeyd etmək ölçməni yorucu edirdi; timer analitiki addım-addım aparan rejimlə tamamlandı (#17).
- **Sübut:** `docs/baseline/`, PR #7, #10, #13, #17, #21. Nəticə: median ≈ 8.3 dəq, vaxtın 36%-i intel saytlarında.
- **Məhdudiyyət:** 12 alert və 2 analitik: nəticə istiqamət göstərir, statistik cəhətdən güclü deyil.

**SOAR PoC: n8n və Python, ADR-0001 (1.4a, 1.4c).** Eyni ssenari üç platformada 2 saatlıq time-box ilə quruldu, meyar və çəkilər PoC-dan əvvəl razılaşdırıldı. Python PoC-da fail-open səhvi (mənbə cavab verməyəndə "təmiz") pytest ilə tapıldı: bu, qərar məntiqinin kodda saxlanmasının əsas səbəbi oldu. Sübut: `docs/poc/`, ADR-0001.

**SOAR PoC: Shuffle (1.4b)**

- **Nə quruldu:** Shuffle-da eyni PoC ssenarisi: webhook → VirusTotal → nəticəyə görə bildiriş, 2 saatlıq time-box ilə.
- **Əsas qərar:** Shuffle orta bal 3.0 / 5 aldı və seçilmədi: vizuallıq güclüdür (5), amma test edilə bilmə (2), retry (2) və versiya nəzarəti (2) zəifdir.
- **Çətinlik və həlli:** Ən ciddi tapıntı: workflow export JSON-una API açarı düşürdü, Authentication bölməsi istifadə olunanda da. Fayl silindi və bu, ADR-0001-də əsas arqumentlərdən biri oldu.
- **Sübut:** `docs/poc/shuffle.md`, PR #16, ADR-0001.
- **Məhdudiyyət:** PoC ~80 dəqiqə ilə məhdud idi; Docker Swarm qurulumu vaxtın bir hissəsini apardı.

**Intel API tədqiqatı (1.5)**

- **Nə quruldu:** VirusTotal v3, AbuseIPDB və OTX API-lərinin tədqiqatı: endpoint-lər, autentifikasiya, limitlər, cavab formatları, skor sahələri; testlər üçün real cavab nümunələri (fixture).
- **Əsas qərar:** Hər mənbədən yalnız qərar üçün lazım olan sahələr götürülür (məs. VT `last_analysis_stats`, AbuseIPDB `abuseConfidenceScore`, OTX `pulse_info.count`). Açarlar heç bir sənədə yazılmır.
- **Çətinlik və həlli:** Pulsuz planların limitləri fərqlidir; VT dəqiqədə 4 sorğu ilə ən sərt məhdudiyyət oldu və sonradan rate limiter-in (3.4) əsasını təşkil etdi.
- **Sübut:** `docs/intel-sources.md`, `tests/fixtures/`, PR #2.
- **Məhdudiyyət:** Limitlər hesab planından asılıdır və dəyişə bilər.

**FN riski və fallback cədvəli, ADR-0002 (1.6)**

- **Nə quruldu:** FN riskinin təhlili və fallback siyasəti (ADR-0002): auto-close meyarları, qoruyucular, intel mənbələri əlçatmaz olanda 9 vəziyyət üçün davranış cədvəli.
- **Əsas qərar:** Risk asimmetrikdir: zərərli alert-i bağlamaq onu insana göndərməkdən qat-qat bahalıdır. Prinsip fail-safe: şübhə varsa insana; məlumat azaldıqca sistem daha ehtiyatlı olur.
- **Çətinlik və həlli:** Auto-close meyarlarını həm sərt, həm də ölçülə bilən etmək lazım idi; nəticədə 6 şərt (verdict, etibarlılıq ≥ 0.67, ziddiyyət yoxdur, enrichment tam, imtiyazlı istifadəçi deyil, asset kritik deyil) birlikdə tələb olunur.
- **Sübut:** `docs/adr/0002-fn-risk-and-fallback.md`, PR #12.
- **Məhdudiyyət:** Hədlər (0.67 və s.) evristikdir, ölçmələrlə yoxlanılıb, amma kiçik dataset üzərində.

### 10.3 Məlumat və ingest

**Vahid alert schema, OCSF (2.1)**

- **Nə quruldu:** Bütün mənbələr üçün vahid alert modeli (`NormalizedAlert`), OCSF Detection Finding (class 2004) sahə adları ilə; JSON Schema və OCSF/ECS uyğunluq cədvəli.
- **Əsas qərar:** Tam OCSF obyekti yox, lazım olan alt çoxluq: yüzlərlə sahə saxlanmır, amma sahə adları və severity şkalası standartdandır, istənilən vaxt tam OCSF-ə çevirmək olur.
- **Çətinlik və həlli:** Üç mənbənin (Wazuh, EDR, proxy) fərqli sahələrini bir modelə uyğunlaşdırmaq; IOC-lar ayrıca `observables[]` siyahısına çıxarıldı.
- **Sübut:** `app/schemas/alert.py`, `schemas/`, `docs/schema-mapping.md`, PR #25.
- **Məhdudiyyət:** Yalnız üç alert tipi (`malicious_hash`, `suspicious_url`, `suspicious_login`) modelləşdirilib.

**Dataset: HASH (2.2a-1)**

- **Nə quruldu:** 12 fayl hash-ı (4 zərərli, 4 təmiz, 4 qeyri-müəyyən) və hər biri üçün toplama günündəki VT və OTX cavablarının snapshot-ları.
- **Əsas qərar:** Zərərli hash-lar MalwareBazaar-dan, təmizlər rəsmi installer-lərdən (7-Zip, PuTTY, Notepad++) götürüldü; təhlükəsizlik üçün EICAR test faylı da daxildir. Faylların özü yüklənmir, yalnız hash mətni saxlanılır.
- **Çətinlik və həlli:** Qeyri-müəyyən hash tapmaq: VT-də heç görülməmiş və ya az detection-lu hash-lar seçildi.
- **Sübut:** `dataset/iocs_hash.csv`, `dataset/snapshots/`, PR #31.
- **Məhdudiyyət:** IOC reputasiyası zamanla dəyişir (drift); snapshot etiketləmə gününün vəziyyətini sübut edir.

**Dataset: URL (2.2a-2)**

- **Nə quruldu:** 12 URL (zərərli, təmiz, qeyri-müəyyən) və VT/OTX snapshot-ları.
- **Əsas qərar:** Zərərlilər URLhaus-dan, təmizlər Tranco top siyahısından, qeyri-müəyyənlər pulsuz dynamic DNS və yeni qeydiyyatlı domenlərdən. Dataset-də URL-lər defang formada saxlanılır.
- **Çətinlik və həlli:** Qeyri-müəyyən URL-lər zamanla dəyişdi: Phase 6-da dynamic DNS URL-ləri VT-də "0 zərərli" göründü və bu, ADR-0003-dəki qoruyucuya gətirdi.
- **Sübut:** `dataset/iocs_url.csv`, PR #27, ADR-0003.
- **Məhdudiyyət:** URL-lərin reputasiyası ən tez dəyişən IOC növüdür.

**Dataset: LOGIN (2.2a-3)**

- **Nə quruldu:** 12 login IP-si (zərərli, təmiz, qeyri-müəyyən) və AbuseIPDB/VT/OTX snapshot-ları.
- **Əsas qərar:** Zərərlilər Tor exit node-ları və yüksək AbuseIPDB skorlu IP-lər, təmizlər böyük provayderlərin ictimai IP-ləri (korporativ VPN rolunda, allowlist-ə düşür), qeyri-müəyyənlər AbuseIPDB skoru 20–60 olan IP-lər.
- **Çətinlik və həlli:** AbuseIPDB skorları günlər ərzində dəyişir; rəy turunda (5.4) `weak_signal` həddi 25-dən 20-yə endirildi ki, qeyri-müəyyən login-lər təmiz sayılmasın.
- **Sübut:** `dataset/iocs_login.csv`, PR #28.
- **Məhdudiyyət:** Bir IP (`203.0.113.10`, TEST-NET-3) daxili sayılır və intel-ə getmir (`resilience.md`, məhdudiyyət 2).

**Alert JSON-ları və etiketləmə (2.2b)**

- **Nə quruldu:** 36 alert-in etiketlənməsi: hər alert üçün `malicious`, `clean` və ya `uncertain` və səbəbi (`expected.csv`).
- **Əsas qərar:** Etiket snapshot-lara əsaslanır və səbəbi yazılır (məs. "VT 66/75; OTX 50; kritik host DC-01"), ki sonradan hər qərar yoxlanıla bilsin.
- **Çətinlik və həlli:** `uncertain` ilə `clean` arasındakı sərhəd: heç bir mənbədə məlumat olmayan IOC təmiz yox, `uncertain` etiketləndi. Bu qayda sonra sistemin "clean" şərtinə də keçdi.
- **Sübut:** `dataset/expected.csv`, PR #36.
- **Məhdudiyyət:** Etiketlər etiketləmə gününün intel vəziyyətinə bağlıdır.

Generator: dataset IOC-larından üç mənbənin (Wazuh, EDR, proxy) real formatında 36 alert JSON-u yaradır, etiketlər `expected.csv`-də saxlanılır.

**Simulyator, IOC çıxarma, parser-lər (2.3, 2.4a, 2.4b-1, 2.4b-2, 2.4b-3).** Simulyator alert-ləri HMAC imzası ilə istənilən tempdə göndərir (`--rate`, `--burst`, `--only`). Parser-lər üç mənbənin formatını `NormalizedAlert`-ə çevirir; IOC-lar refang olunur, daxili IP-lər işarələnir. Fingerprint host-suz hesablanır: eyni IOC fərqli host-larda bir alert sayılır. Sübut: `app/normalize/`, `tests/unit/test_normalize.py`, `test_iocs.py`.

**Ingest API, Redis Streams, baza, audit, worker, DLQ (2.5a, 2.5b).** API yalnız imzanı yoxlayır və alert-i stream-ə yazır (202), ağır iş worker-dədir. Mesaj emal bitəndən sonra ACK olunur, çökmüş worker-in mesajı 60 s sonra başqasına keçir, 3 uğursuz cəhddən sonra DLQ. Audit log hash zənciri ilə qorunur və `UPDATE`/`DELETE` trigger ilə qadağandır. Sübut: `app/main.py`, `app/worker.py`, `app/audit/`.

**Testlər və CI (2.6)**

- **Nə quruldu:** Phase 2 üçün unit testlər (ingest, HMAC, normalizasiya, IOC çıxarma) və GitHub Actions CI: lint, testlər, coverage.
- **Əsas qərar:** CI hər PR-da işləyir və coverage 85%-dən aşağı düşəndə PR-ı bloklayır; testlər real Redis/API olmadan, saxta secret-lərlə işləyir.
- **Çətinlik və həlli:** Testlərin lokal `.env`-dən asılı olmaması üçün `conftest.py` test secret-lərini məcburi təyin edir: testlər hər kompüterdə və CI-da eyni işləyir (#38).
- **Sübut:** `tests/unit/`, `.github/workflows/ci.yml`, PR #37, #38.
- **Məhdudiyyət:** Unit testlər xarici servisləri saxta cavablarla əvəz edir; inteqrasiya E2E testlərdədir (6.4).

### 10.4 Enrichment

**Provider interfeysi, VirusTotal, AbuseIPDB, OTX adapterləri (3.1a, 3.1b, 3.1c)**

- **Nə quruldu:** Provider interfeysi, ümumi HTTP klienti və üç adapter: VirusTotal (hash, IP, domen, URL), AbuseIPDB (IP), OTX (hamısı). Hər adapter cavabı vahid `ProviderResult`-a çevirir: status, verdict, skor, evidence.
- **Əsas qərar:** Adapterlər yalnız tərcümə edir, qərar vermir: verdict birləşdirmədə (3.5) çıxarılır. Status-lar ayrılır: `ok`, `not_found`, `timeout`, `rate_limited`, `auth_error`, `error`.
- **Çətinlik və həlli:** VT URL endpoint-i URL-in özünü yox, base64url ID-sini tələb edir; `not_found` (404) xəta kimi yox, ayrıca nəticə kimi işlənir.
- **Sübut:** `app/enrich/base.py`, `providers.py`, `http.py`, `tests/unit/test_abuseipdb.py`, `test_otx.py`, PR #39, #40.
- **Məhdudiyyət:** Hər mənbədən yalnız bir neçə sahə istifadə olunur.

**Timeout, retry, circuit breaker (3.2)**

- **Nə quruldu:** Hər xarici sorğu üçün timeout (8 s), 3 cəhdlik retry (backoff) və provider başına circuit breaker (5 ardıcıl xəta → 60 s açıq).
- **Əsas qərar:** Çökmüş mənbəyə sorğu göndərməyə davam etmək həm vaxt itirir, həm də limitləri yeyir; breaker açıq olanda sorğu getmir, nəticə dərhal `skipped` olur. 401-də provider söndürülür, çünki açar özü düzəlməyəcək.
- **Çətinlik və həlli:** Chaos testində (3.7) sorğu vaxtları 3 × 8 s + backoff ilə 30 s-dən aşağı qaldı, worker çökmədi.
- **Sübut:** `app/enrich/breaker.py`, `http.py`, PR #42, `docs/resilience.md` (ssenari 3, 4).
- **Məhdudiyyət:** Breaker vəziyyəti hər worker prosesinin yaddaşındadır, prosesler arasında paylaşılmır.

**Redis cache (3.3)**

- **Nə quruldu:** Intel cavabları üçün Redis cache: açar `provider + IOC tipi + dəyərin hash-ı`, TTL verdict-ə görə (malicious 24 saat, clean 6 saat, digərləri 1 saat).
- **Əsas qərar:** Etibarlı nəticə uzun, qeyri-müəyyən nəticə qısa saxlanılır: təmiz və ya naməlum IOC tez dəyişə bilər. Redis əlçatmaz olanda cache proses yaddaşına keçir və enrichment dayanmır.
- **Çətinlik və həlli:** Cache 6.2-də ən böyük fərqi yaratdı: warm ssenarisində median 50 s-dən 0.09 s-ə düşdü.
- **Sübut:** `app/enrich/cache.py`, `tests/unit/test_cache.py`, PR #43, `docs/measure/mttr_warm.md`.
- **Məhdudiyyət:** Cache-dəki nəticə TTL bitənə qədər intel-dəki dəyişikliyi görmür.

**Rate limiter, nəticələrin birləşdirilməsi, test mühiti və chaos testləri (3.4, 3.5, 3.7a, 3.7b-c).** VT limiti üçün Redis-də Lua skripti ilə atomik token bucket: bir neçə worker eyni limiti paylaşır. Birləşdirmə güclü mənbələrin maksimumunu və çəkili ortalamanı qarışdırır, çəkilər `rules/weights.yaml`-dadır. Chaos testləri WireMock və Toxiproxy ilə real API-yə sorğu göndərmədən 7 xəta ssenarisini təkrarlayır. Sübut: `app/enrich/ratelimit.py`, `aggregate.py`, `docs/resilience.md`.

**Enrichment servisi, fallback, yenidən enrichment (3.6)**

- **Nə quruldu:** Enrichment orkestrasiyası: hər IOC üçün cache → breaker → rate limit → provider → fallback; nəticələrin birləşdirilməsi; `partial`/`failed` alert-lərin 15 dəqiqədən bir yenidən enrich olunması.
- **Əsas qərar:** Heç bir mənbənin xətası alert-i dayandırmır: alert natamam nəticə ilə davam edir, amma natamam enrichment heç vaxt auto-close olmur (ADR-0002).
- **Çətinlik və həlli:** Mənbələrin bir hissəsi cavab verəndə statusun düzgün təyini (`ok`, `partial`, `failed`) və yenidən enrichment-in eyni alert-i təkrar emal etməməsi.
- **Sübut:** `app/enrich/service.py`, `reenrich.py`, `tests/unit/test_service.py`, PR #47.
- **Məhdudiyyət:** Yenidən enrichment 15 dəqiqə gecikmə ilə işləyir.

### 10.5 Qərar və hərəkət

**Daxili kontekst: asset, istifadəçi, allowlist (4.1)**

- **Nə quruldu:** Daxili kontekst: asset-lər (vaciblik: low…crown_jewel), istifadəçilər (imtiyaz, VIP) və allowlist (`owner`, `reason`, `expires_at` məcburi).
- **Əsas qərar:** Kontekst fayllarda (`context/`) saxlanılır və dəyişəndə restart-sız yenidən oxunur; müddəti keçmiş allowlist qeydi avtomatik tətbiq olunmur.
- **Çətinlik və həlli:** Allowlist-in özü risk mənbəyidir: sahibsiz və müddətsiz qeyd qadağan edildi, yoxlama 6.6b-də avtomatlaşdırıldı.
- **Sübut:** `context/`, `app/context/loader.py`, `tests/unit/test_context.py`, PR #50, #51.
- **Məhdudiyyət:** Kontekst statik fayldır, CMDB və ya AD ilə inteqrasiya yoxdur.

**Qayda mühərriki, severity.yaml (4.2)**

- **Nə quruldu:** Deklarativ qayda mühərriki: qaydalar `rules/severity.yaml`-da, yuxarıdan aşağı ilk uyğun gələn qayda verdict, severity və hərəkəti təyin edir; qərarlar `decisions` cədvəlinə yazılır (miqrasiya 0002).
- **Əsas qərar:** `eval` yoxdur: şərtlər məhdud operatorlarla yazılır, hər qərarın qaydası, versiyası və səbəbləri saxlanılır, yəni hər qərar izah edilə bilir.
- **Çətinlik və həlli:** Qayda faylının restart-sız yenilənməsi: fayl dəyişikliyi mtime ilə aşkarlanır.
- **Sübut:** `rules/severity.yaml`, `app/rules/engine.py`, `tests/unit/test_rules_engine.py`, PR #52, #53.
- **Məhdudiyyət:** Qaydalar statikdir; dəyişiklik yalnız PR ilə (rəy dövrəsi təklif edir, insan təsdiqləyir).

**Auto-close qoruyucuları, shadow mode, kill switch (4.3)**

- **Nə quruldu:** Auto-close qoruyucuları (qayda "bağla" desə də case açan şərtlər), shadow mode və kill switch (`AUTO_CLOSE_ENABLED`).
- **Əsas qərar:** Qızıl qayda: intel `malicious` deyirsə, heç bir allowlist və ya qayda alert-i bağlaya bilməz. Shadow mode "bağlayardım" qərarını yazır, amma alert insana gedir.
- **Çətinlik və həlli:** Qoruyucuların sırası və allowlist-in hansı qoruyucunu keçə biləcəyi; 6.3-də kill switch-in 6.4 s-də işlədiyi ölçüldü.
- **Sübut:** `app/rules/guards.py`, `tests/unit/test_guards.py`, PR #54, `docs/measure/killswitch.md`.
- **Məhdudiyyət:** Kill switch mühit dəyişənidir, worker-in yenidən yaradılmasını tələb edir.

**Case interfeysi, fayl və TheHive backend-ləri (4.4a, 4.4b)**

- **Nə quruldu:** Case backend interfeysi və iki backend: fayl (`var/cases/*.json`) və TheHive 5 REST API (service account açarı ilə).
- **Əsas qərar:** Backend `.env`-dən seçilir (`CASE_BACKEND`): TheHive olmadan sistem tam işləyir. Eyni fingerprint üçün 24 saatda bir case (idempotentlik); başlıqda IOC defang olunur.
- **Çətinlik və həlli:** TheHive əlçatmaz olanda alert itməməlidir: `case_pending` statusu və case DLQ ilə həll olundu (4.6a ilə birlikdə).
- **Sübut:** `app/case/`, `tests/unit/test_case.py`, PR #54.
- **Məhdudiyyət:** TheHive yalnız bir üzvün kompüterində sınanıb.

**Slack, Telegram, bildiriş servisi (4.5a, 4.5b)**

- **Nə quruldu:** Slack webhook, Telegram bot və bildiriş servisi: yalnız P1 və P2; P1 üçün həmişə, chat alınmayanda isə email (Mailpit).
- **Əsas qərar:** Bildiriş yorğunluğuna qarşı throttle: eyni fingerprint üçün P1 15 dəqiqədə, P2 1 saatda bir dəfə. Bildiriş xətası pipeline-ı dayandırmır.
- **Çətinlik və həlli:** Kanalların hər biri müstəqil uğursuz ola bilər; fallback zənciri (chat → email) bunu örtür.
- **Sübut:** `app/notify/service.py`, `tests/unit/test_case_notify.py`, PR #55.
- **Məhdudiyyət:** Throttle Redis-dədir; Redis əlçatmaz olanda throttle tətbiq olunmur.

**Pipeline, case DLQ, housekeeping (4.6a)**

- **Nə quruldu:** Mərhələlərin bir pipeline-a yığılması (normalize → enrich → decide → correlate → act → notify), case DLQ və hər 2 dəqiqədə işləyən housekeeping (gözləyən case-lər, DLQ dərinliyi).
- **Əsas qərar:** Hər mərhələ audit-ə yazılır və öz xətasını idarə edir; case yaradıla bilməyəndə alert `case_pending` olur, sonra avtomatik tamamlanır.
- **Çətinlik və həlli:** TheHive inteqrasiyası sınanarkən tapıldı: korrelyasiya köhnə fayl case-inə bağlananda şərh səhv backend-ə gedirdi və alert DLQ-ya düşürdü. Şərh case-in öz backend-i ilə göndərilir, xəta alert-i dayandırmır (#68).
- **Sübut:** `app/pipeline.py`, `tests/unit/test_pipeline.py`, PR #56, #68.
- **Məhdudiyyət:** Housekeeping intervalı sabitdir (2 dəqiqə).

**n8n axını, xəta workflow-u (4.6b)**

- **Nə quruldu:** n8n-də pipeline-ın vizual axını: mərhələlər `/stage/*` endpoint-ləri ilə çağırılır; xəta workflow-u Mailpit-ə email göndərir; `send_n8n.py` alert-ləri n8n webhook-una göndərir.
- **Əsas qərar:** Qərar məntiqi Python-da qalır, n8n yalnız orkestrasiya edir (ADR-0001): eyni kod həm worker, həm n8n yolunda işləyir.
- **Çətinlik və həlli:** n8n 2.x-də xəta workflow-u yalnız publish olunanda işə düşür; credential-lar import zamanı n8n-in öz açarı ilə şifrələnir, açıq mətnli fayl silinir.
- **Sübut:** `n8n/`, `app/stages.py`, `tools/send_n8n.py`, `tools/n8n_credentials.py`, PR #58.
- **Məhdudiyyət:** n8n yolu demo və alternativ üçündür; ölçmələr worker yolu ilə aparılıb.

**Log maskası, audit yoxlaması, timeline (4.7a)**

- **Nə quruldu:** Loglarda secret maskası, audit hash zəncirinin yoxlanması (`tools.verify_audit`) və alert-in bütün mərhələlərini göstərən timeline endpoint-i.
- **Əsas qərar:** Audit log append-only-dir (trigger) və hər sətir əvvəlkinin hash-ını saxlayır: dəyişiklik zənciri qırır və aşkarlanır.
- **Çətinlik və həlli:** Secret-lərin log-a düşməməsi: konfiqurasiyadakı secret dəyərləri log filtrində maskalanır, ona görə xəta mesajında belə görünmür; 6.6b-də loglarda secret 0 tapıldı.
- **Sübut:** `app/audit/`, `tools/verify_audit.py`, PR #57, `docs/security-review.md` (yoxlama 4, 5).
- **Məhdudiyyət:** DB sahibi trigger-i silə bilər; hash zənciri bunu aşkarlayır, amma qarşısını almır.

**Prometheus metrikaları, Grafana (4.7b)**

- **Nə quruldu:** Prometheus metrikaları (alert sayı, dublikatlar, mərhələ vaxtları, qəbul → hərəkət vaxtı, intel nəticələri, bildirişlər, DLQ dərinliyi) və Grafana paneli.
- **Əsas qərar:** Metrikalar api-də `/metrics`, worker-də ayrıca portda (9100); müşahidə steki ayrıca profil kimi qalxır (`make up-obs`).
- **Çətinlik və həlli:** Worker HTTP server deyil; metrikalar üçün ayrıca port açıldı və prod compose-da healthcheck kimi də istifadə olunur.
- **Sübut:** `app/audit/metrics.py`, `grafana/`, `prometheus/`, PR #57.
- **Məhdudiyyət:** Alert qaydaları (alerting) qurulmayıb, yalnız panel.

**Testlər: qaydalar, qoruyucular, case, bildiriş, pipeline (4.8a, 4.8b, 4.8c)**

- **Nə quruldu:** Phase 4 testləri: qaydalar və qoruyucular (qızıl qayda daxil), case və bildiriş kənar halları, test factory-ləri və pipeline testləri (QA nümunəsi, korrelyasiya, retry, n8n mərhələləri).
- **Əsas qərar:** Factory-lər (`tests/unit/factories.py`) testlərdə alert və kontekst yaratmağı bir sətirə endirir; testlər real servis olmadan işləyir.
- **Çətinlik və həlli:** Pipeline-ın asinxron mərhələlərini və xəta yollarını saxta backend-lərlə təkrarlamaq.
- **Sübut:** `tests/unit/test_rules_engine.py`, `test_guards.py`, `test_case_notify.py`, `test_pipeline.py`, PR #59.
- **Məhdudiyyət:** Xarici servislərin real davranışı E2E testlərdə (6.4) yoxlanılır.

### 10.6 Rəy dövrəsi və korrelyasiya

**Rəyin toplanması, TheHive webhook (5.1)**

- **Nə quruldu:** Analitik rəyinin toplanması: `feedback` cədvəli (miqrasiya 0003), TheHive `CaseClosed` webhook-u (`/feedback/thehive`, Bearer token) və əl ilə rəy (`/feedback`).
- **Əsas qərar:** Rəy sistemin qərarı ilə yanaşı saxlanılır (razıdır / razı deyil), ki tuner səhv qərarları sayaraq təklif hazırlaya bilsin.
- **Çətinlik və həlli:** TheHive 5.8-in webhook payload formatı gözləniləndən fərqli idi; real E2E sınağında tapıldı və düzəldildi (#68).
- **Sübut:** `app/feedback/`, `tests/unit/test_feedback_collector.py`, PR #61, #68.
- **Məhdudiyyət:** Real analitik rəyi azdır; turda rəylər `expected.csv`-dən yaradıldı.

**Replay, tuner, safety gate (5.2)**

- **Nə quruldu:** Replay (qayda və çəkiləri keçmiş alert-lər üzərində yenidən işlədib confusion matrix çıxarır) və tuner (rəylərdən qayda/çəki təklifi).
- **Əsas qərar:** Tuner heç vaxt production-u özü dəyişmir: təklifi ayrıca branch-a commit edir, PR-ı insan açır. Safety gate: təklif FN-i artırırsa rədd edilir.
- **Çətinlik və həlli:** Təklifin dəyərini ölçmək: replay eyni alert-ləri köhnə və yeni qaydalarla işlədib FN/FP fərqini göstərir.
- **Sübut:** `tools/replay.py`, `tools/tuner.py`, `tests/unit/test_replay.py`, `test_tuner.py`, PR #63, #64, `docs/feedback/proposal-2026-11-05.md`.
- **Məhdudiyyət:** Təklif evristikdir; son qərar insanındır.

**Korrelyasiya C1–C4 (5.3)**

- **Nə quruldu:** Case korrelyasiyası C1–C4: eyni IOC (yeni case yox), eyni istifadəçidə fərqli tip (severity +1), eyni host-da hash + URL zənciri (P1), eyni /24-dən 60 dəqiqədə 5+ login (brute-force case-i).
- **Əsas qərar:** İndeks Redis-dədir (IOC/istifadəçi/host → case ID, 24 saat pəncərə); qaydalar `rules/correlation.yaml`-da ayrıca yandırılıb-söndürülür.
- **Çətinlik və həlli:** Ölçmə dataset-ində IOC-lar unikal olduğu üçün C1, C3, C4 işə düşmürdü; ayrıca 11 demo alert hazırlandı (`dataset/demo`). C3-də proxy alert-lərinin host sahəsi düzəldildi (#69).
- **Sübut:** `app/correlation/`, `tests/unit/test_correlation.py`, PR #66, #69.
- **Məhdudiyyət:** Pəncərə 24 saatdır; daha uzun kampaniyalar ayrı case-lər kimi qalır.

**Testlər və rəy dövrəsinin tam turu (5.4)**

- **Nə quruldu:** Phase 5 testləri və rəy dövrəsinin tam turu: 36 alert → rəy → replay → tuner.
- **Əsas qərar:** Tur real intel ilə aparıldı ki, düzəlişlər nəzəri yox, faktiki səhvlərə əsaslansın.
- **Çətinlik və həlli:** Tur 5 problem tapdı: üç qayda/çəki problemi (HASH-11, HASH-12, URL-12, LOGIN-09, LOGIN-12 səhvən bağlana bilərdi), `FLUSHDB`-dən sonra worker-in çökməsi (`NOGROUP`) və yarımçıq reset. Düzəlişlərdən sonra FN 2 → 0, recall 0.92 → 1.0.
- **Sübut:** `docs/feedback/tour-2026-11-05.md`, `tests/unit/test_feedback_loop.py`, PR #67.
- **Məhdudiyyət:** Rəylər süni yaradılıb: mexanizm göstərilir, dəqiqlik 6.3-də ölçülüb.

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
