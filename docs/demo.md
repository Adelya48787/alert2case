# Demo ssenarisi

**Müddət:** 15 dəqiqə (13 dəqiqə demo + 2 dəqiqə suallar).
**Laptop:** demo laptopu (TheHive bu kompüterdə qurulub).
**Rollar:**
- **Operator:** demo laptopunun sahibidir, əmrləri o işlədir. Danışanlar ekranı izah edir.
- **Danışanlar 1–4:** Team Lead təyin edir. Tövsiyə: hər kəs öz qurduğu hissəni danışsın.

| Rol | Hissə | Tövsiyə olunan |
|---|---|---|
| Danışan 1 | Problem, nəticələr, suallar | baseline və ölçmələri aparan |
| Danışan 2 | Alert-in yolu, timeline | pipeline, n8n və TheHive-ı quran |
| Danışan 3 | Chaos, korrelyasiya | breaker, cache, korrelyasiyanı quran |
| Danışan 4 | Rəy dövrəsi | replay və tuner-i quran |

Əsas mesaj, bir cümlədə: *analitikin 4 dəqiqəlik əl işi 50 saniyəlik avtomatik hazırlığa çevrildi, sistem şübhədə heç vaxt bağlamır və bunu ölçmələrlə sübut edirik.*

---

## 1. Ssenari

| Dəq | Ekranda | Danışan | Ehtiyat |
|---|---|---|---|
| 0:00–2:00 | Slayd: problem və baseline | 1 | slayd |
| 2:00–5:00 | Zərərli hash: n8n axını → TheHive case (P1) → Slack | 2 | video (6.8b) |
| 5:00–7:00 | Timeline: 6 mərhələ, saniyələrlə | 2 | `docs/demo/timeline-HASH-02.json` |
| 7:00–9:00 | Chaos: VT kəsilir, alert bağlanmır, worker çökmür | 3 | `docs/resilience.md`, ssenari 4–5 |
| 9:00–11:00 | Korrelyasiya: 7 uğursuz login → bir kampaniya case-i | 3 | `docs/demo/thehive-c4.png` |
| 11:00–13:00 | Rəy: case FP kimi bağlanır → feedback → tuner → replay | 4 | `docs/feedback/proposal-2026-11-05.md` |
| 13:00–15:00 | Slayd: nəticələr, URL-11 tapıntısı, məhdudiyyətlər; suallar | 1 | slayd |

Hər addımın ehtiyatı var. Canlı hissə 30 saniyədən çox ilişsə, danışan "eyni axın məşqdə belə görünürdü" deyib ehtiyata keçir və ssenari dayanmır.

---

## 2. Addım-addım

Bütün əmrlər repo kökündən işlədilir, venv aktivdir. Token-lər ekrana çıxmır: hazırlıqda (bölmə 3) dəyişənə oxunur.

### 0:00–2:00 · Problem (Danışan 1, slayd)

> "SOC analitiki hər alert üçün eyni 8 addımı əl ilə təkrarlayır: alert-i oxuyur, IOC-ları çıxarır, onları VirusTotal, AbuseIPDB və OTX-də yoxlayır, qərar verir, ticket açır, komandaya yazır. İki analitiklə 40 ölçmə apardıq: median 4.2 dəqiqə, URL alert-ində 7 dəqiqə. İlk ölçmədə vaxtın üçdə biri intel saytlarında, dörddə biri ticket yazmaqda keçirdi. Eyni alert-ə iki analitik 20 halın 4-ündə fərqli qərar verdi."

### 2:00–5:00 · Alert-in yolu (Danışan 2)

Ekran: n8n → **Executions**, sonra TheHive, sonra Slack.

```bash
python tools/send_n8n.py --only HASH-02
```

> "Bu, domen kontrollerində (DC-01) EICAR test faylıdır. Alert n8n-ə gəlir və n8n mərhələləri bir-bir çağırır: normalizasiya, IOC çıxarma, üç intel mənbəyi, qayda, qoruyucular, case. Qərar məntiqi Python-dadır və testlərlə yoxlanılır, n8n isə axını göstərir."

- n8n-də execution yaşıl: hər node-un üstündə vaxt.
- TheHive: yeni case, **P1**, başlıqda IOC defang olunub, təsvirdə qərarın səbəbləri (VT 66/75, crown_jewel).
- Slack: P1 bildirişi.

> "Analitik bu case-i açanda intel nəticələri, qərar və səbəbi artıq hazırdır."

### 5:00–7:00 · Timeline (Danışan 2)

```bash
ID=$(docker compose exec -T postgres psql -U soc -d alert2case -tAc \
  "select alert_id from alerts where source_ref='HASH-02' order by received_at desc limit 1")
curl -s -H "X-Admin-Token: $T" localhost:8000/alerts/$ID/timeline \
  | python3 -c "import json,sys; [print(f\"+{e['t_plus_s']:>6.2f} s  {e['stage']:<10} {e['event']}\") for e in json.load(sys.stdin)]"
```

> "Hər mərhələ audit log-a yazılır və hər sətir əvvəlkinin hash-ını saxlayır: tarixçəni dəyişmək zənciri qırır. Bu alert qəbuldan case-ə qədər bu qədər saniyə çəkdi. Analitik üçün eyni iş 4 dəqiqədir."

### 7:00–9:00 · Chaos (Danışan 3)

```bash
tools/demo_chaos.sh off
python tools/simulator.py --only HASH-07 --rate 1
sleep 20
docker compose exec -T postgres psql -U soc -d alert2case -c \
  "select a.source_ref, a.doc->'enrichment'->>'status' as enrichment, d.verdict, d.action
   from alerts a join decisions d using (alert_id) where a.source_ref='HASH-07';"
docker compose logs --since 2m worker | grep -c Traceback
tools/demo_chaos.sh on
```

> "İndi VirusTotal-ı kəsirik. HASH-07 təmiz fayldır: ölçmələrdə sistem onu "təmiz" saydı və shadow mode-da "bağlayardım" dedi. Amma VT cavab vermir: enrichment natamamdır, sistem bağlamır, case açır. Worker çökmür, loglarda 0 xəta var. Qayda sadədir: məlumat azaldıqca sistem daha ehtiyatlı olur."

Gözlənilən: `enrichment` `partial` və ya `failed`, `action` `create_case`, Traceback `0`.

### 9:00–11:00 · Korrelyasiya (Danışan 3)

```bash
for i in 1 2 3 4 5 6 7; do
  python tools/simulator.py --dataset dataset/demo --only DEMO-C4-$i --rate 1 | tail -1
  sleep 4
done
```

> "Bir saat ərzində eyni /24 şəbəkəsindən 7 uğursuz login. Tək-tək baxsan, hər biri kiçik alert-dir. Sistem 5-cidən sonra bunu kampaniya kimi tanıyır: bir case, qalanları ona bağlanır. Analitik 7 ticket yox, bir case görür."

TheHive: bir kampaniya case-i, şərhlərdə bağlanan alert-lər.

### 11:00–13:00 · Rəy dövrəsi (Danışan 4)

TheHive-da 2:00-dakı case-dən fərqli bir case aç (məs. C4 case-i və ya P4 case) → **Close** → *False Positive*.

```bash
docker compose exec -T postgres psql -U soc -d alert2case -c \
  "select analyst, source, auto_verdict, human_verdict, rule_id from feedback order by id desc limit 1;"
python -m tools.tuner                 # docs/feedback/proposal-<tarix>.md yaranır
python -m tools.replay | tail -8
```

> "Analitik case-i bağlayanda verdict webhook ilə sistemə qayıdır. Tuner rəylərdən qayda təklifi hazırlayır, replay onu keçmiş alert-lərdə sınayır: FN artarsa təklif rədd edilir. Sistem özünü özü dəyişmir: təklif PR kimi gəlir, insan təsdiqləyir. Rəy dövrəsinin tam turunda bu mexanizm FN-i 2-dən 0-a endirdi."

### 13:00–15:00 · Nəticələr (Danışan 1, slayd)

> "Eyni 20 alert-də triaj vaxtı 249 saniyədən 50 saniyəyə endi, 80% azalma. Cache dolu olanda saniyənin onda biri, 36 alert bir anda gələndə 142 saniyə: VirusTotal-ın pulsuz limiti. Dörd ssenarinin hamısında FN 0, yəni zərərli alert heç vaxt bağlanmayıb. Dəqiqlik eyni 20 alert-də sistemdə 80%, analitiklərdə 65%.
>
> Ən maraqlı tapıntı ölçmədən çıxdı. İki dynamic DNS URL-i VirusTotal-da '0/93 təmiz' görünməyə başladı və sistem onları bağlayardı. Biz qoruyucu əlavə etdik və auto-close-u açmamaq qərarına gəldik: sistem shadow mode-da işləyir, kill switch 6 saniyədə dayandırır.
>
> Məhdudiyyətlər: 36 alert-lik dataset kiçikdir, VT pulsuz limiti yük altında yavaşladır, intel zamanla dəyişir."

Suallar üçün hazır cavablar: bölmə 5.

---

## 3. Demodan 1 saat əvvəl (Operator)

```bash
cd ~/projects/alert2case && source .venv/bin/activate
git checkout main && git pull
make up-full && make up-obs
docker compose ps --format '{{.Service}} {{.State}}'           # hamısı running
grep -E '^(AUTO_CLOSE_ENABLED|SHADOW_MODE|CASE_BACKEND)=' .env  # false, true, thehive

# 1) sistem işləyir
make reset-data && make e2e                                    # 7 passed (panel ilə 8)
docker compose exec -T api python -m tools.verify_audit        # OK: ... zəncir bütövdür

# 2) cache-i isit: demoda göstəriləcək IOC-lar VT limitinə düşməsin
python tools/simulator.py --only HASH-02,HASH-07 --rate 0.2
for i in 1 2 3 4 5 6 7; do python tools/simulator.py --dataset dataset/demo --only DEMO-C4-$i --rate 1 | tail -1; sleep 15; done

# 3) alert-ləri təmizlə, cache qalsın (dublikat sayılmasınlar)
make reset-keep-cache

# 4) token-i dəyişənə oxu (ekrana çıxmır), sınaq
T=$(grep -E '^ADMIN_TOKEN=' .env | cut -d= -f2-)
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Admin-Token: $T" localhost:8000/dlq   # 200
```

Brauzer sekmələri bu sırada açıq olsun:

1. n8n: Executions
2. TheHive: Cases
3. Slack kanalı
4. Mailpit
5. Grafana
6. GitHub: repo

**Bundan əlavə:**
- **Bildirişlər:** Windows-da "Do not disturb" yandırılır, Slack və e-poçt pop-up-ları bağlanır.
- **Görünüş:** terminalın şrifti böyüdülür (`Ctrl +`), brauzer zoom-u 125%.
- **VT limiti:** 10 dəqiqə ərzində heç kim test göndərmir, yoxsa demoda alert `rate_limited` olur.

---

## 4. Ehtiyat materiallar (məşq 1-də toplanır)

Hamısı `docs/demo/` qovluğunda saxlanılır. Videolar böyük olduğu üçün repo-ya qoyulmur: demo laptopunda və ortaq qovluqda saxlanılır.

| Fayl | Necə yaradılır |
|---|---|
| `timeline-HASH-02.json` | 5:00-dakı `curl` əmri, `\| python3 -m json.tool > docs/demo/timeline-HASH-02.json` ilə |
| `thehive-hash02.png` | 2:00 addımından sonra TheHive case-inin ekran görüntüsü |
| `thehive-c4.png` | 9:00 addımından sonra kampaniya case-i |
| `slack-p1.png` | Slack-dəki P1 mesajı. Webhook URL-i və ya token görünməməlidir |
| `chaos.txt` | 7:00 addımının terminal çıxışı (`script` və ya kopyala-yapışdır) |
| `n8n-execution.png` | n8n Executions → HASH-02 |
| video (6.8b) | 2:00–5:00 hissəsinin 2–3 dəqiqəlik ekran yazısı |

Ekran görüntüsündən əvvəl ekranda `.env`, token, API açarı və ya webhook URL-i olmadığını yoxlayın.

---

## 5. Gözlənilən suallar

| Sual | Qısa cavab | Sübut |
|---|---|---|
| Niyə auto-close açılmayıb? | Qoruyucu FN-i gördükdən sonra eyni 36 alert-də yoxlandı, ümumiləşdiyini sübut etmir; intel dəyişkəndir; fayda kiçik, FN-in qiyməti böyükdür. Açılma şərtləri yazılıb. | ADR-0003 |
| Sistem səhv edərsə? | Səhvlər təhlükəsiz tərəfədir: təmiz alert insana gedir (FP), zərərli heç vaxt bağlanmır. Kill switch 6.4 s. | `accuracy.md`, `killswitch.md` |
| VirusTotal çöksə? | Retry, breaker, cache; natamam enrichment heç vaxt bağlanmır; 15 dəqiqədən bir yenidən. Chaos testində alert itmədi. | `resilience.md` |
| Niyə SOAR platforması yox? | 3 PoC: Shuffle 2.80, n8n 3.35, Python 3.80. Qərar məntiqi test olunmalıdır; Shuffle export-unda API açarı çıxırdı. Hibrid: məntiq Python-da, axın n8n-də. | ADR-0001 |
| Analitikdən daha dəqiqdirsə, niyə insan lazımdır? | 36 alert kiçikdir; analitik konteksti (işçinin səfərdə olması və s.) bilir; sistemin işi hazırlamaqdır, son söz analitikindir. | `final-report.md`, bölmə 9 |
| Sirlər necə qorunur? | Yalnız `.env`; gitleaks bütün tarixçədə 0; loglarda 0; container root deyil; rotasiya məşq olunub. | `security-review.md` |
| Real SOC-da necə işləyər? | Wazuh/EDR/proxy webhook-u `/ingest`-ə; TheHive case backend-i; ilk ay shadow mode, rəy toplanır, sonra auto-close şərtləri yoxlanılır. | `operations.md` |
