# ADR-0003: Auto-close qərarı və dynamic DNS qoruyucusu

* **Status:** Proposed (komanda səsverməsi gözlənilir: bu qərarın təsdiqi)
* **Tarix:** 2026-11-06
* **Müəllif:** Komanda
* **Task:** Phase 6 · Task 6.3 (Dəqiqlik)
* **Əlaqəli:** ADR-0002 (FN riski və fallback), `docs/measure/accuracy.md`, `docs/measure/summary.md`

---

## 1. Kontekst

ADR-0002 auto-close-u yalnız ölçmə ilə sübut olunandan sonra açmağa icazə verir: bütün ssenarilərdə FN 0, QA nümunəsində səhv bağlama 0, kill switch test olunub. 6.2 və 6.3-də sistem 36 alert-lik dataset-də dörd ssenaridə (cold, warm, burst, chaos) ölçüldü və iki analitikin 40 manual ölçməsi ilə müqayisə olundu.

### Ölçmə nəticələri (dynamic DNS qoruyucusundan əvvəl)

| Ssenari | FN | Dəqiqlik | Kappa | Median (s) |
|---|---|---|---|---|
| cold | 1 | 75.0% | 0.61 | 46.7 |
| warm | 2 | 83.3% | 0.75 | 0.07 |
| burst | 1 | 72.2% | 0.57 | 149.7 |
| chaos | 0 | (WireMock) | — | 121.0 |

Eyni 20 alert-də (6.1 nümunəsi):

| | Dəqiqlik | Kappa | Təhlükəlini "clean" sayan |
|---|---|---|---|
| Analitik 1 | 65% | 0.46 | 3 |
| Analitik 2 | 65% | 0.46 | 3 |
| Sistem (cold) | 85% | 0.77 | 1 |

Analitiklər arası razılaşma: 80%, kappa 0.69. Manual median triaj vaxtı 249 s, sistem (cold) eyni alert-lərdə 45.7 s.

Sistem analitikdən həm tez, həm də dəqiqdir. Amma auto-close şərti "FN 0" ödənmir.

### Ölçmə nəticələri (dynamic DNS qoruyucusu ilə, 2026-11-07)

| Ssenari | FN | FP | Dəqiqlik | Kappa | Auto-close payı | Median (s) | Manual ilə azalma |
|---|---|---|---|---|---|---|---|
| cold | **0** | 8 | 72.2% | 0.57 | 8.3% | 50.0 | 79.8% |
| warm | **0** | 5 | 72.2% | 0.57 | 16.7% | 0.09 | ~100% |
| burst | **0** | 9 | 69.4% | 0.52 | 5.6% | 141.6 | 49.0% |
| chaos | **0** | 11 | (WireMock) | — | 0.0% | 123.0 | 52.3% |

Bütün ssenarilərdə hərəkətə çatmayan alert 0. Sistem (cold) eyni 20 alert-də: dəqiqlik 80%, kappa 0.69, FN 0. Verdict dəqiqliyi qaçışlar arasında intel cavablarının dəyişməsi ilə 69–83% arasında tərpənir; qoruyucu heç bir verdict-i dəyişmir, yalnız hərəkəti.

warm-da URL-09, URL-11 və URL-12-nin üçü də intel-də "clean" (R07-CLEAN) çıxdı və üçünü də qoruyucu blokladı: qoruyucusuz warm-da FN 3 olardı. burst-da VT limiti səbəbindən bu URL-lər onsuz da "unknown" oldu (fail-safe).

## 2. Problem: dynamic DNS URL-ləri "təmiz" görünür

Bütün FN-lər eyni sinifdəndir:

| Alert | Domen | Etiket | Sistem | Qayda |
|---|---|---|---|---|
| URL-11 | `backup-storage[.]duckdns[.]org` | uncertain | clean | R07-CLEAN |
| URL-12 | `home-iot[.]ddns[.]net` | uncertain | clean | R07-CLEAN |

Etiketlənəndə VirusTotal hər iki URL-i tanımırdı (NotFound), OTX-də 0 pulse var idi: heç kimin tanımadığı IOC, yəni "uncertain". Ölçmə zamanı VT hər ikisini **tanıyır**: URL 93 mühərrikdə, domen 92 mühərrikdə 0 zərərli. `aggregate.py`-nin "clean" şərti (hər IOC güclü mənbədə tapılıb, skor aşağıdır) ödəndiyi üçün R07-CLEAN auto-close verir.

Nəticə VT limitindən asılı idi. cold-un bir qaçışında URL-11-in VT URL sorğusu rate limit-ə düşdü, verdict "unknown" oldu və case açıldı. warm-da hər iki sorğu cavab aldı və hər ikisi bağlanardı. Bu, etibarlı qoruma deyil.

**Ehtimal olunan səbəb (sübut olunmayıb):** 6.1 manual ölçməsində analitiklər bu URL-ləri VT-də axtarıb. Nümunədəki üç dynamic DNS URL-inin (URL-09, URL-11, URL-12) üçü də sonradan VT-də "0 zərərli" vəziyyətinə keçdi. VT tanımadığı URL-i axtaranda onu skan edir və yeni qeyd yaradır. Yeni domeni o anda heç bir mühərrik tanımır, nəticə "0 zərərli" olur. Sistem VT-nin ilk görülmə tarixini saxlamadığı üçün bunu bazadan təsdiqləmək mümkün olmadı.

Səbəbdən asılı olmayaraq risk realdır. Dynamic DNS alt domenini hər kəs pulsuz və dəqiqələr içində yaradır. Hücumçu yeni alt domeni VT-yə skan etdirsə, "0/93" alır və sistem alert-i bağlayardı. Dynamic DNS hücumçu infrastrukturunda (C2, phishing) geniş istifadə olunur.

## 3. Nəzərdən keçirilən variantlar

| Variant | Təsvir | Niyə seçilmədi / seçildi |
|---|---|---|
| **A. Dynamic DNS qoruyucusu** | `guards.py`-də blocker: dynamic DNS provayderinin domeni olan alert auto-close olmur | **Seçildi.** Kiçik, test olunan dəyişiklik. Riskin sinfini bağlayır, VT-nin vəziyyətindən asılı deyil |
| B. VT ilk görülmə tarixi | Yeni (< 30 gün) VT qeydi "təmiz" sayılmır | Daha geniş, amma provider-in, cache-in və aggregate-in dəyişməsini tələb edir. Gələcək iş kimi qalır |
| C. Etiketi "clean" etmək | `expected.csv`-də URL-11/12 dəyişir | FN rəqəmdən yox olur, risk qalır. Rədd edildi |
| D. URL tipi üçün auto-close bağlı | Bütün URL alert-ləri insana gedir | Ən təhlükəsiz, amma lazımsız yerə auto-close payını azaldır |

## 4. Qərar

**Auto-close hələ açılmır. Sistem shadow mode-da işləməyə davam edir.**

1. `app/rules/guards.py`-yə **dynamic DNS blocker** əlavə olunur. Alert-in URL və ya domain observable-ının host-u `DYNAMIC_DNS` siyahısındakı provayderin özü və ya alt domenidirsə, auto-close bloklanır və case açılır (`reasons`: "dynamic DNS domeni: …"). Siyahı kodda saxlanılır (31 provayder: duckdns.org, ddns.net, hopto.org, no-ip.* və s.), dəyişiklik PR və review tələb edir. İnsanın təsdiqlədiyi allowlist digər qoruyucularda olduğu kimi bu blokeri də keçə bilər.
2. `SHADOW_MODE=true` qalır. Sistem "bağlayardı" qərarlarını qeyd edir, amma alert insana gedir.

### Niyə indi açılmır

* **Düzəliş eyni məlumatda yoxlanılıb.** Qoruyucu URL-11/12 FN-i görüldükdən sonra yazıldı. Eyni 36 alert-də "FN 0" onun işlədiyini göstərir, amma ümumiləşdiyini sübut etmir. Bunu yalnız görülməmiş alert-lər sübut edər.
* **Nəticə qaçışdan qaçışa dəyişir.** Eyni alert VT limiti və intel dəyişkənliyi səbəbindən bir qaçışda bağlanır, digərində yox. Dynamic DNS sinfi bağlandı, amma yeni qeydiyyatdan keçmiş adi domenlər üçün eyni mexanizm qalır.
* **Fayda kiçik, risk asimmetrikdir (ADR-0002).** Auto-close payı 36 alert-də 8–28% təşkil edir. Bir FN real hücumun gözdən qaçması deməkdir.
* **ADR-0002 şərtlərinin bir hissəsi hələ yoxlanmayıb:** kill switch testi, QA nümunəsi və rəy dövrəsi.

Sürət qazancı auto-close olmadan da qalır. Sistem hər alert-i zənginləşdirib qərar təklifi ilə ~50 s-də hazırlayır (manual median 249 s). Analitik təmiz alert-i yalnız təsdiqləyir.

## 5. Auto-close-u açmaq üçün şərtlər

Auto-close yalnız aşağıdakıların **hamısı** ödənəndə və komanda yenidən səs verəndə açılır. O zaman bu ADR yeni ADR ilə əvəz olunur.

| Şərt | Hədd | Vəziyyət |
|---|---|---|
| FN (shadow daxil), 4 ssenaridə, qoruyucu ilə | 0 | ✓ Ödənib (2026-11-07: cold, warm, burst, chaos hamısında 0) |
| Kill switch: `AUTO_CLOSE_ENABLED=false` 1 dəqiqədə dayandırır | test olunub | Gözlənilir |
| Görülməmiş alert-lərdə (ən azı 30, dataset-dən kənar) FN | 0 | Gözlənilir |
| Shadow mode dövründə "sistem bağlayardı, analitik malicious/suspicious dedi" | 0 | Gözlənilir |
| QA nümunəsində (bağlananların 10%-i) səhv bağlama | 0 | Gözlənilir |
| Komanda səsverməsi | 4/4 | Gözlənilir |

Mərhələli açılma mümkündür: ilk mərhələdə yalnız `malicious_hash` tipi. Fayl hash-ı domen kimi dəqiqələr içində yaradılıb "təmiz" görünə bilmir və ölçmələrdə HASH-da FN olmayıb. Bu da eyni şərtlərə tabedir.

## 6. Nəticələr

* **Müsbət:** riskli sinif (yeni dynamic DNS URL-ləri) VT-nin vəziyyətindən asılı olmadan insana gedir. Dataset-də URL-09, URL-11 və URL-12 bu qoruyucuya düşür.
* **Mənfi:** dynamic DNS üzərində işləyən legitim xidmətlər (ev kameraları, IoT) da insana gedir və analitikə kiçik əlavə yük düşür. Bu, ADR-0002-nin FP/FN asimmetriyası ilə qəbul olunandır.
* **Qalıq risk:** siyahıda olmayan provayderlər və yeni qeydiyyatdan keçmiş adi domenlər. Bunu B variantı (VT ilk görülmə tarixi) bağlayar. 36 alert-lik testdə "FN 0" FN-in heç vaxt olmayacağı demək deyil, QA nümunəsi və shadow mode qalıq riski azaldır.
* **Proses:** ölçmə bələdçisinə qeyd: VT-də tanınmayan URL-i axtarmaq onu skan edir və intel-i dəyişir. Ölçmələrdə yalnız mövcud qeydlərə baxılır.
