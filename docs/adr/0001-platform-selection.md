# ADR-0001: Orkestrasiya platformasının seçimi

- **Status:** Accepted
- **Tarix:** 2026-10-29
- **Qərarı verən:** Team Lead (komandanın PoC nəticələri əsasında)
- **İlkin şablon:** Elvin (`feature/t1-4a-soar-evaluation`)

## Kontekst

alert2case alert-i qəbul edir, IOC-ları çıxarır, intel mənbələrində yoxlayır, qərar verir və case/bildiriş yaradır. Məhdudiyyətlər: 4 nəfərlik komanda, laptoplar (8–16 GB RAM), təxminən 6 həftə, yalnız pulsuz alətlər.

Platforma seçimi bütün sonrakı fazaları müəyyən edir. Ona görə seçim fikirlə yox, eyni ssenari üzrə sınaqla verildi.

## Variantlar

| Variant | Nədir | Sınandı? |
|---|---|---|
| Shuffle | Açıq mənbəli SOAR | ✅ Bəli |
| n8n | Ümumi təyinatlı vizual workflow aləti | ✅ Bəli |
| Tam Python | FastAPI + httpx (+ Redis, öz qayda mühərriki) | ✅ Bəli |
| TheHive + Cortex | Case idarəsi + analyzer mühərriki | ❌ Xeyr: resurs və vaxt. Cortex tam orkestrasiya mühərriki deyil, TheHive isə artıq case sistemi kimi stekdədir |
| Kommersiya (Cortex XSOAR, Splunk SOAR, Tines) | — | Lisenziyaya görə sınanmır, sənaye konteksti kimi qeyd olunur |

## PoC ssenarisi

Hər platformada eyni mini-axın: webhook ilə SHA256 qəbul et → VirusTotal-da yoxla → `malicious ≥ 5` isə bildiriş göndər. Time-box: hər platforma üçün 2 saat. Meyarlar və çəkilər PoC-dan **əvvəl** razılaşdırıldı.

## PoC nəticələri

| Variant | Quraşdırma | Axın | Node / sətir | Ssenari | Qeyd |
|---|---|---|---|---|---|
| Shuffle | ≈ 34 dəq (30 dəq Docker Swarm problemi) | ≈ 45 dəq (cəmi ≈ 80 dəq) | — | Qismən: yalnız VT sorğusu | 6.9 GB RAM; **API açarı export JSON-una düşür** |
| n8n | 0 dəq (stekdə artıq var) | ≈ 21 dəq | 4 node | Tam | Açar Credentials-də, export-a düşmür; xətada workflow dayanır |
| Python | ≈ 1 dəq | ≈ 2.5 dəq (kod runbook-dan hazır) | ≈ 36 sətir | Tam | Fail-open səhvi pytest ilə tutuldu və düzəldildi |

Ətraflı qeydlər: [`docs/poc/shuffle.md`](../poc/shuffle.md), [`docs/poc/n8n.md`](../poc/n8n.md), [`docs/poc/python.md`](../poc/python.md).

## Ağırlıqlı matris

Ballar 1-dən (zəif) 5-ə (əla) qədərdir. Hər sütun həmin PoC-u aparan üzvün qiymətləndirməsidir. Yekun bal = Σ (bal × çəki) / 100.

| Meyar | Çəki | Shuffle | n8n | Python |
|---|---:|---:|---:|---:|
| Test edilə bilmə | 20 | 2 | 2 | 5 |
| Hazır inteqrasiyalar | 15 | 4 | 4 | 2 |
| Rate limit / retry | 15 | 2 | 3 | 4 |
| Versiya nəzarəti | 15 | 2 | 3 | 5 |
| Öyrənmə əyrisi | 10 | 3 | 4 | 3 |
| Resurs tələbi | 10 | 2 | 4 | 5 |
| Vizuallıq / demo | 10 | 5 | 5 | 1 |
| Lisenziya / lock-in | 5 | 4 | 3 | 5 |
| **Yekun** | **100** | **2.80** | **3.35** | **3.80** |

## Qərar

**Hibrid model: qərar məntiqi Python-da, vizual orkestrasiya n8n-də.**

Tək bir platforma bütün meyarları ödəmir. Python ən yüksək çəkili meyarda (test, 20) və versiya nəzarətində qalib gəlir, amma vizual deyil. n8n vizuallıqda və hazır inteqrasiyalarda güclüdür, amma məntiqini avtomatik test etmək mümkün deyil. Bu iki alət bir-birinin zəif tərəfini örtür.

Python PoC-da tapılan fail-open səhvi qərarın əsas səbəbini göstərir. Səhv qərar məntiqi (ADR-0002) testsiz yazılsa, belə səhvlər görünmədən qalır.

## Hansı hissə harada

**Python servisi (FastAPI + Redis + PostgreSQL):**
- alert-in qəbulu (HMAC), növbə və DLQ;
- normalizasiya və IOC çıxarma;
- enrichment: VT, AbuseIPDB, OTX adapterləri, cache, rate limit, retry, circuit breaker;
- qayda mühərriki, auto-close qoruyucuları, shadow mode, kill switch (ADR-0002);
- case yaratma (TheHive / file backend), bildiriş, audit log.

**n8n (vizual qat):**
- alert-in yolunu mərhələlər üzrə göstərən axın, Python servisinin endpoint-lərini çağırır;
- xəta workflow-u: uğursuz icralar haqqında bildiriş;
- demo və analitik üçün görünən panel.

## Nəticələr

**Müsbət:**
- Qərar məntiqi pytest ilə yoxlanılır, CI-da işləyir, PR-da adi kod kimi review olunur.
- API açarları yalnız `.env`-də və n8n Credentials-də saxlanılır, heç biri Git-ə düşmür.
- Əlavə ağır servis yoxdur: n8n artıq stekdədir, Python servisi bir container olacaq.
- Alert-in yolu demoda vizual göstərilir.

**Mənfi:**
- İnteqrasiyaları (VT, AbuseIPDB, OTX, TheHive, Slack) Python-da özümüz yazmalıyıq: daha çox kod.
- İki alətin sərhədini aydın saxlamaq lazımdır: məntiq yalnız Python-da, n8n-də yalnız çağırış və göstərmə.
- n8n workflow JSON-u Git-də saxlanacaq, amma review üçün əlverişsizdir.

## Rədd edilən variantlar

- **Shuffle:** ən aşağı bal (2.80). Ağır resurs tələbi, Docker Swarm asılılığı, retry mexanizminin olmaması və ən əsası API açarının export faylına düşməsi.
- **Tək n8n:** qərar məntiqini avtomatik test etmək mümkün deyil. Auto-close kimi riskli qərar üçün bu qəbuledilməzdir.
- **Tək Python:** UI yoxdur, alert-in yolunu göstərmək üçün ayrıca vizual qat lazımdır.
- **TheHive + Cortex:** sınanmadı. TheHive onsuz da case sistemi kimi istifadə olunur. Cortex isə orkestrasiya yox, analyzer mühərrikidir.

## Məhdudiyyətlər

- Hər platformanı bir üzv sınayıb, ballar həmin üzvün qiymətləndirməsidir.
- Python PoC-un vaxtları kodun runbook-dan hazır götürülməsi səbəbindən azdır.
- Shuffle-da webhook və bildiriş addımları vaxt çatmadığı üçün sınanmadı.
- Bütün PoC-larda bildiriş Slack əvəzinə Mailpit (SMTP) ilə sınandı. Slack Phase 4-də qurulacaq.
