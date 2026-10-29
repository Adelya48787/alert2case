# PoC: Python (FastAPI + httpx)

Tarix: 28.10.2026, 22:43–22:50 (Bakı vaxtı). Time-box: 2 saat, istifadə olunan təxminən 7 dəqiqə.

## Ssenari
Webhook (`POST /hook`) ilə SHA256 hash qəbul et → VirusTotal v3-də yoxla → `malicious ≥ 5` olarsa bildiriş göndər, yoxsa yalnız cavab qaytar.

Bildiriş Slack əvəzinə **Mailpit (SMTP, localhost:1025)** ilə sınandı. Slack/Telegram Phase 4-də (4.5a) qurulacaq. Göndərmə hissəsi 6 sətirdir, Slack-ə keçid bir HTTP sorğusudur.

## Nəticələr
| Göstərici | Dəyər |
|---|---|
| Alətlər | Python 3.12, FastAPI, httpx, uvicorn (layihənin mövcud venv-i) |
| Quraşdırma vaxtı | ≈ 1 dəq (`make up` artıq işləyirdi, 17 paket ≈ 3 saniyədə) |
| Axını qurmaq vaxtı | ≈ 2.5 dəq |
| Kod həcmi | ≈ 36 sətir (ruff-format-dan sonra) |
| Ssenari tam işlədi? | Bəli: webhook → VT → bildiriş |

**Vacib qeyd:** kod runbook-dan hazır götürüldü (yalnız bildiriş Mailpit-ə dəyişdirildi). Ona görə vaxtlar "sıfırdan yazmaq" vaxtı deyil. Kodu sıfırdan yazmaq Python və async bilən biri üçün təxminən 20–30 dəqiqə olardı.

## Sınaq
| Giriş | VT status | malicious | Bildiriş |
|---|---|---|---|
| EICAR (`275a021b…fd0f`) | 200 | 66 | ✅ Mailpit-də 1 e-mail |
| Mövcud olmayan hash (`000…0`) | 404 | 0 | yoxdur |

## Ən vacib tapıntı: fail-open
Runbook-dakı ilkin kod VirusTotal xəta verəndə (404, 429, 5xx) `malicious = 0` götürürdü, yəni **xətanı "təmiz" sayırdı**. Bu, ADR-0002-nin qadağan etdiyi fail-open davranışıdır.

1. Saxta VT cavabı (429) ilə `pytest` testi yazıldı. Real API-yə sorğu getmədi, açar və limit xərclənmədi.
2. Test **qırmızı** oldu: səhv tutuldu.
3. Kodda 2 sətir dəyişdi: xəta zamanı `None` ("bilinmir"), bildiriş yoxlaması `mal is not None and mal >= 5`.
4. Test **yaşıl** oldu.

Bütün dövr təxminən 3.5 dəqiqə çəkdi. Vizual alətlərdə (Shuffle, n8n) bu davranışı avtomatik testlə tutmaq mümkün olmadı və ya çətindir.

## Nə işlədi
- Bütün ssenari ilk cəhddə işlədi.
- API açarı yalnız `.env`-dən mühit dəyişəni kimi oxunur, kodda və fayllarda yoxdur. Kod Git-ə olduğu kimi qoyula bilər.
- Ayrıca konteyner və ya servis lazım olmadı: mövcud venv-də bir proses.

## Nə işləmədi və ya çatışmır
- UI yoxdur: axını göstərmək üçün diaqram və ya n8n kimi vizual qat lazımdır.
- Hazır inteqrasiya yoxdur: hər API (VT, AbuseIPDB, OTX, TheHive, Slack) əl ilə yazılmalıdır.
- Retry/backoff və rate limit hazır deyil, özümüz yazmalıyıq (runbook Phase 3-də planlaşdırılıb).

## Meyarlar üzrə bal (1–5)
| Meyar | Çəki | Bal | Qısa səbəb |
|---|---:|---:|---|
| Test edilə bilmə | 20 | 5 | pytest + saxta cavab ilə fail-open səhvi dəqiqələr içində tutuldu və düzəldildi |
| Hazır inteqrasiyalar | 15 | 2 | Hazır connector yoxdur, hər API əl ilə yazılır |
| Rate limit / retry | 15 | 4 | Tam nəzarət var, amma mexanizmi özümüz yazmalıyıq |
| Versiya nəzarəti | 15 | 5 | Adi `.py` faylı, açar kodda deyil, diff və review normaldır |
| Öyrənmə əyrisi | 10 | 3 | Python və async bilgisi tələb edir, komandada səviyyə fərqlidir |
| Resurs tələbi | 10 | 5 | Əlavə konteyner yoxdur, bir Python prosesi |
| Vizuallıq / demo | 10 | 1 | UI yoxdur |
| Lisenziya / lock-in | 5 | 5 | Açıq mənbəli kitabxanalar (MIT/BSD), heç bir platformaya bağlılıq yoxdur |

**Orta (çəkisiz):** 3.75 / 5

**Çəkili nəticə (20/15/15/15/10/10/10/5):** 3.8 / 5

## Qeyd
PoC kodu (`python_poc.py`, `test_poc.py`) runbook qaydasına görə repo-ya qoyulmur. Bu fayl yalnız nəticəni sənədləşdirir.
