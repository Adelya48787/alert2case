# PoC: n8n

Tarix: 28–29.10.2026 (Bakı vaxtı). Time-box: 2 saat, istifadə olunan təxminən 23 dəqiqə (axın + sınaqlar).

## Ssenari
Webhook (`POST /webhook-test/poc-hash`) ilə SHA256 hash qəbul et → HTTP Request node ilə VirusTotal v3-də yoxla → IF `malicious ≥ 5` → Send Email.

Bildiriş Slack əvəzinə **Mailpit (SMTP, host `mailpit:1025`)** ilə sınandı. Slack/Telegram Phase 4-də (4.5a) qurulacaq.

## Nəticələr
| Göstərici | Dəyər |
|---|---|
| Versiya | n8n 2.20.0 (layihənin compose stekindən) |
| Quraşdırma vaxtı | 0 dəq (`make up` ilə artıq işləyir, owner hesabı Phase 1-də yaradılıb) |
| Axını qurmaq vaxtı | ≈ 21 dəq (dünən ≈ 3 dəq + bu gün ≈ 18 dəq) |
| Node sayı | 4 (Webhook, HTTP Request, If, Send Email) + 2 credential (VirusTotal Header Auth, Mailpit SMTP) |
| Ssenari tam işlədi? | Bəli: webhook → VT → IF → e-mail |

## Sınaq
| Giriş | Nəticə |
|---|---|
| EICAR (`275a021b…fd0f`) | VT 200, malicious 66 → True Branch → e-mail `accepted` |
| Mövcud olmayan hash (`000…0`) | HTTP Request 404-də xəta verdi, workflow dayandı: e-mail yoxdur, "təmiz" qərarı da yoxdur |

## Təhlükəsizlik və versiya nəzarəti
- VT açarı **Credentials**-də (şifrələnmiş) saxlanılır, node-un içində yox.
- Credential **yalnız `www.virustotal.com` domeninə** bağlandı (Allowed HTTP Request Domains), açar başqa ünvana göndərilə bilməz.
- Workflow export edildi (Download → JSON) və açar faylda axtarıldı: **tapılmadı (0)**. Export yalnız credential-ın adını və ID-sini saxlayır. Shuffle-da açar export faylına düşürdü.

## Xəta davranışı (ADR-0002 ilə müqayisə)
- n8n defolt olaraq HTTP xətasında **dayanır**, alert-i "təmiz" saymır. Python PoC-un ilkin kodu isə xətanı `malicious = 0` kimi qəbul edirdi (fail-open).
- Amma alert **səssizcə ilişib qalır**: yalnız Executions siyahısında qırmızı sətir görünür, heç kimə bildiriş getmir. "Alert heç vaxt itmir" prinsipi üçün ayrıca **Error Workflow** lazımdır (runbook 4.6b).
- Node Settings-də **Retry On Fail** (cəhd sayı, gözləmə) və **On Error** (dayan / davam et) seçimləri var. 429 üçün xüsusi məntiq və backoff isə yoxdur.

## Nə işlədi
- Bütün ssenari vizual olaraq quruldu, kod yazılmadı.
- Hər node-un giriş və çıxışı ekranda görünür, debug rahatdır.
- Pin data ilə eyni nümunə ilə dəfələrlə sınamaq mümkündür.

## Nə çətin oldu
- HTTP Request node kətana əlavə olunsa da Webhook-a bağlanmamışdı ("No input connected").
- URL-də yapışdırma zamanı baş boşluq qaldı, "URL must start with http" xətası verdi.
- Webhook test məlumatı icra xətasından sonra itdi, mock data ilə pin etmək lazım oldu.
- E-mailin Text sahəsi Expression rejiminə keçirilməmişdi, ifadə mətn kimi qaldı.

Bu problemlərin hamısı UI-dakı kiçik detallardır, amma birlikdə vaxtın yarıdan çoxunu apardı.

## Nə çatışmır
- Workflow-a **avtomatik test** (pytest kimi) yazmaq mümkün deyil, sınaq yalnız əl ilə "Execute" ilə aparılır.
- Export JSON böyük və oxunması çətindir, PR-da review etmək çətindir.

## Meyarlar üzrə bal (1–5)
| Meyar | Çəki | Bal | Qısa səbəb |
|---|---:|---:|---|
| Test edilə bilmə | 20 | 2 | Avtomatik test yoxdur, yalnız əl ilə Execute və pin data |
| Hazır inteqrasiyalar | 15 | 4 | Webhook, HTTP, IF, Email, Slack, Telegram, TheHive node-ları hazırdır; VT HTTP Request ilə rahat qoşuldu |
| Rate limit / retry | 15 | 3 | Retry On Fail və On Error var, amma 429 və backoff məntiqi yoxdur |
| Versiya nəzarəti | 15 | 3 | Açar export-a düşmür (yaxşı), amma JSON diff-i review üçün əlverişsizdir |
| Öyrənmə əyrisi | 10 | 4 | İntuitivdir, amma bir neçə UI detalı vaxt apardı |
| Resurs tələbi | 10 | 4 | Stekdə artıq işləyən bir container, əlavə resurs lazım olmadı |
| Vizuallıq / demo | 10 | 5 | Axın və hər node-un məlumatı ekranda aydın görünür |
| Lisenziya / lock-in | 5 | 3 | Sustainable Use License: daxili istifadə pulsuzdur, amma OSI açıq mənbə deyil; workflow formatı n8n-ə bağlıdır |

**Orta (çəkisiz):** 3.5 / 5

**Çəkili nəticə (20/15/15/15/10/10/10/5):** 3.35 / 5

## Qeyd
Workflow JSON-u runbook qaydasına görə repo-ya qoyulmur. Bu fayl yalnız nəticəni sənədləşdirir.

## Əlavə sınaq (2026-10-29, axşam)
- **Never Error riski:** HTTP node-da "Never Error" yandırılanda 404/429/5xx xəta deyil, adi cavab kimi ötürülür; `?? 0` ilə birlikdə `malicious = 0` olur və zərərli hash "log" qoluna düşür (fail-open). Default davranış (dayanmaq) daha təhlükəsizdir; Never Error istifadə olunarsa ayrıca status/error yoxlaması (If) məcburidir.
- **Rate limit / dedup:** 6 sorğu eyni saniyədə göndərildi: 6/6 uğurlu, VT 429 qaytarmadı; n8n özü limit və dedup tətbiq etmir, Mailpit-ə 6 eyni məktub getdi.
- **Credential:** UI-da VT açarını yapışdırmaq "Wrong API key" verdi (açar curl ilə 200 qaytarırdı); `n8n import:credentials` ilə həll olundu (~25 dəq itki). Credential testi ("Couldn't connect") etibarlı deyil.
- **Resurs:** n8n container ~539 MiB RAM (boş halda).
- **Test URL:** hər "Execute workflow" yalnız 1 çağırış qəbul edir; ardıcıl test üçün publish lazımdır.
