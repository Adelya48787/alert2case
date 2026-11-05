
## TheHive 5.8 inteqrasiyası (5.1 webhook, 2026-11-05)

| Simptom | Səbəb | Həll |
|---|---|---|
| Worker/api: `CaseError: TheHive əlçatmazdır: ConnectError ... No address associated with hostname`; container-dən `socket.gethostbyname('thehive')` xəta verir, `postgres`/`redis` isə tapılır | Günlərlə işləyən TheHive steki (thehive, cassandra, elasticsearch) Docker-in daxili DNS-indən düşüb (alias yerindədir, ad həll olunmur) | `docker compose --profile thehive restart cassandra elasticsearch`, healthy olanda `... restart thehive`. Yalnız thehive-ı restart etsəniz o da `cassandra`-nı tapmayacaq |
| TheHive-da webhook/notification API ilə yazılır (200), amma heç vaxt işə düşmür | TheHive 5.8 köhnə `PUT /api/config/organisation/notification` açarını qəbul edir, amma istifadə etmir | Endpoint: `PUT /api/v1/admin/config/organisation/endpoint` (`type: webhook`, `auth: {type: bearer, key}`). Notification: `PUT /api/v1/notification/organisation` (obyekt, `trigger: {name: CaseClosed}`, `notifiers: [{name: "Webhook", endpoint, enabled: true}]`). Notifier adı böyük hərflə: `Webhook` |
| `/feedback/thehive` 200 qaytarır, amma `feedback` cədvəlinə heç nə yazılmır | TheHive 5.8 webhook v0 nəticəni `resolutionStatus`-da yox, `object.extendedStatus`-da (`status: Resolved`) və `details.status`-da göndərir | `app/feedback/collector.py` artıq bütün sahələri yoxlayır. Yeni format çıxsa: `docker compose logs api` və payload sahə adlarını müqayisə edin |
| Notifications menyusu görünmür | Platforma admini (`admin@thehive.local`) ilə daxil olmusunuz | SOC-Lab təşkilatının `org-admin` profilli istifadəçisi ilə daxil olun |
| Korrelyasiya olunan alert emal olunmur, `CaseError` şərh yazarkən | Köhnə case başqa backend-dədir (məs. `file`), şərh cari backend-ə (`thehive`) gedirdi | Düzəldilib: şərh case-in öz backend-i ilə yazılır, alınmasa `act/comment_failed` audit olunur, alert davam edir |
