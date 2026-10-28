# Shuffle PoC qeydləri (27-28.10.2026)

- Başlama: 27.10 23:19. Dayanma: 28.10 00:20 (~60 dəq istifadə olunub, limit 2 saat).
- Qurma: image-lərin yüklənməsi ~4 dəq. Sonra ~30 dəq Docker Swarm problemi
  (docker swarm init, overlay şəbəkəni Orborus özü yaratdı).
- Hazır inteqrasiyalar: VirusTotal, AbuseIPDB, TheHive, Slack tapıldı (Discover Public Apps).
- VT sınağı: get_an_ip_address_report, 8.8.8.8 -> status 200, icra ~5 saniyə.
- Resurs: used 6.9 GiB, available 2.8 GiB (cəmi 9.7 GiB). App xidmətləri 3 replika.
- Retry/timeout: node UI-da yalnız Delay var. Optional Parameters = Headers, Queries, Ssl verify, To file.
- Export JSON (poc-vt-check.json, 49 KB): API açarı İÇİNDƏ idi (yoxlama: ACAR VAR). Fayl silindi.
  Səbəb: açar node parametrinə yazılıb, Add Authentication istifadə edilməyib.
  Git-ə qoymazdan əvvəl açarı təmizləmək lazımdır.
- QALIR: test edilə bilmə, bal matrisi, ADR sətri, təmizləmə.

## 28.10 əlavə
- Lisenziya: AGPL-3.0 (pulsuz, açıq mənbə).
- Authentication bölməsi ilə VT sınağı: status 200.
- Authentication ilə export: ACAR VAR (açar yenə fayla düşdü). Köhnə node parametrinin qalması ehtimalı yoxlanmayıb. Fayl silindi.
- Versiya nəzarəti balı: 2. PoC bitdi, ~80 dəq istifadə olunub.
