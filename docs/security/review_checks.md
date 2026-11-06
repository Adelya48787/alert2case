# Təhlükəsizlik yoxlamaları: avtomatik nəticələr

Tarix: 2026-11-07 01:24 · Skript: `python -m tools.security_review`

| # | Nəticə | Necə yoxlanıldı | Sübut |
|---|---|---|---|
| 1 | OK | token-siz və səhv token ilə 11 sorğu | 11/11 endpoint 401/403 qaytardı |
| 2 | OK | `docker ps` port bağlamaları | 8 port yalnız 127.0.0.1-də |
| 3 | OK | 300 KB payload → /ingest/edr | cavab 413 (gözlənilən 413, limit 256 KB) |
| 4 | OK | `docker compose logs` içində .env-dəki hər secret-in dəyəri axtarılır (dəyər çap olunmur) | 10 secret yoxlandı, 2787 log sətri; tapılan: 0 |
| 5 | OK | `tools.verify_audit` + UPDATE/DELETE cəhdi | zəncir: OK: 274 sətir, zəncir bütövdür; UPDATE/DELETE: trigger rədd etdi |
| 6 | OK | prod image-də `id -u`, prod compose config-də read_only və cap_drop | image alert2case:1.0.0: uid 10001; read_only + cap_drop ALL: api, worker |
| 7 | OK | URL case başlıqları (var/cases) və Mailpit bildirişləri | 12 URL case başlığı, defang olunmamış: 0; 50 bildiriş, defang olunmamış URL: 0 |
| 8 | OK | `context/allowlist.yaml`: owner, reason, expires_at | 2 qeyd, hamısı tam və müddəti keçməyib |
| 9 | OK | unit testlər `-k malicious` (+ E2E `test_malicious_never_closed`, 6.4) | pytest: 265 passed, 402 deselected, 1 warning in 5.88s |
| 10 | ƏL İLƏ | 1.5-dəki qeydiyyat | VirusTotal şərtləri: komanda bir açar və qeyri-kommersiya istifadəni təsdiqləyir |
