# Kill switch testi

Tarix: 2026-11-07 01:05 · Skript: `tools/killswitch_test.sh` · Nəticə: **OK**

| Addım | Nəticə |
|---|---|
| ON (AUTO_CLOSE_ENABLED=true, SHADOW_MODE=false), 36 alert | closed_auto: 1 (HASH-05) |
| Kill switch: AUTO_CLOSE_ENABLED=false, worker yeni dəyərlə işləyir | 6.4 s (hədd 60 s) |
| OFF, eyni 36 alert (intel cache dolu) | closed_auto: 0; 'kill switch bağlıdır' səbəbli case: 4 |

ON-da bağlanan alert-lər OFF-da:

| Alert | Status | Qayda | Səbəb |
|---|---|---|---|
| HASH-05 | case_created | R07-CLEAN | kill switch |

Kill switch worker-in mühit dəyişənidir: dəyişiklik worker yenidən yaradılanda qüvvəyə minir.
Növbədə gözləyən alert-lər yeni worker tərəfindən emal olunur və artıq bağlanmır.
