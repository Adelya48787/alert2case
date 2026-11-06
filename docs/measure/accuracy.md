# 6.3 · Dəqiqlik: xülasə

Yeniləndi: 2026-11-06 23:19

## Sistem: ssenarilər üzrə

| Ssenari | Alert | FN | FP | Dəqiqlik | Kappa | Auto-close payı |
|---|---:|---:|---:|---:|---:|---:|
| cold | 36 | **1** | 6 | 77.8% | 0.66 | 16.7% |
| warm | — | — | — | — | — | — |
| burst | 36 | **1** | 8 | 72.2% | 0.57 | 11.1% |
| chaos | 36 | **0** | 11 | 36.1% | 0.04 | 0.0% |

Chaos-da intel mənbələri WireMock-dur (hamısına "zərərli" cavab verir): orada verdict dəqiqliyi məna daşımır, yalnız FN (heç nə səhvən bağlanmırmı) vacibdir.

## Auto-close qərarı üçün şərtlər (runbook 6.3)

| Şərt | Hədd |
|---|---|
| FN (shadow daxil), bütün ssenarilərdə | 0 |
| QA nümunəsində səhv bağlama | 0 |
| Rəy dövrəsində "sistem bağlayardı, analitik malicious dedi" | 0 |
| Kill switch: AUTO_CLOSE_ENABLED=false 1 dəqiqədə dayandırır | test olunub |

36 alert-lik testdə "FN 0" FN-in heç vaxt olmayacağı demək deyil: qoruyucular və QA nümunəsi qalıq riski azaldır.
