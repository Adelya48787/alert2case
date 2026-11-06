# 6.3 · Dəqiqlik: xülasə

Yeniləndi: 2026-11-07 00:22

## Sistem: ssenarilər üzrə

| Ssenari | Alert | FN | FP | Dəqiqlik | Kappa | Auto-close payı |
|---|---:|---:|---:|---:|---:|---:|
| cold | 36 | **0** | 8 | 72.2% | 0.57 | 8.3% |
| warm | 36 | **0** | 5 | 72.2% | 0.57 | 16.7% |
| burst | 36 | **0** | 9 | 69.4% | 0.52 | 5.6% |
| chaos | 36 | **0** | 11 | 36.1% | 0.05 | 0.0% |

Chaos-da intel mənbələri WireMock-dur (hamısına "zərərli" cavab verir): orada verdict dəqiqliyi məna daşımır, yalnız FN (heç nə səhvən bağlanmırmı) vacibdir.

## Manual (6.1): analitiklər həqiqətə qarşı

| Analitik | Alert | Dəqiqlik | Kappa | Zərərli/şübhəli → clean |
|---|---:|---:|---:|---:|
| adile | 20 | 65.0% | 0.46 | 3 |
| teymur | 20 | 65.0% | 0.46 | 3 |

Analitiklər arası razılaşma (20 alert): 80.0%, kappa 0.69

Sistem (cold) eyni 20 alert-də: dəqiqlik 80.0%, kappa 0.69, FN 0

## Auto-close qərarı üçün şərtlər (runbook 6.3)

| Şərt | Hədd |
|---|---|
| FN (shadow daxil), bütün ssenarilərdə | 0 |
| QA nümunəsində səhv bağlama | 0 |
| Rəy dövrəsində "sistem bağlayardı, analitik malicious dedi" | 0 |
| Kill switch: AUTO_CLOSE_ENABLED=false 1 dəqiqədə dayandırır | test olunub |

36 alert-lik testdə "FN 0" FN-in heç vaxt olmayacağı demək deyil: qoruyucular və QA nümunəsi qalıq riski azaldır.
