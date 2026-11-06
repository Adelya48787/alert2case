# Avtomatik MTTR · warm

Tarix: 2026-11-07 00:10 · Alert: 36, hərəkətə çatan: 36, çatmayan: 0

## Qəbul → hərəkət (saniyə)

| Tip | n | Median | P90 | Orta | Max |
|---|---:|---:|---:|---:|---:|
| HASH | 12 | 0.07 | 4.05 | 1.08 | 7.33 |
| LOGIN | 12 | 0.08 | 0.60 | 2.25 | 25.13 |
| URL | 12 | 28.99 | 55.74 | 28.44 | 56.76 |
| **Hamısı** | 36 | 0.09 | 45.31 | 10.59 | 56.76 |

Qəbul → bildiriş (bütün prioritetlər): median 0.12 s, P90 45.34 s

## Manual ilə müqayisə (eyni alert-lər, median)

Manual: 40 ölçmə, 20 alert. Avtomatik: həmin alert-lərdən 20.

| Tip | Manual median (s) | Avtomatik median (s) | Azalma |
|---|---:|---:|---:|
| HASH | 206 | 0.06 | 100.0% |
| LOGIN | 276 | 0.08 | 100.0% |
| URL | 412 | 43.89 | 89.3% |
| **Hamısı** | 249 | 0.07 | 100.0% |

Qeyd: avtomatik vaxt "case hazırdır" anına qədərdir. Analitik P1/P2 case-i yenə oxuyur və araşdırır.
