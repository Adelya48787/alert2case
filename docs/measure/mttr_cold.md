# Avtomatik MTTR · cold

Tarix: 2026-11-07 00:04 · Alert: 36, hərəkətə çatan: 36, çatmayan: 0

## Qəbul → hərəkət (saniyə)

| Tip | n | Median | P90 | Orta | Max |
|---|---:|---:|---:|---:|---:|
| HASH | 12 | 13.94 | 49.74 | 23.81 | 57.25 |
| LOGIN | 12 | 35.61 | 56.36 | 34.51 | 57.31 |
| URL | 12 | 66.46 | 79.65 | 66.97 | 83.96 |
| **Hamısı** | 36 | 50.03 | 69.94 | 41.76 | 83.96 |

Qəbul → bildiriş (bütün prioritetlər): median 50.06 s, P90 69.97 s

## Manual ilə müqayisə (eyni alert-lər, median)

Manual: 40 ölçmə, 20 alert. Avtomatik: həmin alert-lərdən 20.

| Tip | Manual median (s) | Avtomatik median (s) | Azalma |
|---|---:|---:|---:|
| HASH | 206 | 9.85 | 95.2% |
| LOGIN | 276 | 42.27 | 84.7% |
| URL | 412 | 66.58 | 83.8% |
| **Hamısı** | 249 | 50.31 | 79.8% |

Qeyd: avtomatik vaxt "case hazırdır" anına qədərdir. Analitik P1/P2 case-i yenə oxuyur və araşdırır.
