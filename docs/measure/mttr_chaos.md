# Avtomatik MTTR · chaos

Tarix: 2026-11-07 00:22 · Alert: 36, hərəkətə çatan: 36, çatmayan: 0

## Qəbul → hərəkət (saniyə)

| Tip | n | Median | P90 | Orta | Max |
|---|---:|---:|---:|---:|---:|
| HASH | 12 | 56.09 | 95.63 | 57.51 | 111.37 |
| LOGIN | 12 | 123.04 | 155.11 | 121.16 | 160.92 |
| URL | 12 | 215.93 | 250.78 | 214.10 | 267.13 |
| **Hamısı** | 36 | 123.04 | 234.92 | 130.92 | 267.13 |

Qəbul → bildiriş (bütün prioritetlər): median 123.08 s, P90 234.95 s

## Manual ilə müqayisə (eyni alert-lər, median)

Manual: 40 ölçmə, 20 alert. Avtomatik: həmin alert-lərdən 20.

| Tip | Manual median (s) | Avtomatik median (s) | Azalma |
|---|---:|---:|---:|
| HASH | 206 | 58.75 | 71.5% |
| LOGIN | 276 | 118.98 | 56.9% |
| URL | 412 | 235.93 | 42.7% |
| **Hamısı** | 249 | 118.98 | 52.3% |

Qeyd: avtomatik vaxt "case hazırdır" anına qədərdir. Analitik P1/P2 case-i yenə oxuyur və araşdırır.
