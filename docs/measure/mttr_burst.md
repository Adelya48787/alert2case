# Avtomatik MTTR · burst

Tarix: 2026-11-07 00:16 · Alert: 36, hərəkətə çatan: 36, çatmayan: 0

## Qəbul → hərəkət (saniyə)

| Tip | n | Median | P90 | Orta | Max |
|---|---:|---:|---:|---:|---:|
| HASH | 12 | 55.99 | 96.03 | 58.91 | 96.57 |
| LOGIN | 12 | 141.64 | 174.26 | 145.66 | 188.99 |
| URL | 12 | 251.87 | 296.41 | 249.18 | 299.60 |
| **Hamısı** | 36 | 141.64 | 267.30 | 151.25 | 299.60 |

Qəbul → bildiriş (bütün prioritetlər): median 141.67 s, P90 267.32 s

## Manual ilə müqayisə (eyni alert-lər, median)

Manual: 40 ölçmə, 20 alert. Avtomatik: həmin alert-lərdən 20.

| Tip | Manual median (s) | Avtomatik median (s) | Azalma |
|---|---:|---:|---:|
| HASH | 206 | 48.82 | 76.4% |
| LOGIN | 276 | 127.14 | 53.9% |
| URL | 412 | 267.26 | 35.1% |
| **Hamısı** | 249 | 127.14 | 49.0% |

Qeyd: avtomatik vaxt "case hazırdır" anına qədərdir. Analitik P1/P2 case-i yenə oxuyur və araşdırır.
