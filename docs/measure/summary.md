# 6.2 · Avtomatik ölçmə: xülasə

Yeniləndi: 2026-11-07 00:22

| Ssenari | Alert | Çatmayan | Median (s) | P90 (s) | Manual median (s) | Eyni 20 alert median (s) | Azalma |
|---|---:|---:|---:|---:|---:|---:|---:|
| cold | 36 | 0 | 50.03 | 69.94 | 249 | 50.31 | 79.8% |
| warm | 36 | 0 | 0.09 | 45.31 | 249 | 0.07 | 100.0% |
| burst | 36 | 0 | 141.64 | 267.30 | 249 | 127.14 | 49.0% |
| chaos | 36 | 0 | 123.04 | 234.92 | 249 | 118.98 | 52.3% |

- **cold:** boş cache, 10 saniyədə bir alert (real SOC tempi).
- **warm:** eyni alert-lər, intel cache dolu.
- **burst:** 36 alert bir anda; vaxtın çoxu VirusTotal limitinin (dəqiqədə 4) növbəsindədir.
- **chaos:** intel mənbələri test stekində 3 s (±1 s) gecikmə ilə.

Avtomatik vaxt "case hazırdır" anına qədərdir. Dürüst müqayisə: analitikin triaja sərf etdiyi vaxt manual median-dan avtomatik median-a düşdü; analitik P1/P2 case-i yenə araşdırır.
