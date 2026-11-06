# 6.2 · Avtomatik ölçmə: xülasə

Yeniləndi: 2026-11-06 23:19

| Ssenari | Alert | Çatmayan | Median (s) | P90 (s) | Manual median (s) | Eyni 20 alert median (s) | Azalma |
|---|---:|---:|---:|---:|---:|---:|---:|
| cold | 36 | 0 | 46.65 | 64.91 | — | — | — |
| warm | 36 | 0 | 0.69 | 40.40 | — | — | — |
| burst | 36 | 0 | 149.71 | 259.81 | — | — | — |
| chaos | 36 | 0 | 121.04 | 234.92 | — | — | — |

- **cold:** boş cache, 10 saniyədə bir alert (real SOC tempi).
- **warm:** eyni alert-lər, intel cache dolu.
- **burst:** 36 alert bir anda; vaxtın çoxu VirusTotal limitinin (dəqiqədə 4) növbəsindədir.
- **chaos:** intel mənbələri test stekində 3 s (±1 s) gecikmə ilə.

Avtomatik vaxt "case hazırdır" anına qədərdir. Dürüst müqayisə: analitikin triaja sərf etdiyi vaxt manual median-dan avtomatik median-a düşdü; analitik P1/P2 case-i yenə araşdırır.
