# Dəqiqlik · cold

Tarix: 2026-11-07 00:04 · Müqayisə olunan alert: 36

## Verdict (sətir: expected.csv, sütun: sistem; suspicious və unknown = uncertain)

|  | sistem: malicious | sistem: uncertain | sistem: clean |
|---|---:|---:|---:|
| həqiqət: malicious | 9 | 2 | 0 |
| həqiqət: uncertain | 0 | 13 | 1 |
| həqiqət: clean | 0 | 7 | 4 |

Sistemin xam cavabları: clean 5, malicious 9, suspicious 10, unknown 12

- Verdict dəqiqliyi: 72.2%
- Cohen's kappa (sistem vs həqiqət): 0.57

## Auto-close təhlükəsizliyi (shadow qərarları daxil)

- TP 25 · **FN 0** · FP 8 · TN 3
- Recall (insana çatmalı olanlardan çatanlar): 100.0%
- Auto-close payı (sistemin bağlayacağı alert-lər): 8.3%

## Uyğun gəlməyən alert-lər

| Alert | Həqiqət | Sistem | Qayda | Bağlayardı |
|---|---:|---:|---:|---:|
| HASH-05 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-06 | clean | unknown | R99-DEFAULT | xeyr |
| HASH-08 | clean | unknown | R99-DEFAULT | xeyr |
| LOGIN-06 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| LOGIN-08 | clean | unknown | R99-DEFAULT | xeyr |
| URL-02 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| URL-04 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| URL-06 | clean | unknown | R99-DEFAULT | xeyr |
| URL-07 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| URL-12 | uncertain | clean | R07-CLEAN | xeyr |
