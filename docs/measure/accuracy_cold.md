# Dəqiqlik · cold

Tarix: 2026-11-06 21:55 · Müqayisə olunan alert: 36

## Verdict (sətir: expected.csv, sütun: sistem; suspicious və unknown = uncertain)

|  | sistem: malicious | sistem: uncertain | sistem: clean |
|---|---:|---:|---:|
| həqiqət: malicious | 8 | 3 | 0 |
| həqiqət: uncertain | 0 | 13 | 1 |
| həqiqət: clean | 0 | 4 | 7 |

Sistemin xam cavabları: clean 8, malicious 8, suspicious 8, unknown 12

- Verdict dəqiqliyi: 77.8%
- Cohen's kappa (sistem vs həqiqət): 0.66

## Auto-close təhlükəsizliyi (shadow qərarları daxil)

- TP 24 · **FN 1** · FP 6 · TN 5
- Recall (insana çatmalı olanlardan çatanlar): 96.0%
- Auto-close payı (sistemin bağlayacağı alert-lər): 16.7%

**DİQQƏT: FN var. Auto-close açılmamalıdır.**

| Alert | Həqiqət | Sistem | Qayda |
|---|---:|---:|---:|
| URL-11 | uncertain | clean | R07-CLEAN |

## Uyğun gəlməyən alert-lər

| Alert | Həqiqət | Sistem | Qayda | Bağlayardı |
|---|---:|---:|---:|---:|
| HASH-03 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-07 | clean | unknown | R99-DEFAULT | xeyr |
| LOGIN-08 | clean | unknown | R99-DEFAULT | xeyr |
| URL-02 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| URL-04 | malicious | unknown | R99-DEFAULT | xeyr |
| URL-06 | clean | unknown | R99-DEFAULT | xeyr |
| URL-08 | clean | unknown | R99-DEFAULT | xeyr |
| URL-11 | uncertain | clean | R07-CLEAN | bəli |
