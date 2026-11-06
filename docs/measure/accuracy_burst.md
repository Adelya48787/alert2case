# Dəqiqlik · burst

Tarix: 2026-11-06 23:13 · Müqayisə olunan alert: 36

## Verdict (sətir: expected.csv, sütun: sistem; suspicious və unknown = uncertain)

|  | sistem: malicious | sistem: uncertain | sistem: clean |
|---|---:|---:|---:|
| həqiqət: malicious | 7 | 4 | 0 |
| həqiqət: uncertain | 0 | 13 | 1 |
| həqiqət: clean | 0 | 5 | 6 |

Sistemin xam cavabları: clean 7, malicious 7, suspicious 12, unknown 10

- Verdict dəqiqliyi: 72.2%
- Cohen's kappa (sistem vs həqiqət): 0.57

## Auto-close təhlükəsizliyi (shadow qərarları daxil)

- TP 24 · **FN 1** · FP 8 · TN 3
- Recall (insana çatmalı olanlardan çatanlar): 96.0%
- Auto-close payı (sistemin bağlayacağı alert-lər): 11.1%

**DİQQƏT: FN var. Auto-close açılmamalıdır.**

| Alert | Həqiqət | Sistem | Qayda |
|---|---:|---:|---:|
| URL-11 | uncertain | clean | R07-CLEAN |

## Uyğun gəlməyən alert-lər

| Alert | Həqiqət | Sistem | Qayda | Bağlayardı |
|---|---:|---:|---:|---:|
| HASH-02 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-03 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-05 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| LOGIN-08 | clean | unknown | R99-DEFAULT | xeyr |
| URL-02 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| URL-04 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| URL-06 | clean | unknown | R99-DEFAULT | xeyr |
| URL-07 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| URL-08 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| URL-11 | uncertain | clean | R07-CLEAN | bəli |
