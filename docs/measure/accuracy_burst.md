# Dəqiqlik · burst

Tarix: 2026-11-07 00:16 · Müqayisə olunan alert: 36

## Verdict (sətir: expected.csv, sütun: sistem; suspicious və unknown = uncertain)

|  | sistem: malicious | sistem: uncertain | sistem: clean |
|---|---:|---:|---:|
| həqiqət: malicious | 7 | 4 | 0 |
| həqiqət: uncertain | 0 | 14 | 0 |
| həqiqət: clean | 0 | 7 | 4 |

Sistemin xam cavabları: clean 4, malicious 7, suspicious 11, unknown 14

- Verdict dəqiqliyi: 69.4%
- Cohen's kappa (sistem vs həqiqət): 0.52

## Auto-close təhlükəsizliyi (shadow qərarları daxil)

- TP 25 · **FN 0** · FP 9 · TN 2
- Recall (insana çatmalı olanlardan çatanlar): 100.0%
- Auto-close payı (sistemin bağlayacağı alert-lər): 5.6%

## Uyğun gəlməyən alert-lər

| Alert | Həqiqət | Sistem | Qayda | Bağlayardı |
|---|---:|---:|---:|---:|
| HASH-03 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-04 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-07 | clean | unknown | R99-DEFAULT | xeyr |
| HASH-08 | clean | unknown | R99-DEFAULT | xeyr |
| LOGIN-05 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| LOGIN-08 | clean | unknown | R99-DEFAULT | xeyr |
| URL-02 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| URL-04 | malicious | unknown | R99-DEFAULT | xeyr |
| URL-06 | clean | unknown | R99-DEFAULT | xeyr |
| URL-07 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| URL-08 | clean | unknown | R99-DEFAULT | xeyr |
