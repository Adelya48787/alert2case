# Dəqiqlik · chaos

Tarix: 2026-11-06 23:18 · Müqayisə olunan alert: 36

## Verdict (sətir: expected.csv, sütun: sistem; suspicious və unknown = uncertain)

|  | sistem: malicious | sistem: uncertain | sistem: clean |
|---|---:|---:|---:|
| həqiqət: malicious | 8 | 3 | 0 |
| həqiqət: uncertain | 9 | 5 | 0 |
| həqiqət: clean | 8 | 3 | 0 |

Sistemin xam cavabları: malicious 25, suspicious 10, unknown 1

- Verdict dəqiqliyi: 36.1%
- Cohen's kappa (sistem vs həqiqət): 0.04

## Auto-close təhlükəsizliyi (shadow qərarları daxil)

- TP 25 · **FN 0** · FP 11 · TN 0
- Recall (insana çatmalı olanlardan çatanlar): 100.0%
- Auto-close payı (sistemin bağlayacağı alert-lər): 0.0%

## Uyğun gəlməyən alert-lər

| Alert | Həqiqət | Sistem | Qayda | Bağlayardı |
|---|---:|---:|---:|---:|
| HASH-02 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-03 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-04 | malicious | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-05 | clean | malicious | R03-HASH-MALICIOUS | xeyr |
| HASH-06 | clean | malicious | R03-HASH-MALICIOUS | xeyr |
| HASH-07 | clean | malicious | R03-HASH-MALICIOUS | xeyr |
| HASH-08 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| HASH-10 | uncertain | malicious | R03-HASH-MALICIOUS | xeyr |
| HASH-12 | uncertain | malicious | R03-HASH-MALICIOUS | xeyr |
| LOGIN-05 | clean | malicious | R04-MALICIOUS | xeyr |
| LOGIN-06 | clean | malicious | R04-MALICIOUS | xeyr |
| LOGIN-07 | clean | malicious | R04-MALICIOUS | xeyr |
| LOGIN-08 | clean | unknown | R99-DEFAULT | xeyr |
| LOGIN-09 | uncertain | malicious | R04-MALICIOUS | xeyr |
| LOGIN-10 | uncertain | malicious | R04-MALICIOUS | xeyr |
| LOGIN-11 | uncertain | malicious | R04-MALICIOUS | xeyr |
| LOGIN-12 | uncertain | malicious | R04-MALICIOUS | xeyr |
| URL-01 | uncertain | malicious | R04-MALICIOUS | xeyr |
| URL-06 | clean | malicious | R04-MALICIOUS | xeyr |
| URL-07 | clean | suspicious | R06-SUSPICIOUS | xeyr |
| URL-08 | clean | malicious | R04-MALICIOUS | xeyr |
| URL-09 | uncertain | malicious | R04-MALICIOUS | xeyr |
| URL-11 | uncertain | malicious | R04-MALICIOUS | xeyr |
