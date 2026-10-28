# Baseline: manual L1 triage

## Metod
- 12 alert (NET×4, HASH×4, WEB×4), hər biri 2 analitik, təsadüfi sıra
- Alət: tools/timer.py · Tarix: 2026-10-28
- Məhdudiyyətlər: kiçik nümunə, Hawthorne effekti, analitiklər tələbədir


## Nəticələr
<!-- report_output.md-dən cədvəllər bura əlavə olunacaq -->
![addımlar](steps_boxplot.png)

## Qərar fərqləri və razılaşdırılmış cavablar
| Sual | Razılaşdırılmış qayda |
|---|---|
| VT-də 1–4 detection | suspicious, insana göndər |

## Avtomatlaşdırma üçün nəticə
- S3+S4 vaxtın __%-i → enrichment modulu (Phase 3)
- S7+S8 → case + notify (Phase 4)
