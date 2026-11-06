# Korrelyasiya demo alert-ləri

Ölçmə dataset-i (`dataset/raw`, 36 alert) korrelyasiya qaydalarının C1, C3 və C4-ünü işə salmır:
orada hər IOC unikaldır, eyni hostda URL → fayl zənciri və eyni `/24` şəbəkədən çoxlu login yoxdur.
Bu qovluq həmin qaydaları göstərmək üçün ayrıca hazırlanıb və ölçmələrə (6.1–6.3) daxil deyil.

| Fayllar | Qayda | Ssenari | Gözlənilən |
|---|---|---|---|
| `DEMO-C1-A`, `DEMO-C1-B` | C1 eyni IOC | Eyni phishing URL-i iki istifadəçiyə gəlir | İkinci alert yeni case açmır, birincinin case-inə bağlanır |
| `DEMO-C3-URL`, `DEMO-C3-HASH` | C3 hostda zəncir | `WS-034`-də əvvəl arxiv yüklənir, sonra ondan fayl işə düşür | Fayl alert-i ən azı Critical (P1) olur, case-lər bir-birinə istinad edir |
| `DEMO-C4-1` … `DEMO-C4-7` | C4 brute force | Bir saatda `185.220.101.0/24`-dən 7 uğursuz login | 5-ci login kampaniya case-i açır, 6-cı və 7-ci ona bağlanır |

Domenlər `.example` (RFC 2606) zonasındadır, fayl hash-i heç bir real fayla aid deyil.
Sıra vacibdir: hər cütün ikinci alert-i birincinin case-i yarandıqdan sonra göndərilməlidir.
`tools/phase5_exit.sh` onları bu sıra ilə, bir-bir göndərir.

Əl ilə göndərmək:

```bash
python tools/simulator.py --dataset dataset/demo --only DEMO-C1-A
```
