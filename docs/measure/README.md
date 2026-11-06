# 6.1 · Manual ölçmə

Məqsəd: layihənin öz dataset-indən 20 alert-in əl ilə triaj vaxtını 1.3-dəki S1–S8 protokolu ilə ölçmək. 6.2-də avtomatik MTTR **eyni alert-lər** üzərində ölçülür və bu nəticə ilə müqayisə olunur.

## Fayllar

| Fayl | Nədir |
|---|---|
| `sample.txt` | 20 alert: HASH 7, URL 7, LOGIN 6. Sabit toxumla seçilib, hər tipdə zərərli, təmiz və qeyri-müəyyən alert var |
| `assignment.csv` | Kim hansı alert-i, hansı oturumda və hansı sırada ölçür |
| `alerts/*.md` | Alert kartları: yalnız mənbənin göndərdiyi sahələr, baseline kartlarının formatında |
| `raw/<ad>.csv` | Hər analitikin öz ölçmə faylı (timer yazır) |
| `manual_raw.csv` | Bütün analitiklərin birləşmiş nəticəsi (`check` yaradır, 6.2 bunu oxuyur) |

Fayllar `python -m tools.measure plan` ilə yaradılır. Əmri yalnız hazırlayan işlədir. Yenidən işlətsəniz, eyni nəticə alınır.

## Qaydalar

1. **Blind test.** Ölçmə bitənə qədər `dataset/expected.csv`-ni, `dataset/snapshots/`-u və `dataset/iocs_*.csv`-ni açmayın. Sistemdə bu alert-lərin nəticəsini (case, Grafana, timeline) də axtarmayın.
2. **Hər alert-i iki analitik ölçür.** Bölgü `assignment.csv`-dədir: 13–14 alert/nəfər, iki oturum.
3. **Bir oturumda ən çox 10 alert.** Oturumlar arasında ən azı 1 saat fasilə verin.
4. **Sıra dəyişdirilmir.** Hər analitikin sırası fərqlidir (öyrənmə effekti bərabər paylanır).
5. **Intel yaddaşdan götürülmür.** IOC-u əvvəlki alert-dən xatırlasanız da, saytı yenidən açıb yoxlayın.
6. **Kəsilmə olsa** (zəng, internet, başqa iş), həmin addımda `o` + Enter basın. Ölçmə "outlier" kimi işarələnir və hesabatdan çıxarılır.
7. **Addım sərhədləri 1.3a-dakı kimidir.** S7: GitHub issue şablonunu doldurmaq (baseline-da olduğu kimi ortaq repo-da açılmır). S8: WhatsApp-da mesajı şablonla yazmaq.

## İşə salma

```bash
cd ~/projects/alert2case
git checkout main && git pull
source .venv/bin/activate
python tools/baseline_run.py --set measure --analyst <ad> --session 1
```

`<ad>`: `elcin`, `teymur` və ya `elvin`. İkinci oturum üçün `--session 2`. Yarıda Ctrl+C ilə çıxsanız, eyni əmr qaldığı yerdən davam edir.

Nəticə `docs/measure/raw/<ad>.csv`-yə yazılır, baseline faylına toxunulmur. Oturumdan sonra:

```bash
git checkout -b measure/<ad>-s<N>
git add docs/measure/raw/<ad>.csv
git commit -m "measure: <ad> oturum <N>"
git push -u origin measure/<ad>-s<N>
```

və PR açın. Hər analitik yalnız öz faylını dəyişdiyi üçün PR-lar arasında konflikt olmur.

## Yoxlama

```bash
python -m tools.measure check
```

Skript `raw/*.csv` fayllarını `manual_raw.csv`-də birləşdirir.

Keçmə şərtləri: hər alert ən azı 2 tam ölçmə, hər tipdən ən azı 6 alert, nümunədən kənar alert yoxdur, `docs/baseline/baseline_raw.csv` dəyişməyib. Skript median və P90 vaxtı da çap edir.

## Məhdudiyyətlər

- Analitiklər sistemi özləri qurub və bəzi dataset alert-lərini əvvəllər testlərdə görüb. Bu, vaxtı real analitikə nisbətən azalda bilər.
- Kəşfiyyat mənbələrinin cavabları etiketləmə günündən fərqli ola bilər. Vaxt ölçülür, verdict-in düzgünlüyü 6.3-də ayrıca qiymətləndirilir.
- Timer `suspicious` qəbul edir, `expected.csv` isə `uncertain` yazır. 6.3-də ikisi eyni sayılır.
