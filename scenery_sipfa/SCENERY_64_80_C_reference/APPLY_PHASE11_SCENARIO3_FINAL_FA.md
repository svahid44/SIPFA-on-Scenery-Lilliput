# راهنمای اعمال Phase 11 — نهایی‌سازی سناریوی ۳

## ۱. اعمال Patch

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
unzip -o /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_scenario3_final_patch.zip -d .
```

## ۲. Build و تست

```bash
make clean
make all
make test | tee phase11_scenario3_final_test.log
```

## ۳. اجرای کامل سناریوی ۳

محیط مجازی Python را فعال کن:

```bash
source .venv/bin/activate
```

سپس:

```bash
make scenario3-final | tee phase11_scenario3_final.log
```

این target مراحل زیر را اجرا می‌کند:

1. هشت کمپین ثابت infection و بازیابی کامل `SK28`؛
2. صد آزمایش مستقل روی کلید و `delta` تصادفی؛
3. تولید CSVهای آماری؛
4. تولید نمودارهای PNG/PDF/SVG و جدول‌های CSV/Markdown/LaTeX.

اجرای مستقیم با seed قابل تنظیم:

```bash
bash scripts/run_scenario3_final_analysis.sh 100 0x5343454E45525933
```

## ۴. بازسازی فقط گزارش‌ها

اگر CSVهای تکرارشونده از قبل موجودند:

```bash
make scenario3-report
```

## ۵. خروجی‌های کلیدی

```bash
cat results/scenario3_final_analysis_summary.json
cat results/scenario3_success_curve.csv
cat results/scenario3_success_thresholds.csv
cat results/scenario3_full_sk28_recovery_summary.csv
```

خروجی‌های مقاله‌ای:

```text
paper_artifacts/scenario3/figures/
paper_artifacts/scenario3/tables/
paper_artifacts/scenario3/SCENARIO3_ANALYSIS.xlsx
paper_artifacts/scenario3/FIGURES_CONTACT_SHEET.png
```

## ۶. نتیجه مورد انتظار

```text
Recovered SK28 = A3B7389D
Actual SK28    = A3B7389D
Final-grid success = 100/100 observed trials
```
