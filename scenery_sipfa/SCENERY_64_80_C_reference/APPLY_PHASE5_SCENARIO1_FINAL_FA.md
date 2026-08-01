# اعمال بسته نهایی نمودارها و جدول‌های سناریوی ۱ در WSL

## ۱. ورود به پروژه

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

## ۲. اعمال patch

```bash
unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase5_scenario1_final_patch.zip \
  -d .
```

## ۳. نصب وابستگی رسم شکل

```bash
python3 -m pip install --user -r requirements-analysis.txt
```

## ۴. build و تست

```bash
make clean
make all
make test | tee phase5_test.log
```

## ۵. تولید کامل داده‌ها، تکرارها، جدول‌ها و نمودارها

اجرای پیش‌فرض با ۱۰۰ تکرار:

```bash
make scenario1-final | tee phase5_scenario1_final.log
```

یا اجرای مستقیم:

```bash
bash scripts/run_scenario1_final_analysis.sh 100 \
  0x5343454E45525931
```

## ۶. بررسی نتایج اصلی

```bash
cat results/scenario1_success_curve.csv
cat results/scenario1_success_thresholds.csv
cat results/scenario1_final_analysis_summary.json
```

## ۷. بررسی شکل‌ها و جدول‌ها

```bash
find paper_artifacts/figures -maxdepth 1 -type f | sort
find paper_artifacts/tables -maxdepth 1 -type f | sort
```

## ۸. فایل Excel

فایل آماده Excel از قبل داخل patch قرار دارد:

```text
paper_artifacts/SCENARIO1_ANALYSIS.xlsx
```

این فایل بر اساس اجرای مرجع ۱۰۰تکراری ساخته شده است. اگر آزمایش‌ها را با seed یا تعداد تکرار متفاوت اجرا کنی، CSVها و شکل‌ها بازتولید می‌شوند؛ Excel مرجع ثابت باقی می‌ماند.

## ۹. ثبت در Git

```bash
git add Makefile CMakeLists.txt README_FA.md \
  APPLY_PHASE5_SCENARIO1_FINAL_FA.md requirements-analysis.txt \
  tools/scenario1_repeated_experiments.c \
  scripts/scenario1_analysis.py scripts/run_scenario1_final_analysis.sh \
  docs/SCENARIO1_FINAL_REPORT_FA.md docs/SCENARIO1_RESULTS_TEXT_EN.md \
  results/scenario1_repeated_trials.csv \
  results/scenario1_repeated_words.csv \
  results/scenario1_success_curve.csv \
  results/scenario1_query_complexity.csv \
  results/scenario1_per_sbox_success.csv \
  results/scenario1_success_thresholds.csv \
  results/scenario1_final_analysis_summary.json \
  paper_artifacts

git commit -m "Finalize Scenario 1 statistics figures and paper tables"
```
