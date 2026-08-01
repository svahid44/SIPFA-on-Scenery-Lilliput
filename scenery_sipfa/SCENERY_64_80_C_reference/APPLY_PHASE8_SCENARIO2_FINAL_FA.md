# اعمال بسته نهایی سناریوی ۲ در WSL

## ۱. ورود به پروژه

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

قبل از اعمال patch بهتر است تغییرات مرحله قبل commit شده باشند.

## ۲. اعمال patch

```bash
unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_scenario2_final_patch.zip \
  -d .
```

## ۳. فعال‌کردن محیط Python

اگر `.venv` مرحله سناریوی ۱ وجود دارد:

```bash
source .venv/bin/activate
```

اگر وجود ندارد:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-analysis.txt
```

## ۴. build و test

```bash
make clean
make all
make test | tee phase8_scenario2_final_test.log
```

## ۵. اجرای کامل سناریوی ۲

```bash
make scenario2-final | tee phase8_scenario2_final.log
```

این دستور موارد زیر را انجام می‌دهد:

```text
fixed 512-sample Algorithm-2 attack
100 repeated random experiments
generation of figures and tables
```

اجرای معادل با script:

```bash
bash scripts/run_scenario2_final_analysis.sh \
  100 \
  0x5343454E45525932 | tee phase8_scenario2_final.log
```

## ۶. ساخت مجدد فقط نمودارها و جدول‌ها

پس از اینکه CSVهای تکراری وجود دارند، برای جلوگیری از تکرار آزمایش‌ها:

```bash
make scenario2-report
```

## ۷. بررسی نتیجه

```bash
cat results/scenario2_final_analysis_summary.json
cat results/scenario2_success_curve.csv
cat results/scenario2_success_thresholds.csv
```

نتیجه بیشینه dataset باید شامل این مقادیر باشد:

```text
localization_success_at_max = 1.0
unique_delta_success_at_max = 1.0
target_18_of_20_plus_delta_success_at_max = 1.0
mean_recovered_bits_at_max = 18.0
median_surviving_candidates_at_max = 4.0
```

## ۸. خروجی‌های مقاله

```bash
ls paper_artifacts/scenario2/figures
ls paper_artifacts/scenario2/tables
ls -lh paper_artifacts/scenario2/SCENARIO2_ANALYSIS.xlsx
```

## ۹. ثبت در Git

```bash
git add Makefile CMakeLists.txt README_FA.md \
  APPLY_PHASE8_SCENARIO2_FINAL_FA.md \
  include/unknown_detection_attack.h \
  src/unknown_detection_attack.c \
  tools/scenario2_repeated_experiments.c \
  scripts/scenario2_analysis.py \
  scripts/run_scenario2_final_analysis.sh \
  docs/SCENARIO2_FINAL_REPORT_FA.md \
  docs/SCENARIO2_RESULTS_TEXT_EN.md \
  reports/PHASE8_SCENARIO2_FINAL_TEST_REPORT_FA.md \
  results/scenario2_repeated_trials.csv \
  results/scenario2_repeated_roles.csv \
  results/scenario2_success_curve.csv \
  results/scenario2_complexity.csv \
  results/scenario2_per_sbox_performance.csv \
  results/scenario2_per_delta_performance.csv \
  results/scenario2_role_recovery.csv \
  results/scenario2_success_thresholds.csv \
  results/scenario2_final_analysis_summary.json \
  paper_artifacts/scenario2 \
  phase8_scenario2_final_test.log \
  phase8_scenario2_final.log

git commit -m "Finalize SIPFA scenario 2 analysis and paper artifacts"
```
