# اعمال فاز چهارم سناریوی ۱ در WSL

این patch باید روی پروژه‌ای اعمال شود که فازهای ۱ تا ۳ آن قبلاً PASS شده‌اند.

## ۱. ورود به پروژه

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

بهتر است قبل از اعمال patch، working tree تمیز باشد.

## ۲. اعمال patch

```bash
unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase4_patch.zip \
  -d .
```

## ۳. build و اجرای همه تست‌ها

```bash
make clean
make all
make test | tee phase4_test.log
```

انتهای خروجی باید شامل این خط باشد:

```text
PASS: eight Algorithm-1 campaigns recovered the complete 32-bit SK28.
```

## ۴. تولید هشت dataset مستقل

```bash
make scenario1-all-datasets | tee phase4_datasets.log
```

این فرمان فایل‌های زیر را می‌سازد:

```text
results/scenario1_all_sboxes_ineffective.csv
results/scenario1_all_sboxes_detection_summary.csv
```

## ۵. بازیابی کامل SK28 فقط از CSV

```bash
make scenario1-recover-full | tee phase4_recovery.log
```

خروجی مورد انتظار:

```text
successful S-boxes:  8/8
recovered SK28:      A3B7389D
actual SK28:         A3B7389D
PASS: eight known-fault campaigns recovered the complete 32-bit SK28.
```

## ۶. اجرای کامل مرحله با یک فرمان

```bash
make scenario1-step4 | tee phase4_full_run.log
```

## ۷. بررسی CSVهای نتیجه

```bash
cat results/scenario1_full_sk28_summary.csv
cat results/scenario1_all_sboxes_detection_summary.csv
```

کنترل تعداد سطرهای dataset:

```bash
wc -l results/scenario1_all_sboxes_ineffective.csv
```

با تنظیم پیش‌فرض باید نتیجه زیر باشد:

```text
32769 results/scenario1_all_sboxes_ineffective.csv
```

یک header و 32768 ciphertext بی‌اثر.

## ۸. ثبت در Git

بعد از PASS شدن همه اجراها:

```bash
git add Makefile CMakeLists.txt README_FA.md APPLY_PHASE4_FA.md \
  include/known_detection_attack.h \
  src/known_detection_attack.c \
  tests/test_known_detection_full_attack.c \
  tools/scenario1_collect_all_detection.c \
  tools/scenario1_recover_full_key.c \
  docs/PHASE4_SCENARIO1_FULL_SK28_RECOVERY_FA.md \
  results/scenario1_all_sboxes_ineffective.csv \
  results/scenario1_all_sboxes_detection_summary.csv \
  results/scenario1_all_sboxes_histograms.csv \
  results/scenario1_full_sk28_summary.csv \
  phase4_test.log phase4_datasets.log phase4_recovery.log

git commit -m "Recover complete SCENERY SK28 with SIPFA Algorithm 1"
```

## خروجی لازم برای مرحله بعد

```bash
cat phase4_test.log
cat phase4_recovery.log
cat results/scenario1_full_sk28_summary.csv
```

مرحله بعد، معکوس‌کردن دور ۲۸ با SK28 بازیابی‌شده و ساخت histogram دور ۲۷ خواهد بود.
