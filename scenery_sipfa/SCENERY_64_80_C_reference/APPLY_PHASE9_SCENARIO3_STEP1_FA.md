# راهنمای اعمال Phase 9 — سناریوی ۳، قدم اول

این Patch مدل infection-based مطابق Algorithm 3 و بازیابی یک word از `SK28` را اضافه می‌کند.

## اعمال Patch

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status

unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase9_scenario3_step1_patch.zip \
  -d .
```

## Build

```bash
make clean
make all
```

## اجرای تمام تست‌ها

```bash
make test | tee phase9_scenario3_step1_test.log
```

خروجی نهایی تست جدید باید شامل این خط باشد:

```text
PASS: Algorithm-3 minimum-frequency recovery reproduced the target four bits of SK28.
```

## اجرای قدم اول سناریوی ۳

```bash
make scenario3-step1 | tee phase9_scenario3_step1_run.log
```

نتیجه مورد انتظار:

```text
minimum value:            0x9
minimum gap:              348
recovered SK28 word:      0xC
actual SK28 word:         0xC
PASS
```

## بررسی فایل‌های خروجی

```bash
cat results/scenario3_known_infection_collection_summary.csv
cat results/scenario3_known_infection_recovery_summary.csv
head results/scenario3_known_infection_histogram.csv
```

فایل عمومی زیر هیچ برچسب رخداد داخلی ندارد:

```text
results/scenario3_known_infection_ciphertexts.csv
```

ساختار:

```text
sample_index,ciphertext
```

## Commit پیشنهادی

```bash
git add Makefile CMakeLists.txt README_FA.md \
  APPLY_PHASE9_SCENARIO3_STEP1_FA.md \
  include/infection_dataset.h \
  include/known_infection_attack.h \
  src/infection_dataset.c \
  src/known_infection_attack.c \
  tests/test_known_infection_attack.c \
  tools/scenario3_collect_known_infection.c \
  tools/scenario3_recover_word.c \
  docs/PHASE9_SCENARIO3_STEP1_FA.md \
  results/scenario3_known_infection_ciphertexts.csv \
  results/scenario3_known_infection_collection_summary.csv \
  results/scenario3_known_infection_histogram.csv \
  results/scenario3_known_infection_recovery_summary.csv \
  phase9_scenario3_step1_test.log \
  phase9_scenario3_step1_run.log

git commit -m "Add known-fault infection oracle and recover one SK28 word"
```
