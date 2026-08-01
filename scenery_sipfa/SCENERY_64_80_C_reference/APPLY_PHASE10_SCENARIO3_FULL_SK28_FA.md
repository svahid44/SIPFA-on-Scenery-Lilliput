# راهنمای اعمال Phase 10 — سناریوی ۳، بازیابی کامل SK28

این Patch هشت کمپین مستقل infection-based، بازیابی هشت word چهاربیتی و مونتاژ کامل `SK28` را اضافه می‌کند.

## اعمال Patch

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status

unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase10_scenario3_full_sk28_patch.zip \
  -d .
```

## بررسی فایل‌های جدید

```bash
ls tests/test_known_infection_full_attack.c
ls tools/scenario3_collect_all_infection.c
ls tools/scenario3_recover_full_key.c
```

## Build و تست

```bash
make clean
make all
make test | tee phase10_scenario3_full_test.log
```

خروجی تست جدید باید شامل این خط باشد:

```text
PASS: eight Algorithm-3 minimum-frequency campaigns recovered the complete 32-bit SK28.
```

## اجرای مرحله

```bash
make scenario3-step2 | tee phase10_scenario3_full_run.log
```

خروجی نهایی مورد انتظار:

```text
successful S-boxes:  8/8
recovered SK28:      A3B7389D
actual SK28:         A3B7389D
PASS: eight known-fault infection campaigns recovered the complete 32-bit SK28.
```

## فایل‌های خروجی

```text
results/scenario3_all_sboxes_infection_ciphertexts.csv
results/scenario3_all_sboxes_infection_collection_summary.csv
results/scenario3_all_sboxes_infection_histograms.csv
results/scenario3_full_sk28_recovery_summary.csv
```

بررسی خلاصه:

```bash
cat results/scenario3_all_sboxes_infection_collection_summary.csv
cat results/scenario3_full_sk28_recovery_summary.csv
```

آخرین ردیف خلاصه بازیابی باید چنین باشد:

```text
complete_sk28,,,,,,,,0xA3B7389D,0xA3B7389D,PASS
```

## Commit پیشنهادی

```bash
git add Makefile CMakeLists.txt README_FA.md \
  APPLY_PHASE10_SCENARIO3_FULL_SK28_FA.md \
  include/known_infection_attack.h \
  src/known_infection_attack.c \
  tests/test_known_infection_full_attack.c \
  tools/scenario3_collect_all_infection.c \
  tools/scenario3_recover_full_key.c \
  docs/PHASE10_SCENARIO3_FULL_SK28_FA.md \
  results/scenario3_all_sboxes_infection_ciphertexts.csv \
  results/scenario3_all_sboxes_infection_collection_summary.csv \
  results/scenario3_all_sboxes_infection_histograms.csv \
  results/scenario3_full_sk28_recovery_summary.csv \
  phase10_scenario3_full_test.log \
  phase10_scenario3_full_run.log

git commit -m "Recover complete SK28 under known-fault infection"
```
