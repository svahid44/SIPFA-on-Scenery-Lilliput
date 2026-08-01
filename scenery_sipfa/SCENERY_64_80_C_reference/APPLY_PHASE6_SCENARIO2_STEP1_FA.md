# اعمال سناریوی ۲، قدم اول در WSL

## ۱. ورود به شاخه توسعه

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

پیش از اعمال patch مطمئن شو تغییر ثبت‌نشده مهمی باقی نمانده باشد.

## ۲. اعمال patch

```bash
unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase6_scenario2_step1_patch.zip \
  -d .
```

## ۳. build و تست کامل

```bash
make clean
make all
make test | tee phase6_scenario2_step1_test.log
```

انتهای تست باید شامل این پیام باشد:

```text
PASS: one global missing value identified the unknown faulty S-box and public missing word.
```

## ۴. اجرای قدم اول سناریوی ۲

```bash
make scenario2-step1 | tee phase6_scenario2_step1_run.log
```

این target ابتدا یک dataset عمومی بدون label می‌سازد و سپس محل fault را فقط از همان فایل عمومی شناسایی می‌کند.

## ۵. بررسی فایل‌های خروجی

```bash
head -n 10 results/scenario2_unknown_detection_ciphertexts.csv
cat results/scenario2_unknown_detection_collection_summary.csv
cat results/scenario2_fault_identification_summary.csv
cat results/scenario2_unknown_detection_ground_truth.csv
```

فایل عمومی باید فقط دو ستون داشته باشد:

```text
ineffective_index,ciphertext
```

خلاصه حمله مورد انتظار:

```text
sample_count,256
global_missing_count,1
detected_sbox,5
detected_missing_value,0xC
status,PASS
```

فایل ground truth باید فقط برای مقایسه بعد از حمله استفاده شود:

```text
secret_sbox,5
secret_delta,0xB
actual_sk28_word,0x7
expected_missing,0xC
```

## ۶. ثبت مرحله در Git

پس از PASS شدن همه اجراها:

```bash
git add Makefile CMakeLists.txt README_FA.md \
  APPLY_PHASE6_SCENARIO2_STEP1_FA.md \
  include/unknown_detection_attack.h \
  src/unknown_detection_attack.c \
  tests/test_unknown_detection_attack.c \
  tools/scenario2_collect_unknown_detection.c \
  tools/scenario2_identify_fault.c \
  docs/PHASE6_SCENARIO2_STEP1_FA.md \
  results/scenario2_unknown_detection_ciphertexts.csv \
  results/scenario2_unknown_detection_collection_summary.csv \
  results/scenario2_unknown_detection_ground_truth.csv \
  results/scenario2_unknown_detection_histograms.csv \
  results/scenario2_fault_identification_summary.csv \
  phase6_scenario2_step1_test.log \
  phase6_scenario2_step1_run.log

git commit -m "Identify unknown faulty S-box for SIPFA scenario 2"
```

## خروجی لازم برای قدم بعد

```bash
cat phase6_scenario2_step1_test.log
cat phase6_scenario2_step1_run.log
cat results/scenario2_fault_identification_summary.csv
cat results/scenario2_unknown_detection_ground_truth.csv
```
