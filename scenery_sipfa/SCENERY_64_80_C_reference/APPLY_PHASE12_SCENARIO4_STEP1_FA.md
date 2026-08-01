# راهنمای اعمال Phase 12 — سناریوی ۴، قدم اول

این Patch بخش اول Algorithm 4 را اضافه می‌کند: تولید خروجی‌های infection بدون label، مکان‌یابی fault ناشناخته با SEI و ساخت ۱۶ فرضیه زوجی `delta/SK28-word`.

## اعمال Patch

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status

unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase12_scenario4_step1_patch.zip \
  -d .
```

## Build و تست

```bash
make clean
make all
make test | tee phase12_scenario4_step1_test.log
```

تست جدید باید با خط زیر تمام شود:

```text
PASS: Algorithm-4 Step 1 localized the unknown infected fault and retained the true delta/key-word pair among 16 coupled candidates.
```

## اجرای قدم اول سناریوی ۴

```bash
make scenario4-step1 | tee phase12_scenario4_step1_run.log
```

نتیجه مورد انتظار اجرای ثابت:

```text
detected S-box:       5
public minimum:       0xC
SEI gap:              0.000138804316521
remaining ambiguity:  16 coupled pairs
PASS
```

## بررسی خروجی‌ها

```bash
cat results/scenario4_unknown_infection_generation_summary.csv
cat results/scenario4_fault_localization_summary.csv
cat results/scenario4_step1_verification.csv
cat results/scenario4_fault_localization_scores.csv
cat results/scenario4_delta_key_word_candidates.csv
```

فایل عمومی مهاجم:

```text
results/scenario4_unknown_infection_ciphertexts.csv
```

فقط این دو ستون را دارد:

```text
sample_index,ciphertext
```

## اجرای پارامتر سفارشی

```bash
./build/scenario4_collect_unknown_infection \
  32768 0x6A09E667F3BCC909 5 0xB

./build/scenario4_identify_fault \
  results/scenario4_unknown_infection_ciphertexts.csv 5 0xB
```

دو آرگومان آخر ابزار دوم فقط برای verification شبیه‌سازی پس از پایان حمله‌اند و به attack core داده نمی‌شوند.

## Commit پیشنهادی

```bash
git add Makefile CMakeLists.txt README.md README_FA.md \
  APPLY_PHASE12_SCENARIO4_STEP1_FA.md \
  include/unknown_infection_attack.h \
  src/unknown_infection_attack.c \
  tests/test_unknown_infection_attack.c \
  tools/scenario4_collect_unknown_infection.c \
  tools/scenario4_identify_fault.c \
  docs/PHASE12_SCENARIO4_STEP1_FA.md \
  reports/PHASE12_SCENARIO4_STEP1_TEST_REPORT_FA.md \
  results/scenario4_unknown_infection_ciphertexts.csv \
  results/scenario4_unknown_infection_generation_summary.csv \
  results/scenario4_unknown_infection_histograms.csv \
  results/scenario4_fault_localization_scores.csv \
  results/scenario4_delta_key_word_candidates.csv \
  results/scenario4_fault_localization_summary.csv \
  results/scenario4_step1_verification.csv \
  phase12_scenario4_step1_test.log \
  phase12_scenario4_step1_run.log

git commit -m "Add unknown-fault infection localization with SEI"
```
