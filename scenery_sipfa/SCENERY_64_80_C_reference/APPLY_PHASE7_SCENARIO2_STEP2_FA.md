# اعمال فاز ۷ — سناریوی ۲، قدم دوم در WSL

## ۱. ورود به پروژه

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

## ۲. اعمال patch

فایل زیر را در Downloads ویندوز قرار بده:

```text
SCENERY_64_80_SIPFA_phase7_scenario2_step2_patch.zip
```

سپس:

```bash
unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase7_scenario2_step2_patch.zip \
  -d .
```

## ۳. Build و تست

```bash
make clean
make all
make test | tee phase7_scenario2_step2_test.log
```

انتهای تست جدید باید شامل موارد زیر باشد:

```text
tested active candidates:    1048576
surviving candidates:        4
recovered active key bits:   18/20
recovered delta:             0xB
PASS: partial decryption retained the four structural candidates, recovered 18/20 active bits, and recovered delta.
```

## ۴. اجرای کامل قدم دوم

```bash
make scenario2-step2 | tee phase7_scenario2_step2_run.log
```

این دستور به ترتیب اجرا می‌کند:

1. تولید ۵۱۲ ciphertext بی‌اثر بدون برچسب؛
2. شناسایی S-box خراب و مقدار عمومی غایب؛
3. جست‌وجوی کامل `2^20` نامزد فعال؛
4. partial decryption دور ۲۸؛
5. فیلتر missing-value دور ۲۷؛
6. verification جداگانه با ground truth.

## ۵. بررسی خروجی‌ها

```bash
cat results/scenario2_partial_decryption_summary.csv
cat results/scenario2_active_key_candidates.csv
cat results/scenario2_active_key_consensus.csv
cat results/scenario2_step2_verification.csv
```

خلاصه مورد انتظار:

```text
sample_count,512
tested_candidates,1048576
surviving_candidates,4
recovered_active_bits,18
active_key_bits,20
delta_recovered,YES
recovered_delta,0xB
status,PASS
```

نامزدها:

```text
0x3B37E
0x3B77E
0x3BB7E   <- نامزد واقعی در verification
0x3BF7E
```

## ۶. ثبت در Git

پس از PASS شدن همه تست‌ها:

```bash
git add Makefile CMakeLists.txt README_FA.md \
  APPLY_PHASE7_SCENARIO2_STEP2_FA.md \
  include/unknown_detection_attack.h \
  src/unknown_detection_attack.c \
  tests/test_unknown_detection_partial_decryption.c \
  tools/scenario2_filter_active_key.c \
  tools/scenario2_verify_active_key.c \
  docs/PHASE7_SCENARIO2_STEP2_FA.md \
  results/scenario2_active_key_candidates.csv \
  results/scenario2_active_key_consensus.csv \
  results/scenario2_candidate_previous_round_histograms.csv \
  results/scenario2_partial_decryption_summary.csv \
  results/scenario2_step2_verification.csv \
  phase7_scenario2_step2_test.log \
  phase7_scenario2_step2_run.log
```

```bash
git commit -m "Filter active SK28 candidates with Algorithm-2 partial decryption"
```

## خروجی موردنیاز برای ادامه

```bash
cat phase7_scenario2_step2_test.log
cat phase7_scenario2_step2_run.log
cat results/scenario2_partial_decryption_summary.csv
cat results/scenario2_step2_verification.csv
```
