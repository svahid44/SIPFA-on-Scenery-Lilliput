# اعمال قدم سوم سناریوی ۱ در WSL

این patch باید روی پروژه‌ای اعمال شود که قدم دوم آن قبلاً PASS شده و فایل زیر را دارد:

```text
results/scenario1_detection_ineffective.csv
```

## ۱. ورود به پروژه

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

بهتر است قبل از اعمال patch، تغییر ثبت‌نشده نداشته باشی.

## ۲. اعمال patch

فایل ZIP را در Downloads ویندوز قرار بده و سپس اجرا کن:

```bash
unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase3_patch.zip \
  -d .
```

## ۳. build و اجرای تست‌ها

```bash
make clean
make all
make test | tee phase3_test.log
```

در انتهای تست جدید باید این نتیجه دیده شود:

```text
missing value:         0x9
recovered SK28 word:   0xC
actual SK28:           A3B7389D
actual SK28 word:      0xC
PASS: Algorithm-1 missing-value recovery reproduced the target four bits of SK28.
```

## ۴. اجرای ابزار بازیابی روی dataset قدم دوم

```bash
make scenario1-recover-word | tee phase3_recovery.log
```

اگر فایل dataset قدم دوم را پاک کرده‌ای، ابتدا آن را دوباره بساز:

```bash
make scenario1-dataset
make scenario1-recover-word | tee phase3_recovery.log
```

یا هر دو را یکجا اجرا کن:

```bash
make scenario1-step3 | tee phase3_full_run.log
```

## ۵. بررسی فایل‌های نتیجه

```bash
cat results/scenario1_word_recovery_summary.csv
cat results/scenario1_target_sbox_histogram.csv
```

خلاصه مورد انتظار:

```text
parameter,value
target_sbox,3
known_delta,0x5
sample_count,4096
missing_count,1
missing_value,0x9
recovered_sk28_word,0xC
actual_sk28,0xA3B7389D
actual_sk28_word,0xC
verified,PASS
```

## ۶. ثبت در Git

```bash
git add Makefile CMakeLists.txt README_FA.md APPLY_PHASE3_FA.md \
  include/known_detection_attack.h \
  src/known_detection_attack.c \
  tests/test_known_detection_attack.c \
  tools/scenario1_recover_word.c \
  docs/PHASE3_SCENARIO1_TARGET_WORD_RECOVERY_FA.md \
  results/scenario1_target_sbox_histogram.csv \
  results/scenario1_word_recovery_summary.csv \
  phase3_test.log phase3_recovery.log

git commit -m "Recover one final-round key word with SIPFA Algorithm 1"
```

## خروجی لازم برای قدم بعد

```bash
cat phase3_test.log
cat phase3_recovery.log
cat results/scenario1_word_recovery_summary.csv
```
