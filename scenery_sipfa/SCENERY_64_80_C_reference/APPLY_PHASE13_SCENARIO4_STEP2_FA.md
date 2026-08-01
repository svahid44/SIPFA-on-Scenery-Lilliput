# راهنمای اعمال فاز ۱۳ — سناریوی چهارم، قدم دوم

این patch باید روی پروژه‌ای اعمال شود که فاز ۱۲ سناریوی چهارم را دارد.

## ۱. اعمال patch

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference

git switch sipfa-development
git status

unzip -o \
  /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase13_scenario4_step2_patch.zip \
  -d .
```

## ۲. ساخت و اجرای همه تست‌ها

```bash
make clean
make all
make test | tee phase13_scenario4_step2_test.log
```

در انتهای log باید تست زیر نیز PASS شود:

```text
./build/test_unknown_infection_partial_decryption
PASS: Algorithm-4 full 2^20 SEI ranking recovered 18/20 active bits and the unique unknown delta without secret-key input.
```

## ۳. اجرای کامل قدم دوم

```bash
make scenario4-step2 | tee phase13_scenario4_step2_run.log
```

توجه: این فرمان عمداً dataset قبلی ۳۲٬۷۶۸ نمونه‌ای را با dataset مرجع
۶۵٬۵۳۶ نمونه‌ای بازتولید می‌کند و سپس رتبه‌بندی را انجام می‌دهد.

خروجی مورد انتظار:

```text
tested candidates:          1048576
rank-1 structural ties:     4
recovered active key bits:  18/20
recovered delta:            0xB
actual candidate rank:      1 (tie count 4)
PASS
```

## ۴. بررسی فایل‌های نتیجه

```bash
cat results/scenario4_partial_decryption_summary.csv
cat results/scenario4_step2_verification.csv
cat results/scenario4_active_key_consensus.csv
head -n 13 results/scenario4_active_key_ranking_top64.csv
```

خلاصه‌ی مرجع:

```text
sample_count             = 65536
tested_candidates        = 1048576
top_candidate_count      = 4
recovered_active_bits    = 18
recovered_delta          = 0xB
actual_candidate_rank    = 1
status                   = PASS
```

## ۵. Commit پیشنهادی

```bash
git add .
git commit -m "Rank full Scenario 4 active-key space with exact SEI"
```

## نکته علمی

این مرحله کلید یا delta را به تابع حمله نمی‌دهد. همه‌ی `2^20` نامزد فعال
به‌صورت دقیق رتبه‌بندی می‌شوند. چهار نامزد رتبه اول یک ابهام ساختاری دارند،
پس نتیجه‌ی صادقانه `18/20 bits + unique delta` است.
