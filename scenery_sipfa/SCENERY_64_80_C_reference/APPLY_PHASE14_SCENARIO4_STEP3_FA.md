# راهنمای اعمال فاز ۱۴ — سناریوی چهارم، قدم سوم

این patch باید روی پروژه‌ای اعمال شود که فاز ۱۳ سناریوی چهارم روی آن نصب و
تست شده است.

## ۱. رفتن به پروژه

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

بهتر است قبل از اعمال patch، working tree تمیز باشد.

## ۲. اعمال patch

فرض شده فایل zip در Downloads ویندوز قرار دارد:

```bash
unzip -o /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase14_scenario4_step3_patch.zip -d .
```

## ۳. ساخت و اجرای تمام تست‌ها

```bash
make clean
make all
make test | tee phase14_test.log
```

در انتهای تست‌ها باید پیام زیر دیده شود:

```text
PASS: the two unresolved bits are structurally unidentifiable under the current one-word SEI observation
```

## ۴. اجرای قدم سوم

اگر خروجی‌های قدم دوم موجود هستند:

```bash
make scenario4-audit-tie | tee phase14_step3.log
```

برای اجرای کامل سناریوی چهارم از جمع‌آوری dataset تا ممیزی tie:

```bash
make scenario4-step3 | tee phase14_full_run.log
```

## ۵. خروجی‌های مهم

```bash
cat results/scenario4_rank1_equivalence_summary.csv
cat results/scenario4_step3_verification.csv
cat results/scenario4_rank1_equivalence_matrix.csv
cat results/scenario4_prefix_equivalence.csv
```

خروجی مرجع خلاصه:

```text
rank1_candidate_count,4
unique_exact_sequences,2
xor_equivalence_classes,1
unique_sei_scores,1
all_pairs_constant_xor,YES
all_prefix_scores_equal,YES
more_samples_can_break_current_sei_tie,NO
honest_recovery,18/20 active bits + unique delta
status,PASS
```

## ۶. ثبت در Git

```bash
git add .
git commit -m "Prove Scenario 4 rank-one structural equivalence"
```

## فایل‌هایی که برای بررسی ارسال شوند

```bash
cat phase14_test.log
cat phase14_step3.log
cat results/scenario4_rank1_equivalence_summary.csv
cat results/scenario4_step3_verification.csv
```
