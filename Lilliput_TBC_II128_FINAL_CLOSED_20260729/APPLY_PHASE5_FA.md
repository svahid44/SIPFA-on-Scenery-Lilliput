# اعمال فاز پنجم — سناریوی چهارم مقاله روی Lilliput-TBC-II-128

این patch سناریوی چهارم SIPFA را اضافه می‌کند:

- countermeasure از نوع `infection-based`
- fault پایدار روی S-box مشترک
- ورودی fault نامعلوم
- استفاده از تمام ciphertextهای منتشرشده بدون label
- جست‌وجوی 256 کاندیدای fault input
- partial inversion دور آخر برای هر کاندیدا
- رتبه‌بندی با `SEI`
- بازیابی fault input و کل `RTK[31]`

## اعمال patch در WSL

از ریشه پروژه:

```bash
cd ~/projects/lilliput_phase2/Lilliput_TBC_II128_phase2
```

patch را استخراج کنید:

```bash
unzip -o /mnt/c/Users/SADRA/Downloads/Lilliput_TBC_II128_phase5_scenario4_patch.zip -d .
```

سپس:

```bash
make clean
make test 2>&1 | tee phase5_test.log
```

خروجی تست جدید باید شامل این خط باشد:

```text
PASS: Scenario 4 unknown-fault infection-based SEI recovery verified.
```

## اجرای سناریوی چهارم

```bash
make scenario4 2>&1 | tee results/scenario4_run.log
```

خروجی نهایی مورد انتظار:

```text
recovered fault input:  0x5a
actual fault input:     0x5a
recovered RTK[31]:      b3ed58adabab101d
actual RTK[31]:         b3ed58adabab101d
PASS: Scenario 4 recovered the unknown persistent fault input and complete RTK[31] under an infection-based countermeasure.
```

## فایل‌های نتیجه

```text
results/scenario4_published_ciphertexts.csv
results/scenario4_final_histogram.csv
results/scenario4_candidates.csv
results/scenario4_run.log
phase5_test.log
```

فایل ciphertextها فقط شامل این ستون‌هاست:

```text
sample_index,ciphertext
```

هیچ label مربوط به effective/ineffective به تابع attack داده نمی‌شود.

## اجرای دستی

```bash
./build/scenario4_unknown_infection \
  100000 0x5a 0x9B05688C2B3E6C1F \
  results/scenario4_published_ciphertexts.csv \
  results/scenario4_final_histogram.csv \
  results/scenario4_candidates.csv
```
