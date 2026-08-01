# اعمال فاز چهارم — سناریوی سوم مقاله روی Lilliput-TBC-II-128

این بسته سناریوی سوم SIPFA را به پروژه فعلی اضافه می‌کند:

- countermeasure از نوع `infection-based`
- fault پایدار تک‌ورودی روی S-box مشترک
- ورودی fault معلوم
- استفاده از تمام ciphertextهای منتشرشده بدون label
- جایگزینی خروجی‌های effective با رشته تصادفی 128 بیتی
- بازیابی کامل `RTK[31]` با کمترین فراوانی histogram مطابق Algorithm 3 مقاله

## اعمال patch در WSL

ابتدا وارد ریشه پروژه شوید:

```bash
cd ~/projects/lilliput_phase2/Lilliput_TBC_II128_phase2
```

سپس patch را استخراج کنید:

```bash
unzip -o /mnt/c/Users/SADRA/Downloads/Lilliput_TBC_II128_phase4_scenario3_patch.zip -d .
```

بعد تست کامل را اجرا کنید:

```bash
make clean
make test 2>&1 | tee phase4_test.log
```

خروجی تست جدید باید شامل این خط باشد:

```text
PASS: Scenario 3 known-fault infection-based recovery verified.
```

## اجرای سناریوی سوم

```bash
make scenario3 2>&1 | tee results/scenario3_run.log
```

خروجی نهایی مورد انتظار:

```text
known fault input:      0x5a
published samples:      100000
recovered RTK[31]:      b3ed58adabab101d
actual RTK[31]:         b3ed58adabab101d
PASS: Scenario 3 recovered the complete RTK[31] under a known persistent fault and infection-based countermeasure.
```

برای هر هشت lane باید status برابر `PASS` باشد.

## فایل‌های نتیجه

```text
results/scenario3_published_ciphertexts.csv
results/scenario3_final_histogram.csv
results/scenario3_lane_minima.csv
results/scenario3_run.log
phase4_test.log
```

فایل ciphertextها عمداً فقط شامل این ستون‌ها است:

```text
sample_index,ciphertext
```

هیچ label مربوط به effective/ineffective به attack داده نمی‌شود.

## اجرای دستی با پارامتر دلخواه

```bash
./build/scenario3_known_infection \
  100000 0x5a 0xA54FF53A5F1D36F1 \
  results/scenario3_published_ciphertexts.csv \
  results/scenario3_final_histogram.csv \
  results/scenario3_lane_minima.csv
```
