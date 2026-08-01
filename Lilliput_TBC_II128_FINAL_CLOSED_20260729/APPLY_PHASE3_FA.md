# اعمال فاز سوم — سناریوی دوم مقاله روی Lilliput-TBC-II-128

این بسته سناریوی دوم SIPFA را به پروژه فاز دوم اضافه می‌کند:

- countermeasure از نوع detection-based
- fault ماندگار
- ورودی fault نامعلوم
- استفاده فقط از ciphertextهای ineffective
- فیلتر 256 کاندیدا با partial inversion دور آخر و آزمون missing value دور قبل

## اعمال patch در WSL

ابتدا وارد ریشه پروژه فاز دوم شوید:

```bash
cd ~/projects/lilliput_phase2/Lilliput_TBC_II128_phase2
```

سپس patch را از Downloads ویندوز استخراج کنید:

```bash
unzip -o /mnt/c/Users/SADRA/Downloads/Lilliput_TBC_II128_phase3_scenario2_patch.zip -d .
```

بعد تست کامل:

```bash
make clean
make test 2>&1 | tee phase3_test.log
```

اجرای سناریوی دوم و ذخیره لاگ:

```bash
make scenario2 2>&1 | tee results/scenario2_run.log
```

## خروجی مورد انتظار

در تست جدید:

```text
PASS: Scenario 2 unknown-fault detection recovery verified.
```

در اجرای سناریو:

```text
initial delta candidates:256
surviving candidates:   1
recovered fault input:  0x5a
recovered RTK[31]:      b3ed58adabab101d
actual RTK[31]:         b3ed58adabab101d
PASS: Scenario 2 recovered the unknown persistent fault input and complete RTK[31].
```

## فایل‌های نتیجه

```text
results/scenario2_ineffective_samples.csv
results/scenario2_final_histogram.csv
results/scenario2_candidates.csv
results/scenario2_run.log
phase3_test.log
```

برای دیدن کاندیدای باقی‌مانده:

```bash
awk -F, 'NR==1 || $2==1' results/scenario2_candidates.csv
```

برای شمارش نمونه‌ها:

```bash
wc -l results/scenario2_ineffective_samples.csv
```

باید 4001 خط باشد: یک header و 4000 نمونه ineffective.
