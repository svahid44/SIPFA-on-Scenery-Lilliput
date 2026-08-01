# اعمال قدم دوم سناریوی ۱ روی SCENERY در WSL

این patch باید روی پروژه‌ای اعمال شود که فاز اول persistent fault را با موفقیت گذرانده است.

## ۱. ورود به پروژه و کنترل branch

```bash
cd ~/projects/scenery_sipfa/SCENERY_64_80_C_reference
git switch sipfa-development
git status
```

پیش از اعمال patch بهتر است commit فاز اول در history موجود باشد:

```bash
git log --oneline --decorate -5
```

## ۲. اعمال patch فاز دوم

فایل `SCENERY_64_80_SIPFA_phase2_patch.zip` را در Downloads ویندوز قرار بده و اجرا کن:

```bash
unzip -o /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase2_patch.zip -d .
```

## ۳. build و اجرای همه تست‌ها

```bash
make clean
make all
make test | tee phase2_test.log
```

انتهای خروجی باید علاوه بر PASSهای قبلی شامل این بخش باشد:

```text
target logical S-box:     3
known fault input delta:  0x5
target ineffective:       4096
ineffective outputs kept: 4096
PASS: detection-based oracle retained only verified ineffective ciphertexts.
```

## ۴. تولید dataset سناریوی ۱

```bash
make scenario1-dataset | tee phase2_dataset.log
```

دو فایل ساخته می‌شوند:

```text
results/scenario1_detection_ineffective.csv
results/scenario1_detection_summary.csv
```

## ۵. بررسی نتایج

```bash
cat results/scenario1_detection_summary.csv
head -n 10 results/scenario1_detection_ineffective.csv
wc -l results/scenario1_detection_ineffective.csv
```

با target پیش‌فرض ۴۰۹۶، خروجی `wc -l` باید ۴۰۹۷ باشد؛ یک سطر header و ۴۰۹۶ نمونه.

## ۶. اجرای ابزار با پارامترهای دیگر

ساختار دستور:

```bash
./build/scenario1_collect_detection \
  [target_ineffective] [max_queries] [seed]
```

مثال:

```bash
mkdir -p results
./build/scenario1_collect_detection 2000 30000 0x123456789ABCDEF0
```

## ۷. کنترل تغییرات

```bash
git status
git diff -- Makefile CMakeLists.txt README_FA.md \
  include/detection_dataset.h src/detection_dataset.c \
  tests/test_detection_dataset.c \
  tools/scenario1_collect_detection.c \
  docs/PHASE2_SCENARIO1_DETECTION_DATASET_FA.md \
  APPLY_PHASE2_FA.md
```

## ۸. commit فاز دوم

فقط پس از PASS شدن تمام تست‌ها:

```bash
git add Makefile CMakeLists.txt README_FA.md APPLY_PHASE2_FA.md \
  include/detection_dataset.h \
  src/detection_dataset.c \
  tests/test_detection_dataset.c \
  tools/scenario1_collect_detection.c \
  docs/PHASE2_SCENARIO1_DETECTION_DATASET_FA.md \
  results/scenario1_detection_ineffective.csv \
  results/scenario1_detection_summary.csv \
  phase2_test.log phase2_dataset.log

git commit -m "Add SIPFA detection-based ineffective dataset collector"
```

## خروجی موردنیاز برای قدم بعد

این سه خروجی را ارسال کن:

```bash
cat phase2_test.log
cat phase2_dataset.log
cat results/scenario1_detection_summary.csv
```

قدم بعد از تأیید آن‌ها، ساخت histogram شانزده‌مقداری برای S-box هدف و بررسی یکتاشدن مقدار غایب خواهد بود. هنوز در این فاز هیچ بازیابی کلیدی انجام نشده است.
