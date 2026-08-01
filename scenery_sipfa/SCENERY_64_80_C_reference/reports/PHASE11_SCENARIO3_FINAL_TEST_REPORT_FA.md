# گزارش اعتبارسنجی Phase 11 — سناریوی ۳ نهایی

## نتیجه عملکردی

- بازیابی یک word با minimum-frequency: PASS
- بازیابی کامل `SK28` در هشت کمپین: PASS
- `Recovered SK28 = A3B7389D`: PASS
- آزمایش‌های تکرارشونده ۱۰۰تایی: PASS
- تولید ۱۳ نمودار در سه فرمت: PASS
- تولید جدول‌های CSV/Markdown/LaTeX: PASS
- داشبورد Excel و اسکن خطا: PASS

## نتیجه آماری

- موفقیت کامل در ۸۱۹۲ نمونه/S-box: ۹۰٪
- موفقیت کامل در ۱۲۲۸۸ نمونه/S-box: ۹۴٪
- موفقیت کامل در ۱۶۳۸۴ نمونه/S-box: ۹۹٪
- موفقیت مشاهده‌شده در ۲۴۵۷۶ و ۳۲۷۶۸ نمونه/S-box: ۱۰۰/۱۰۰
- موفقیت word در ۱۶۳۸۴ نمونه/S-box: ۹۹٫۸۷۵٪

## اعتبارسنجی ساخت و ایمنی

نتیجه نهایی اجرای GCC، Clang، CMake/CTest، AddressSanitizer، UndefinedBehaviorSanitizer و اعمال مستقل patch در انتهای فرآیند بسته‌بندی ثبت می‌شود.

## نتایج نهایی اعتبارسنجی مهندسی

```text
GCC build and full test suite:          PASS
Clang build and full test suite:        PASS
CMake configure/build:                  PASS
CTest:                                  13/13 PASS
AddressSanitizer:                       PASS
UndefinedBehaviorSanitizer:             PASS
Chunked 100-trial reproducibility run:  PASS
Scenario-3 analysis generation:         PASS
Excel formula-error scan:               PASS
```

تست‌های CMake شامل بردارهای رسمی، trace بیست‌وهشت‌دور، key schedule، cross-validation، تست‌های ساختاری، زیرساخت fault و تمام تست‌های سناریوهای ۱ تا ۳ بود. زمان اجرای CTest مرجع تقریباً ۱٫۱ ثانیه و نتیجه `100% tests passed` بود.

## اعتبارسنجی اعمال Patch

Patch نهایی روی یک کپی مستقل از Phase 10 اعمال شد. سپس build کامل، تمام تست‌ها، یک اجرای chunked آزمایشی و تولید گزارش‌ها انجام شد:

```text
Independent patch overlay: PASS
Patch-overlay GCC build:   PASS
Patch-overlay test suite:  PASS
Patch-overlay repeated run:PASS
Patch-overlay analysis:    PASS
```
