# گزارش نهایی سناریوی ۱ SIPFA روی SCENERY-64/80

## دامنه نتیجه

سناریوی ۱ مدل «خطای معلوم + countermeasure تشخیصی» را مطابق Algorithm 1 اصلی SIPFA پیاده‌سازی می‌کند. خروجی نهایی این سناریو بازیابی کامل کلید دور آخر `SK28` است. بازیابی دورهای قبل و master key در دامنه این سناریو قرار نگرفته است.

## مدل آزمایش

- ساختار هدف: SCENERY-64/80؛
- تعداد دور: ۲۸؛
- تعداد S-boxهای منطقی: ۸؛
- اندازه ورودی هر S-box: ۴ بیت؛
- fault: تغییر دقیقاً یک ورودی معلوم از یک S-box منطقی؛
- خروجی خراب: `(S(delta)+1) mod 16`؛
- countermeasure: انتشار خروجی فقط برای رخدادهای بی‌اثر؛
- رابطه بازیابی: `SK28[j] = missing[j] XOR delta`؛
- کلیدهای آزمایش تکراری: ۱۰۰ کلید تصادفی ۸۰ بیتی؛
- مقدار `delta`: مستقل و تصادفی در هر تکرار؛
- کمپین‌ها: هشت fault مستقل در هر تکرار؛
- شبکه نمونه: ۱۵ مقدار از ۱۶ تا ۲۵۶ ciphertext بی‌اثر برای هر S-box.

## نتیجه اجرای نهایی با ۴۰۹۶ نمونه برای هر S-box

| S-box | Missing | Recovered word | Actual word | Result |
|---:|---:|---:|---:|---|
| 0 | `0xE` | `0xB` | `0xB` | PASS |
| 1 | `0x6` | `0x3` | `0x3` | PASS |
| 2 | `0xF` | `0xA` | `0xA` | PASS |
| 3 | `0x9` | `0xC` | `0xC` | PASS |
| 4 | `0xB` | `0xE` | `0xE` | PASS |
| 5 | `0x2` | `0x7` | `0x7` | PASS |
| 6 | `0x5` | `0x0` | `0x0` | PASS |
| 7 | `0xE` | `0xB` | `0xB` | PASS |

```text
Recovered SK28 = A3B7389D
Actual SK28    = A3B7389D
```

## آزمایش‌های تکراری و منحنی موفقیت

هر نقطه با ۱۰۰ کلید تصادفی و ۱۰۰ مقدار fault تصادفی اجرا شده است.

| Ineffective / S-box | Full SK28 success | Word success | Mean recovered words |
|---:|---:|---:|---:|
| 48 | 0% | 12.4% | 0.99 / 8 |
| 56 | 7% | 27.6% | 2.21 / 8 |
| 64 | 20% | 44.5% | 3.56 / 8 |
| 72 | 34% | 58.6% | 4.69 / 8 |
| 80 | 59% | 76.0% | 6.08 / 8 |
| 96 | 83% | 90.1% | 7.21 / 8 |
| 112 | 94% | 96.8% | 7.74 / 8 |
| 128 | 99% | 99.5% | 7.96 / 8 |
| 160 | 100% | 100% | 8.00 / 8 |
| 256 | 100% | 100% | 8.00 / 8 |

نکته آماری: مشاهده موفقیت ۱۰۰ از ۱۰۰ در ۱۶۰ نمونه به معنی احتمال موفقیت ریاضی دقیقاً یک نیست. فاصله Wilson ۹۵ درصد برای این نقطه تقریباً `[96.3%, 100%]` است.

## آستانه‌های مشاهده‌شده

| هدف | حداقل نمونه بی‌اثر برای هر S-box | نرخ مشاهده‌شده |
|---:|---:|---:|
| 50% | 80 | 59% |
| 80% | 96 | 83% |
| 90% | 112 | 94% |
| 95% | 128 | 99% |
| 99% | 128 | 99% |
| 100% در ۱۰۰ تکرار | 160 | 100% |

## پیچیدگی پرس‌وجو

| Ineffective / S-box | Mean total queries over 8 S-boxes | Standard deviation |
|---:|---:|---:|
| 80 | 3920.37 | 136.25 |
| 96 | 4690.25 | 143.96 |
| 112 | 5472.38 | 161.66 |
| 128 | 6254.28 | 167.60 |
| 160 | 7802.62 | 182.05 |
| 256 | 12442.32 | 251.91 |

برای اجرای نهایی ۴۰۹۶ نمونه‌ای:

```text
Total ineffective outputs = 32768
Total oracle queries       = 200337
Blocked effective events   = 167569
Empirical rate             = 0.163564394
Theoretical rate           = 0.164132936
```

## شکل‌های تولیدشده

تمام شکل‌ها در سه فرمت `PNG`، `PDF` و `SVG` تولید می‌شوند.

1. منحنی موفقیت کامل و کلمه‌ای با فاصله Wilson؛
2. احتمال شکست در مقیاس لگاریتمی؛
3. میانگین تعداد کلمات بازیابی‌شده؛
4. پیچیدگی پرس‌وجو برحسب تعداد نمونه؛
5. boxplot توزیع تعداد پرس‌وجو؛
6. همگرایی نرخ تجربی به نرخ نظری؛
7. heatmap موفقیت هر S-box؛
8. نرخ تجربی هشت کمپین نهایی؛
9. تعداد پرس‌وجو و رخدادهای مسدودشده؛
10. خطای مطلق نرخ هر S-box؛
11. heatmap کامل histogramها و missing valueها؛
12. مقایسه کلمات بازیابی‌شده و واقعی؛
13. missing value هر کمپین.

مسیر:

```text
paper_artifacts/figures/
```

## جدول‌های تولیدشده

- جدول منحنی موفقیت؛
- جدول پیچیدگی پرس‌وجو؛
- جدول موفقیت هر S-box؛
- جدول کمپین‌های ثابت؛
- جدول ۱۲۸ مقدار histogram؛
- جدول بازیابی نهایی؛
- جدول آستانه‌های موفقیت؛
- نسخه‌های آماده مقاله در قالب CSV، Markdown و LaTeX.

مسیر:

```text
paper_artifacts/tables/
```

## داشبورد Excel

فایل زیر شامل Dashboard، جدول‌های خلاصه، داده موفقیت، پیچیدگی پرس‌وجو، آمار هر S-box، histogramها و نتیجه نهایی است:

```text
paper_artifacts/SCENARIO1_ANALYSIS.xlsx
```

## نتیجه قابل استفاده در مقاله

> Under the known-fault and detection-based countermeasure model, eight independent persistent-fault campaigns recover the complete 32-bit final-round key SK28. In 100 independent experiments with random 80-bit keys and random known fault inputs, the full-key recovery rate reached 83% with 96 ineffective ciphertexts per logical S-box, 99% with 128 samples, and 100/100 observed successes with 160 samples. The empirical ineffective-event rate closely follows the theoretical value `(15/16)^28`.

## محدودیت ادعا

این نتیجه بازیابی `SK28` را ثابت می‌کند، نه بازیابی master key ۸۰ بیتی. همچنین تمام نتایج فعلی شبیه‌سازی نرم‌افزاری هستند و شامل تزریق fault فیزیکی روی سخت‌افزار نمی‌شوند.
