# گزارش اعتبارسنجی قدم سوم سناریوی ۱

تاریخ اجرا: 2026-07-28

## دامنه

این مرحله، بخش missing-value recovery از Algorithm 1 مقاله SIPFA را برای یک S-box منطقی هدف در دور آخر SCENERY پیاده‌سازی و آزمایش می‌کند.

در این مرحله بازیابی کامل subkey سی‌ودوبیتی انجام نشده است؛ فقط چهار بیت متناظر با S-box شماره ۳ بازیابی شده‌اند.

## ورودی عمومی حمله

```text
results/scenario1_detection_ineffective.csv
```

هسته حمله فقط موارد زیر را دریافت می‌کند:

- ciphertextهای بی‌اثر منتشرشده؛
- S-box هدف برابر ۳؛
- fault input معلوم برابر `0x5`.

کلید واقعی و `SK28` ورودی الگوریتم بازیابی نیستند.

## نتیجه histogram

| مقدار | count |
|---:|---:|
| 0x0 | 300 |
| 0x1 | 265 |
| 0x2 | 276 |
| 0x3 | 275 |
| 0x4 | 255 |
| 0x5 | 278 |
| 0x6 | 256 |
| 0x7 | 283 |
| 0x8 | 273 |
| 0x9 | 0 |
| 0xA | 287 |
| 0xB | 283 |
| 0xC | 257 |
| 0xD | 279 |
| 0xE | 282 |
| 0xF | 247 |

فقط مقدار `0x9` غایب است.

## بازیابی

```text
missing = 0x9
known delta = 0x5
recovered SK28[3] = 0x9 XOR 0x5 = 0xC
```

Ground truth:

```text
actual SK28 = A3B7389D
actual bitslice word for S-box 3 = 0xC
```

نتیجه بازیابی با مقدار واقعی برابر است.

## نتیجه تست‌ها

| آزمون | نتیجه |
|---|---|
| چهار تست‌وکتور رسمی | PASS |
| trace کامل ۲۸ دور | PASS |
| key schedule | PASS |
| ۲۰۰ cross-validation | PASS |
| ۱۰۰۰۰ round-trip | PASS |
| persistent fault | PASS |
| detection dataset | PASS |
| missing-value word recovery | PASS |
| GCC بدون warning | PASS |
| Clang بدون warning | PASS |
| CMake/CTest | 8/8 PASS |
| AddressSanitizer | PASS |
| UndefinedBehaviorSanitizer | PASS |

## فایل‌های نتیجه

```text
results/scenario1_target_sbox_histogram.csv
results/scenario1_word_recovery_summary.csv
```

## نتیجه نهایی

قدم سوم مطابق رابطه اصلی Algorithm 1 موفق است. یک مقدار غایب یکتا از ciphertextهای بی‌اثر استخراج شد و چهار بیت هدف از subkey دور آخر بدون استفاده از کلید در هسته حمله بازیابی شدند.
