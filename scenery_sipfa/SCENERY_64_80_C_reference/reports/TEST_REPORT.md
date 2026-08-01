# گزارش اعتبارسنجی پیاده‌سازی C الگوریتم SCENERY-64/80

تاریخ اجرا: 2026-07-27

## نتیجه نهایی

تمام آزمون‌های تعریف‌شده موفق بوده‌اند.

| آزمون | تعداد | نتیجه |
|---|---:|---|
| تست‌وکتور رسمی مقاله | 4 | PASS |
| تطبیق رد کامل دورها | 28 دور | PASS |
| تطبیق round keyهای کلید صفر | 28 | PASS |
| cross-validation با Python | 200 | PASS |
| آزمون round-trip تصادفی | 10,000 | PASS |
| آزمون in-place | 10,000 | PASS |
| آزمون خطی‌بودن MixColumns | 5,000 | PASS |
| GCC release build | کامل | PASS |
| Clang release build | کامل | PASS |
| CMake/CTest | 5/5 | PASS |
| AddressSanitizer + UBSan | همه تست‌ها | PASS |

## نتایج رسمی

| بردار | Plaintext | Key | Expected | Actual |
|---|---|---|---|---|
| TV1 | 0000000000000000 | 00000000000000000000 | 82EFEDBA3336CD92 | 82EFEDBA3336CD92 |
| TV2 | 0000000000000000 | FFFFFFFFFFFFFFFFFFFF | CE6E5005CF04E426 | CE6E5005CF04E426 |
| TV3 | FFFFFFFFFFFFFFFF | 00000000000000000000 | 480B5421D5611B60 | 480B5421D5611B60 |
| TV4 | FFFFFFFFFFFFFFFF | FFFFFFFFFFFFFFFFFFFF | F752C84E84124C59 | F752C84E84124C59 |

## آزمون رد دورها

برای تست اول، در هر یک از 28 دور این مقادیر بررسی شدند:

- round key؛
- L و R ورودی؛
- خروجی AddRoundKey؛
- خروجی SubColumns؛
- خروجی MixColumns؛
- L و R خروجی.

تمام 252 فیلد دوری با فایل JSON مرجع برابر بودند.

## Cross-validation

200 زوج key/plaintext با seed ثابت `0x5343454E455259` در Python تولید و ciphertextها داخل تست C تثبیت شدند. تمام خروجی‌های C با مرجع Python برابر بودند.

## Sanitizer

کد با گزینه‌های زیر ساخته و اجرا شد:

```text
-fsanitize=address,undefined -fno-omit-frame-pointer
```

هیچ خطای حافظه یا رفتار تعریف‌نشده گزارش نشد.

## نتیجه

پیاده‌سازی C با چهار تست‌وکتور مقاله و رفتار مرجع Python سازگار است و برای پژوهش، تحلیل رمز، شبیه‌سازی fault و تولید trace مناسب است.
