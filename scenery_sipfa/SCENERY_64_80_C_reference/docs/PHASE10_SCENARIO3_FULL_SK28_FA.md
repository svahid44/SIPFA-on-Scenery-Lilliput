# سناریوی ۳، قدم دوم: بازیابی کامل SK28 با Algorithm 3

## هدف

در قدم اول، معیار minimum-frequency برای یک logical S-box از SCENERY تأیید شد. در این مرحله همان حمله برای هر هشت logical S-box به‌صورت مستقل اجرا می‌شود تا هشت word چهاربیتی کلید دور آخر بازیابی و سپس `SK28` سی‌ودوبیتی مونتاژ شود.

این مرحله ادامه مستقیم Algorithm 3 مرجع SIPFA است؛ تفاوت آن با پیاده‌سازی DES فقط در دامنه چهاربیتی S-box و نمایش bitslice کلید دور SCENERY است.

## مدل حمله

برای هر کمپین، مهاجم می‌داند:

- شماره logical S-box خراب؛
- ورودی fault یعنی `delta`؛
- ciphertextهای عمومی منتشرشده.

مهاجم نمی‌داند:

- کلید اصلی ۸۰بیتی؛
- `SK28` واقعی؛
- plaintextهای داخلی؛
- برچسب effective یا ineffective؛
- ciphertextهای صحیح و faulted داخلی؛
- خروجی تصادفی infection.

## هشت کمپین مستقل

برای هر `j` از صفر تا هفت، یک fault پایدار روی همان logical S-box و ورودی معلوم `delta=0x5` اعمال می‌شود. در هر query:

```text
C_correct == C_faulty  =>  C_public = C_correct
C_correct != C_faulty  =>  C_public = random64
```

برای جلوگیری از انتقال وضعیت یا تصادف‌های یکسان میان کمپین‌ها، هر S-box seed مستقل و قطعی دارد. فایل عمومی شامل شماره کمپین، شماره نمونه و ciphertext است:

```text
target_sbox,sample_index,ciphertext
```

شماره S-box در سناریوی ۳ محرمانه نیست، زیرا محل fault برای مهاجم معلوم فرض شده است.

## بازیابی هر word

برای هر S-box یک histogram شانزده‌خانه‌ای از word عمومی دور آخر ساخته می‌شود. به دلیل خروجی‌های infection، مقدار هدف غایب نیست؛ اما طبق Algorithm 3 باید کم‌فراوان‌ترین مقدار یکتا باشد:

```text
minimum[j] = delta XOR SK28[j]
```

در نتیجه:

```text
SK28[j] = minimum[j] XOR delta
```

شرط پذیرش هر کمپین:

```text
minimum_multiplicity = 1
```

یعنی کمینه باید یکتا باشد. فاصله آماری زیر نیز برای گزارش ثبت می‌شود:

```text
minimum_gap = second_minimum_count - minimum_count
```

## مونتاژ bitslice

هشت word بازیابی‌شده به‌ترتیب logical S-boxهای صفر تا هفت هستند. تابع زیر آن‌ها را به نمایش خارجی ۳۲بیتی کلید دور تبدیل می‌کند:

```c
scenery_compose_round_key_sbox_words(recovered_words)
```

این تابع بیت `r` از word شماره `j` را در بیت `j` از بایت ردیف `r` قرار می‌دهد؛ بنابراین معکوس دقیق تابع استخراج bitslice است.

## نتیجه اجرای مرجع

پارامترها:

```text
known delta               = 0x5
published per S-box       = 32768
number of campaigns       = 8
total public outputs      = 262144
```

آمار داخلی شبیه‌سازی:

```text
total ineffective         = 43547
total infected            = 218597
empirical ineffective rate= 0.166118622
theoretical rate          = 0.164132936
```

نتیجه هشت histogram:

| S-box | minimum | minimum count | second minimum | gap | recovered word | actual word |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | `0xE` | 1672 | 1986 | 314 | `0xB` | `0xB` |
| 1 | `0x6` | 1637 | 2019 | 382 | `0x3` | `0x3` |
| 2 | `0xF` | 1745 | 2010 | 265 | `0xA` | `0xA` |
| 3 | `0x9` | 1740 | 1961 | 221 | `0xC` | `0xC` |
| 4 | `0xB` | 1694 | 2010 | 316 | `0xE` | `0xE` |
| 5 | `0x2` | 1714 | 1982 | 268 | `0x7` | `0x7` |
| 6 | `0x5` | 1774 | 2012 | 238 | `0x0` | `0x0` |
| 7 | `0xE` | 1762 | 1994 | 232 | `0xB` | `0xB` |

هشت word بازیابی‌شده:

```text
[B, 3, A, C, E, 7, 0, B]
```

پس از مونتاژ bitslice:

```text
Recovered SK28 = A3B7389D
Actual SK28    = A3B7389D
```

نتیجه:

```text
successful S-boxes = 8/8
PASS
```

## مرز attack و verification

برنامه `scenario3_recover_full_key` ابتدا فقط dataset عمومی و `delta` معلوم را می‌خواند و کلید را بازیابی می‌کند. کلید اصلی ثابت آزمایش فقط بعد از پایان حمله برای محاسبه `actual_sk28` و verification معرفی می‌شود.

بنابراین attack core هیچ دسترسی‌ای به master key یا round key واقعی ندارد.

## فایل‌های اضافه‌شده

```text
tests/test_known_infection_full_attack.c
tools/scenario3_collect_all_infection.c
tools/scenario3_recover_full_key.c
```

فایل‌های توسعه‌یافته:

```text
include/known_infection_attack.h
src/known_infection_attack.c
Makefile
CMakeLists.txt
README_FA.md
```

## محدوده نتیجه

این مرحله کل subkey دور آخر یعنی `SK28` را بازیابی می‌کند. مطابق تصمیم پروژه، بازیابی دورهای قبل یا master key در سناریوی ۳ در این مرحله انجام نمی‌شود.

قدم بعدی پس از تأیید اجرای WSL، آزمایش‌های تکرارشونده روی کلید، `delta` و S-boxهای تصادفی و تولید نمودارها و جدول‌های مقاله برای نهایی‌کردن سناریوی ۳ است.
