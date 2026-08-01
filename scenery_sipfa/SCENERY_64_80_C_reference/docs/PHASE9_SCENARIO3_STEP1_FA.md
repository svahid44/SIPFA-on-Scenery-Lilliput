# سناریوی ۳، قدم اول: fault معلوم و infection-based countermeasure

## هدف

این مرحله، بخش ابتدایی Algorithm 3 مرجع SIPFA را روی SCENERY-64/80 پیاده‌سازی می‌کند. هدف فعلی بازیابی یک word چهاربیتی از `SK28` است تا مدل infection و معیار minimum-frequency به‌صورت مستقل اعتبارسنجی شوند.

## مدل مهاجم

مهاجم موارد زیر را می‌داند:

- شماره logical S-box خراب؛
- ورودی fault یعنی `delta`؛
- مجموعه ciphertextهای عمومی.

مهاجم موارد زیر را نمی‌داند:

- کلید اصلی؛
- `SK28` واقعی؛
- plaintextهای داخلی؛
- برچسب رخداد مؤثر یا بی‌اثر؛
- ciphertext صحیح یا faulted داخلی؛
- بلوک تصادفی استفاده‌شده برای infection.

## مدل infection مطابق Algorithm 3

برای هر plaintext تصادفی، رمزنگاری صحیح و faulted داخل شبیه‌ساز محاسبه می‌شوند.

اگر:

```text
C_correct == C_faulty
```

رخداد بی‌اثر است و خروجی عمومی برابر ciphertext صحیح خواهد بود.

اگر:

```text
C_correct != C_faulty
```

رخداد مؤثر است و countermeasure یک بلوک تصادفی مستقل ۶۴‌بیتی منتشر می‌کند:

```text
C_public = random64
```

در هر دو حالت دقیقاً یک ciphertext عمومی منتشر می‌شود و مهاجم نمی‌فهمد نمونه متعلق به کدام حالت بوده است.

## تفاوت با سناریوی ۱

در detection-based countermeasure فقط رخدادهای بی‌اثر منتشر می‌شدند؛ بنابراین مقدار هدف در histogram کاملاً غایب بود.

در infection-based countermeasure خروجی‌های تصادفی bins را پر می‌کنند. در نتیجه مقدار هدف معمولاً صفر نیست، اما انتظار می‌رود کم‌فراوان‌ترین مقدار باشد.

برای logical S-box شماره `j`:

```text
minimum[j] = delta XOR SK28[j]
```

و بنابراین:

```text
SK28[j] = minimum[j] XOR delta
```

## نگاشت روی SCENERY

در SCENERY، نیمه چپ ciphertext برابر حالت عمومی پیش از XOR کلید دور آخر است. ابزار حمله از تابع عمومی زیر برای استخراج word منطقی هدف استفاده می‌کند:

```c
scenery_last_round_public_word(ciphertext, target_sbox)
```

سپس histogram شانزده‌خانه‌ای ساخته می‌شود و minimum یکتا استخراج می‌شود.

## اجرای مرجع

پارامترهای آزمایش:

```text
target_sbox = 3
known_delta = 0x5
published_samples = 32768
```

آمار داخلی شبیه‌سازی:

```text
internal ineffective = 5342
internal infected    = 27426
empirical rate       = 0.163024902
theoretical rate     = 0.164132936
```

نتیجه histogram:

```text
minimum value        = 0x9
minimum count        = 1654
second minimum count = 2002
minimum gap          = 348
```

بازیابی:

```text
recovered SK28[3] = 0x9 XOR 0x5 = 0xC
actual SK28[3]    = 0xC
```

نتیجه:

```text
PASS
```

## مرز حمله و verification

فایل عمومی فقط شامل این ستون‌ها است:

```text
sample_index,ciphertext
```

تابع حمله فقط ciphertext، شماره S-box و `delta` را دریافت می‌کند. کلید واقعی پس از تکمیل بازیابی و فقط برای verification محاسبه می‌شود.

## فایل‌های جدید

```text
include/infection_dataset.h
include/known_infection_attack.h
src/infection_dataset.c
src/known_infection_attack.c
tests/test_known_infection_attack.c
tools/scenario3_collect_known_infection.c
tools/scenario3_recover_word.c
```

## قدم بعدی

در قدم بعد، همین کمپین برای هر هشت logical S-box به‌صورت مستقل اجرا می‌شود تا تمام هشت word چهاربیتی `SK28` با معیار minimum-frequency بازیابی و کل subkey سی‌ودوبیتی مونتاژ شود.
