# گزارش تست Phase 10 — بازیابی کامل SK28 در سناریوی ۳

## نتیجه عملکردی

هشت کمپین مستقل known-fault + infection اجرا شدند. در هر کمپین ۳۲۷۶۸ خروجی عمومی منتشر شد و مهاجم بدون دریافت برچسب رخداد، کمینه یکتای histogram را استخراج کرد.

```text
successful S-boxes = 8/8
recovered SK28     = A3B7389D
actual SK28        = A3B7389D
```

کمترین فاصله میان کمینه و دومین مقدار کم‌فراوان در اجرای مرجع برابر ۲۲۱ و بیشترین فاصله برابر ۳۸۲ بود. تمام کمینه‌ها یکتا بودند.

## سازگاری آماری

```text
total public outputs       = 262144
total ineffective          = 43547
total infected             = 218597
empirical ineffective rate = 0.166118622
theoretical rate           = 0.164132936
```

## اعتبارسنجی ساخت و اجرا

```text
GCC build/test:             PASS
Clang build/test:           PASS
CMake/CTest:                13/13 PASS
AddressSanitizer:           PASS
UndefinedBehaviorSanitizer: PASS
Full SK28 recovery:         PASS
```

## مرز مهاجم

Dataset عمومی تنها شامل `target_sbox`, `sample_index` و `ciphertext` است. target S-box و delta در سناریوی ۳ معلوم فرض می‌شوند. master key و `SK28` واقعی فقط پس از پایان attack برای verification استفاده شده‌اند.
