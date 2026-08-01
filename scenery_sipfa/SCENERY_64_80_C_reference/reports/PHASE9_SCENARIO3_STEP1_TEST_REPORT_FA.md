# گزارش تست Phase 9 — سناریوی ۳، قدم اول

## نتیجه عملکردی

```text
published samples          = 32768
internal ineffective       = 5342
internal infected          = 27426
minimum value              = 0x9
minimum count              = 1654
second minimum count       = 2002
minimum gap                = 348
recovered SK28 word        = 0xC
actual SK28 word           = 0xC
status                     = PASS
```

## اعتبارسنجی

```text
GCC build                  PASS
Full Make test suite       PASS
Clang build/test           PASS
CMake/CTest                12/12 PASS
AddressSanitizer           PASS
UndefinedBehaviorSanitizer PASS
```

Warningهای sign-conversion مشاهده‌شده در build sanitizer مربوط به کدهای قبلی bitslice هستند و warning یا خطای جدیدی از فایل‌های سناریوی ۳ گزارش نشده است.

## نتیجه علمی

مدل infection همه queryها را منتشر می‌کند، اما رخدادهای مؤثر را با بلوک تصادفی مستقل جایگزین می‌کند. مقدار `delta XOR SK28[3]` در اثر بخش بی‌اثر جرم احتمالی کمتری دارد و در اجرای مرجع minimum یکتای histogram شد. این رفتار همان معیار minimum-frequency در Algorithm 3 است.
