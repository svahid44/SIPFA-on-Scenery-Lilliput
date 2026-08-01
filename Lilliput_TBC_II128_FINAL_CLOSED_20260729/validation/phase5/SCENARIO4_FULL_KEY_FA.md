# اعتبارسنجی فاز ۵ — بستن کامل سناریوی ۴

## هدف

بازیابی زنجیرهٔ کامل زیر برای `Lilliput-TBC-II-128` در سناریوی خطای ماندگار ناشناخته و countermeasure از نوع infection:

```text
unlabeled published ciphertexts
        ↓ SIPFA Algorithm 4 / SEI
unknown δ + RTK[31]
        ↓ one-round peeling
penultimate-round distributions
        ↓ SIPFA Algorithm 3 / minimum count
RTK[30]
        ↓ Lilliput tweakey-schedule inversion over GF(2)
128-bit master key
```

## مرز ورودی حمله

تابع نهایی فقط این داده‌ها را دریافت می‌کند:

- ciphertextهای منتشرشده و بدون برچسب؛
- تعداد نمونه‌ها؛
- tweak عمومی.

موارد زیر وارد API حمله نمی‌شوند:

- کلید اصلی؛
- plaintextها؛
- برچسب effective/ineffective؛
- مقدار واقعی خطا یا خروجی faulty؛
- RTKهای واقعی؛
- traceهای اعتبارسنجی.

## تطبیق با مقاله

1. تعیین `δ` و `RTK[31]` همان مرحلهٔ candidate ranking با SEI در Algorithm 4 است.
2. بعد از معلوم‌شدن `δ` و `RTK[31]`، یک دور partial decryption انجام می‌شود. در این نقطه مدل به حالت known-fault تبدیل شده و کمینهٔ فراوانی در هر lane مطابق Algorithm 3 برای `RTK[30]` استفاده می‌شود.
3. تبدیل دو RTK به کلید اصلی در مقالهٔ SIPFA برای Lilliput نوشته نشده است. این گام، تخصصی‌سازی شفاف و مستقل برای Tweakey Schedule رسمی Lilliput است و با یک دستگاه `128×128` روی `GF(2)` انجام می‌شود.

## نتیجهٔ مرجع

برای پارامترهای پیش‌فرض:

```text
samples              = 100000
secret δ             = 0x5a
recovered δ          = 0x5a
RTK[31]              = b3ed58adabab101d
RTK[30]              = 8ae2660cd1ea6cc0
GF(2) rank           = 128
master key           = 000102030405060708090a0b0c0d0e0f
validation ciphertext= fdb0d1a0b68a8e3c9579e9aa7a5704b9
```

سه مدل خطای مستقل با `δ ∈ {0x00,0x5a,0xff}` و سه مقدار متفاوت `fault_xor` همگی PASS شده‌اند.

## محدودیت‌های ادعا

این بسته فقط مدل زیر را اعتبارسنجی می‌کند:

- یک خطای ماندگار روی یک ورودی S-box مشترک؛
- خروجی infection تصادفی مطابق شبیه‌ساز پروژه؛
- tweak عمومی و ثابت؛
- ۱۰۰هزار ciphertext منتشرشده؛
- بدون missed fault، نویز اضافی، چندخطایی یا countermeasure متفاوت.

بنابراین نتیجه به‌معنی اثبات تجربی برای تمام دستگاه‌ها و تمام مدل‌های نویز نیست.
