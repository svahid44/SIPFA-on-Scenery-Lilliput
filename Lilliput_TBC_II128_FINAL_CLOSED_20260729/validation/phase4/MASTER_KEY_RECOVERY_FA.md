# فاز ۴ — بازیابی کلید اصلی ۱۲۸بیتی در سناریوی ۱

## دامنه

این فاز ادامهٔ مستقیم خروجی فاز ۳ است:

- `RTK[31] = b3ed58adabab101d`
- `RTK[30] = 8ae2660cd1ea6cc0`
- tweak عمومی ۱۲۸بیتی
- سناریوی Known Fault + Detection-based
- همان dataset پذیرفته‌شده برای بازیابی دو RTK

هیچ مدل missed fault، نویز، چندخطا، plaintext داخل API حمله، یا دادهٔ ground-truth
به تابع بازیابی کلید داده نمی‌شود.

## مرز نسبت با مقاله SIPFA

Algorithm 1 مقاله SIPFA مسیر کلی زیر را بیان می‌کند:

1. بازیابی زیرکلید دور آخر؛
2. partial decryption؛
3. بازیابی زیرکلیدهای دورهای قبلی؛
4. رسیدن به کلید اصلی با استفاده از ساختار کلیدگذاری رمز هدف.

مقاله، Lilliput-TBC را بررسی نمی‌کند و دستگاه دقیق Tweakey Schedule آن را ارائه
نمی‌دهد. بنابراین بخش تبدیل `RTK[30]` و `RTK[31]` به master key یک
**تخصصی‌سازی cipher-specific بر اساس Tweakey Schedule رسمی Lilliput** است،
نه یک تکنیک خطای جدید و نه extension مربوط به missed fault/noise.

## معادلات

در Lilliput-TBC-II-128، حالت Tweakey شامل چهار lane شصت‌وچهاربیتی است:

- دو lane مربوط به tweak عمومی؛
- دو lane مربوط به کلید ۱۲۸بیتی.

برای دور `r`:

```text
RTK[r] =
    M^r(T0)
  XOR (M^2)^r(T1)
  XOR (M^3)^r(K0)
  XOR (M^4)^r(K1)
  XOR RC[r]
```

پس با معلوم بودن tweak:

```text
RTK[r] = A_r K XOR b_r(T)
```

برای دو دور ۳۰ و ۳۱:

```text
[ A_30 ] K = [ RTK[30] XOR b_30(T) ]
[ A_31 ]     [ RTK[31] XOR b_31(T) ]
```

این دو RTK در مجموع ۱۲۸ بیت خروجی می‌دهند و دستگاه حاصل یک ماتریس
`128×128` روی `GF(2)` است.

## روش ساخت ماتریس

برای هر بیت پایهٔ کلید `e_j`:

1. کلید پایه‌ای با فقط بیت `j` برابر یک ساخته می‌شود؛
2. سهم کلیدی آن در `RTK[30]` و `RTK[31]` با تبدیلات رسمی `M^3` و `M^4`
   محاسبه می‌شود؛
3. خروجی ۱۲۸بیتی به‌عنوان ستون `j` ماتریس قرار می‌گیرد.

بردار سمت راست با حذف سهم tweak و round constant از دو RTK بازیابی‌شده ساخته
می‌شود.

## حل

حل با Gaussian elimination روی `GF(2)` انجام می‌شود.

نتیجهٔ اجرای مرجع:

```text
equation count: 128
rank:           128
consistent:     yes
unique:         yes
```

کلید بازیابی‌شده:

```text
000102030405060708090a0b0c0d0e0f
```

کلید واقعی شبیه‌سازی:

```text
000102030405060708090a0b0c0d0e0f
```

## اعتبارسنجی

سه سطح اعتبارسنجی انجام شده است:

1. بازتولید دقیق `RTK[30]` و `RTK[31]` از کلید بازیابی‌شده؛
2. مقایسه با کلید واقعی فقط در لایهٔ validation؛
3. رمزگذاری یک plaintext مستقل با کلید واقعی و کلید بازیابی‌شده و مقایسه
   ciphertextها.

خروجی validation:

```text
fdb0d1a0b68a8e3c9579e9aa7a5704b9
```

## تست تصادفی

حل‌کننده روی ۲۵۶ زوج تصادفی مستقل از key/tweak، علاوه بر بردار ثابت پروژه،
اجرا شده است. برای همهٔ موارد:

```text
rank = 128
recovered key = actual key
encryption verification = PASS
```

## ورودی API حمله

تابع `lilliput_recover_master_key_from_rtk30_rtk31` فقط این ورودی‌ها را
دریافت می‌کند:

```text
public tweak
recovered RTK[30]
recovered RTK[31]
```

این تابع plaintext، ciphertext، کلید واقعی، RTK واقعی، trace داخلی یا helper
اعتبارسنجی دریافت نمی‌کند.
