# فاز ۳ — بازیابی RTK[30] در سناریوی ۱

## محدوده

این فاز فقط حالت **known fault value + detection-based countermeasure** را
مطابق Algorithm 1 مقالهٔ SIPFA ادامه می‌دهد. ورودی تابع حمله شامل موارد زیر
است:

- ciphertextهای صحیح/پذیرفته‌شده توسط countermeasure؛
- مقدار معلوم ورودی معیوب S-box یعنی `delta`.

تابع حمله به plaintext، کلید اصلی، Tweak، label رخداد، RTK واقعی یا trace
داخلی دسترسی ندارد.

## نگاشت مقاله به Lilliput

شماره‌گذاری پیاده‌سازی صفرمبنا و شماره‌گذاری مقاله یک‌مبنا است:

- `RTK[31]` متناظر با `sk_n`؛
- `RTK[30]` متناظر با `sk_{n-1}`؛
- بایت‌های `C[0..7]` متناظر با `x_n`؛
- خروجی `lilliput_attack_extract_penultimate_inputs` متناظر با `x_{n-1}`.

برای هر lane در دور آخر:

```text
missing_n[lane] = delta XOR RTK[31][lane]
RTK[31][lane]   = missing_n[lane] XOR delta
```

سپس با RTK[31] بازیابی‌شده یک دور partial decryption انجام می‌شود و همان
ciphertextهای پذیرفته‌شده دوباره استفاده می‌شوند:

```text
C --peel(RTK[31])--> state before final round --> x_{n-1}
```

برای دور قبل:

```text
missing_{n-1}[lane] = delta XOR RTK[30][lane]
RTK[30][lane]       = missing_{n-1}[lane] XOR delta
```

## نکتهٔ روش‌شناختی

این فاز روش جدیدی اضافه نمی‌کند. مراحل recovery و one-round partial
decryption همان ادامهٔ Algorithm 1 مقاله هستند. تفاوت فقط نگاشت ساختار
Lilliput-TBC-II-128 و Round Tweakey آن به نمادگذاری عمومی مقاله است.

## نتیجهٔ مرجع

برای کلید و Tweak مرجع پروژه:

```text
RTK[31] = b3ed58adabab101d
RTK[30] = 8ae2660cd1ea6cc0
```

هر دو مقدار از همان مجموعهٔ ۵۰۰۰ ciphertext پذیرفته‌شده بازیابی شدند.
آزمایش برای سه fault متفاوت انجام شد:

```text
delta=0x00, fault_xor=0x01
delta=0x5a, fault_xor=0x80
delta=0xff, fault_xor=0x5a
```

در هر سه حالت، هر lane دقیقاً یک مقدار غایب داشت و هر دو RTK صحیح بازیابی
شدند.

## موارد عمداً خارج از این فاز

- تشکیل دستگاه معادلات کلید اصلی؛
- بازیابی کلید ۱۲۸بیتی؛
- سناریوی unknown fault؛
- سناریوی infection-based؛
- missed fault، noise، contamination و multiple faults.
