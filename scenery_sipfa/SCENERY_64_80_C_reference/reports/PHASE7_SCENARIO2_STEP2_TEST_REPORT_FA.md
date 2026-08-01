# گزارش تست فاز ۷ — سناریوی ۲، قدم دوم

## دامنه

- جست‌وجوی تمام `2^20` نامزد فعال `SK28`؛
- partial decryption یک دور؛
- histogram دور ۲۷؛
- فیلتر نامزدها بر اساس missing-value؛
- تحلیل اجماع بیت‌ها؛
- verification مستقل.

## نتیجه مرجع

```text
samples                    = 512
detected S-box             = 5
public missing             = 0xC
tested candidates          = 1,048,576
candidate-sample evals     = 56,845,492
surviving candidates       = 4
recovered active bits      = 18/20
recovered delta            = 0xB
actual candidate present   = YES
```

## تست partial decryption

خروجی helper برای نامزد واقعی با `L27[j]` موجود در trace رسمی رمزگذاری مقایسه شد و دقیقاً برابر بود.

## نامزدهای باقی‌مانده

```text
0x3B37E
0x3B77E
0x3BB7E
0x3BF7E
```

نامزد واقعی `0x3BB7E` است.

## محدودیت ساختاری

چهار نامزد فقط در word نقش C تفاوت دارند و مقادیر آن‌ها `{3,7,B,F}` است. در این مسیر MixColumns فقط یک مؤلفه Boolean از آن S-box را مشاهده می‌کند؛ بنابراین معیار missing-value دو بیت بالایی را تفکیک نمی‌کند.

## نتیجه تست ابزارها

| آزمون | نتیجه |
|---|---|
| تست‌وکتورهای رسمی | PASS |
| trace ۲۸ دور | PASS |
| key schedule | PASS |
| cross-validation Python/C | PASS |
| سناریوی ۱ | PASS |
| شناسایی fault ناشناخته | PASS |
| partial decryption helper | PASS |
| جست‌وجوی `2^20` | PASS |
| حضور نامزد واقعی | PASS |
| بازیابی delta | PASS |
| GCC | PASS |
| Clang | PASS |
| CMake/CTest | PASS |
| AddressSanitizer | PASS |
| UndefinedBehaviorSanitizer | PASS |
