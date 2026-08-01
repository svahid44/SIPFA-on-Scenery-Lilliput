# فاز ۷ — سناریوی ۲، قدم دوم: جست‌وجوی کلید فعال و Partial Decryption

## هدف

این فاز مراحل ۱۰ تا ۱۶ Algorithm 2 مقاله SIPFA را روی SCENERY-64/80 پیاده‌سازی می‌کند. ورودی حمله فقط شامل موارد زیر است:

- ciphertextهای بی‌اثر منتشرشده؛
- شماره S-box خراب که در قدم اول پیدا شد؛
- مقدار عمومی غایب دور آخر.

تابع حمله به کلید اصلی، `SK28` واقعی، `delta` واقعی، plaintextها یا فایل ground truth دسترسی ندارد.

## معکوس‌سازی یک دور SCENERY

برای دور آخر داریم:

```text
L29 = R28 XOR F(L28, SK28)
R29 = L28
C = R29 || L29
```

پس:

```text
L28 = C_left
L27 = R28 = C_right XOR F(C_left, SK28)
```

برای بررسی خاصیت غیبت در S-box خراب شماره `j` فقط کلمه منطقی `L27[j]` لازم است.

## بیت‌های فعال SK28

خروجی کلمه `j` از MixColumns فقط به پنج خروجی S-box وابسته است. ترتیب نقش‌ها در کد چنین است:

```text
A = j-1
B = j
C = j+2
D = j+3
E = j+4       (mod 8)
```

برای `j = 5`:

```text
A,B,C,D,E = 4,5,7,0,1
```

بنابراین فضای فعال برابر است با:

```text
5 words × 4 bits = 20 bits
2^20 = 1,048,576 candidates
```

سه word شماره ۲، ۳ و ۶ در محاسبه `L27[5]` دخالت ندارند و در این قدم حدس زده نمی‌شوند.

## معیار فیلتر Algorithm 2

برای هر نامزد ۲۰بیتی:

1. دور ۲۸ برای word هدف به‌صورت جزئی معکوس می‌شود؛
2. histogram شانزده‌مقداری `L27[j]` ساخته می‌شود؛
3. اگر تمام ۱۶ مقدار دیده شوند، نامزد حذف می‌شود؛
4. اگر حداقل یک مقدار غایب باشد، نامزد نگه داشته می‌شود.

این همان معیار missing-value دور قبل در Algorithm 2 است.

## نتیجه اجرای مرجع

پارامترهای عمومی:

```text
ineffective samples = 512
detected S-box      = 5
public missing      = 0xC
```

فضای کامل جست‌وجوشده:

```text
tested candidates = 1,048,576
candidate-sample evaluations = 56,845,492
```

چهار نامزد باقی ماندند:

| Packed | A=SK28[4] | B=SK28[5] | C=SK28[7] | D=SK28[0] | E=SK28[1] | Missing in round 27 |
|---|---:|---:|---:|---:|---:|---:|
| `0x3B37E` | E | 7 | 3 | B | 3 | 4 |
| `0x3B77E` | E | 7 | 7 | B | 3 | 5 |
| `0x3BB7E` | E | 7 | B | B | 3 | 5 |
| `0x3BF7E` | E | 7 | F | B | 3 | 4 |

نامزد واقعی:

```text
actual packed active key = 0x3BB7E
```

در مجموعه نامزدها حضور دارد.

## بازیابی بیت‌های فعال

اجماع چهار نامزد:

| Role | S-box | Known mask | Known value | Bits recovered |
|---|---:|---:|---:|---:|
| A | 4 | F | E | 4 |
| B | 5 | F | 7 | 4 |
| C | 7 | 3 | 3 | 2 |
| D | 0 | F | B | 4 |
| E | 1 | F | 3 | 4 |

در مجموع:

```text
18 / 20 active key bits recovered
```

## بازیابی delta

از قدم اول داریم:

```text
public_missing = delta XOR SK28[5]
```

چون word نقش B در تمام نامزدها دقیقاً `0x7` است:

```text
delta = 0xC XOR 0x7 = 0xB
```

پس مقدار fault نیز بدون خواندن ground truth بازیابی می‌شود.

## علت باقی‌ماندن چهار نامزد

این ابهام با افزایش تعداد نمونه از بین نمی‌رود. در word نقش C فقط بیت صفر خروجی S-box وارد word هدف MixColumns می‌شود. برای این مؤلفه، چهار مقدار کلید زیر توابعی تولید می‌کنند که نسبت به معیار «وجود یک مقدار غایب» با یک انتقال ثابت قابل تفکیک نیستند:

```text
{0x3, 0x7, 0xB, 0xF}
```

در نتیجه دو بیت پایین `SK28[7]` تعیین می‌شوند، اما دو بیت بالایی در این مشاهده خاص نامشخص می‌مانند. این یک محدودیت ساختاری نگاشت Algorithm 2 به MixColumns الگوریتم SCENERY است، نه خطای برنامه و نه کمبود نمونه.

## مرز verification

دو ابزار جداگانه وجود دارد:

```text
scenario2_filter_active_key
scenario2_verify_active_key
```

ابزار اول فقط داده عمومی را می‌خواند و نامزدها را می‌سازد. ابزار دوم پس از پایان حمله، فایل ground truth را برای ارزیابی شبیه‌سازی می‌خواند.

## خروجی‌ها

```text
results/scenario2_active_key_candidates.csv
results/scenario2_active_key_consensus.csv
results/scenario2_candidate_previous_round_histograms.csv
results/scenario2_partial_decryption_summary.csv
results/scenario2_step2_verification.csv
```

## نتیجه

این فاز هدف اصلی قدم دوم Algorithm 2 را محقق می‌کند:

- جست‌وجوی تمام بیت‌های فعال `SK28`؛
- partial decryption دور آخر؛
- فیلتر نامزدها با خاصیت missing-value دور قبل؛
- حضور نامزد واقعی در مجموعه؛
- بازیابی ۱۸ بیت از ۲۰ بیت فعال؛
- بازیابی کامل `delta`.

ادعای بازیابی یکتای هر ۲۰ بیت مطرح نمی‌شود، زیرا چهار نامزد باقی‌مانده ناشی از ابهام ساختاری هستند.
