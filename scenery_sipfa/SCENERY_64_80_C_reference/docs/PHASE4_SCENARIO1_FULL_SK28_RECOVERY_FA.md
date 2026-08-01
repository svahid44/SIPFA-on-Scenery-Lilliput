# فاز چهارم سناریوی ۱ — بازیابی کامل SK28 با هشت کمپین Algorithm 1

## هدف

در فاز سوم فقط چهار بیت متناظر با یک S-box منطقی بازیابی شد. در این فاز همان حمله برای هر هشت S-box منطقی SCENERY تکرار می‌شود و هشت کلمه چهار‌بیتی بازیابی‌شده، کل subkey دور آخر را تشکیل می‌دهند.

این مرحله متناظر مستقیم با حلقه زیر در Algorithm 1 اصلی SIPFA روی DES است:

```text
for Fault.Sbox = 0 to 7:
    collect ineffective ciphertexts
    find the unique missing value X
    rk[Fault.Sbox] = X XOR delta
compose the complete final-round subkey
```

## انتخاب delta

کد اصلی DES یک `row/col` را یک‌بار انتخاب می‌کند و همان ورودی خراب را هنگام تکرار حمله روی S-boxهای ۰ تا ۷ استفاده می‌کند. برای حفظ همین ساختار، در SCENERY نیز مقدار معلوم زیر در هر هشت کمپین استفاده شده است:

```text
delta = 0x5
S(delta) = 0xE
S_faulty(delta) = 0xF
```

هر کمپین فقط یک S-box منطقی را خراب می‌کند و مستقل از کمپین‌های دیگر است.

## رابطه بازیابی

برای S-box منطقی j در دور ۲۸:

```text
X28[j] = V28[j] XOR SK28[j]
```

در یک ciphertext بی‌اثر، ورودی خراب در هیچ دوری ظاهر نشده است؛ بنابراین در دور آخر نیز:

```text
X28[j] != delta
```

پس مقدار زیر از histogram شانزده‌خانه‌ای `V28[j]` غایب است:

```text
missing[j] = delta XOR SK28[j]
```

و:

```text
SK28[j] = missing[j] XOR delta
```

## مرز اطلاعات مهاجم

فرآیند به دو برنامه مستقل تقسیم شده است:

1. `scenario1_collect_all_detection` هشت dataset بی‌اثر را تولید می‌کند.
2. `scenario1_recover_full_key` فقط CSV منتشرشده و delta معلوم را می‌خواند.

کلید اصلی یا SK28 واقعی وارد تابع حمله نمی‌شود. مقدار واقعی فقط پس از پایان حمله برای verification محاسبه می‌شود.

## نتایج مرجع

| S-box | مقدار غایب | کلمه بازیابی‌شده | کلمه واقعی |
|---:|---:|---:|---:|
| 0 | 0xE | 0xB | 0xB |
| 1 | 0x6 | 0x3 | 0x3 |
| 2 | 0xF | 0xA | 0xA |
| 3 | 0x9 | 0xC | 0xC |
| 4 | 0xB | 0xE | 0xE |
| 5 | 0x2 | 0x7 | 0x7 |
| 6 | 0x5 | 0x0 | 0x0 |
| 7 | 0xE | 0xB | 0xB |

پس از مونتاژ bitslice:

```text
Recovered SK28 = A3B7389D
Actual SK28    = A3B7389D
```

## پیچیدگی داده اجرای مرجع

- ineffective برای هر S-box: 4096
- تعداد کمپین‌ها: 8
- کل ineffectiveها: 32768
- کل پرس‌وجوها: 200337
- کل رخدادهای مؤثر مسدودشده: 167569
- نرخ aggregate تجربی: 0.163564394
- نرخ نظری هر کمپین: `(15/16)^28 = 0.164132936`

## فایل‌های جدید

```text
tests/test_known_detection_full_attack.c
tools/scenario1_collect_all_detection.c
tools/scenario1_recover_full_key.c
docs/PHASE4_SCENARIO1_FULL_SK28_RECOVERY_FA.md
APPLY_PHASE4_FA.md
```

فایل‌های زیر توسعه یافته‌اند:

```text
include/known_detection_attack.h
src/known_detection_attack.c
Makefile
CMakeLists.txt
README_FA.md
```

## خروجی‌های CSV

```text
results/scenario1_all_sboxes_ineffective.csv
results/scenario1_all_sboxes_detection_summary.csv
results/scenario1_all_sboxes_histograms.csv
results/scenario1_full_sk28_summary.csv
```

## دامنه ادعا

این فاز کل subkey دور ۲۸ را بازیابی می‌کند، نه کلید اصلی ۸۰ بیتی. ادامه مستقیم Algorithm 1، معکوس‌کردن دور آخر با SK28 و بازیابی SK27 از همان datasetهای بی‌اثر است.
