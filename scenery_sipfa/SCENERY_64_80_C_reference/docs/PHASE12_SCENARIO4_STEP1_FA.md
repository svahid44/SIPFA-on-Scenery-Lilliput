# Phase 12 — سناریوی ۴، قدم اول: مکان‌یابی fault ناشناخته در حالت infection

## ۱. دامنه این مرحله

این فاز، بخش اول **Algorithm 4** مرجع SIPFA را روی SCENERY-64/80 پیاده‌سازی می‌کند:

- countermeasure از نوع infection است؛
- محل logical S-box خراب برای مهاجم ناشناخته است؛
- ورودی خراب `delta` برای مهاجم ناشناخته است؛
- تمام queryها یک ciphertext عمومی تولید می‌کنند؛
- خروجی عمومی هیچ برچسب effective/ineffective ندارد؛
- محل fault با معیار **Squared Euclidean Imbalance (SEI)** شناسایی می‌شود.

هدف این قدم بازیابی کلید نیست. خروجی علمی این مرحله عبارت است از:

```text
faulty logical S-box location
public minimum = delta XOR SK28[faulty_sbox]
16 coupled (delta, SK28 word) hypotheses
```

## ۲. oracle عمومی infection

برای هر plaintext تصادفی، شبیه‌ساز دو رمزنگاری داخلی انجام می‌دهد:

```text
C_correct = E_K(P)
C_faulty  = E_K^fault(P)
```

اگر رخداد بی‌اثر باشد:

```text
C_correct == C_faulty  =>  C_public = C_correct
```

اگر رخداد مؤثر باشد:

```text
C_correct != C_faulty  =>  C_public = random64
```

در هر دو حالت دقیقاً یک ciphertext عمومی منتشر می‌شود. فایل مهاجم فقط ساختار زیر را دارد:

```text
sample_index,ciphertext
```

آمار داخلی رخدادها فقط برای اعتبارسنجی شبیه‌سازی ذخیره می‌شود و به تابع حمله داده نمی‌شود.

## ۳. نگاشت Algorithm 4 روی SCENERY

SCENERY هشت logical S-box چهاربیتی را به‌صورت bitslice اجرا می‌کند. مدل fault این پروژه، مطابق مدل lane-local مرجع SIPFA، دقیقاً یک ورودی از یک logical S-box را به‌طور پایدار خراب می‌کند.

برای هر ciphertext عمومی، هشت word چهاربیتی دور آخر استخراج می‌شوند:

```text
V_j = scenery_last_round_public_word(C_public, j)
```

برای هر lane شماره `j` و مقدار `x`:

```text
p_j[x] = count_j[x] / N
```

معیار عدم‌تعادل مربعی برابر است با:

```text
SEI_j = sum_{x=0}^{15} (p_j[x] - 1/16)^2
```

خروجی‌های random infection توزیع هر lane را به سمت یکنواختی می‌برند. بااین‌حال بخش بی‌اثر در lane خراب هنوز اثر fault پایدار را حفظ می‌کند؛ بنابراین lane خراب باید بزرگ‌ترین SEI را داشته باشد.

شرط پذیرش این مرحله:

```text
unique argmax_j SEI_j
```

## ۴. minimum عمومی و ابهام زوجی

پس از شناسایی lane خراب، کم‌فراوان‌ترین مقدار آن lane محاسبه می‌شود. در اجرای کافی‌نمونه:

```text
public_minimum = delta XOR SK28[faulty_sbox]
```

چون هم `delta` و هم word کلید ناشناخته‌اند، این رابطه به‌تنهایی آن‌ها را جدا نمی‌کند. برای هر فرض `d` از صفر تا پانزده:

```text
candidate_delta = d
candidate_SK28_word = public_minimum XOR d
```

بنابراین قدم اول دقیقاً ۱۶ فرضیه زوجی باقی می‌گذارد. این ابهام شکست حمله نیست؛ مرز طبیعی بین بخش اول و دوم Algorithm 4 است.

## ۵. مرز حمله و ground truth

تابع اصلی حمله فقط این اطلاعات را می‌گیرد:

```text
unlabeled public ciphertexts
sample count
```

و این اطلاعات را دریافت نمی‌کند:

```text
master key
SK28
plaintexts
faulty S-box index
secret delta
fault output
effective/ineffective labels
correct/faulty internal ciphertexts
```

کلید و پارامترهای واقعی fault فقط پس از پایان حمله در ابزار شبیه‌سازی برای verification استفاده می‌شوند.

## ۶. اجرای مرجع

پارامترها:

```text
secret S-box        = 5
secret delta        = 0xB
published samples   = 32768
seed                = 0x6A09E667F3BCC909
actual SK28         = A3B7389D
actual SK28[5]      = 0x7
```

آمار oracle:

```text
internal ineffective = 5492
internal infected    = 27276
empirical rate       = 0.167602539062
theoretical rate     = 0.164132936375
```

نتیجه SEI:

| S-box | Rank | SEI | Minimum | Minimum count | Gap |
|---:|---:|---:|---:|---:|---:|
| 0 | 3 | `4.2133033e-05` | `0x4` | 1928 | 32 |
| 1 | 4 | `4.0246174e-05` | `0xE` | 1953 | 35 |
| 2 | 6 | `2.9765069e-05` | `0x8` | 1955 | 4 |
| 3 | 7 | `2.6561320e-05` | `0xC` | 1984 | 5 |
| 4 | 8 | `2.2556633e-05` | `0xA` | 1970 | 20 |
| **5** | **1** | **`1.8464029e-04`** | **`0xC`** | **1650** | **336** |
| 6 | 2 | `4.5835972e-05` | `0x8` | 1892 | 110 |
| 7 | 5 | `3.5814941e-05` | `0xA` | 1986 | 19 |

فاصله بهترین و دومین score:

```text
SEI gap = 0.000138804316521
```

رابطه عمومی بازیابی‌شده:

```text
0xC = delta XOR SK28[5]
```

فرض واقعی در مجموعه ۱۶تایی:

```text
delta = 0xB
SK28[5] = 0xC XOR 0xB = 0x7
```

نتیجه verification:

```text
localization match      = YES
minimum relation match  = YES
actual pair retained    = YES
status                  = PASS
```

## ۷. بررسی پوشش تمام محل‌ها و deltaها

علاوه بر تست ثابت، یک sweep قطعی روی تمام ترکیب‌ها انجام شد:

```text
8 S-box locations × 16 delta values = 128 experiments
```

با ۳۲٬۷۶۸ خروجی عمومی در هر آزمایش:

```text
correct localizations = 128/128
minimum observed SEI gap = 2.76789069176e-05
```

این نتیجه یک بررسی مهندسی فراگیر برای فاز فعلی است، نه جایگزین آزمایش‌های تکرارشونده تصادفی و فاصله اطمینان که در فاز نهایی سناریوی ۴ انجام خواهند شد.

## ۸. فایل‌های جدید

```text
include/unknown_infection_attack.h
src/unknown_infection_attack.c
tests/test_unknown_infection_attack.c
tools/scenario4_collect_unknown_infection.c
tools/scenario4_identify_fault.c
```

خروجی‌های اجرای مرجع:

```text
results/scenario4_unknown_infection_ciphertexts.csv
results/scenario4_unknown_infection_generation_summary.csv
results/scenario4_unknown_infection_histograms.csv
results/scenario4_fault_localization_scores.csv
results/scenario4_delta_key_word_candidates.csv
results/scenario4_fault_localization_summary.csv
results/scenario4_step1_verification.csv
```

## ۹. اجرای مرحله

```bash
make clean
make all
make test
make scenario4-step1
```

## ۱۰. قدم بعدی

قدم دوم، مجموعه‌ی ۱۶ فرضیه‌ی زوجی را با partial decryption دور آخر و معیار SEI دور قبل رتبه‌بندی می‌کند. به‌دلیل dependency واقعی `MixColumns`، فضای فعال و ابهام ساختاری باید به‌صورت تجربی و صادقانه اندازه‌گیری شود؛ تا قبل از اجرای آن مرحله، ادعای بازیابی یکتای `delta` یا کل `SK28` مطرح نمی‌شود.
