# گزارش نهایی سناریوی ۲ SIPFA روی SCENERY-64/80

## ۱. دامنه سناریو

این سناریو متناظر با **Algorithm 2** مقاله اصلی SIPFA است:

- countermeasure از نوع detection؛
- محل fault پایدار برای مهاجم ناشناخته؛
- ورودی خراب `delta` برای مهاجم ناشناخته؛
- داده عمومی فقط ciphertextهای بی‌اثر است؛
- تحلیل با شناسایی محل fault، حدس بیت‌های فعال `SK28` و partial decryption دور آخر انجام می‌شود.

هدف نهایی این پروژه عمداً به‌صورت صادقانه چنین تعریف شده است:

```text
18/20 active SK28 bits + unique delta
with four structurally equivalent candidates
```

ادعای بازیابی یکتای تمام ۲۰ بیت یا کل `SK28` در این سناریو مطرح نمی‌شود.

## ۲. نتیجه اجرای ثابت

پارامتر شبیه‌سازی مرجع:

```text
secret S-box = 5
secret delta = 0xB
public missing value = 0xC
```

مرحله شناسایی عمومی بدون دسترسی به ground truth به نتیجه زیر رسید:

```text
detected S-box = 5
public missing = 0xC
```

در مرحله partial decryption تمام فضای فعال زیر بررسی شد:

```text
2^20 = 1,048,576 candidates
```

چهار نامزد باقی ماندند:

```text
0x3B37E
0x3B77E
0x3BB7E  <- actual candidate
0x3BF7E
```

اجماع آن‌ها:

| Role | Source S-box | Known mask | Known value | Known bits |
|---|---:|---:|---:|---:|
| A | 4 | `0xF` | `0xE` | 4 |
| B | 5 | `0xF` | `0x7` | 4 |
| C | 7 | `0x3` | `0x3` | 2 |
| D | 0 | `0xF` | `0xB` | 4 |
| E | 1 | `0xF` | `0x3` | 4 |

بنابراین:

```text
recovered active bits = 18/20
recovered delta       = 0xC XOR 0x7 = 0xB
```

دو بیت مبهم متعلق به role C هستند و ابهام آن‌ها از dependency واقعی MixColumns ناشی می‌شود. افزایش تعداد نمونه این چهارگانگی ساختاری را حذف نمی‌کند.

## ۳. طراحی آزمایش‌های تکراری

برای ارزیابی مقاله‌ای، ۱۰۰ اجرای مستقل انجام شد. در هر اجرا موارد زیر تصادفی بودند:

- کلید اصلی ۸۰بیتی؛
- محل S-box خراب از میان ۸ S-box منطقی؛
- مقدار `delta` از میان ۱۶ ورودی S-box؛
- seed تولید plaintextها.

شبکه تعداد ciphertextهای بی‌اثر عمومی:

```text
64, 96, 128, 160, 192, 256, 320, 384, 512
```

برای هر نقطه موارد زیر ثبت شد:

- موفقیت مکان‌یابی محل fault؛
- حفظ نامزد واقعی در مجموعه نامزدها؛
- بازیابی یکتای `delta`؛
- تعداد بیت‌های قطعی active key؛
- تعداد نامزدهای باقی‌مانده؛
- تعداد oracle query؛
- تعداد candidate-sample evaluation.

## ۴. منحنی موفقیت

| Public ineffective samples | Localization | Unique delta | 18/20 + delta | Median candidates |
|---:|---:|---:|---:|---:|
| 64 | 11% | 0% | 0% | 247460 |
| 96 | 82% | 0% | 0% | 33998 |
| 128 | 95% | 0% | 0% | 4380 |
| 160 | 100% | 0% | 0% | 578 |
| 192 | 100% | 0% | 0% | 76 |
| 256 | 100% | 73% | 68% | 4 |
| 320 | 100% | 98% | 96% | 4 |
| 384 | 100% | 99% | 97% | 4 |
| 512 | 100/100 | 100/100 | 100/100 | 4 |

فاصله Wilson نودوپنج درصد برای نتیجه `100/100` تقریباً برابر است با:

```text
[96.3%, 100%]
```

بنابراین عبارت علمی مناسب «۱۰۰ موفقیت مشاهده‌شده در ۱۰۰ اجرا» است، نه احتمال ریاضی قطعی ۱۰۰ درصد.

## ۵. آستانه‌های مشاهده‌شده

### مکان‌یابی fault

- حداقل ۹۰٪: ۱۲۸ نمونه؛
- حداقل ۹۹٪: ۱۶۰ نمونه؛
- `100/100`: ۱۶۰ نمونه.

### بازیابی یکتای delta

- حداقل ۵۰٪: ۲۵۶ نمونه؛
- حداقل ۹۵٪: ۳۲۰ نمونه؛
- حداقل ۹۹٪: ۳۸۴ نمونه؛
- `100/100`: ۵۱۲ نمونه.

### نتیجه کامل این سناریو: ۱۸/۲۰ بیت + delta یکتا

- حداقل ۵۰٪: ۲۵۶ نمونه؛
- حداقل ۹۵٪: ۳۲۰ نمونه؛
- حداقل ۹۹٪ و `100/100`: ۵۱۲ نمونه.

## ۶. پیچیدگی داده

میانگین oracle query:

| Samples | Mean queries | Standard deviation |
|---:|---:|---:|
| 64 | 388.17 | 43.91 |
| 128 | 786.68 | 61.23 |
| 256 | 1563.26 | 88.47 |
| 320 | 1950.69 | 96.65 |
| 384 | 2340.53 | 108.13 |
| 512 | 3115.36 | 125.81 |

نرخ نظری رخداد بی‌اثر:

```text
(15/16)^28 = 0.164132936375
```

میانگین نرخ تجربی در ۵۱۲ نمونه:

```text
0.164610545787
```

## ۷. پیچیدگی محاسباتی

فضای کلید فعال در تمام اجراها ثابت است:

```text
2^20 candidates
```

در اجرای ۵۱۲نمونه‌ای، میانگین تعداد candidate-sample evaluation برابر بود با:

```text
56,845,647.16
```

تعداد evaluation تقریباً از ۱۶۰ نمونه به بعد ثابت می‌شود، زیرا اکثر نامزدهای غلط پس از مشاهده هر ۱۶ مقدار خیلی زود حذف می‌شوند و فقط نامزدهای ساختاری تا انتهای dataset باقی می‌مانند.

## ۸. یکنواختی نسبت به محل و مقدار fault

در بیشینه dataset یعنی ۵۱۲ نمونه:

- هر هشت محل S-box در تمام trialهای مربوط به خود موفق بودند؛
- هر شانزده مقدار `delta` در تمام trialهای مربوط به خود موفق بودند؛
- برای همه آن‌ها ۱۸ بیت قطعی و چهار نامزد ساختاری به دست آمد.

تعداد trial در هر گروه دقیقاً برابر نبود، زیرا محل و delta به‌صورت تصادفی انتخاب شدند. داده خام برای بازبینی کامل در CSVها موجود است.

## ۹. مرز اطلاعات مهاجم

ورودی عمومی حمله فقط شامل موارد زیر است:

```text
ineffective ciphertexts
```

مرحله عمومی به کلید، plaintext، محل واقعی fault یا `delta` واقعی دسترسی ندارد. ground truth فقط پس از پایان حمله برای این موارد استفاده می‌شود:

- بررسی حضور نامزد واقعی؛
- بررسی درستی بیت‌های consensus؛
- بررسی درستی `delta` بازیابی‌شده؛
- محاسبه نرخ موفقیت آزمایش‌ها.

تابع prefix profiler فقط یک ابزار بهینه‌سازی برای آزمایش‌های تکراری است. این ابزار نتایج همان فیلتر `2^20` را برای چند prefix با یک پیمایش مشترک محاسبه می‌کند و منطق حمله یا معیار پذیرش نامزد را تغییر نمی‌دهد.

## ۱۰. خروجی‌های آماده مقاله

### داده خام

```text
results/scenario2_repeated_trials.csv
results/scenario2_repeated_roles.csv
```

### خلاصه آماری

```text
results/scenario2_success_curve.csv
results/scenario2_complexity.csv
results/scenario2_per_sbox_performance.csv
results/scenario2_per_delta_performance.csv
results/scenario2_role_recovery.csv
results/scenario2_success_thresholds.csv
results/scenario2_final_analysis_summary.json
```

### شکل‌ها

سیزده شکل، هرکدام در سه قالب PNG، PDF و SVG:

```text
paper_artifacts/scenario2/figures/
```

### جدول‌ها

جدول‌های CSV، Markdown و LaTeX:

```text
paper_artifacts/scenario2/tables/
```

### داشبورد Excel

```text
paper_artifacts/scenario2/SCENARIO2_ANALYSIS.xlsx
```

## ۱۱. نتیجه نهایی قابل‌استفاده در مقاله

> Algorithm 2 of SIPFA was instantiated on SCENERY by deriving a 20-bit active last-round subkey space from the cipher's MixColumns dependency. Across 100 independent random-key, random-location, and random-delta trials, 512 public ineffective ciphertexts yielded correct fault localization, unique recovery of the persistent-fault input, retention of the true key candidate, and recovery of 18 of the 20 active subkey bits in all 100 observed trials. The remaining two bits form a four-candidate structural equivalence class and are not identifiable from this observation alone.

## ۱۲. ادعایی که نباید مطرح شود

عبارت‌های زیر نادرست‌اند:

```text
Scenario 2 uniquely recovers all 20 active bits.
Scenario 2 recovers the complete SK28.
Scenario 2 recovers the 80-bit master key.
```

عبارت درست:

```text
Scenario 2 recovers 18/20 active SK28 bits and the unknown delta uniquely,
leaving four structurally equivalent active-key candidates.
```
