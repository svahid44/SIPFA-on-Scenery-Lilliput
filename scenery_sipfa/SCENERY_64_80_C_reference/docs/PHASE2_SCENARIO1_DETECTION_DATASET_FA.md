# فاز دوم سناریوی ۱ — مدل تشخیصی و مجموعه‌داده رخدادهای بی‌اثر

## دامنه این فاز

این فاز دومین قدم سناریوی «fault معلوم و countermeasure تشخیصی» است. در این مرحله فقط oracle تشخیصی و جمع‌آوری داده ساخته می‌شود. histogram، استخراج مقدار غایب و بازیابی کلید دور آخر عمداً به قدم بعد موکول شده‌اند.

## تطابق با روش اصلی SIPFA روی DES

در Algorithm 1 مقاله SIPFA، مهاجم یک خطای پایدار معلوم را روی یک S-box مشخص ایجاد می‌کند. برای هر plaintext، اجرای صحیح و اجرای faulted در مدل آزمایش مقایسه می‌شوند. اگر خروجی‌ها متفاوت باشند، countermeasure تشخیصی رخداد مؤثر را تشخیص می‌دهد و هیچ ciphertext قابل استفاده‌ای به مهاجم نمی‌دهد. اگر خروجی‌ها برابر باشند، رخداد بی‌اثر است و ciphertext صحیح منتشر می‌شود.

همین منطق بدون تغییر مفهومی در SCENERY استفاده شده است:

```text
C_correct = Encrypt(P, K)
C_faulty  = EncryptFaulty(P, K)

اگر C_correct == C_faulty:
    نمونه ineffective است
    P و C_correct در dataset ذخیره می‌شوند
در غیر این صورت:
    نمونه effective است
    detector خروجی را مسدود می‌کند
```

کد جمع‌آوری هیچ ciphertext مربوط به رخداد مؤثر را به callback حمله تحویل نمی‌دهد.

## مدل fault استفاده‌شده

مدل همان فاز اول است:

```text
logical S-box = 3
delta         = 0x5
S(delta)      = 0xE
S_faulty      = 0xF = (0xE + 1) mod 16
```

fault روی یک خانه از یک S-box منطقی باقی می‌ماند و در همه ۲۸ دور و همه پرس‌وجوها تا reset فعال است.

## نرخ نظری رخداد بی‌اثر

برای یک S-box چهار بیتی، احتمال اجتناب از ورودی خراب در یک دور برابر `15/16` است. با فرض استاندارد یکنواخت و مستقل بودن ورودی S-box در ۲۸ دور، نرخ نظری مقاله برای این نگاشت برابر است با:

```text
P_ineffective = (15/16)^28
              ≈ 0.164132936375
```

این فرمول برای مدل تک-S-box منطقی معتبر است. اگر یک جدول مشترک به‌طور هم‌زمان هر هشت lane را خراب کند، این احتمال و الگوریتم حمله دیگر همین شکل را نخواهند داشت.

## فایل‌های افزوده‌شده

```text
include/detection_dataset.h
src/detection_dataset.c
tests/test_detection_dataset.c
tools/scenario1_collect_detection.c
docs/PHASE2_SCENARIO1_DETECTION_DATASET_FA.md
APPLY_PHASE2_FA.md
```

فایل‌های زیر نیز به‌روزرسانی شده‌اند:

```text
Makefile
CMakeLists.txt
README_FA.md
```

## API مجموعه‌داده

```c
int scenery_detection_collect(
    const scenery_ctx *ctx,
    uint64_t target_ineffective,
    uint64_t max_queries,
    uint64_t seed,
    scenery_detection_stats *stats,
    scenery_ineffective_callback callback,
    void *user_data
);
```

پارامتر `target_ineffective` تعداد خروجی‌های بی‌اثر موردنیاز را مشخص می‌کند. `max_queries` مانع حلقه نامحدود در صورت تنظیم نامعتبر یا نرخ غیرمنتظره می‌شود. PRNG از seed ثابت استفاده می‌کند تا آزمایش بازتولیدپذیر باشد.

## مرز اطلاعات مهاجم

فایل داده عمومی فقط شامل موارد زیر است:

```text
query_index
ineffective_index
plaintext
ciphertext
```

plaintext انتخاب مهاجم و ciphertext خروجی پذیرفته‌شده دستگاه هستند. در داده عمومی هیچ‌یک از موارد زیر قرار نمی‌گیرد:

- ciphertext faulted رخداد مؤثر؛
- محل فعال‌شدن fault در دورهای داخلی؛
- ورودی‌های میانی S-box؛
- round key یا master key؛
- خروجی خراب داخلی S-box.

شمارنده `effective_count` فقط برای ارزیابی شبیه‌سازی و محاسبه نرخ تجربی در فایل summary ثبت می‌شود. الگوریتم بازیابی آینده به آن نیاز ندارد.

## آزمون صحت dataset

تست `test_detection_dataset` برای هر نمونه تحویل‌شده به callback دوباره هر دو مسیر رمزگذاری را اجرا و بررسی می‌کند که:

```text
C_correct == C_faulty == C_published
```

این آزمون تضمین می‌کند هیچ رخداد مؤثری به dataset حمله وارد نشده است.

## نتایج اجرای مرجع

با پارامترهای زیر:

```text
target ineffective = 4096
max queries        = 50000
seed               = 0xBB67AE8584CAA73B
```

خروجی ابزار مستقل چنین بود:

```text
total oracle queries:     25570
effective events blocked: 21474
ineffective outputs kept: 4096
theoretical rate:         0.164132936
empirical rate:           0.160187720
absolute error:           0.003945216
```

تست واحد با seed جداگانه نیز نتیجه زیر را تولید کرد:

```text
total oracle queries:     25049
ineffective outputs kept: 4096
empirical rate:           0.163519502
absolute error:           0.000613435
```

## فایل‌های خروجی

اجرای دستور زیر:

```bash
make scenario1-dataset
```

این دو فایل را تولید می‌کند:

```text
results/scenario1_detection_ineffective.csv
results/scenario1_detection_summary.csv
```

## آنچه در این فاز انجام نشده است

- ساخت histogram برای ۱۶ مقدار ورودی S-box دور آخر؛
- تعیین مقدار غایب؛
- استفاده از رابطه `missing = delta XOR subkey_lane`؛
- بازیابی subkey دور ۲۸؛
- برگشت یک دور و تکرار Algorithm 1؛
- نمودار موفقیت بر حسب تعداد نمونه؛
- آزمایش‌های تکرارشونده چندکلیدی.

این موارد در قدم‌های بعدی به‌صورت جداگانه و قابل‌آزمون اضافه خواهند شد.
