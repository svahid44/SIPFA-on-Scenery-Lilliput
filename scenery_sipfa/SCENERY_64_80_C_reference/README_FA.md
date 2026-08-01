# پیاده‌سازی مرجع C برای SCENERY-64/80

این بسته یک پیاده‌سازی مستقل، تمیز، قابل‌آزمایش و پژوهش‌محور از رمز بلوکی سبک **SCENERY-64/80** ارائه می‌کند.

## پارامترها

- اندازه بلوک: 64 بیت
- اندازه کلید: 80 بیت
- ساختار: فایستل متوازن
- تعداد دور: 28
- تابع دور: AddRoundKey → SubColumns → MixColumns
- S-box: جدول 4×4 مشترک با RECTANGLE
- نمایش خارجی داده و کلید: big-endian

## سازگاری

کد C با این منابع تطبیق داده شده است:

1. چهار تست‌وکتور ضمیمه مقاله؛
2. پیاده‌سازی مرجع Python ارسال‌شده؛
3. رد کامل 28 دور تست‌وکتور اول؛
4. 200 بردار مستقل Python↔C؛
5. 10000 آزمون round-trip و in-place.

## ساخت با Make

```bash
make clean
make all
make test
make examples
```

خروجی موفق نهایی:

```text
Summary: 4/4 official vectors passed
PASS: all 28 encryption-round trace records match round_trace_tv1.json.
PASS: all 28 zero-master-key round keys match the reference trace.
PASS: 200 deterministic cross-validation vectors match the Python reference.
PASS: component properties, 10000 round trips, and in-place tests succeeded.
```

## ساخت با CMake

```bash
cmake -S . -B build-cmake
cmake --build build-cmake
ctest --test-dir build-cmake --output-on-failure
```

در ویندوز می‌توان فایل زیر را اجرا کرد:

```text
BUILD_AND_TEST_WINDOWS.bat
```

## استفاده پایه

```c
#include "scenery.h"

scenery_ctx ctx;
uint8_t ciphertext[8];
uint8_t recovered[8];

scenery_init(&ctx, key);
scenery_encrypt_block(&ctx, plaintext, ciphertext);
scenery_decrypt_block(&ctx, ciphertext, recovered);
```

## رد کامل دورها

```c
scenery_round_trace trace[SCENERY_ROUNDS];
scenery_encrypt_block_trace(&ctx, plaintext, ciphertext, trace);
```

هر رکورد شامل round key، ورودی‌های چپ و راست، خروجی AddRoundKey، SubColumns، MixColumns و دو نیمه خروجی دور است.

## ساختار پروژه

```text
include/scenery.h
src/scenery.c
tests/test_vectors.c
tests/test_trace_tv1.c
tests/test_key_schedule.c
tests/test_cross_validation.c
tests/test_structural.c
examples/example.c
examples/trace_example.c
docs/
reports/
build/
```

## نکات امنیتی

این کد برای بازتولید علمی، تست، تحلیل رمز و حملات خطا نوشته شده است. پیاده‌سازی table-based تضمین constant-time ندارد و برای کاربرد عملی بدون ممیزی امنیتی مناسب نیست.


---

## توسعه SIPFA — وضعیت فاز اول

زیرساخت خطای پایدار تک‌ورودی مطابق مدل Algorithm 1 حمله SIPFA روی DES افزوده شده است.

```bash
make clean
make all
make test
```

جزئیات فنی:

```text
docs/PHASE1_PERSISTENT_FAULT_FA.md
```

راهنمای اعمال patch در WSL:

```text
APPLY_PHASE1_FA.md
```


---

## توسعه SIPFA — وضعیت قدم دوم سناریوی ۱

مدل countermeasure تشخیصی و جمع‌آوری فقط ciphertextهای بی‌اثر اضافه شده است.

```bash
make clean
make all
make test
make scenario1-dataset
```

خروجی‌های داده:

```text
results/scenario1_detection_ineffective.csv
results/scenario1_detection_summary.csv
```

شرح علمی:

```text
docs/PHASE2_SCENARIO1_DETECTION_DATASET_FA.md
```

راهنمای WSL:

```text
APPLY_PHASE2_FA.md
```

در این قدم هنوز histogram و بازیابی کلید دور آخر پیاده‌سازی نشده‌اند.

---

## توسعه SIPFA — وضعیت قدم سوم سناریوی ۱

بخش missing-value recovery از Algorithm 1 مقاله برای یک S-box هدف پیاده‌سازی شده است. ابزار حمله فقط CSV منتشرشده، شماره S-box معلوم و `delta` معلوم را دریافت می‌کند.

```bash
make clean
make all
make test
make scenario1-recover-word
```

خروجی مرجع:

```text
missing value:         0x9
recovered SK28 word:   0xC
actual SK28:           A3B7389D
actual SK28 word:      0xC
PASS
```

فایل‌های نتیجه:

```text
results/scenario1_target_sbox_histogram.csv
results/scenario1_word_recovery_summary.csv
```

شرح علمی:

```text
docs/PHASE3_SCENARIO1_TARGET_WORD_RECOVERY_FA.md
```

راهنمای WSL:

```text
APPLY_PHASE3_FA.md
```

در این قدم فقط چهار بیت متناظر با S-box شماره ۳ از `SK28` بازیابی می‌شوند. تکرار حمله برای هشت S-box و بازسازی کامل subkey دور آخر در قدم بعد انجام خواهد شد.


---

## توسعه SIPFA — وضعیت فاز چهارم

هشت کمپین مستقل known-fault/detection مطابق حلقه هشت S-box در Algorithm 1 اجرا می‌شوند و کل `SK28` بازیابی می‌شود.

```bash
make scenario1-step4
```

نتیجه مرجع:

```text
Recovered SK28 = A3B7389D
```

مستندات:

```text
docs/PHASE4_SCENARIO1_FULL_SK28_RECOVERY_FA.md
APPLY_PHASE4_FA.md
```


---

## پایان سناریوی ۱ — آمار، نمودارها و جدول‌های مقاله

سناریوی ۱ با بازیابی کامل `SK28`، اجرای ۱۰۰ آزمایش مستقل، منحنی موفقیت، پیچیدگی پرس‌وجو، فاصله اطمینان و خروجی‌های آماده مقاله تکمیل شده است.

اجرای کامل:

```bash
python3 -m pip install --user -r requirements-analysis.txt
make scenario1-final
```

خروجی‌ها:

```text
results/scenario1_repeated_trials.csv
results/scenario1_repeated_words.csv
results/scenario1_success_curve.csv
results/scenario1_query_complexity.csv
results/scenario1_per_sbox_success.csv
results/scenario1_success_thresholds.csv
paper_artifacts/figures/
paper_artifacts/tables/
paper_artifacts/SCENARIO1_ANALYSIS.xlsx
```

گزارش نهایی:

```text
docs/SCENARIO1_FINAL_REPORT_FA.md
```


---

## سناریوی ۲ — قدم اول: fault و delta ناشناخته

مراحل ۴ تا ۹ از Algorithm 2 اصلی SIPFA برای SCENERY اضافه شده‌اند:

- dataset عمومی فقط شامل ciphertextهای بی‌اثر و بدون label است؛
- histogram هر هشت S-box منطقی ساخته می‌شود؛
- یک missing-value سراسری، محل S-box خراب را مشخص می‌کند؛
- `delta` و کلید هنوز ناشناخته باقی می‌مانند و در قدم بعد با partial decryption بررسی خواهند شد.

اجرای مرحله:

```bash
make scenario2-step1
```

مستند فنی:

```text
docs/PHASE6_SCENARIO2_STEP1_FA.md
```


---

## سناریوی ۲ — قدم دوم: Partial Decryption و فیلتر نامزدهای فعال

مراحل ۱۰ تا ۱۶ Algorithm 2 پیاده‌سازی شده‌اند:

```bash
make scenario2-step2
```

این مرحله تمام `2^20` نامزد فعال `SK28` را بررسی می‌کند، دور آخر را برای word هدف به‌صورت جزئی معکوس می‌کند و نامزدها را با missing-value دور ۲۷ فیلتر می‌کند.

نتیجه مرجع:

```text
samples                  = 512
tested candidates        = 1,048,576
surviving candidates     = 4
recovered active bits    = 18/20
recovered delta          = 0xB
actual candidate present = YES
```

چهار نامزد باقی‌مانده یک ابهام ساختاری MixColumns هستند؛ برنامه ادعای بازیابی یکتای ۲۰ بیت را مطرح نمی‌کند.

جزئیات:

```text
docs/PHASE7_SCENARIO2_STEP2_FA.md
APPLY_PHASE7_SCENARIO2_STEP2_FA.md
```


---

## سناریوی ۲ نهایی — Unknown fault + Detection

سناریوی دوم مطابق منطق Algorithm 2 اصلی SIPFA روی SCENERY پیاده‌سازی و با ۱۰۰ اجرای مستقل ارزیابی شده است.

نتیجه صادقانه:

```text
18/20 active SK28 bits recovered
unknown delta recovered uniquely
four structurally equivalent candidates remain
```

اجرای کامل:

```bash
source .venv/bin/activate
make scenario2-final
```

بازسازی فقط شکل‌ها و جدول‌ها بدون تکرار آزمایش:

```bash
make scenario2-report
```

مستندات:

```text
docs/SCENARIO2_FINAL_REPORT_FA.md
docs/SCENARIO2_RESULTS_TEXT_EN.md
APPLY_PHASE8_SCENARIO2_FINAL_FA.md
```

خروجی‌های مقاله:

```text
paper_artifacts/scenario2/SCENARIO2_ANALYSIS.xlsx
paper_artifacts/scenario2/figures/
paper_artifacts/scenario2/tables/
```

## سناریوی ۳ — fault معلوم و countermeasure از نوع infection

قدم اول سناریوی ۳ مطابق Algorithm 3 پیاده‌سازی شده است:

- محل S-box خراب و ورودی fault یعنی `delta` برای مهاجم معلوم است؛
- رخداد بی‌اثر، ciphertext صحیح را منتشر می‌کند؛
- رخداد مؤثر، یک بلوک تصادفی مستقل ۶۴‌بیتی منتشر می‌کند؛
- هیچ برچسب effective/ineffective در dataset عمومی وجود ندارد؛
- کم‌فراوان‌ترین مقدار histogram دور آخر برای بازیابی چهار بیت هدف `SK28` استفاده می‌شود.

اجرای قدم اول:

```bash
make scenario3-step1
```

خروجی‌های اصلی:

```text
results/scenario3_known_infection_ciphertexts.csv
results/scenario3_known_infection_collection_summary.csv
results/scenario3_known_infection_histogram.csv
results/scenario3_known_infection_recovery_summary.csv
```

شرح علمی کامل در:

```text
docs/PHASE9_SCENARIO3_STEP1_FA.md
```

## Phase 11 — نهایی‌سازی سناریوی ۳

سناریوی known-fault + infection با آزمایش‌های ۱۰۰تکراری، منحنی موفقیت، تحلیل minimum-gap، نمودارها، جدول‌های مقاله و داشبورد Excel نهایی شده است.

```bash
make scenario3-final
```

نتیجه مرجع:

```text
Recovered SK28 = A3B7389D
99% complete-key success at 16384 samples/S-box
100/100 observed successes at 24576 and 32768 samples/S-box
```

---

## Phase 12 — سناریوی ۴، قدم اول: fault ناشناخته + infection

بخش نخست Algorithm 4 برای SCENERY اضافه شده است:

- همه‌ی queryها یک ciphertext عمومی بدون event label تولید می‌کنند؛
- هشت histogram چهاربیتی دور آخر ساخته می‌شود؛
- محل logical S-box خراب با بزرگ‌ترین SEI یکتا شناسایی می‌شود؛
- minimum lane خراب رابطه `delta XOR SK28[j]` را می‌دهد؛
- چون delta و word کلید هر دو ناشناخته‌اند، ۱۶ زوج سازگار باقی می‌ماند.

اجرای مرحله:

```bash
make scenario4-step1
```

نتیجه ثابت:

```text
detected S-box       = 5
public minimum       = 0xC
SEI gap              = 0.000138804316521
coupled hypotheses   = 16
actual pair retained = YES
```

شرح کامل:

```text
docs/PHASE12_SCENARIO4_STEP1_FA.md
APPLY_PHASE12_SCENARIO4_STEP1_FA.md
```

---

## Phase 13 — سناریوی ۴، قدم دوم: رتبه‌بندی کامل فضای فعال

در این فاز، مرحله دوم Algorithm 4 بدون استفاده از کلید یا delta واقعی اجرا
می‌شود:

```bash
make scenario4-step2
```

پیاده‌سازی همه‌ی `2^20` نامزد پنج word فعال `SK28` را با partial decryption
و SEI رتبه‌بندی می‌کند. برای جلوگیری از حلقه‌ی مستقیم بسیار بزرگ، امتیازها
به‌صورت دقیق با Walsh–Hadamard محاسبه می‌شوند.

نتیجه مرجع:

```text
samples                    = 65536
tested candidates          = 1048576
rank-1 candidates          = 4
recovered active key bits  = 18/20
recovered delta            = 0xB
actual candidate rank      = 1, tied with 4
```

چهار نامزد فقط در دو بیت ساختاری نقش `C` متفاوت‌اند؛ بنابراین ادعای درست
`18/20 bits + unique delta` است.

مستندات:

```text
docs/PHASE13_SCENARIO4_STEP2_FA.md
APPLY_PHASE13_SCENARIO4_STEP2_FA.md
```


---

## سناریوی ۴ — قدم سوم: ممیزی ابهام ساختاری

چهار نامزد رتبه اول قدم دوم با همان مشاهده partial decryption و معیار SEI
به‌صورت sample-by-sample بررسی می‌شوند:

```bash
make scenario4-step3
```

نتیجه اثباتی این مرحله نشان می‌دهد خروجی هر دو نامزد یا دقیقاً یکسان است یا
با یک XOR ثابت به خروجی نامزد دیگر تبدیل می‌شود. بنابراین histogramها در هر
تعداد نمونه فقط permutation یکدیگرند و امتیاز SEI برای تمام prefixها برابر
می‌ماند. افزایش تعداد نمونه دو بیت باقی‌مانده را با همین مدل مشاهده بازیابی
نمی‌کند. ادعای علمی نهایی این مرحله همان `18/20 بیت فعال + delta یکتا` است.

مستند فنی:

```text
docs/PHASE14_SCENARIO4_STEP3_FA.md
```
