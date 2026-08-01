# سناریوی ۲، قدم اول — شناسایی محل خطای ناشناخته با countermeasure تشخیصی

## هدف

در سناریوی دوم مقاله SIPFA، مهاجم نه محل خطای پایدار را می‌داند و نه مقدار ورودی خراب `delta` را. هدف این قدم فقط بازتولید مراحل ابتدایی Algorithm 2 است:

1. تولید ciphertextهای بی‌اثر با detector؛
2. مخفی‌کردن محل fault و `delta` از داده عمومی؛
3. ساخت histogram برای هر هشت S-box منطقی دور آخر؛
4. شمارش مقادیر غایب در کل فضای `8 × 16`؛
5. شناسایی S-box خراب وقتی دقیقاً یک مقدار در کل histogramها غایب است.

در این قدم هنوز کلید دور یا `delta` بازیابی نمی‌شود.

## انطباق با Algorithm 2 اصلی

در کد اصلی SIPFA روی DES، برای هر ciphertext بی‌اثر مقدار عمومی ورودی دور آخر برای تمام هشت S-box استخراج می‌شود. سپس آرایه‌های `arr[8][64]` ساخته می‌شوند. اگر فقط یک خانه در کل هشت آرایه مشاهده نشده باشد، شماره ردیف محل S-box خراب را مشخص می‌کند.

در SCENERY همان منطق به دامنه چهار بیتی نگاشت شده است:

```text
DES:     8 × 64 histogram cells
SCENERY: 8 × 16 histogram cells
```

برای هر ciphertext منتشرشده و هر S-box منطقی `j` مقدار زیر از نیمه اول ciphertext استخراج می‌شود:

```text
V28[j] = lane_j(L28)
```

زیرا خروجی SCENERY به صورت `R29 || L29` منتشر می‌شود و `R29 = L28` است.

اگر fault ناشناخته روی S-box شماره `f` و ورودی `delta` باشد، در مجموعه ciphertextهای بی‌اثر مقدار زیر در histogram همان S-box دیده نمی‌شود:

```text
m = delta XOR SK28[f]
```

پس اگر در کل هشت histogram فقط یک مقدار صفر باشد:

```text
detected_sbox = f
detected_missing_value = m
```

## چرا هنوز کلید بازیابی نشده است؟

از رابطه

```text
m = delta XOR SK28[f]
```

و با ناشناخته‌بودن هر دو مقدار، ۱۶ زوج ممکن باقی می‌ماند:

```text
(delta, SK28[f]) = (0, m), (1, m XOR 1), ..., (15, m XOR 15)
```

مطابق Algorithm 2 اصلی، حذف این ابهام باید با حدس بخش لازم از subkey دور آخر، معکوس‌کردن یک دور و بررسی باقی‌ماندن خاصیت missing-value در دور قبل انجام شود. این بخش عمداً به قدم بعد موکول شده است.

## مرز اطلاعات مهاجم

فایل عمومی حمله فقط شامل این ستون‌ها است:

```text
ineffective_index,ciphertext
```

موارد زیر در فایل عمومی وجود ندارند:

- plaintext؛
- شماره S-box خراب؛
- `delta`؛
- خروجی صحیح و خراب S-box؛
- کلید اصلی؛
- `SK28`؛
- برچسب‌های داخلی effective/ineffective.

فایل `ground_truth` فقط برای صحت‌سنجی شبیه‌سازی تولید می‌شود و ابزار حمله آن را نمی‌خواند.

## فایل‌های این قدم

```text
include/unknown_detection_attack.h
src/unknown_detection_attack.c
tests/test_unknown_detection_attack.c
tools/scenario2_collect_unknown_detection.c
tools/scenario2_identify_fault.c
docs/PHASE6_SCENARIO2_STEP1_FA.md
APPLY_PHASE6_SCENARIO2_STEP1_FA.md
```

## خروجی اجرای مرجع

پارامترهای مخفی شبیه‌سازی:

```text
secret S-box = 5
secret delta = 0xB
actual SK28[5] = 0x7
expected missing = 0xB XOR 0x7 = 0xC
```

نتیجه حمله عمومی:

```text
public ineffective samples = 256
global missing count       = 1
detected S-box             = 5
public missing value       = 0xC
```

بنابراین محل خطای ناشناخته بدون استفاده از `delta` یا کلید شناسایی شد.

## فایل‌های نتیجه

```text
results/scenario2_unknown_detection_ciphertexts.csv
results/scenario2_unknown_detection_collection_summary.csv
results/scenario2_unknown_detection_ground_truth.csv
results/scenario2_unknown_detection_histograms.csv
results/scenario2_fault_identification_summary.csv
```

## محدودیت فعلی

این قدم فقط مراحل تشخیص محل fault را پوشش می‌دهد. ادعای صحیح در پایان این فاز:

> The unknown faulty logical S-box and the corresponding public missing value were identified from unlabeled ineffective ciphertexts.

ادعای بازیابی `delta` یا `SK28` در این فاز مجاز نیست.
