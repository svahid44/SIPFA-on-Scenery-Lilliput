# فاز اول سناریوی ۱ — زیرساخت خطای پایدار تک‌ورودی در SCENERY-64/80

## هدف این فاز

این فاز هنوز حمله بازیابی کلید را اجرا نمی‌کند. هدف آن ساختن همان زیربنایی است که در پروژه Lilliput پیش از شروع سناریوی اول ایجاد شد:

1. حفظ کامل پیاده‌سازی مرجع و تست‌وکتورهای رسمی SCENERY؛
2. افزودن یک مسیر رمزگذاری faulted مستقل؛
3. تعریف fault پایدار روی دقیقاً یک ورودی از دقیقاً یک S-box منطقی؛
4. مشاهده هر دو رخداد effective و ineffective؛
5. آزمون ماندگاری fault و بازگشت به حالت صحیح پس از reset.

## نگاشت مستقیم مدل SIPFA-DES به SCENERY

در کد اصلی SIPFA روی DES، مهاجم یک S-box مشخص و یک ورودی مشخص از آن را انتخاب می‌کند. خروجی همان خانه به صورت زیر تغییر می‌کند:

```text
S_faulty[box][delta] = (S_correct[box][delta] + 1) mod 16
```

همین مدل در SCENERY اعمال شده است:

```text
S_faulty[sbox_index][delta] = faulty_output
```

در تست این فاز نیز `faulty_output` دقیقاً برابر `(correct_output + 1) mod 16` انتخاب شده است.

## چرا fault باید lane-local باشد؟

SCENERY در هر دور هشت S-box چهار بیتی را به صورت bitslice ارزیابی می‌کند. از نظر الگوریتمی این هشت جایگاه، هشت S-box منطقی مستقل‌اند. برای تطابق مستقیم با Algorithm 1 مقاله SIPFA، فقط یک S-box منطقی هدف قرار می‌گیرد.

اگر یک خانه از جدول نرم‌افزاری مشترک تغییر کند و هر هشت lane را هم‌زمان تحت تأثیر قرار دهد، مدل دیگر همان مدل DES مقاله نخواهد بود. در آن صورت احتمال رخداد بی‌اثر بسیار کوچک می‌شود و الگوریتم جمع‌آوری داده باید بازطراحی شود. چنین مدل shared-table می‌تواند در آینده به عنوان یک سناریوی جدا بررسی شود، اما در این پروژه پایه قرار نمی‌گیرد.

## احتمال نظری رخداد بی‌اثر

برای یک S-box چهار بیتی و ۲۸ دور، احتمال آن‌که ورودی خراب `delta` در هیچ دوری دیده نشود برابر است با:

```text
P_ineffective = (15/16)^28 ≈ 0.1641329364
```

این مقدار تقریباً ۱۶٫۴ درصد است و با مدل تک-S-box مقاله سازگار است.

## فایل‌های افزوده‌شده

```text
include/persistent_fault.h
src/persistent_fault.c
tests/test_persistent_fault.c
docs/PHASE1_PERSISTENT_FAULT_FA.md
APPLY_PHASE1_FA.md
```

فایل‌های زیر نیز برای build به‌روزرسانی شده‌اند:

```text
Makefile
CMakeLists.txt
README_FA.md
```

## API جدید

```c
void scenery_fault_reset(void);

int scenery_fault_inject(
    uint8_t sbox_index,
    uint8_t input,
    uint8_t faulty_output
);

int scenery_encrypt_block_faulty(
    const scenery_ctx *ctx,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);
```

توابع metadata نیز محل fault، ورودی خراب، خروجی صحیح و خروجی خراب را گزارش می‌کنند.

## آزمون‌های فاز اول

آزمون `test_persistent_fault` موارد زیر را بررسی می‌کند:

- مسیر صحیح و faulted پیش از تزریق یکسان‌اند؛
- فقط یک خانه از یک S-box منطقی تغییر کرده است؛
- رخداد effective پیدا می‌شود؛
- رخداد ineffective پیدا می‌شود؛
- اجرای مجدد همان plaintext تحت fault همان ciphertext را می‌دهد؛
- reset رفتار صحیح را بازمی‌گرداند؛
- چهار تست‌وکتور رسمی، trace دورها، key schedule و cross-validation قبلی همچنان PASS هستند.

## خروجی تأییدشده این بسته

```text
Summary: 4/4 official vectors passed
PASS: all 28 encryption-round trace records match round_trace_tv1.json.
PASS: all 28 zero-master-key round keys match the reference trace.
PASS: 200 deterministic cross-validation vectors match the Python reference.
PASS: component properties, 10000 round trips, and in-place tests succeeded.
PASS: single-entry persistent fault, effective/ineffective events, persistence, and reset verified.
```

## آنچه عمداً در این فاز انجام نشده است

موارد زیر مربوط به قدم بعدی سناریوی ۱ هستند و هنوز اضافه نشده‌اند:

- countermeasure تشخیصی؛
- جمع‌آوری فقط ciphertextهای ineffective؛
- histogram ورودی S-box دور آخر؛
- استخراج مقدار غایب؛
- بازیابی subkey دور ۲۸؛
- فایل CSV نتایج و نمودارها؛
- اجرای تکراری و success-rate.

این جداسازی مرحله‌ای عمداً انجام شده است تا هر جزء مستقل تست و commit شود.
