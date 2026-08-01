# گزارش آزمون فاز ۱۴ — سناریوی چهارم، قدم سوم

## هدف آزمون

بررسی اینکه چهار نامزد رتبه اول قدم دوم واقعاً از دید observation تک‌word و
معیار SEI هم‌ارزند و این tie با افزایش نمونه شکسته نمی‌شود.

## محیط اعتبارسنجی

```text
Language: C99
Primary compiler: GCC
Secondary compiler: Clang
Build systems: GNU Make, CMake
Dynamic checks: AddressSanitizer, UndefinedBehaviorSanitizer
```

## آزمون جدید

```text
tests/test_unknown_infection_structural_equivalence.c
```

این آزمون:

1. یک dataset infection-based مستقل با 4096 نمونه تولید می‌کند؛
2. چهار نامزد رتبه اول را بدون دادن کلید به تابع ممیزی بررسی می‌کند؛
3. رابطه constant-XOR هر 16 زوج مرتب نامزد را کنترل می‌کند؛
4. برابری histogramها تحت permutation را بررسی می‌کند؛
5. برابری دقیق SEI numeratorها را کنترل می‌کند؛
6. رابطه S-box نقش C را برای تمام 16 ورودی اثبات می‌کند؛
7. در انتها فقط برای verification حضور نامزد واقعی را بررسی می‌کند.

## خروجی آزمون جدید

```text
public samples:              4096
rank-1 candidates:           4
unique exact sequences:      2
XOR-equivalence classes:     1
unique SEI scores:           1
actual active candidate:     0x3BB7E
PASS
```

## اجرای ابزار روی dataset اصلی

```text
public samples:              65536
rank-1 candidates:           4
unique exact sequences:      2
XOR-equivalence classes:     1
unique SEI scores:           1
varying mask:                0xC
constant mask:               0x3
all prefix scores equal:     YES
PASS
```

## Regression

تمام آزمون‌های قبلی پروژه نیز اجرا شدند:

```text
Make test:       16/16 PASS
CMake/CTest:     16/16 PASS
GCC build:       PASS
Clang build/test PASS
ASan/UBSan:      PASS
```

هشدارهای sanitizer build که در توابع قدیمی bitslice مشاهده شدند مربوط به
`-Wsign-conversion` هستند و خطای runtime یا sanitizer گزارش نشد.

## نتیجه

```text
status = PASS
```

قدم سوم با یک نتیجه منفی اما اثباتی تکمیل شد: دو بیت باقی‌مانده تحت مدل
مشاهده فعلی قابل شناسایی یکتا نیستند. نتیجه صحیح و قابل گزارش همان
`18/20 active bits + unique delta` است.
