# گزارش تست فاز ۱۳ — سناریوی چهارم، قدم دوم

## دامنه تست

- رتبه‌بندی کامل `2^20` نامزد فعال `SK28`؛
- محاسبه دقیق SEI با Walsh–Hadamard؛
- مقایسه امتیاز Walsh با partial decryption مستقیم؛
- حفظ مرز داده عمومی و ground truth؛
- بررسی GCC، Clang، CMake/CTest و ASan/UBSan؛
- regression تمام سناریوهای قبلی.

## اجرای مرجع

```text
samples                    = 65536
detected S-box             = 5
public minimum             = 0xC
active roles               = 4,5,7,0,1
candidates tested          = 1048576
Walsh masks                = 15
rank-1 ties                = 4
top score numerator        = 8340224
second score numerator     = 6884000
SEI gap                    = 2.11908482015e-05
recovered active bits      = 18/20
recovered delta            = 0xB
actual candidate rank      = 1, tied with 4 candidates
```

## نامزدهای رتبه اول

```text
0x3B37E
0x3B77E
0x3BB7E  actual
0x3BF7E
```

## تست صحت تبدیل سریع

تست واحد برای نامزد واقعی و یک نامزد مستقل، numerator محاسبه‌شده با تبدیل
Walsh را با numerator به‌دست‌آمده از histogram مستقیم partial decryption
مقایسه می‌کند. هر دو برابر بودند.

## نتایج build و test

```text
GCC make test        PASS
Clang make test      PASS
CMake/CTest          15/15 PASS
ASan/UBSan           PASS
```

## منابع مصرفی اندازه‌گیری‌شده در محیط اعتبارسنجی

```text
unit test full rank  elapsed 0:00.54, max RSS about 18.5 MB
full step2 tool      elapsed 0:00.77, max RSS about 43 MB
```

مقادیر زمان وابسته به سیستم هستند. پیچیدگی الگوریتم رتبه‌بندی به‌جای حلقه
مستقیم `N × 2^20`، از ۱۵ convolution دقیق Walsh روی آرایه `2^20` استفاده
می‌کند.

## نتیجه

فاز ۱۳ از نظر کدنویسی و تست PASS است. نتیجه‌ی علمی:

```text
unknown S-box location recovered
unknown delta recovered uniquely
18/20 active round-key bits recovered
four MixColumns-equivalent candidates remain
```
