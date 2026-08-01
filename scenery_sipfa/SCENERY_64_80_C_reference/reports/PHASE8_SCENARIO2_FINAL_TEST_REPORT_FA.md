# گزارش تست نهایی سناریوی ۲

## دامنه

این گزارش بسته نهایی سناریوی دوم SIPFA روی SCENERY-64/80 را پوشش می‌دهد:

```text
Unknown persistent fault location
Unknown persistent-fault input delta
Detection-based countermeasure
Algorithm-2 partial decryption
```

## نتیجه حمله ثابت

```text
public ineffective samples: 512
tested active candidates:   1,048,576
surviving candidates:       4
recovered active bits:      18/20
recovered delta:            0xB
actual candidate present:   YES
```

## نتیجه آزمایش‌های تکراری

```text
independent trials: 100
random master keys: YES
random faulty S-box locations: YES
random delta values: YES
sample grid: 64,96,128,160,192,256,320,384,512
```

در ۵۱۲ نمونه:

```text
fault localization:                 100/100
actual candidate retention:         100/100
unique delta recovery:              100/100
18/20 bits + unique delta outcome:  100/100
mean recovered active bits:         18.0
median surviving candidates:        4
```

## Build و test

| بررسی | نتیجه |
|---|---|
| GCC build با warningهای سخت‌گیرانه | PASS |
| GCC test suite | PASS |
| Clang build | PASS |
| Clang test suite | PASS |
| CMake configure/build | PASS |
| CTest | 11/11 PASS |
| AddressSanitizer | PASS |
| UndefinedBehaviorSanitizer | PASS |
| fixed Scenario-2 run | PASS |
| repeated experiment executable | PASS |
| Python analysis script | PASS |
| 13 figures in PNG/PDF/SVG | PASS |
| PDF render verification | PASS |
| Excel formula-error scan | PASS |

## صحت prefix profiler

تابع profiling چند prefix با یک traversal، در تست واحد روی prefix ۵۱۲ با تابع اصلی exhaustive filter مقایسه شد. موارد زیر دقیقاً برابر بودند:

```text
tested candidate count
candidate-sample evaluation count
surviving candidate count
known-bit masks and values
recovered active bits
recovered delta
```

بنابراین این profiler فقط بهینه‌سازی آزمایش‌های تکراری است و منطق Algorithm 2 را تغییر نمی‌دهد.

## دامنه ادعا

نتیجه قابل پشتیبانی:

```text
18/20 active SK28 bits + unique delta
four structurally equivalent candidates
```

این بسته بازیابی یکتای ۲۰ بیت، `SK28` کامل یا کلید اصلی ۸۰بیتی را ادعا نمی‌کند.
