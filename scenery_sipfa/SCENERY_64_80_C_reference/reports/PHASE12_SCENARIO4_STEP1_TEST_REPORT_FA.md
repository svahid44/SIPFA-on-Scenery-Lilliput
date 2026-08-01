# گزارش تست Phase 12 — سناریوی ۴، قدم اول

## نتیجه عملکردی ثابت

```text
published samples          = 32768
internal ineffective       = 5492
internal infected          = 27276
secret S-box               = 5
secret delta               = 0xB
detected S-box             = 5
public minimum             = 0xC
best SEI                   = 0.000184640288353
second-best SEI            = 0.0000458359718323
SEI gap                    = 0.000138804316521
actual SK28 word           = 0x7
coupled candidates         = 16
actual pair retained       = YES
status                     = PASS
```

## پوشش محل و delta

```text
all S-box/delta combinations = 128
correct localizations        = 128/128
minimum positive SEI gap     = 2.76789069176e-05
```

## اعتبارسنجی ساخت و تست

```text
GCC build/test             PASS
Clang build/test           PASS
CMake/CTest                14/14 PASS
AddressSanitizer           PASS
UndefinedBehaviorSanitizer PASS
```

کامپایل با گزینه‌های زیر بدون warning جدید در فایل‌های Phase 12 انجام شد:

```text
-std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
```

## نتیجه علمی

معیار SEI توانست lane خراب را از میان هشت logical S-box با یک بیشینه یکتا جدا کند. minimum lane شناسایی‌شده رابطه `delta XOR SK28[j]` را آشکار کرد، اما چون fault input و word کلید هر دو ناشناخته‌اند، نتیجه این فاز عمداً به ۱۶ زوج سازگار محدود است. بازیابی یکتای delta یا کلید به قدم دوم وابسته است.
