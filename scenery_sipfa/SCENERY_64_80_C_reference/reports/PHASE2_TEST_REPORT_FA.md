# گزارش اعتبارسنجی قدم دوم سناریوی ۱

## وضعیت

همه تست‌های نسخه پایه، زیرساخت fault و مجموعه‌داده تشخیصی موفق بوده‌اند.

| آزمون | نتیجه |
|---|---|
| چهار تست‌وکتور رسمی | PASS |
| trace کامل ۲۸ دور | PASS |
| key schedule | PASS |
| ۲۰۰ cross-validation با Python | PASS |
| ۱۰۰۰۰ round-trip | PASS |
| persistent fault | PASS |
| callback فقط برای رخداد بی‌اثر | PASS |
| سازگاری شمارنده‌ها | PASS |
| مقایسه نرخ نظری و تجربی | PASS |
| GCC بدون warning | PASS |
| Clang بدون warning | PASS |
| CMake/CTest | 7/7 PASS |

## خروجی تست dataset

```text
target logical S-box:     3
known fault input delta:  0x5
target ineffective:       4096
total oracle queries:     25049
effective events blocked: 20953
ineffective outputs kept: 4096
theoretical rate:         0.164132936
empirical rate:           0.163519502
absolute error:           0.000613435
PASS
```

## خروجی ابزار تولید داده

```text
target ineffective:       4096
total oracle queries:     25570
effective events blocked: 21474
ineffective outputs kept: 4096
theoretical rate:         0.164132936
empirical rate:           0.160187720
absolute error:           0.003945216
PASS
```

## نتیجه علمی این فاز

oracle تشخیصی دقیقاً خروجی‌های مؤثر را حذف می‌کند و فقط plaintext/ciphertextهای رخدادهای بی‌اثر را در اختیار مرحله حمله قرار می‌دهد. نرخ تجربی با مدل تک-S-box چهار بیتی در ۲۸ دور سازگار است. این فاز هنوز بازیابی subkey را اثبات نمی‌کند.
