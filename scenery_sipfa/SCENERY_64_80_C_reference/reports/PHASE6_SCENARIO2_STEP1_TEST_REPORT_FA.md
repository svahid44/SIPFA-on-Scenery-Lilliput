# گزارش اعتبارسنجی سناریوی ۲، قدم اول

## دامنه

این گزارش فقط شناسایی محل fault ناشناخته و مقدار عمومی غایب را پوشش می‌دهد. `delta` و کلید دور هنوز بازیابی نشده‌اند.

## نتیجه اجرای مرجع

```text
public ineffective samples: 256
total oracle queries:       1480
effective events blocked:   1224
global missing count:       1
detected S-box:             5
public missing value:       0xC
```

صحت‌سنجی داخلی شبیه‌سازی:

```text
secret delta:      0xB
actual SK28 word:  0x7
0xB XOR 0x7:       0xC
```

## آزمون‌ها

| آزمون | نتیجه |
|---|---|
| تست‌وکتورهای رسمی SCENERY | PASS |
| trace کامل ۲۸ دور | PASS |
| key schedule | PASS |
| cross-validation پایتون/C | PASS |
| persistent fault | PASS |
| detection dataset | PASS |
| سناریوی ۱ کامل | PASS |
| ingestion تمام هشت histogram | PASS |
| دقیقاً یک missing global | PASS |
| شناسایی S-box ناشناخته | PASS |
| تطبیق missing با `delta XOR SK28` | PASS |

## نتیجه

قدم اول Algorithm 2 با دامنه چهار بیتی SCENERY بازتولید شد. مرحله بعد باید ۱۶ زوج ممکن `(delta, key-word)` را با partial decryption دور آخر و آزمون missing-value در دور ۲۷ کاهش دهد.
