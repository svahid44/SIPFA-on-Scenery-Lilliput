# قدم سوم سناریوی ۱ — بازیابی چهار بیت هدف از SK28

## هدف

در این قدم، بخش بعدی Algorithm 1 مقاله SIPFA برای حالت fault معلوم و countermeasure تشخیصی روی SCENERY اجرا می‌شود. ورودی حمله فقط مجموعه ciphertextهای بی‌اثر تولیدشده در قدم دوم، شماره S-box هدف و ورودی fault معلوم `delta` است.

این قدم فقط چهار بیت متناظر با S-box شماره ۳ از subkey دور ۲۸ را بازیابی می‌کند. بازیابی کامل subkey سی‌ودوبیتی در قدم بعد با تکرار همین فرآیند برای هشت S-box منطقی انجام خواهد شد.

## رابطه دور آخر SCENERY

رابطه دور فایستل SCENERY به صورت زیر است:

```text
L_(i+1) = R_i XOR F(L_i, SK_i)
R_(i+1) = L_i
```

پس از دور ۲۸، ciphertext با swap نهایی منتشر می‌شود:

```text
C = R_29 || L_29
```

از رابطه فایستل داریم:

```text
R_29 = L_28
```

در نتیجه نیمه چپ ciphertext، همان ورودی چپ دور ۲۸ پیش از XOR با subkey است:

```text
C_left = L_28
```

برای S-box منطقی شماره `j`، مقدار عمومی قابل استخراج از ciphertext را با `V[j]` نشان می‌دهیم:

```text
V[j] = BitsliceWord_j(C_left)
```

ورودی واقعی S-box در دور آخر برابر است با:

```text
X_28[j] = V[j] XOR SK_28[j]
```

## استفاده از رخدادهای بی‌اثر

در یک رخداد بی‌اثر، ورودی خراب `delta` در هیچ‌یک از ۲۸ فراخوانی S-box هدف دیده نشده است. بنابراین در دور آخر نیز:

```text
X_28[j] != delta
```

با جایگذاری رابطه ورودی دور آخر:

```text
V[j] XOR SK_28[j] != delta
```

پس مقدار زیر در histogram شانزده‌مقداری `V[j]` ظاهر نمی‌شود:

```text
missing = delta XOR SK_28[j]
```

و چهار بیت subkey از رابطه اصلی Algorithm 1 بازیابی می‌شوند:

```text
SK_28[j] = missing XOR delta
```

## مرز اطلاعات مهاجم

ابزار `scenario1_recover_word` فقط این اطلاعات را به هسته حمله می‌دهد:

- فایل عمومی ciphertextهای بی‌اثر؛
- شماره S-box هدف؛
- `delta` معلوم.

کلید اصلی و `SK28` ورودی تابع بازیابی نیستند. پس از پایان بازیابی، کلید ثابت آزمایش فقط برای ground-truth verification محاسبه می‌شود.

## فایل‌های افزوده‌شده

```text
include/known_detection_attack.h
src/known_detection_attack.c
tests/test_known_detection_attack.c
tools/scenario1_recover_word.c
docs/PHASE3_SCENARIO1_TARGET_WORD_RECOVERY_FA.md
APPLY_PHASE3_FA.md
```

## خروجی مرجع

برای dataset قدم دوم با ۴۰۹۶ ciphertext بی‌اثر، S-box شماره ۳ و `delta=0x5`، histogram زیر به دست آمد:

```text
value  count
0x0    300
0x1    265
0x2    276
0x3    275
0x4    255
0x5    278
0x6    256
0x7    283
0x8    273
0x9      0   <-- unique missing
0xA    287
0xB    283
0xC    257
0xD    279
0xE    282
0xF    247
```

بنابراین:

```text
missing = 0x9
SK28[3] = 0x9 XOR 0x5 = 0xC
```

مقدار واقعی subkey دور آخر برای کلید آزمایش:

```text
SK28 = A3B7389D
```

چهار بیت bitslice متناظر با S-box شماره ۳ نیز `0xC` هستند؛ پس بازیابی با ground truth برابر است.

## فایل‌های نتیجه

```text
results/scenario1_target_sbox_histogram.csv
results/scenario1_word_recovery_summary.csv
```

## آنچه هنوز انجام نشده است

- تکرار fault برای S-boxهای ۰ تا ۷؛
- بازیابی کامل ۳۲ بیت `SK28`؛
- اجرای تکراری روی کلیدها و seedهای مختلف؛
- نمودار موفقیت بر حسب تعداد نمونه؛
- بازیابی کلید اصلی ۸۰ بیتی از subkeyها.
