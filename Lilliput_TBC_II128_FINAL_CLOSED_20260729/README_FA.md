# Lilliput-TBC-II-128 — بسته مرتب کد C

این پوشه شامل هسته C موردنیاز برای اجرای مستقل **Lilliput-TBC-II-128** است.
کدهای cipher و tweakey از پیاده‌سازی مرجع عمومی Lilliput-AE نسخه 1.1 استخراج شده‌اند و
فقط ساختار پوشه‌ها و سیستم build ساده شده است. منطق رمز دست‌کاری نشده است.

## مشخصات هدف

- Block: 128 bit
- Key: 128 bit
- Tweak: 128 bit
- Rounds: 32
- Round tweakey: 64 bit

## ساختار

```text
include/
  parameters.h       پارامترهای II-128
  constants.h        اندازه‌ها و ثابت‌ها
  cipher.h           API رمز و رمزگشایی
  tweakey.h          API زمان‌بندی tweakey
  multiplications.h  تبدیل‌های خطی tweakey
src/
  cipher.c           هسته Lilliput-TBC
  tweakey.c          زمان‌بندی tweakey
tests/
  test_tbc.c         تست مستقل با بردار رسمی VHDL و encryption/decryption
```

## اجرا در Linux / WSL / MinGW

```bash
make test
```

خروجی باید در پایان شامل این خط باشد:

```text
PASS: official ciphertext vector and encryption/decryption round-trip succeeded.
```

## وضعیت پژوهشی فعلی

این شاخه علاوه بر baseline صحیح، چهار سناریوی SIPFA و دو زنجیرهٔ بازیابی کامل کلید را دارد:

1. سناریوی ۱: `known fault + detection-based` و بازیابی `RTK[31]` از missing value.
2. سناریوی ۲: `unknown fault + detection-based`، جست‌وجوی 256 کاندیدا،
   partial inversion دور آخر و فیلتر missing-value در دور قبل.
3. سناریوی ۳: `known fault + infection-based`، استفاده از تمام ciphertextهای
   منتشرشده بدون label و بازیابی `RTK[31]` از کمترین فراوانی histogram.
4. سناریوی ۴: `unknown fault + infection-based`، ساخت 256 کاندیدای fault input،
   partial inversion دور آخر، رتبه‌بندی با SEI و بازیابی fault input و `RTK[31]`.

زنجیره‌های کامل افزوده‌شده:

- سناریوی ۱: `RTK[31] → RTK[30] → master key`.
- سناریوی ۴: `unknown δ → RTK[31] → RTK[30] → master key`.

در هر دو مسیر، تبدیل `RTK[30]` و `RTK[31]` به کلید اصلی با وارون‌سازی دستگاه `128×128` زمان‌بندی tweakey روی `GF(2)` انجام می‌شود.

اجرای سناریوها:

```bash
make scenario1
make scenario2
make scenario3
make scenario4
make scenario1-full-key
make scenario4-full-key
```

مستندات:

```text
docs/PHASE2_SCENARIO1_KNOWN_DETECTION.md
docs/PHASE3_SCENARIO2_UNKNOWN_DETECTION.md
docs/PHASE4_SCENARIO3_KNOWN_INFECTION.md
docs/PHASE5_SCENARIO4_UNKNOWN_INFECTION.md
validation/phase5/SCENARIO4_FULL_KEY_FA.md
```

## منابع رسمی

- مخزن مرجع: https://git.kevinlegouguec.net/lilliput-ae-reference-implementation
- صفحه پروژه: https://paclido.fr/lilliput-ae/
- بسته NIST: https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/round-1/submissions/lilliput-ae.zip

## وضعیت بسته‌شدن پروژه

برای مدل شبیه‌سازی‌شدهٔ تعریف‌شده در این مخزن، مسیرهای زیر بسته شده‌اند:

```text
known fault + detection-based → full 128-bit key       PASS
unknown fault + infection-based → full 128-bit key     PASS
```

این نتیجه شامل missed fault، چندخطایی، نویز اضافی یا آزمایش سخت‌افزاری جدید نیست.
