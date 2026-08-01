# شرح مرحله‌به‌مرحله الگوریتم SCENERY-64/80

## رمزگذاری

1. بلوک 64 بیتی را به دو نیمه 32 بیتی L و R تقسیم کن.
2. 28 round key سی‌ودوبیتی را از کلید 80 بیتی بساز.
3. برای دورهای 1 تا 28:
   - `A = L xor SK[i]`
   - `B = SubColumns(A)`
   - `M = MixColumns(B)`
   - `newL = R xor M`
   - `newR = L`
   - `L = newL`, `R = newR`
4. خروجی را به صورت `R || L` منتشر کن.

## رمزگشایی

همین فرآیند با ترتیب معکوس round keyها اجرا می‌شود.

## S-box

```text
x : 0 1 2 3 4 5 6 7 8 9 A B C D E F
S : 6 5 C A 1 E 7 9 B 0 3 D 8 F 4 2
```

## تست‌وکتورهای رسمی

```text
P=0000000000000000  K=00000000000000000000  C=82EFEDBA3336CD92
P=0000000000000000  K=FFFFFFFFFFFFFFFFFFFF  C=CE6E5005CF04E426
P=FFFFFFFFFFFFFFFF  K=00000000000000000000  C=480B5421D5611B60
P=FFFFFFFFFFFFFFFF  K=FFFFFFFFFFFFFFFFFFFF  C=F752C84E84124C59
```
