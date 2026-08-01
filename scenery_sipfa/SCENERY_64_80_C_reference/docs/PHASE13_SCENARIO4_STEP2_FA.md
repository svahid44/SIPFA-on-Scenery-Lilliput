# فاز ۱۳ — سناریوی چهارم، قدم دوم

## عنوان

**Unknown persistent fault + infection — رتبه‌بندی کامل `2^20` نامزد فعال با Partial Decryption و SEI**

## هدف مرحله

در قدم اول سناریوی چهارم، بدون استفاده از کلید، `delta` یا برچسب رخدادها،
S-box منطقی خراب شناسایی شد و مقدار عمومی زیر به دست آمد:

```text
faulty_sbox = 5
public_minimum = 0xC
public_minimum = delta XOR SK28[5]
```

این رابطه به‌تنهایی ۱۶ زوج سازگار `(delta, SK28[5])` باقی می‌گذارد. هدف
قدم دوم، استفاده از partial decryption دور آخر و رتبه‌بندی آماری نامزدهای
زیرکلید است.

## مرز حمله

تابع حمله فقط ورودی‌های زیر را دریافت می‌کند:

```text
ciphertextهای عمومی و بدون برچسب infection-based
شماره S-box شناسایی‌شده در قدم اول
public_minimum به‌دست‌آمده در قدم اول
```

تابع حمله دریافت نمی‌کند:

```text
master key
SK28 واقعی
fault delta واقعی
خروجی صحیح یا خراب S-box
plaintext
برچسب effective/ineffective
آمار داخلی شبیه‌ساز
```

کلید و delta واقعی فقط بعد از پایان حمله، در ابزار مستقل، برای بررسی
ground truth استفاده می‌شوند.

## کلمات فعال دور آخر

برای word هدف `j`، پنج word از `SK28` در خروجی متناظر تابع دور مؤثرند:

```text
A = j - 1
B = j
C = j + 2
D = j + 3
E = j + 4          (mod 8)
```

برای اجرای مرجع با `j = 5`:

```text
A,B,C,D,E = 4,5,7,0,1
```

هر word چهار بیت دارد؛ بنابراین فضای نامزد فعال برابر است با:

```text
16^5 = 2^20 = 1,048,576 candidates
```

هیچ word واقعی زیرکلید به تابع رتبه‌بندی داده نمی‌شود.

## Partial decryption

ساختار دور SCENERY به‌صورت زیر است:

```text
L_(i+1) = R_i XOR F(L_i, SK_i)
R_(i+1) = L_i
```

خروجی پیاده‌سازی پس از دور ۲۸ برابر `R29 || L29` است. پس برای نامزد فعال
`k` می‌توان word هدف پیش از دور آخر را محاسبه کرد:

```text
Y_s(k) = L27_s[j]
       = public_right_s[j] XOR partial_F(public_left_s, k)[j]
```

تابع `partial_F` فقط به پنج word فعال `A..E` نیاز دارد و لازم نیست ۳۲ بیت
کامل `SK28` حدس زده شود.

## امتیاز SEI

برای هر نامزد `k`، histogram شانزده‌مقداری `Y_s(k)` ساخته می‌شود. اگر
`H_k[y]` تعداد وقوع مقدار `y` در `N` نمونه باشد:

```text
p_k[y] = H_k[y] / N
SEI(k) = sum_y (p_k[y] - 1/16)^2
```

نامزد صحیح باید bias ناشی از خطای ماندگار را پس از حذف دور آخر حفظ کند.
نامزدهای اشتباه معمولاً توزیع نزدیک‌تری به یکنواخت ایجاد می‌کنند.

## چرا حلقه مستقیم استفاده نشده است؟

محاسبه‌ی مستقیم نیازمند تقریباً زیر است:

```text
2^20 candidates × 65536 samples
```

که بیش از ۶۸ میلیارد ارزیابی partial decryption است. برای جلوگیری از این
هزینه، امتیازها به‌صورت دقیق در دامنه Walsh محاسبه می‌شوند.

برای ماسک غیرصفر چهاربیتی `w` تعریف می‌کنیم:

```text
T_w(k) = sum_s (-1) ^ <w, Y_s(k)>
```

طبق رابطه Parseval:

```text
SEI(k) = 1 / (16 N^2) × sum_(w=1..15) T_w(k)^2
```

از طرف دیگر `Y_s(k)` XOR پنج contribution مستقل از نقش‌های `A..E` است.
بنابراین تمام `T_w(k)`ها برای همه‌ی `2^20` نامزد، یک convolution بیست‌بیتی
روی گروه XOR هستند. پیاده‌سازی با تبدیل Walsh–Hadamard سریع، این convolution
را دقیقاً محاسبه می‌کند.

این روش approximation، sampling یا heuristic نیست. تست واحد، امتیاز Walsh
نامزد واقعی و یک نامزد مستقل را با histogram مستقیم partial decryption
مقایسه می‌کند.

## داده مرجع

```text
master key              = 00112233445566778899
secret faulty S-box     = 5
secret delta            = 0xB
public samples          = 65536
seed                    = 0x6A09E667F3BCC909
public minimum          = 0xC
```

تعداد ۶۵٬۵۳۶ نمونه برای اجرای مرجع قدم دوم انتخاب شده است. اجرای
`make scenario4-step2` dataset قدم اول را با همین تعداد دوباره تولید می‌کند.

## نتیجه مرجع

```text
tested active candidates = 1,048,576
Walsh masks evaluated    = 15
rank-1 candidate count   = 4
```

چهار نامزد رتبه اول:

```text
packed   A B C D E   delta
3B37E    E 7 3 B 3   B
3B77E    E 7 7 B 3   B
3BB7E    E 7 B B 3   B   <-- actual
3BF7E    E 7 F B 3   B
```

امتیازها:

```text
top score numerator     = 8,340,224
second score numerator  = 6,884,000
top SEI                 = 0.000121366232634
second SEI              = 0.000100175384432
SEI gap                 = 0.0000211908482015
```

consensus چهار نامزد رتبه اول:

```text
role  word source  known mask  known value  recovered bits
A     S-box 4      F           E            4
B     S-box 5      F           7            4
C     S-box 7      3           3            2
D     S-box 0      F           B            4
E     S-box 1      F           3            4
```

نتیجه نهایی این قدم:

```text
18 / 20 active SK28 bits recovered
SK28[5] = 0x7 recovered completely
unknown delta = 0xC XOR 0x7 = 0xB recovered uniquely
four structurally equivalent candidates remain
```

## علت باقی‌ماندن چهار نامزد

چهار نامزد فقط در word نقش `C` متفاوت‌اند:

```text
C in {0x3, 0x7, 0xB, 0xF}
```

در partial observation مربوط به یک word هدف، contribution نقش `C` فقط بخشی
از خروجی S-box را وارد MixColumns می‌کند. در نتیجه دو بیت بالایی این word
در این مشاهده قابل تفکیک نیستند. همان کلاس چهارعضوی در سناریوی دوم نیز
مشاهده شد.

بنابراین ادعای علمی درست این است:

```text
18/20 bits + unique delta
```

و نه بازیابی یکتای ۲۰ بیت فعال.

## فایل‌های اضافه‌شده یا تغییرکرده

```text
include/unknown_infection_attack.h
src/unknown_infection_attack.c
tests/test_unknown_infection_partial_decryption.c
tools/scenario4_rank_active_key.c
tools/scenario4_collect_unknown_infection.c
Makefile
CMakeLists.txt
```

## خروجی‌های CSV

```text
results/scenario4_active_key_ranking_top64.csv
results/scenario4_active_key_consensus.csv
results/scenario4_partial_decryption_summary.csv
results/scenario4_step2_verification.csv
```

## اجرای مرحله

```bash
make scenario4-step2
```

این target سه بخش را به‌ترتیب اجرا می‌کند:

```text
جمع‌آوری 65536 خروجی عمومی infection-based
شناسایی S-box و public minimum
رتبه‌بندی کامل 2^20 نامزد فعال
```

## وضعیت پایان مرحله

```text
fault location recovered
unknown delta recovered uniquely
18 of 20 active SK28 bits recovered
four structural key candidates remain
master key not recovered
complete 32-bit SK28 not recovered in Scenario 4
```

آزمایش‌های تکرارشونده، منحنی موفقیت برحسب تعداد نمونه، نمودارها و جدول‌های
مقاله باید در فاز نهایی سناریوی چهارم انجام شوند.
