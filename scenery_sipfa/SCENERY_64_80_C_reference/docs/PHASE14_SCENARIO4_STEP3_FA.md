# فاز ۱۴ — سناریوی چهارم، قدم سوم

## عنوان

**Unknown persistent fault + infection — اثبات ابهام ساختاری چهار نامزد رتبه اول**

## هدف

قدم دوم سناریوی چهارم، تمام `2^20` نامزد فعال `SK28` را رتبه‌بندی کرد و
چهار نامزد هم‌امتیاز زیر را در رتبه اول نگه داشت:

```text
0x3B37E   A,B,C,D,E = E,7,3,B,3
0x3B77E   A,B,C,D,E = E,7,7,B,3
0x3BB7E   A,B,C,D,E = E,7,B,B,3   <-- نامزد واقعی در شبیه‌سازی
0x3BF7E   A,B,C,D,E = E,7,F,B,3
```

هدف قدم سوم این بود که مشخص کند آیا این tie با افزایش تعداد نمونه یا یک
تحلیل دقیق‌تر از همان مشاهده‌ی partial decryption و SEI شکسته می‌شود، یا
اینکه چهار نامزد از دید مدل فعلی واقعاً هم‌ارزند.

## مرز حمله

تابع ممیزی فقط ورودی‌های عمومی زیر را دریافت می‌کند:

```text
ciphertextهای عمومی و بدون برچسب infection-based
شماره word هدف
چهار نامزد رتبه اول منتشرشده توسط قدم دوم
```

تابع ممیزی دریافت نمی‌کند:

```text
master key
SK28 واقعی
fault delta واقعی
plaintext
برچسب effective/ineffective
خروجی صحیح در رخدادهای infected
آمار داخلی شبیه‌ساز
```

کلید واقعی فقط پس از پایان ممیزی، در بخش verification ابزار، برای بررسی
حضور نامزد واقعی داخل کلاس رتبه اول استفاده می‌شود.

## محل دقیق ابهام

برای word هدف `j = 5`، پنج word فعال دور آخر عبارت‌اند از:

```text
A = S-box 4
B = S-box 5
C = S-box 7
D = S-box 0
E = S-box 1
```

چهار نامزد فقط در نقش `C` تفاوت دارند:

```text
C ∈ {0x3, 0x7, 0xB, 0xF}
```

در decomposition تابع `MixColumns`، contribution نقش `C` به word هدف فقط
یک بیت است:

```text
role_C(x, k) = bit_0(S(x XOR k))
```

دو بیت بالایی نامزد word کلید تنها از طریق همین تابع تک‌بیتی مشاهده می‌شوند.

## اثبات روی کل دامنه S-box

برای هر ورودی عمومی `x` در دامنه `0..15`، جدول کامل S-box نشان می‌دهد:

```text
g_3(x) = g_F(x)
g_7(x) = g_B(x)
g_7(x) = g_3(x) XOR 1
```

که در آن:

```text
g_k(x) = bit_0(S(x XOR k))
```

بنابراین این رابطه وابسته به seed یا dataset مرجع نیست؛ برای تمام ورودی‌های
ممکن برقرار است.

## نتیجه sample-by-sample

اگر خروجی partial decryption برای نامزد `k` را با `Y_k[s]` نشان دهیم، برای
تمام نمونه‌های عمومی داریم:

```text
Y_3[s] = Y_F[s]
Y_7[s] = Y_B[s]
Y_3[s] = Y_7[s] XOR 1
```

در نتیجه چهار نامزد فقط دو sequence دقیق تولید می‌کنند، ولی هر دو sequence
با یک XOR ثابت به یکدیگر تبدیل می‌شوند.

## چرا SEI نمی‌تواند tie را بشکند؟

اگر برای دو نامزد رابطه زیر برقرار باشد:

```text
Y_b[s] = Y_a[s] XOR c
```

آنگاه histogramها فقط permutation یکدیگرند:

```text
H_b[v] = H_a[v XOR c]
```

و چون SEI از مجموع مربع فاصله‌ی تمام binها از توزیع یکنواخت تشکیل می‌شود،
نسبت به permutation مقدار binها ناوردا است:

```text
SEI(a) = SEI(b)
```

این استدلال برای هر prefix از dataset نیز برقرار است. بنابراین افزایش تعداد
نمونه، حتی در حد نامتناهی، tie را با همین observation و همین score نمی‌شکند.

## نتیجه اجرای مرجع

```text
public samples                     = 65536
rank-1 candidates                  = 4
unique exact sequences             = 2
XOR-equivalence classes            = 1
unique SEI scores                  = 1
varying role                       = C
varying source S-box               = 7
varying key-bit mask               = 0xC
constant/recovered key-bit mask    = 0x3
all pairwise relations constant    = YES
all tested prefix scores equal     = YES
more samples can break this tie    = NO
```

برای هر چهار نامزد، امتیاز دقیق برابر است با:

```text
score numerator = 8,340,224
SEI              = 0.000121366232633591
```

prefixهای بررسی‌شده:

```text
64, 256, 1024, 4096, 16384, 65536 samples
```

در تمام prefixها امتیاز هر چهار نامزد دقیقاً برابر بود.

## نتیجه علمی صادقانه

قدم سوم نشان داد ابهام مشاهده‌شده ناشی از کمبود نمونه یا خطای عددی نیست،
بلکه یک **کلاس هم‌ارزی ساختاری** در observation فعلی است. بنابراین نتیجه
قابل دفاع سناریوی چهارم تا این مرحله عبارت است از:

```text
fault location              = uniquely recovered
unknown delta               = uniquely recovered as 0xB
active SK28 bits recovered  = 18 / 20
rank-1 key class            = 4 candidates
actual candidate in class   = YES
unique 20-bit recovery      = NO
```

این نتیجه با ماهیت بخش دوم Algorithm 4 مرجع نیز سازگار است؛ کد مرجع رتبه‌ی
نامزد کلید را گزارش می‌کند و برای محدودکردن هزینه محاسباتی بخشی از بیت‌های
زیرکلید را معلوم فرض می‌کند. بنابراین ادعای بازیابی یکتای تمام بیت‌ها در
این انتقال به SCENERY بدون observation اضافه، علمی نیست.

## چه چیزی برای شکستن tie لازم است؟

یکی از فرض‌های حمله باید تغییر کند؛ برای مثال:

```text
یک observation مستقل که بیت‌های دیگری از خروجی S-box نقش C را ببیند؛
یک کمپین fault مستقل با محل یا mapping متفاوت؛
leakage جانبی اضافه؛
یا اطلاعات اضافی درباره زیرکلید/ساختار کلید.
```

هیچ‌یک از این موارد جزو سناریوی چهارم فعلی نیست؛ بنابراین در این پروژه به
صورت مصنوعی از ground truth برای انتخاب نامزد واقعی استفاده نشده است.

## فایل‌های اضافه‌شده یا تغییرکرده

```text
include/unknown_infection_attack.h
src/unknown_infection_attack.c
tests/test_unknown_infection_structural_equivalence.c
tools/scenario4_audit_structural_tie.c
Makefile
CMakeLists.txt
README.md
README_FA.md
```

## خروجی‌های CSV

```text
results/scenario4_rank1_equivalence_matrix.csv
results/scenario4_rank1_equivalence_summary.csv
results/scenario4_prefix_equivalence.csv
results/scenario4_role_c_truth_table.csv
results/scenario4_step3_verification.csv
```

## اجرا

برای اجرای کامل قدم‌های ۱ تا ۳ سناریوی چهارم:

```bash
make scenario4-step3
```

اگر خروجی‌های قدم دوم از قبل موجود باشند و فقط ممیزی قدم سوم لازم باشد:

```bash
make scenario4-audit-tie
```

## وضعیت پایان قدم سوم

```text
Step 3 structural audit = PASS
more samples under current observation = insufficient by proof
final honest recovery = 18/20 active bits + unique delta
```
