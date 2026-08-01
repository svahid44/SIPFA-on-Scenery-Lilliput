# اعمال فاز اول SIPFA روی پروژه SCENERY در WSL

این patch باید روی نسخه مرجع `SCENERY_64_80_C_reference` اعمال شود.

## ۱. ساخت مخزن محلی پایه

اگر هنوز پروژه را استخراج نکرده‌ای:

```bash
mkdir -p ~/projects/scenery_sipfa
cd ~/projects/scenery_sipfa
unzip /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_C_reference_complete.zip
cd SCENERY_64_80_C_reference
```

## ۲. ثبت baseline در Git

اگر این مخزن هنوز Git ندارد:

```bash
git init
git add .
git commit -m "Import validated SCENERY-64/80 reference implementation"
git branch baseline-reference
git switch -c sipfa-development
```

اگر قبلاً branchها را ساخته‌ای، فقط این را بزن:

```bash
git switch sipfa-development
```

## ۳. اعمال patch فاز اول

فایل patch را در Downloads ویندوز قرار بده و سپس اجرا کن:

```bash
unzip -o /mnt/c/Users/SADRA/Downloads/SCENERY_64_80_SIPFA_phase1_patch.zip -d .
```

## ۴. build و test

```bash
make clean
make all
make test | tee phase1_test.log
```

خروجی نهایی باید شامل این خطوط باشد:

```text
Summary: 4/4 official vectors passed
PASS: all 28 encryption-round trace records match round_trace_tv1.json.
PASS: all 28 zero-master-key round keys match the reference trace.
PASS: 200 deterministic cross-validation vectors match the Python reference.
PASS: component properties, 10000 round trips, and in-place tests succeeded.
PASS: single-entry persistent fault, effective/ineffective events, persistence, and reset verified.
```

## ۵. اجرای جداگانه تست fault

```bash
./build/test_persistent_fault
```

## ۶. کنترل تغییرات

```bash
git status
git diff -- Makefile CMakeLists.txt README_FA.md   include/persistent_fault.h src/persistent_fault.c   tests/test_persistent_fault.c docs/PHASE1_PERSISTENT_FAULT_FA.md
```

## ۷. commit فاز اول

فقط اگر همه تست‌ها PASS شدند:

```bash
git add Makefile CMakeLists.txt README_FA.md APPLY_PHASE1_FA.md   include/persistent_fault.h src/persistent_fault.c   tests/test_persistent_fault.c docs/PHASE1_PERSISTENT_FAULT_FA.md

git commit -m "Add DES-style persistent S-box fault infrastructure"
```

## خروجی موردنیاز برای قدم بعد

پس از اجرا، محتوای این فایل را ارسال کن:

```bash
cat phase1_test.log
```

قدم بعدی فقط پس از تأیید این لاگ، ساخت dataset تشخیصی سناریوی ۱ خواهد بود.
