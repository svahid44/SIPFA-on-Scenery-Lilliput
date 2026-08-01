# اعمال مرحله اول روی مخزن محلی

این بسته باید روی شاخه `sipfa-development` و در ریشه پروژه استخراج شود.

```bash
cd /mnt/c/Users/SADRA/Downloads/Lilliput_TBC_II128_clean

git branch baseline-reference 3d15ec3  # فقط اگر هنوز وجود ندارد

git switch sipfa-development
unzip -o /mnt/c/Users/SADRA/Downloads/Lilliput_TBC_II128_phase1_patch.zip -d .

make clean
make test

git status
git add Makefile include/cipher.h include/persistent_fault.h \
        src/cipher.c src/persistent_fault.c \
        tests/test_persistent_fault.c docs/PHASE1_PERSISTENT_FAULT.md

git commit -m "Add persistent S-box fault infrastructure"
```

خروجی نهایی باید شامل دو پیام PASS باشد.
