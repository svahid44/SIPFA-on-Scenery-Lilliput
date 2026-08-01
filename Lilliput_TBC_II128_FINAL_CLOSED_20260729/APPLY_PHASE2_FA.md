# اعمال مرحله دوم

این patch را فقط روی branch زیر اعمال کنید:

```bash
git switch sipfa-development
```

سپس از ریشه پروژه:

```bash
unzip -o /mnt/c/Users/SADRA/Downloads/Lilliput_TBC_II128_phase2_patch.zip -d .
make clean
make test
make scenario1
```

خروجی مورد انتظار آزمون جدید:

```text
PASS: Scenario 1 known-fault detection dataset and final-round tweakey recovery verified.
```

خروجی اجرای سناریو باید برای هر هشت lane مقدار `PASS` و در پایان پیام زیر را نشان دهد:

```text
PASS: Scenario 1 recovered the complete final-round tweakey.
```
