# بستهٔ نهایی بسته‌شدهٔ پروژه

این پوشه نسخهٔ کامل پروژه پس از فاز ۵ است.

دستورات اصلی:

```bash
make test
make scenario1-full-key
make scenario4-full-key
```

نتیجهٔ نهایی برای مدل شبیه‌سازی‌شده:

```text
Scenario 1 full 128-bit master-key recovery: PASS
Scenario 4 full 128-bit master-key recovery: PASS
```

محدوده: یک خطای ماندگار روی جدول S-box، مدل detection/infection تعریف‌شده در پروژه، بدون missed fault، نویز اضافی یا چندخطایی.
