# راهنمای حذف فضای خالی دور لوگو (macOS)

## روش ۱: استفاده از Preview (پیش‌نمایش) - ساده و سریع

### مراحل:

1. **باز کردن فایل لوگو**
   - فایل `atlas-logo.png` را با دابل‌کلیک باز کنید (به صورت پیش‌فرض در Preview باز می‌شود)

2. **فعال کردن حالت ویرایش**
   - روی آیکون **قلم** (Markup Toolbar) کلیک کنید
   - یا از منو: `Tools` → `Show Markup Toolbar`
   - یا کلید میانبر: `⌘ + Shift + A`

3. **انتخاب ابزار Rectangular Selection**
   - روی آیکون **مستطیل منقط** کلیک کنید
   - یا کلید میانبر: `⌘ + K`

4. **انتخاب فقط لوگو (بدون فضای خالی)**
   - با ماوس یک مستطیل دور **فقط** قسمت لوگو بکشید
   - سعی کنید تا حد امکان نزدیک به لبه‌های لوگو باشید
   - فضای خالی اطراف را شامل نشوید

5. **برش تصویر (Crop)**
   - از منو: `Tools` → `Crop`
   - یا کلید میانبر: `⌘ + K`
   - تصویر به اندازه انتخاب شما برش می‌خورد

6. **ذخیره فایل**
   - `File` → `Save` یا `⌘ + S`
   - فایل با همان نام ذخیره می‌شود

7. **کپی به پوشه پروژه**
   ```bash
   cp ~/Desktop/atlas-logo.png /Users/majlotfi/Desktop/Atlas/frontend/assets/images/atlas-logo.png
   ```

---

## روش ۲: استفاده از Terminal (خودکار با ImageMagick)

اگر ImageMagick نصب داری، این دستور فضای خالی را خودکار حذف می‌کند:

```bash
# نصب ImageMagick (اگر نداری)
brew install imagemagick

# حذف خودکار فضای خالی
convert ~/Desktop/atlas-logo.png -trim +repage /Users/majlotfi/Desktop/Atlas/frontend/assets/images/atlas-logo.png
```

---

## روش ۳: استفاده از Photopea (آنلاین - بدون نصب)

اگر Preview کار نکرد:

1. به سایت بروید: https://www.photopea.com
2. فایل لوگو را Drag & Drop کنید
3. از منو: `Image` → `Trim`
4. گزینه `Transparent Pixels` را انتخاب کنید
5. `OK` بزنید
6. `File` → `Export As` → `PNG`
7. فایل را دانلود و در پوشه پروژه قرار دهید

---

## تست نتیجه

بعد از برش و کپی فایل، صفحه را رفرش کنید:

```
http://localhost:8000/templates/login.html
```

لوگو باید بدون فضای خالی اضافی نمایش داده شود! ✨

---

## نکات مهم:

- ✅ فایل نهایی باید فرمت **PNG** با پس‌زمینه **شفاف** باشد
- ✅ نام فایل دقیقاً باید `atlas-logo.png` باشد
- ✅ مسیر دقیق: `/Users/majlotfi/Desktop/Atlas/frontend/assets/images/atlas-logo.png`
- ✅ بعد از کپی، صفحه را Hard Refresh کنید: `⌘ + Shift + R`
