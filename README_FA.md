<div align="center" dir="rtl">

# زاگرس

**یک پنل. همهٔ هسته‌ها. کنترل کامل.**

پنل مدیریت VPN چندهسته‌ای که هسته‌هایتان را روی همین سرور اجرا می‌کند — و روی هر تعداد نودی که اضافه کنید.

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fzagrosgm%2Fzagros-2496ED?logo=docker&logoColor=white)](https://github.com/ZagrosGM/Zagros/pkgs/container/zagros)
[![Docs](https://img.shields.io/badge/docs-zagros--docs-success)](https://github.com/ZagrosGM/zagros-docs)
[![Cores](https://img.shields.io/badge/cores-7-orange)](#هسته‌های-پشتیبانی‌شده)

### 📖 [**English README**](README.md) &nbsp;·&nbsp; [**مستندات کامل**](https://github.com/ZagrosGM/zagros-docs) &nbsp;·&nbsp; [**نصب**](#نصب)

</div>

---

<div dir="rtl">

## زاگرس چیست

زاگرس یک fork سخت از [مرزبان](https://github.com/Gozargah/Marzban) است که دیگر Xray را **تنها** موتور نمی‌داند و با هر هستهٔ VPN مثل یک شهروند درجه‌یک رفتار می‌کند.

یک کاربرِ داشبورد می‌تواند هم‌زمان پروتکل‌هایی از **هر** هسته داشته باشد. سهمیه، سقف دستگاه و حضور نشستش **یک‌بار** شمرده می‌شود — روی همهٔ هسته‌ها و همهٔ نودها. **یک** لینک اشتراک می‌گیرد و کلاینت هر فرمتی را که می‌فهمد دریافت می‌کند.

هیچ چیز شبیه‌سازی نشده: هر هسته باینری رسمی خودش را در زمان اجرا نصب می‌کند و هیچ باینری هسته‌ای داخل ایمیج پخته نشده است.

</div>

<div align="center">

![داشبورد زاگرس](assets/screenshots/dashboard.png)

</div>

---

<div dir="rtl">

## هسته‌های پشتیبانی‌شده

| هسته | پروتکل‌ها | نحوهٔ مدیریت |
| --- | --- | --- |
| **Xray-core** | VLESS · VMess · Trojan · Shadowsocks | هستهٔ داخلی و محافظت‌شدهٔ پلتفرم |
| **sing-box** | Hysteria2 · TUIC v5 · و خانوادهٔ پروتکل‌های Xray | درایور خودنصب |
| **OpenVPN** | UDP · TCP، چند-اینباند | درایور خودنصب |
| **WireGuard** | WireGuard | درایور خودنصب |
| **SoftEther VPN** | SSTP · L2TP/IPsec · SoftEther بومی | درایور خودنصب |
| **SSH** | تونل SSH، با حسابداری دوطرفه | مدیریت توسط سیستم‌عامل |
| **PPTP** | PPTP + MPPE *(قدیمی — ذاتاً ناامن)* | رانتایم ACCEL-PPP همراه |

همهٔ هسته‌ها از یک رابط درایورِ مبتنی بر قابلیت مدیریت می‌شوند، پس نصب، پیکربندی، اجرا، اندازه‌گیری و حذف — فارغ از موتور زیرین — دقیقاً یک معنا دارند.

---

## امکانات

### کاربران و تحویل
- **یک کاربر، چند هسته** — یک کاربر داشبورد پروتکل‌هایی از هر هستهٔ نصب‌شده را با هم دارد.
- **سهمیهٔ یکپارچه** — مصرف همهٔ هسته‌ها در یک مجموعه شمارنده جمع می‌شود؛ ری‌استارت هرگز ترافیک قدیمی را دوباره نمی‌شمارد.
- **سقف دستگاه سراسری** — اعمال بر اساس اجتماع IPها در همهٔ هسته‌ها، نه حدس جداگانه برای هر هسته.
- **یک لینک اشتراک، چند فرمت** — لینک‌های خام، Clash / Stash / FlClash (فرمت mihomo YAML) و JSON کامل sing-box؛ بر اساس User-Agent کلاینت انتخاب می‌شود یا با `?format=` اجباری.
- **پورتال اشتراک** — مرورگرها یک صفحهٔ واقعی می‌بینند و می‌توانید خودتان طراحی‌اش کنید.
- **قالب‌ها** — پروتکل، سقف داده و انقضا را از یک تعریف قابل استفادهٔ مجدد بسازید.

### نودها
- **نودهایی که خودشان ملحق می‌شوند** — نصب‌کننده را اجرا کنید، اثر انگشت را تأیید کنید؛ نود جفت می‌شود، هویت سرور را می‌پذیرد، اکانت‌ها را می‌گیرد و مصرف را گزارش می‌دهد.
- **کنترل‌پلین با گواهی پین‌شده** — ترافیک نود روی HTTPS پین‌شده و پورت جداگانه.
- **موجودی هسته به تفکیک نود** — روی هر نود هسته‌های متفاوتی نصب و اجرا کنید.

### عملیات
- **Config Studio** — ویرایش اینباند، اوت‌باند، مسیریابی و DNS بر پایهٔ اسکیما، با پیش‌نمایش قبل از اعمال.
- **ورود از لینک** — لینک `vless://`، `vmess://`، `trojan://`، `ss://`، `hysteria2://` یا `tuic://` را بچسبانید تا اوت‌باند ساخته شود.
- **گواهی‌ها** — صدور با ACME، وارد کردن گواهی خودتان، پشتیبانی از wildcard.
- **پشتیبان‌گیری و بازگردانی** — دیتابیس، پیکربندی، گواهی‌ها، کلیدها و وضعیت هسته‌ها در یک آرشیو؛ پشتیبان زمان‌بندی‌شده هم هست.
- **مهاجرت** — انتقال کاربران از Marzban، PasarGuard و 3x-ui، همراه با گزارش dry-run پیش از اعمال.
- **حاکمیت مدیران** — سقف تعداد کاربر، انقضا و تخصیص ترافیک برای هر مدیر، با اعمال ایمن در برابر رقابت هم‌زمانی.
- **ردّ ممیزی** — عملیات ممتاز ثبت می‌شوند.

### امنیت
- **API مدیریتی با احراز هویت sudo** — عملیات ممتاز نیازمند مدیر sudo است.
- **تحویل مهروموم‌شده به کلاینت** — X25519 + HKDF + AES-256-GCM.
- **بدون سوکت داکر، بدون فضای‌نام PID هاست** — کانتینر پنل مالک هاست نمی‌شود.
- **رمزنگاری دو-بک‌اند** — استفاده از AES-GCM سخت‌افزاری در صورت وجود.

### رابط کاربری
- **پوستهٔ تیره و روشن**
- **انگلیسی و فارسی**، با چیدمان کامل راست‌به‌چپ
- **پالت فرمان** — با <kbd>⌘</kbd>+<kbd>K</kbd> به هر جا بپرید

</div>

<div align="center">

| هسته‌ها — هر موتور، یک چرخهٔ عمر | کاربران — یک هویت روی همهٔ هسته‌ها |
| :---: | :---: |
| ![هسته‌ها](assets/screenshots/cores.png) | ![کاربران](assets/screenshots/users.png) |

| نودها | اشتراک‌ها |
| :---: | :---: |
| ![نودها](assets/screenshots/nodes.png) | ![اشتراک‌ها](assets/screenshots/subscriptions.png) |

| مسیریابی | گواهی‌نامه‌ها |
| :---: | :---: |
| ![مسیریابی](assets/screenshots/routing.png) | ![گواهی‌نامه‌ها](assets/screenshots/certificates.png) |

</div>

---

<div dir="rtl">

## نصب

فقط یک دستور. خطی را که با دیتابیس مورد نظرتان می‌خواند انتخاب کنید — بقیهٔ کارها، از جمله نصب داکر در صورت نبودن، خودکار انجام می‌شود.

> **پیش‌نیازها:** یک سرور مجازی لینوکس ۶۴ بیتی و تازه (ترجیحاً Ubuntu 22.04 به بالا یا Debian 12 به بالا)، دسترسی root، و حداقل ۱ گیگابایت RAM.

### SQLite — پیش‌فرض، مناسب استقرارهای کوچک

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/zagros.sh)" -- install
```

### MySQL

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/zagros.sh)" -- install --database mysql
```

### MariaDB

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/zagros.sh)" -- install --database mariadb
```

### PostgreSQL

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/zagros.sh)" -- install --database postgresql
```

پس از پایان، آدرس **`http://<server-ip>:8000/dashboard/`** را باز کنید و اولین مدیر را بسازید:

```bash
sudo zagros advanced create-admin --sudo
```

> پیش از استفادهٔ واقعی، پنل را پشت TLS ببرید — [TLS برای پنل](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/examples/panel-tls.md).

### افزودن نود

روی سرور جدید:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/install-node.sh)"
```

سپس در پنل: **نودها ← نودی که ساختید ← اتصال**، و اثر انگشتی را که نصب‌کننده چاپ کرده تأیید کنید.

### به‌روزرسانی

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/zagros.sh)" -- update
```

به‌روزرسانی ابتدا پشتیبان می‌گیرد و اگر بررسی سلامت شکست بخورد، خودش به عقب برمی‌گردد.

---

## دستورهای روزمره

```bash
sudo zagros status        # سرویس، ایمیج، سلامت و جدول هسته‌ها
sudo zagros logs -f       # دنبال‌کردن لاگ پنل
sudo zagros restart       # بازسازی پنل — همیشه تغییرات .env را اعمال می‌کند
sudo zagros cores         # هسته‌های نصب‌شده: وضعیت، نسخه، سلامت
sudo zagros env show      # فایل .env با مقادیر حساسِ ماسک‌شده
sudo zagros backup        # پشتیبان کامل: دیتابیس، پیکربندی، گواهی، کلید، هسته‌ها
sudo zagros restore latest
sudo zagros advanced doctor   # گزارش کامل سیستم
sudo zagros help
```

مرجع کامل: [خط فرمان](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/cli.md).

---

## مستندات

| | |
| --- | --- |
| [آشنایی](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/introduction.md) | زاگرس چیست و چطور ساخته شده |
| [نصب](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/installation.md) | همهٔ مسیرهای نصب با جزئیات |
| [پیکربندی](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/configuration.md) | تک‌تک متغیرهای محیطی |
| [مهاجرت](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/migration.md) | **از Marzban / 3x-ui، و SQLite ← MySQL** |
| [نودها](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/nodes.md) | جفت‌شدن، موجودی، رفع اشکال |
| [هسته‌ها](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/cores.md) | نصب و رفتار هر هسته |
| [کاربران](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/users.md) | سهمیه، دستگاه، قالب |
| [اشتراک‌ها](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/subscriptions.md) | فرمت‌ها و پورتال |
| [گواهی‌نامه‌ها](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/certificates.md) | ACME، وارد کردن، wildcard |
| [REST API](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/api.md) | یکپارچه‌سازی با هر چیزی |
| [عیب‌یابی](https://github.com/ZagrosGM/zagros-docs/blob/main/fa/docs/troubleshooting.md) | وقتی چیزی درست کار نمی‌کند |

---

## ساختار پروژه

| ریپازیتوری | محتوا |
| --- | --- |
| [**Zagros**](https://github.com/ZagrosGM/Zagros) | خود پنل — API، درایور هسته‌ها، داشبورد |
| [**zagros-scripts**](https://github.com/ZagrosGM/zagros-scripts) | نصب‌کننده‌ها، CLI میزبان `zagros`، ایجنت‌های هاست |
| [**zagros-node**](https://github.com/ZagrosGM/zagros-node) | ایجنت نود و ایمیج آن |
| [**zagros-docs**](https://github.com/ZagrosGM/zagros-docs) | سایت مستندات |

---

## مشارکت

گزارش باگ و pull request پذیرفته می‌شود. مواد توسعه — تست‌ها، یادداشت‌های معماری و ابزار داخلی — در ریپازیتوری جداگانه‌ای نگهداری می‌شوند تا هر ریلیز فقط شامل چیزی باشد که یک اپراتور نصب می‌کند.

لطفاً قرارداد صداقتی که این پروژه بر آن بنا شده را حفظ کنید: **بدون TODO، بدون placeholder، و بدون هیچ ادعایی در رابط کاربری که کد واقعاً انجامش نمی‌دهد.** اگر مقداری قابل اندازه‌گیری نیست، پنل همین را می‌گوید، نه اینکه عددی قابل‌قبول نشان دهد.

---

## مجوز

تحت [AGPL-3.0](LICENSE) منتشر شده است. اجزای شخص ثالث در [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) فهرست شده‌اند.

زاگرس یک fork سخت از [مرزبان](https://github.com/Gozargah/Marzban) است — با تشکر از Gozargah و همهٔ پروژه‌های هستهٔ بالادستی.

</div>

---

<div align="center">

**[⬆ بازگشت به بالا](#زاگرس)** &nbsp;·&nbsp; [English README](README.md)

</div>
