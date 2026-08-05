# Driver Taxonomy — چرا هر ۸ هسته یک Driver مستقل‌اند

> وضعیت: **تصمیم معماری نهایی برای Alpha** (Feature Freeze)
> مرجع: مستندات رسمی هر پروژه + بازبینی کد در همین فاز

## تعریف واحد معماری

در Zagros، **Driver = یک محصول سرورِ مستقلِ قابل‌مدیریت**، نه صرفاً «یک پروتکل».
یک پوشه زیر `app/cores/drivers/` فقط وقتی Driver مستقل می‌شود که **هر سه شرط** را داشته باشد:

1. **باینری/سرویس مستقل** با چرخه‌حیات جدا (install/start/stop/restart, versioning)
2. **سطح مدیریتی (Management Surface) متفاوت** — API، فایل config، ساختار auth یا آمارگیری خاص خود؛ اگر دو «محصول» دقیقاً با همان مکانیزم مدیریت می‌شدند، دومی اضافی بود.
3. **Deployment جداگانه** بدون نیاز به هسته‌ی دیگر قابل اجرا باشد.

اشتراکِ *پروتکل* دلیل ادغام نیست: بازاستفاده از پروتکل در لایه‌ی **Delivery** (share link) و **Chain Outbound** اتفاق می‌افتد، نه در لایه‌ی Driver.

## رأی نهایی برای هر هسته

| Driver | محصول Upstream | سطح مدیریتی متمایز | رأی | چرا نه Plugin/Adapter؟ |
|---|---|---|---|---|
| **xray** | XTLS/Xray-core | Stats API + HandlerService gRPC + hot reload | **Driver مستقل** | — |
| **singbox** | SagerNet/sing-box | Clash API / v2ray_api experimental + config JSON | **Driver مستقل** | — |
| **openvpn** | OpenVPN | Management Interface TCP (`client-list`, `client-kill`, `bytecount`) + PKI کامل | **Driver مستقل** | — |
| **wireguard** | kernel + `wg`/`wg-quick` | کرنل/NIC، per-peer handshake stats از `wg show` | **Driver مستقل** | — |
| **hysteria2** | apernet/hysteria | **Traffic Stats API رسمی** (`/traffic`, `/online`, `/kick`, `/dump/streams`) + auth userpass + Masquerade + ACL | **Driver مستقل** | sing-box هیچ‌کدام از این سطح مدیریتی را برای hy2 ندارد |
| **tuic** | EAimTY/tuic | فقط فایل config (users: uuid→pass)؛ **هیچ stats API در پروتکل وجود ندارد** | **Driver مستقلِ نازک (نگه‌داشته شد با توضیح صادقانه)** | در ادامه |
| **ssh** | OpenSSH | account سیستم + `Match`/`sshd_config` + `ps`/session probe | **Driver مستقل** | — |
| **softether** | SoftEther VPN Server | `vpncmd` RPC (Hub/User/Session/SecureNAT/IPsec) | **Driver مستقل** | L2TP/PPTP از همین سرو مدیریت می‌شود → درایور جدا برای L2TP لازم نیست |

## پرسش کلیدی: Hysteria2 و TUIC فقط «inboundهای sing-box» نیستند؟

بررسی با مستندات رسمی — نتیجه: **خیر، premise درست نیست.** هر دو سرور مستقل رسمی دارند:

### Hysteria2 (apernet/hysteria) — Driver مستقل می‌ماند ✅
- سند رسمی «Traffic Stats API»: endpointهای `GET /traffic` (شمارنده rx/tx هر کاربر)،
  `GET /online` («تعداد instanceهای کلاینت = نزدیک‌ترین چیز به device count»)،
  `POST /kick` + توصیه‌ی رسمی: برای جلوگیری از reconnect، کاربر را در auth backend هم بلاک کن —
  دقیقاً همان کاری که درایور ما با `suspend → remove from config + kick` می‌کند.
- قابلیت‌های سطح بالاتر از sing-box: **Masquerade** (پاسخ HTTP/3 شبیه وب‌سایت واقعی)، ACL،
  محافظ brute-force، bandwidth hint سمت سرور.
- sing-box فقط hysteria2 را به‌عنوان inbound/outbound «پروتکل» پیاده می‌کند و این سطح
  مدیریتی (per-user online/kick/traffic دیتابیس‌گونه) را ندارد. تبدیل hysteria2 به «plugin
  سینگ‌باکس» یعنی **حذف واقعی قابلیت‌ها** — خلاف قاعده‌ی honest-capabilities.

### TUIC (EAimTY/tuic) — Driver مستقلِ نازک، با هشدار ماندگار ✅
- مستندات رسمی: `tuic-server` فقط با JSON config مدیریت می‌شود (`users: {uuid: pass}`,
  `congestion_control`، `zero_rtt_handshake`، …) و **هیچ API آماری ندارد**.
- درایور ما دقیقاً همین را صادقانه منعکس می‌کند: USAGE_ACCOUNTING و ONLINE_TRACKING را
  *claim نمی‌کند* و گزارش مصرف، TUIC را «unaccounted» اعلام می‌کند (به‌جای جعل عدد).
- مزیت استقلال: ارائه‌ی TUIC بدون الزام به sing-box؛ lifecycle و نصب مستقل؛ هویت پروتکل
  در Portal/Quota جدا. هزینه: **repo آپ‌استریم archive شده** — این ریسک در `description`
  متادیتای درایور و همین سند درج شده و اپراتور آگاهانه انتخاب می‌کند.
- جمع‌بندی: ۴۴۴ خط، بدون ادعای اضافه. حذفش فقط «کاهش تعداد» بود نه بهبود معماری.
  (اگر روزی sing-box به‌تنهایی TUIC را با سطح مدیریتی کامل بپوشاند، این تصمیم بازبینی می‌شود.)

## هم‌پوشانی/تکرار — بررسی این فاز

| موضوع | نتیجه |
|---|---|
| sing-box و hy2/tuic | هم‌پوشانی صفر: sing-box آن‌ها را فقط به‌صورت **chain outbound** استفاده می‌کند (`composes outbounds`)، inbound پنل آن‌ها نزد درایور خودشان است |
| wheels shared: DeltaTracker, ManagedProcess, github_install, delivery | قبلاً مشترک بود — بدون تکرار |
| **تولید گواهی self-signed EC (P-256)** | در ۲ backend (hysteria2, tuic) **تکراری بود → refactor شد** به `app/cores/pki.py::ensure_self_signed_cert` (idempotent، chmod 600) |
| OpenVPN PKI | CA + امضای server-key با RSA — منطق متفاوت (mini-CA)؛ **تکراری نیست** و عمداً دست‌نخورده ماند |
| چرخه‌های import | runtime: هیچ‌کدام (۷۶/۷۶ ماژول import شدند). سه یال استاتیک باقی‌مانده عمدی‌اند: `registry↔base` (TYPE_CHECKING + `__init_subclass__` lazy — الگوی auto-register)، `persistence.base→models` (lazy داخل `create_schema`)، legacy `subscription.share↔models.user` (upstream، نواحی قدیمی) |

## قاعده‌ی ممنوعه برای آینده
هیچ Driver جدیدی فقط برای «زیاد شدن تعداد Driverها». اضافه شدن Driver = سه شرط بالا +
مستندسازی در همین فایل. پروتکل‌های جدیدی که محصول مستقل ندارند، در سطح Delivery/Adapter
اضافه می‌شوند نه Driver.
