# Real-Binary Compatibility Notes (تست با باینری واقعی — نتایج اجرا شده)

> این سند نتیجه‌ی اجرای واقعی سوئیت `tests/e2e/` با باینری‌های رسمی دانلودشده از
> GitHub است (نه mock). هر مورد با خطای واقعی باینری کشف و اصلاح شد.
> اجرا: `ZAGROS_E2E=1 python3 -m pytest tests/e2e -q` → **6 passed, 1 skipped**

## باگ‌های واقعی‌ای که فقط با باینری واقعی پیدا شدند

| # | Core | باگ | ریشه | اصلاح |
|---|------|-----|-------|--------|
| 1 | hysteria2 | `FATAL invalid config: auth.userpass: empty auth userpass` | سرور واقعی users خالی را قبول نمی‌کند | bootstrap credential تصادفیِ پایدار (`0600`، در work_dir) تا اولین کاربر واقعی |
| 2 | hysteria2 | Traffic Stats API اصلاً bind نمی‌شد | کلید YAML `traffic:` بود؛ کلید رسمی **`trafficStats:`** است (snake_case بی‌صدا نادیده گرفته می‌شود) | تصحیح کلید + به‌روزرسانی assert تست‌ها |
| 3 | hysteria2 | `FATAL ... userpass[1] expected type 'string', got map` با نام‌هایی مثل `1.alice` | decoder کانفیگ hysteria نقطه‌ی داخل کلید map را **key path تو در تو** تفسیر می‌کند — دقیقاً فرمت account_id رایج پنل‌ها (`{id}.{username}`) | نام هسته‌ای به‌صورت deterministic sanitize شد (`_hy2_name`، فقط `[A-Za-z0-9_-]`) + reverse-map برای traffic/online/kick + تشخیص collision صریح در زمان render |
| 4 | hysteria2/tuic/sing-box | `Executable not found` بعد از install موفق | `ManagedProcess` با argv قدیمی (قبل از تغییر مسیر در install) ساخته شده بود | بازسازی process بعد از install (`_make_proc`) در هر سه backend |
| 5 | hysteria2 (و مشابه) | فرایند یتیم بعد از تست Fail‌شده | نبود cleanup قطعی | `addCleanup(stop)` در همه‌ی سناریوهای e2e |
| 6 | tuic | `users cannot be empty at line 3 column 14` | همان رفتار #1 در tuic-server | bootstrap uuid تصادفیِ پایدار برای tuic |
| 7 | tuic | `endpoint dual-stack socket setting error (os error 92)` | upstream ≤1.0.0 روی **bind صریح IPv4** می‌شکند؛ `[::]` سالم است (باگ upstream، نه پنل) | `dual_stack` فقط برای listen های `[::]?` مصداقی + سند در config_schema + e2e روی `[::]` |
| 8 | sing-box | `FATAL dns.servers[0].type: unknown field` | config روی schema قدیمی 1.11 بود | مهاجزار render به **schema مدرن 1.12** (dns servers با type/tag) + pin نسخه‌ی `release_version=1.12.4` |
| 9 | sing-box | `legacy special outbounds is deprecated in 1.11, removed in 1.13` | outbound ویژه‌ی `{"type":"dns"}` | حذف dns-out؛ DNS interception با `{"protocol":"dns","action":"hijack-dns"}`؛ ترجمه‌ی `OutboundKind.DNS` دیگر construct مستهلک تولید نمی‌کند و صادقانه Unsupported گزارش می‌شود |
| 10 | sing-box | `initialize inbound[0]: missing password` | inboundهای بدون کاربر render می‌شدند | فقط inboundهای با ≥۱ کاربر فعال render می‌شوند؛ core تازه با صفر inbound بالا می‌آید |
| 11 | xray | نصب/آنینستال | درایور SELF_INSTALL ادعا می‌کرد ولی پیاده‌سازی نداشت | install/update/uninstall واقعی (zip رسمی XTLS + geoip/geosite از همان آرشیو) + **سیاست امنیتی: uninstall فقط با marker file** (باینری سیستمی حذف نمی‌شود) |
| 12 | panel DB | restore نتیجه‌ی stale برمی‌گرداند | کپی فایلی DB در حالت **WAL** بدون checkpoint/آزادسازی اتصال‌ها | سناریوی backup/restore با `PRAGMA wal_checkpoint(TRUNCATE)` + dispose + اتصال‌های isolated — همین قاعده برای قابلیت Backup محصول لازم است |
| 13 | نصب از GitHub | `HTTP 403 rate limit exceeded` | وابستگی سخت به REST API ناشناس (۶۰ req/h) | User-Agent + `GITHUB_TOKEN` + fallback مستقیم `releases/latest/download/<asset>` + نصب **pinned** (tag/asset دقیق) برای sing-box |

## محدودیت‌های محیطی صادقانه (نه باگ محصول)
- **xray start در sandbox**: مسیر start از پشته‌ی legacy XrayConfig (DB-seeded) عبور می‌کند؛
  در sandbox برهنه SKIP مستند می‌شود. install/version/uninstall با باینری واقعی پاس شد.
- **wireguard / openvpn / softether / ssh**: نیاز به root یا /dev/net/tun دارند — در محیط
  غیر‌privileged فقط گزارش محیطی صریح چاپ می‌شود (تست سبز جعلی وجود ندارد).
- **TUIC usage**: پروتکل هیچ API آماری ندارد → درایور `CapabilityNotSupportedError`
  می‌دهد (مستند؛ شبیه‌سازی نمی‌شود).

## سناریوهای پوشش‌یافته با باینری واقعی
install ✅ · upgrade/re-install ✅ · start/status/logs ✅ · create/delete user ✅ ·
suspend/resume (+kick واقعی) ✅ · restart ✅ · **crash-failover** (SIGKILL → پنل STOPPED
می‌بیند → بازیابی) ✅ · usage accounting real (hy2) ✅ · نامه‌های Sealed/Delivery ✅ ·
backup/restore/upgrade DB ✅ · no-usage fabrication (tuic) ✅
