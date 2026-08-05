# Security Review — فاز Alpha (۵ اوت ۲۰۲۶)

روش: بازبینی دستی لایه‌به‌لایه + اسکن اتوماتیک + تست‌های fail-closed.
قانون: هر یافته یا اصلاح شد، یا با دلیل مستند باقی ماند.

## یافته‌ها و اقدام‌ها

| # | شدت | یافته | اقدام |
|---|-----|-------|--------|
| 1 | **بحرانی** | تمام endpointهای `/api/zagros/*` (dashboard snapshot، studio raw شامل **کلیدهای خصوصی هسته‌ها**، apply، app-credentials، migrate) **بدون احراز هویت** جواب می‌دادند | روتر ادمین جدا با `Admin.check_sudo_admin` در سطح router؛ fail-closed اگر پشته‌ی auth legacy در دسترس نباشد (۵۰۳، هرگز open)؛ تست دائمی `tests/adminapi/test_router_auth.py` که ۱۰ مسیر را بدون توکن و با همه‌ی methodها چک می‌کند |
| 2 | بالا | Rotation لینک اشتراک لینک‌های قدیمی را باطل نمی‌کرد | ذخیره‌ی jti جاری هر کاربر در settings KV (`SQLSettingsKV`)؛ portal بدون jti جاری ۴۰۴ می‌دهد (fail-closed؛ برای Alpha که هنوز deployment ندارد، بهترین انتخاب) |
| 3 | بالا | `ALLOWED_ORIGINS="*"` + `allow_credentials=True` (ترکیب خطرناک CORS) | پیش‌فرض به same-origin (لیست خالی) تغییر کرد؛ opt-in صریح از env |
| 4 | میانگین | نبود تست سطح-روتر برای تمایز مسیرهای public/private | تست دائمی: مسیرهای client/portal عمداً public می‌مانند (auth جدای خودشان)، admin همیشه guard دارد |
| 5 | میانگین | خطاهای `sing-box check` فقط stdout را نشان می‌داد — پیام واقعی FATAL در stderr بود | هر دو جریان capture می‌شود (یافته در e2e باینری واقعی) |

## مواردی که قبلاً درست بودند و این فاز re-verify شدند
- **Tokenهای کلاینت**: فرمت `zga.<b64>.<sig>`، HS256-only (بدون alg-confusion)،
  type «access»/«sub» جدا، jti رندوم، secret مشتق‌شده با HKDF از کلید اصلی.
- **Legacy admin JWT**: `algorithms=["HS256"]` در هر سه مسیر decode — بدون `none`-confusion ✓
- **Sealed Delivery**: X25519 + HKDF-SHA256 + AES-256-GCM؛ non-contributory points رد
  می‌شوند (در هر دو backend خالص‌پایتون و کتابخانه، قرارداد یکسان).
- **رمزهای اپ**: `secrets.token_urlsafe(15)`، نگهداری فقط به‌صورت scrypt hash، نمایش
  یک‌باره؛ uniform-cost برای نام‌های نامعتبر (ضد user-enumeration) + rate-limit ۵/۶۰ثانیه.
- **Connect Token**: یک‌بارمصرف، TTL ۳۰ثانیه، ذخیره‌ی sha256-hash، خطاهای یکدست
  (unknown/expired/replay غیرقابل تفکیک).
- **Portal/Studio UI**: خروجی HTML در ۵۵ نقطه با `html.escape` رندر می‌شود؛ فیلدهای
  secret با mask/reveal نمایش داده می‌شوند و src اصلی در DOM نیست.
- بدون `eval`/`exec` در لایه‌های جدید؛ بدون string interpolation در SQL (ORM/پارامتری);
  TUIC usage fabrication: گزارش صادقانه‌ی عدم پشتیبانی به‌جای جعل.

## تصمیم‌ها/محدودیت‌های پذیرفته‌شده (ریسک‌های باقی‌مانده، صادقانه)
1. **Admin API rate-limit**: میراث در `/api/admin/token` محدودیت تلاش ندارد — جبران با
   احراز قوی (sudo) + توکن‌های زمان‌دار JWT؛ بهبود در نسخه‌ی بعد (رد نشده، ثبت شد).
2. **توکن ادمین در localStorage** صفحات UI داخلی (dashboard/studio) نگهداری می‌شود —
   استانداردِ اکثر پنل‌های تک‌صفحه‌ای؛ XSS هر لایه‌ی UI می‌تواند آن را بخواند. کاهش ریسک:
   XSS review همین فاز + بدون سرو third-party در UI.
3. **کلید اصلی DB** از `ZAGROS_SECRET_KEY` مشتق می‌شود؛ در فایل env روی دیسک باقی
   می‌ماند — استاندارد عملیاتی است؛ KMS/HSM در roadmap، نه Alpha.
4. Default‌های Postgres/MySQL legacy (config) بدون رمز — بدون تغییر (رفتار upstream)؛
   راهنمای نصب Alpha دستور تنظیم صریح می‌خواهد.

## Performance ↔ Security
جایگزینی backend رمزنگاری با `cryptography` (AES-GCM: 21.9ms→0.005ms، X25519: ده‌ها
ms→0.077ms) هم سرعت را بالا برد و هم سطح اطمینان پیاده‌سازی را (constant-time C).
مسیر خالص‌پایتون حفظ شد اما صرفاً fallback بوت استرپ است؛ تست‌ها هر دو مسیر را روی
همان golden vectors قفل می‌کنند.
