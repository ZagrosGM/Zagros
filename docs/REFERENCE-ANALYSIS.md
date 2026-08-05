# تحلیل پروژه‌های مرجع (Marzban / 3x-ui / vpn-ui) و تصمیم‌های معماری

> هدف: استخراج ایده‌ی معماری، **نه کپی کد**. برای هر ایده: «چرا ارزشمنده / چرا مناسب نیست / چطور بهتر شد».
> وضعیت: بر اساس بررسی کد واقعی (Marzban v0.8.4، 3x-ui، vpn-ui@main).

---

## ۱. Marzban (تحلیل قبلی — جمع‌بندی تصمیماتی که از آن گرفتیم)

| ایده | حکم |
|---|---|
| مدل Node چندسروره + TLS داخلی پنل↔نود | ✅ اتخاذ (در قالب MULTI_NODE هر درایور) |
| gRPC Handler/Stats API برای مدیریت کاربر/آمار | ✅ درون `LegacyXrayBackend` |
| Pipeline جاب‌ها برای مصرف/انقضا | ✅ تعمیم به `UsageRecorder` مرکزی (فاز ۴) |
| Singletonهای سراسری `app.xray` + هاردکد پروتکل | ❌ حذف و پشت `BaseCoreDriver`/Registry رفت |
| کاربر متصل به inbound/porxy های Xray | ❌ جایگزین با `user_core_accounts` |

## ۲. 3x-ui (Go + تک‌کور Xray)

| مشاهده | حکم و دلیل |
|---|---|
| مدیریت inbound-centric قوی و UX عملیاتی تمیز | ➕ ایده‌ی UX؛ در UI فاز بعد استفاده می‌شود |
| تشخیص «آنلاین» با دلتای ترافیک اخیر (نه API واقعی) | ✅ همان الگو: `DeltaProbe` در LegacyXrayBackend — پروتکل‌ها API IP-table ندارند، این تنها راه صادقانه است |
| احراز پنل + session داخلی، بدون API کاربر نهایی | ❌ ما Client API جدا می‌سازیم (اپ موبایل) |
| معماری تک‌هسته‌ای متمرکز بر Xray | ❌ ناسازگار با هدف پلتفرم — رد |
| بسته‌بندی single-binary پنل | 🔸 ایده‌ی deploy خوب، خارج از اسکوپ فعلی |

## ۳. vpn-ui — تحلیل عمیق (فورک 3X-UI با ۱۲ پروتکل دیمون‌محور)

بررسی شد: `backend/*.go`، `web/service/corecatalog.go`، `radius.go`، `units.go`، `clients.go`، مدل دیتابیس.

### ۳.۱ ایده‌های ارزشمند (اتخاذ می‌شوند)

**الف) سرور RADIUS تعبیه‌شده — مهم‌ترین ایده**
- مشاهده: همان‌طور که Xray آمار per-user نداشت اما gRPC داشت، بسیاری از دیمون‌ها (OpenVPN/ocserv/pptpd/xl2tpd/sstp) آمار/احراز native ندارند. vpn-ui یک **سرور RADIUS داخل خود پنل** میزبان می‌کند: دیمون‌ها کاربر را از RADIUS می‌پرسند (`handleAuth`) و Accounting را هم به همان گزارش می‌دهند (`handleAcct`: Start/Interim-Update/Stop با اکتت‌ها هر ۶۰ثانیه). نتیجه: **احراز + آمار per-user + session + kill برای Coreهایی که هیچ API‌یی ندارند.**
- حکم: ✅ اتخاذ به‌صورت تعمیم‌یافته → الگوی **Accounting/Auth Bridge**: هر درایور که Coreش شمارنده native ندارد، یک "پل حسابداری" ارائه می‌دهد (RADIUS، iptables owner counters، disconnect-hook + status، event log). در نسخه‌ی ما برای OpenVPN همان اثر را **بدون پروتکل RADIUS** با Management Interface واقعی پیاده کردیم (`management-client-auth` برای احراز، `status 3` + `client-disconnect` hook برای آمار). اگر بعداً pptp/l2tp/sstp بیاید، یک RADIUS Bridge مشترک (یک `FeatBridgew` مشترک) اضافه می‌کنیم.

**ب) کاتالوگ Core با وابستگی‌های اشتراکی (feats) و refcounting**
- مشاهده: `coreSpec{modules, daemons, feats, paths, usesRadius}`؛ مثلاً **یک charon (strongSwan) یکبار نصب می‌شود و برای دو Core IKEv2 و L2TP/IPsec سرو می‌دهد**؛ حذف آن فقط وقتی آخرین مصرف‌کننده حذف شد. `sharersOf`/reconcile sweep هوشمندانه است.
- حکم: ✅ اتخاذ سبک‌وزن → `CoreMetadata.provides/requires` + گارد حذف وابستگی در CoreManager (در این مرحله پیاده شد). نسخه‌ی ما با Capability/Registry انعطاف‌پذیرتر از کاتالوگ استاتیک آن‌هاست.

**ج) تفکیک باینری Server vs Client**
- مشاهده: باینری‌های سرور با Core نصب می‌شوند؛ باینری‌های کلاینت (pptp/openconnect/sstp) جدا و on-demand — چون برای dial-out (همان Chain مال) لازم‌اند حتی بدون هیچ سرور محلی.
- حکم: ✅ مفهوم اتخاذ → در درایورها `install_server()` vs `install_client_tools()` جدا (WireGuard/OpenVPN درایورهای بعدی).

**د) systemd unit templating برای instanceهای متعدد**
- مشاهده: `openvpn@.service` با `%i.conf` — هر instance کانفیگ خودش.
- حکم: 🔸 ایده خوب برای دیمون‌های متعدد روی یک هاست؛ در نسخه‌ی ما فعلاً `ManagedProcess` پاسخگوست؛ لایه‌ی systemd renderer به‌عنوان گزینه‌ی deploy در Driverهای دیمونی بعدی (SoftEther/OpenVPN چند-instance).

**ه) پچ پروتکل‌های بدون-آمار داخل کورِ دارای-آمار (TUIC/Naive داخل Xray)**
- مشاهده: «به‌جای کور دوم، پروتکل را در کوری که accounting دارد جا می‌دهیم تا ارث‌بری شود».
- حکم: 🔸 **۳ دانش‌پذیری آگاهانه، اتخاذ نمی‌کنیم**: فورک نگه‌داشتنی Xray بدهی فنی می‌سازد و Plugin-Model ما را می‌شکند. جایگزین ما: (۱) Bridge حسابداری، (۲) میزبانی پروتکل‌های سبک داخل sing-box (درایور sing-box می‌تواند inbound های بیشتری رندر کند) — با همان منطق «جایی میزبان کن که قابلیتش را دارد» ولی بدون fork.

### ۳.۲ موارد نامناسب / طراحی ضعیف آن‌ها (اتخاذ نمی‌شود)

| مورد | چرا ضعیف است | طراحی بهتر ما |
|---|---|---|
| کاتالوگ استاتیک `coreSpec` در یک فایل عظیم | OCP نقض می‌شود، محل رشد bug | Registry + auto-register + entry points |
| God-object لایه‌ی `web/service` (۱۰۰+ فایل با ارجاع متقاطع) | SRP نقض؛ تست‌ناپذیر | درایور ایزوله + backend Protocol + پورت‌ها |
| کاربر متصل به inbound (میراث 3x-ui) | مانع اشتراک یکپارچه بین Coreها | `user_core_accounts` + PolicyProfile جهانی |
| RADIUS-محوری برای همه‌چیز | یک سرور اضافه برای Coreهایی که API بهتر دارند | Bridge به‌صورت opt-in per core؛ OpenVPN با mgmt native |
| فورک Xray وصله‌شده (AnyTLS/TUIC/Naive) | بدهی همگام‌سازی با upstream | Plugin + ترجمه؛ بدون fork |
| تست‌ها عمدتاً روی منطق وارداتی/unit محلی، نه قرارداد Core | بدون contract test | تست قرارداد per driver (مانند FakeDriver suite) |

**نکته‌ی تحسین‌برانگیز که حفظش می‌کنیم:** ماتریس OS/هسته‌ی AmneziaWG با توضیح صادقانه‌ی محدودیت‌ها — همان اصل «شفافیت به‌جای وعده» که در Capability/ماتریس ما هم هست.

---

## ۴. تصمیم‌های حاصل برای پلتفرم (در این مرحله اعمال/مستند شد)

1. **الگوی Bridge برای حسابداری/احراز** — OpenVPN با mgmt native؛ RADIUS Bridge مشترک برای دیمون‌های ppp بعداً.
2. **`CoreMetadata.provides/requires` + گارد حذف** — پیاده شد + تست.
3. **تفکیک install server/client** — در WireGuard/OpenVPN.
4. **عدم fork** — هیچ Core پچ‌شده‌ای وارد پروژه نمی‌شود.
5. **Refactorهای لازم قبل از Feature جدید** — انجام شد: `ManagedProcess` (حذف تکرار process-mng بین درایورها)، `DeltaTracker/SessionUsageTracker` (حذف تکرار منطق شمارنده)، پاک‌سازی importهای داخلی manager، خروجی‌های ثابت API.

---

## افزوده: تحلیل مجدد vpn-ui برای فاز پلتفرم (Driver به Driver)

بررسی دقیق `web/service/{sshoutbound,vpnoutbound,vpnrange,corecatalog}.go` و بک‌اندهای `strongswan/libreswan/accel/pppd/sstpc` انجام شد. نتیجه:

**پذیرفته‌شده (ایده، نه کد):**
1. **SSH Xray Outbound** (`sshoutbound.go`): ثابت کرد Xray-core outbound بومی `ssh` دارد → `OutboundKind.SSH` + مترجم xray + Chain ingress در SSHDriver.
2. **الگوی «بررسی آمادگی و گزارش صادقانه»** (matrix AWG-kernel در README): قاعده‌ی تیم ما «هر ناسازگاری = DEGRADED/unsupported صریح».
3. **Catalog فیچرهای مشترک** (corecatalog.go): قبلاً به `provides/requires` + uninstall-guard تعمیم یافته بود (P1) — این فاز در SoftEther/SSH از الگوی «سرویس سیستمی shared» برای تعریف دقیق claim مالکیت (SERVICE_CONTROL نداریم) استفاده شد. نکته‌ی واقعی: vpn-ui مالکیت سرویس‌های systemd را با template-unit حل می‌کند؛ ما فعلاً claim نمی‌کنیم.

**ردشده:**
1. **کپسوله‌سازی همه‌ی پروتکل‌ها داخل فورک xray** — vpn-ui برای TUIC/AnyTLS/Hysteria، xray پچ‌شده می‌سازد «تا per-account accounting موروثی شود». این دقیقاً همان چیزی است که معماری CoreHub حذفش کرده: هر Core با API رسمی خودش (hy2 traffic API, wg dump, SE UserGet) حسابداری می‌کند — بدون وابستگی به فورک.
2. **god-service** (سرویس‌های چندهزارخطی xray.go) — در مقابل: درایور نازک + Backend Protocol + منطق خالص قابل‌تست.
3. **PPTP/L2TP/SSTP accel-ppp** — قابلیت اختیاری (بند اختیاری برنامه)؛ با توجه به SoftEtherDriver که همان سطح L2TP/SSTP را با مدیریت تمیزتر پوشش می‌دهد، فعلاً خارج از برنامه.

**نکته‌ی یادگرفته‌شده برای آینده:** template-unitهای systemd (`openvpnTemplateUnit %i.conf`) برای Multi-instance per-node — در P9 (node-agent عمومی) به‌کار می‌آید.

## افزوده: تحلیل PasarGuard/panel برای فاز برندینگ و محصول

PasarGuard (فورک Marzban با پنل بازطراحی‌شده) صرفاً به‌عنوان **منبع الهام UX** بررسی شد؛ هیچ کد یا assetی کپی نشد (README آن تحلیل شد، نه سورس پنل). نتیجه‌ی پذیرش/رد:

| ایده | تصمیم | دلیل |
|---|---|---|
| کلید یک‌بارمصرف راه‌اندازی (`generate-temp-key` → واردکردن مالک) | **پذیرفته (ایده)** | امن‌تر از پسورد پیش‌فرض؛ برای `zagros-cli` به‌عنوان owner-setup flow در roadmap آمد |
| مستندات SSH port-forwarding برای node | **پذیرفته** | سناریوی واقعی استقرار؛ به docs افزوده می‌شود |
| مستندات چندزبانه (fa/en/ru/zh) | **پذیرفته** | READMEهای چهارزبانه بازنویسی شدند |
| Device limit بر اساس HWID | پذیرفته‌شده **قبلاً** | ما Device-ID + device_sessions داریم (P2.8)؛ HWID اختصاصی در اپ (P7) |
| Periodic traffic reset strategy | پذیرفته‌شده **قبلاً** | `data_limit_reset_strategy` در schema نگه داشته شد |
| RBAC چندسطحی برای ادمین‌ها | roadmap | در P5 هم‌زمان با CRUD کاربران |
| اسکرین‌شات‌محور بودن داشبورد آن‌ها (پولیش UX) | **پذیرفته** (فقط الهام) | سیستم طراحی مستقل Zagros (`--zg-*`) با هویت بصری خود ساخته شد |
| TimescaleDB برای سری‌های زمانی | **ردشده** | dialect-agnostic بودن SQLAlchemy برای ما حیاتی است (sqlite/postgres/mysql)؛ usage_records خام دارد، aggregation بعداً |
| کپی کامپوننت‌های پنل آن‌ها | **ردشده** | قاعده‌ی پروژه: ایده بله، کد/asset هرگز — هویت Zagros مستقل است |
