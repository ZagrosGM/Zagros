# معماری پلتفرم مدیریت چند Core — Marzban Multi-Core (CoreHub)

> نسخه ۰.۱ — سند معماری و نقشه راه
> هدف: تبدیل Marzban از «پنل مدیریت Xray» به «پلتفرم مدیریت چندین VPN Core» به‌صورت Plugin-Based.

---

## ۱. تحلیل وضعیت موجود Marzban (master@v0.8.4)

### ۱.۱ پشته فناوری

| لایه | فناوری فعلی |
|---|---|
| Web/API | FastAPI + uvicorn، مدل‌های Pydantic v2 |
| دیتابیس | SQLAlchemy 2 + Alembic (SQLite / MySQL / PostgreSQL) |
| ارتباط با Xray | gRPC (`xray_api` — سرویس‌های Handler/Stats) |
| نودها | RPyC (پروتکل marzban-node) |
| jobها | APScheduler (record usages، expire، review، restart core) |
| اشتراک | تولید share-link خام (vless/vmess/trojan/ss، قالب‌های Clash/sing-box/v2ray/outline) |
| داشبورد | React (build شده در `app/dashboard`) |
| ربات‌ها | Telegram + Discord |

### ۱.۲ نقاط وابستگی مستقیم به Xray (مشکل اصلی)

این موارد دقیقاً همان جاهایی هستند که باید Generalize شوند:

| # | فایل | وابستگی |
|---|---|---|
| ۱ | `app/xray/__init__.py` | Singletonهای سراسری `core / api / config / nodes / hosts` که همه‌جا مستقیم import می‌شوند |
| ۲ | `app/db/models.py` | پراپرتی `User.inbounds` مستقیماً `xray.config.inbounds_by_protocol` را می‌خواند — **لایه ORM به Core وصل است** |
| ۳ | `app/models/proxy.py` | `ProxyTypes` فقط vmess/vless/trojan/ss با مدل‌های `xray_api.types.account` — هاردکد |
| ۴ | `app/xray/operations.py` | `add_user/remove_user/update_user` مستقیم روی gRPC کور اصلی + همه نودها؛ هویت کاربر = `"{id}.{username}"` |
| ۵ | `app/xray/config.py` + `xray_config.json` | کانفیگ JSON خام Xray مرکز ثقل کل سیستم است |
| ۶ | `app/subscription/*` | خروجی لینک‌های خام با تمام پارامترهای اتصال (UUID، آدرس، SNI و...) — در سناریوی اپ باید کنار گذاشته شود |
| ۷ | `app/jobs/*` | چرخه‌حیات و آماردهی فقط برای Xray پیاده شده |
| ۸ | `app/routers/core.py` | وضعیت/ری‌استارت فقط Xray |
| ۹ | جداول `inbounds / proxies / hosts` | مفاهیم Native ایکس‌ری (بر اساس `tag` کانفیگ) |

### ۱.۳ نقاط قوت (حفظ می‌شوند)

- مدل **Node** چندسروره + گواهی TLS داخلی بین پنل و نودها
- Pipeline ثبت مصرف (jobs → جداول usage → reset/review)
- ادمین‌ها، سطح دسترسی (sudo)، user_template ها، notificationها
- FastAPI + SQLAlchemy: بازار بزرگ توسعه‌دهنده، مناسب توسعه plugin

---

## ۲. اصول و تصمیم‌های کلیدی معماری

1. **Ports & Adapters (Hexagonal):** قلب سیستم (کاربران، اشتراک‌ها، دستگاه‌ها) هیچ وابستگی‌ای به Core ندارد. فقط از طریق `CoreManager` و Interface مشترک (`BaseCoreDriver`) با Coreها حرف می‌زند.
2. **Xray = یک Driver معمولی:** تمام کد موجود `app/xray/` بدنه‌ی `XrayDriver` می‌شود؛ بقیه درایورها مستقل.
3. **User ≠ Proxy:** موجودیت «کاربر» از «اکانت کاربر روی یک Core» جدا می‌شود: جدول `user_core_accounts` (رابطه چندبهچند User↔Core).
4. **Capability Negotiation:** هر درایور اعلام می‌کند چه توانایی‌هایی دارد (آمار، آنلاین‌ترکینگ، suspend و...). UI و سرویس‌ها بر اساس Capability رفتار می‌کنند، نه `if core == "xray"`.
5. **Config Schema (JSON Schema):** هر Core تنظیمات اختصاصی‌اش را با JSON Schema معرفی می‌کند؛ داشبورد فرم را خودکار رندر و API اعتبارسنجی می‌کند.
6. **Event-Driven:** عملیات دامنه (ساخت/حذف/تعلیق کاربر، اتصال/قطع‌شدن دستگاه...) به‌صورت Event منتشر می‌شود؛ CoreManager مشترک آن‌هاست. جایگزین فراخوانی مستقیم `xray.operations`.
7. **Multi-Node از روز اول:** هر Core می‌تواند چند Instance روی Nodeهای مختلف داشته باشد (الگوی فعلی Marzban، تعمیم‌یافته).
8. **Sealed Config Delivery:** اپ موبایل هرگز لینک/کانفیگ خام نمی‌گیرد؛ پیکربندی اتصال رمزنگاری‌شده و فقط در حافظه‌ی اپ ساخته می‌شود (بخش ۸).
9. **افزودن Core جدید = یک پوشه جدید:** بدون دست‌خوردن به کد فعلی (Open/Closed Principle).

---

## ۳. نمای کلی سیستم

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            CLIENTS                                       │
│   Admin Dashboard (React)      Telegram Bot        Mobile App (Flutter)  │
└──────────────┬───────────────────────┬───────────────────┬──────────────┘
               │ /api/* (admin JWT)    │                   │ /client/v1/*
               │                       │                   │ (user JWT + refresh,
               │                       │                   │  device-bound, sealed config)
┌──────────────▼───────────────────────▼───────────────────▼──────────────┐
│                        FastAPI APPLICATION                              │
│  Middlewares: AuthN/Z · RateLimit · AuditLog · SecurityHeaders          │
├─────────────────────────────────────────────────────────────────────────┤
│  SERVICES: UserService · ProvisioningService · DeviceService ·          │
│            SubscriptionService · StatsService · NodeService             │
├──────────────────────────────────────────────────────────────┬──────────┤
│              CORE ABSTRACTION LAYER (✅ این مرحله پیاده شد)   │  EventBus │
│   CoreManager ── orchestrates ──► per-core Drivers           │ pub/sub   │
├──────────────────────────────────────────────────────────────┴──────────┤
│  DRIVERS (Plugins): XrayDriver · SingBoxDriver · WireGuardDriver ·      │
│   OpenVPNDriver · Hysteria2Driver · TUICDriver · SSHDriver · ...        │
├─────────────────────────────────────────────────────────────────────────┤
│  REPOSITORIES (SQLAlchemy) ────► DB: users · user_core_accounts ·       │
│   cores · core_inbounds · devices · sessions · usage · audit · tokens   │
└─────────────────────────────────────────────────────────────────────────┘
            │ gRPC │ wg CLI │ mgmt TCP │ HTTP API │ sshd/vpncmd │
            ▼      ▼        ▼          ▼          ▼             ▼
        Core Instances روی Master و Nodeها (SystemD/Container processes)
```

---

## ۴. ساختار پوشه‌های پیشنهادی

```
marzban/
├── app/
│   ├── api/                        # ← جدید: روترها در دو سطح مجزا
│   │   ├── admin/                  # پنل ادمین (/api/*)
│   │   │   ├── cores.py            #   Core Settings: CRUD + start/stop/logs/...
│   │   │   ├── devices.py          #   مدیریت دستگاه‌ها
│   │   │   └── dashboard.py        #   آمار تجمیعی داشبورد
│   │   └── client/                 # ← API اختصاصی اپ موبایل (/client/v1/*)
│   │       ├── auth.py  services.py  connect.py  devices.py
│   ├── cores/                      # ✅ پیاده‌سازی شده در همین مرحله
│   │   ├── __init__.py
│   │   ├── base.py                 # BaseCoreDriver — قرارداد همه Coreها
│   │   ├── types.py                # DTOها: CoreMetadata, UserAccount, ...
│   │   ├── manager.py              # CoreManager — ارکستراتور + پورت persistence
│   │   ├── registry.py             # ثبت/کشف درایورها (auto-register + entry points)
│   │   ├── events.py               # EventBus
│   │   ├── exceptions.py
│   │   └── drivers/                # هر Core یک پوشه؛ افزودن = همین‌جا
│   │       ├── xray/               # (مرحله بعد: port از app/xray)
│   │       ├── singbox/  wireguard/  openvpn/  hysteria2/  tuic/  ssh/
│   ├── domain/                     # موجودیت‌ها و قوانین خالص (بدون FastAPI/DB)
│   ├── services/                   # ارکستراسیون Use-Caseها
│   ├── repositories/               # آداپترهای SQLAlchemy برای پورت‌های domain
│   ├── security/                   # jwt، sealed-delivery crypto، ratelimit
│   ├── db/                         # مدل‌ها + migrationها (فقط لایه داده)
│   ├── routers/                    # legacy → انتقال تدریجی به app/api
│   ├── xray/                       # legacy → بدنه‌ی XrayDriver می‌شود
│   └── jobs/  telegram/  discord/  templates/  utils/
├── apps/
│   ├── dashboard/                  # React Admin UI (+ صفحه Core Settings)
│   └── mobile/                     # Flutter Client App
├── docs/
│   └── MULTICORE-ARCHITECTURE.md   # ← این سند
└── tests/
    └── cores/test_core_manager.py  # ✅ تست‌های لایه Core (اجراشده)
```

---

## ۵. Plugin System (پیاده‌سازی‌شده در `app/cores/`)

### ۵.۱ قرارداد درایور — `BaseCoreDriver`

هر درایور یک کلاس با **متادیتای کلاس‌سطح** (`CoreMetadata`) است که این Interface را پیاده می‌کند:

```python
class BaseCoreDriver(ABC):
    metadata: ClassVar[CoreMetadata]     # id, name, protocols, capabilities, config_schema, ...

    # چرخه حیات
    async def install(self)            -> None   # دانلود/آماده‌سازی باینری (در صورت SELF_INSTALL)
    async def update(self, version)    -> None
    async def uninstall(self, purge)   -> None
    async def start(self) / stop(self) -> None
    async def restart(self)            -> None   # پیش‌فرض: stop+start
    async def status(self)             -> CoreStatus   # state + health + version + metrics
    async def get_logs(self, tail)     -> AsyncIterator[str]
    async def health_check(self)       -> CoreStatus

    # مدیریت کاربران روی Core
    async def create_account(self, account: UserAccount) -> None
    async def update_account(self, account: UserAccount) -> None
    async def delete_account(self, account_id: str)      -> None
    async def suspend_account(self, account_id: str)     -> None  # پیش‌فرض: disable
    async def resume_account(self, account: UserAccount) -> None
    async def sync_accounts(self, accounts)              -> None  # reconcile بعد از down بودن

    # آمار و مانیتورینگ
    async def get_usage(self, account_ids=None, since=None) -> list[UsageRecord]
    async def get_online_devices(self, account_ids=None)    -> list[DeviceSession]

    # تولید پیکربندی کلاینت (محرمانه — فقط برای sealed delivery)
    async def build_client_config(self, account, node=None) -> ClientConfig
```

### ۵.۲ ثبت و کشف درایورها (`registry.py`)

- **Auto-Registration:** هر subclass مشخص (غیرانتزاعی) به‌محض تعریف، از طریق `__init_subclass__` در Registry ثبت می‌شود.
- **Built-in Discovery:** `discover_builtin()` ماژول‌های `app/cores/drivers/*` را import می‌کند.
- **Entry Points:** `load_entry_points(group="marzban.core_drivers")` → افزودن Core با `pip install` یک پکیج خارجی، بدون هیچ تغییری در کد پروژه.

### ۵.۳ چرخه‌حیات State Machine

```
LOADED ──install──► INSTALLED ──start──► STARTING ──► RUNNING
                        ▲                    │            │  ▲
                        │                    └─fail────► ERROR┘ (retry start مجاز)
                  STOPPED ◄──stop── STOPPING ◄──stop── RUNNING
   INSTALLED/STOPPED ──uninstall──► UNINSTALLED
```

- قوانین گذار در `CoreManager` اعمال می‌شود (مثلاً start دوباره‌ی Core در حال اجرا → `CoreStateError`)
- هر گذار: در Store پایدار می‌شود + رخداد `CORE_STATE_CHANGED` منتشر می‌شود
- `health_monitor` به‌صورت پریودیک `status()` را روی Coreهای RUNNING صدا می‌زند و تغییر سلامت را publish می‌کند

### ۵.۴ Provisioning بین‌چندکوری با جبران (Saga-lite)

`CoreManager.provision_user(accounts: dict[core_id, UserAccount])`:

1. برای هر Core مقصد، `create_account` فراخوانی می‌شود (قابل اجرا موازی).
2. نتیجه هر Core یک `ProvisionResult` است (success/error به‌ازای هر Core) — شکست یک Core بقیه را متوقف نمی‌کند.
3. لایه سرویس با نتایج، وضعیت `user_core_accounts` نشان‌گذاری می‌کند و در صورت نیاز `sync_accounts` بعداً reconcile می‌کند.
4. رویداد کاربر (ساخت/ویرایش/حذف/تعلیق) از `EventBus` به ProvisioningService می‌رسد.

### ۵.۵ Capabilityها

```python
USER_MANAGEMENT · SUSPEND_RESUME · USAGE_ACCOUNTING · ONLINE_TRACKING
HOT_RELOAD · SERVICE_CONTROL · SELF_INSTALL · CLIENT_CONFIG · MULTI_NODE
```

متدها بدون Capability پشتیبان‌شده → `CapabilityNotSupportedError`. UI بر اساس Capability دکمه‌ها را نمایش/مخفی می‌کند.

---

## ۶. طراحی دیتابیس

### ۶.۱ ERD (خلاصه)

```
admins ──┐
         ▼ 1..*
      users ────────────────┐ 1..*                 ┌──► core_inbounds (لیستنرها، per core-instance)
        │ 1..*              ▼                      │
        ├──► user_core_accounts ──*..1──► cores (instances: type × node × enabled × state × settings)
        │ 1..*              │ 1..*                 ▲ 1..*
        ├──► devices ──1..*─┼──► device_sessions   │
        │                   └──► usage_records ────► nodes
        └──► refresh_tokens (device-bound)
admins/users ──► audit_logs
```

### ۶.۲ جداول (ستون‌های کلیدی)

| جدول | ستون‌های کلیدی | توضیح |
|---|---|---|
| `users` | id, username, **password_hash** (ورود اپ), status, data_limit_bytes, used_bytes, expire_at, **device_limit** (NULL=نامحدود), admin_id, note | مثل امروز + پسورد اپ + محدودیت دستگاه |
| `user_core_accounts` | id, user_id FK, core_instance_id FK, account_id (هویت روی Core), protocol, **credentials_enc** (JSON رمزشده‌ی AES-GCM/Fernet با کلید پنل), enabled, provisioned_at | ⭐ قلب سیستم جدید؛ UNIQUE(user_id, core_instance_id) و UNIQUE(core_instance_id, account_id) |
| `cores` | id, **type** (xray/wireguard/...), node_id FK (NULL=master), display_name, core_version, enabled, state, settings (JSON)، installed_at | تعمیمِ تک‌کورِ امروز به N کور |
| `core_inbounds` | id, core_instance_id FK, tag, protocol, listen, port, transport (JSON), security (JSON), enabled | تعمیم `inbounds+hosts` به همه Coreها |
| `nodes` | همان مدل فعلی Marzban (name, address, port, api_port, status, usage_coefficient) | حفظ |
| `devices` | id, user_id FK, device_uid (UUID تولید اپ), name, platform, app_version, status(active/blocked), last_ip, last_seen_at | UNIQUE(user_id, device_uid) |
| `device_sessions` | id, device_id FK, user_core_account_id, node_id, ip, connected_at, disconnected_at, up_bytes, down_bytes | آمار per-device/per-session |
| `usage_records` | core_instance_id, account_id, node_id, up, down, recorded_at | دیتای خام؛ job تجمیع به `users.used_bytes` |
| `refresh_tokens` | id, user_id, device_id, token_hash, expires_at, revoked_at, rotated_from_id | چرخش Refresh + ابطال |
| `audit_logs` | id, actor_type(admin/user), actor_id, action, target, ip, meta(JSON), created_at | ردی‌پذیری کامل |
| `connect_tokens` | token_hash, user_id, account_id, expires_at, used_at | **یک‌بارمصرف، ۶۰ ثانیه‌ای** (ترجیح: Redis) |
| `tls / system / user_templates / admin_usage_logs` | مثل Marzban فعلی | حفظ |

**Migration Strategy:** Alembic؛ جداول جدید افزوده می‌شوند، جداول `proxies/inbounds/hosts` به‌صورت compatibility layer نگه داشته و در اسکریپت Migration به `user_core_accounts + core_inbounds` مپ می‌شوند (پروکسی‌های vmess/vless/trojan/ss → اکانت‌های روی CoreInstance از نوع xray). در نسخه Major بعد حذف می‌شوند.

**Encryption at Rest:** `credentials_enc` با AES-256-GCM (کلید از env/KMS). هرگز در خروجی API decode نمی‌شود مگر مسیر داخلی sealed-delivery.

---

## ۷. طراحی API

### ۷.۱ Admin API — بخش جدید Core Settings (زیر `/api/*`، JWT ادمین)

| Method | Path | توضیح |
|---|---|---|
| GET | `/api/core-types` | درایورهای موجود برای نصب (از Registry: نام، پروتکل‌ها، capabilityها) |
| GET | `/api/cores` | Coreهای نصب‌شده: وضعیت، نسخه، سلامت، نود |
| POST | `/api/cores/{type}/install` | نصب Core (body: node_id + settings طبق config_schema) |
| DELETE | `/api/cores/{id}?purge=` | حذف Core |
| POST | `/api/cores/{id}/start · /stop · /restart` | کنترل سرویس |
| POST | `/api/cores/{id}/update` | بروزرسانی باینری (در صورت SELF_INSTALL) |
| PUT | `/api/cores/{id}/enable · /disable` | فعال/غیرفعال |
| GET | `/api/cores/{id}/status` | state + health + metrics (CPU/RAM/شبکه/کاربران فعال) |
| GET | `/api/cores/{id}/logs?tail=200` | لاگ زنده |
| GET/PUT | `/api/cores/{id}/settings` | تنظیمات اختصاصی (validate با JSON Schema) |
| GET | `/api/cores/{id}/inbounds` + CRUD | لیستنرهای هر Core |
| GET | `/api/dashboard/overview` | کاربران، آنلاین‌ها، Coreهای فعال، CPU/RAM/شبکه هر Core |
| GET/POST/DELETE | `/api/users/{u}/devices · /api/devices/{id}/block·unblock·rename` | مدیریت دستگاه‌ها |
| GET | `/api/audit-logs` | لاگ ممیزی |

### ۷.۲ Client API — اپ موبایل (`/client/v1/*`)

| Method | Path | توضیح | شامل Secret؟ |
|---|---|---|---|
| POST | `/auth/login` | username+password+device(uid, name, platform, app_version) → access(15m)+refresh(30d، چرخشی، device-bound)؛ **اعمال device_limit** | ❌ |
| POST | `/auth/refresh` | چرخش توکن؛ revocation روی reuse | ❌ |
| POST | `/auth/logout` | ابطال refresh + پایان نشست | ❌ |
| GET | `/profile` | نام، وضعیت، انقضا، مصرف، دستگاه‌های مجاز | ❌ |
| GET | `/services` | `[{id, name, protocol, core, expire_at, remaining_days, used_bytes, total_bytes, enabled}]` | ❌ |
| POST | `/services/{id}/connect-token` | توکن یک‌بارمصرف ۶۰ثانیه‌ای | ❌ |
| POST | `/connect` | تعویض connect-token → **پیکربندی رمزنگاری‌شده (sealed)** | ✅ فقط رمزشده |
| POST | `/disconnect` | اعلام قطع اتصال (برای session/usage دقیق) | ❌ |
| GET | `/usage` | نمودار مصرف | ❌ |
| GET | `/devices` | دستگاه‌های خود کاربر | ❌ |
| PATCH | `/devices/{uid}` | rename دستگاه خودش | ❌ |

**قانون طلایی:** هیچ Endpoint خروجی `config` خام، لینک `vless://` و... ندارد. حتی `payload` در `ClientConfig` متد `public_view()` دارد که secretها را حذف می‌کند (در کد اعمال شده).

### ۷.۳ Sealed Config Delivery

```
App                                Server
 │ POST /connect {token, client_eph_pub(X25519)}
 │ ─────────────────────────────►  1) اعتبار token (یک‌بارمصرف، ۶۰ثانیه) + device bound
 │                                 2) ساخت ClientConfig از روی account (RAM only)
 │                                 3) shared = X25519(server_eph, client_eph)
 │                                 4) key = HKDF-SHA256(shared, salt, "marzban-seal-v1")
 │                                 5) sealed = AES-256-GCM(key, config_json)
 │ ◄───────────────────────────── {server_eph_pub, salt, nonce, sealed, engine_hint}
 │ 6) derive key → decrypt در RAM → تحویل به engine → wipe
```

- زیر این کانال، TLS + **Certificate Pinning** در اپ وجود دارد (دو لایه).
- کلید هرگز ذخیره نمی‌شود (نه سرور نه اپ) و هر اتصال Forward Secrecy دارد.

---

## ۸. مدل امنیتی — صادقانه و دقیق

### آنچه تضمین می‌کنیم ✅

- **عدم نمایش هرگز** IP/Port/UUID/Key/SNI/Domain/... در UI اپ
- **عدم Export/Copy** از اپ (بدون دکمه، بدون share، بدون log)
- config فقط **در RAM** → پس از handoff به engine بازنویسی حافظه (zeroization)
- Credential **متفاوت به‌ازای هر Core** (و در آینده per-device) → لو رفتن یک Core = ابطال همان یک اکانت
- TLS اجباری + Certificate Pinning + ECDH sealed delivery
- JWT کوتاه‌عمر + Refresh چرخشی device-bound + تشخیص reuse → revoke خانواده توکن
- Rate Limit روی login/connect، Audit Log کامل، هش پسورد ادمین/کاربر (bcrypt/argon2)

### حقیقت فنی ⚠️ (باید بدانید)

در حالت **Direct Connect**، کلاینت VPN بالاخره باید به سرور واقعی متصل شود؛ پس پارامترهای اتصال «در حافظه‌ی اپ» وجود خواهند داشت. **هیچ سیستمی در جهان** نمی‌تواند جلوی استخراج حافظه روی دستگاه Rooted/Jailbroken توسط خودِ کاربر را ۱۰۰٪ بگیرد. دفاع ما defense-in-depth است: کوتاه‌کردن عمر credentialها، per-user/per-device secrets، obfuscation، anti-tamper، revoke سریع و monitoring. اگر روزی «حتی اپ هم نباید IP سرور را ببیند» خواستید، تنها راه واقعی **حالت Relay** است (اپ به Gateway پنل وصل می‌شود و Gateway ترافیک را به Core می‌رساند) — به‌عنوان گزینه‌ی فازهای بعد در معماری جا دارد، ولی با هزینه‌ی سرور واسط.

---

## ۹. استراتژی درایور هر Core

| Core | کنترل پروسه | مدیریت کاربر | آمار ترافیک | آنلاین | پیچیدگی درایور |
|---|---|---|---|---|---|
| **Xray** | باینری systemd | gRPC HandlerService ✅ | gRPC StatsService ✅ | عبر API/Stats ✅ | کم — port از کد فعلی |
| **sing-box** | باینری | Config render + reload/SIGHUP (بدون API کاربر native) | Clash API (experimental، محدود) | Clash API connections | متوسط |
| **Hysteria 2** | باینری | **Traffic Stats API رسمی + auth hook خارجی** ✅ | `/traffic` per-user ✅ | `/traffic` online ✅ | کم-متوسط، بومی |
| **TUIC v5** | باینری | config reload | ندارد ❌ | ندارد ❌ | کم اما محدود (Capability کم) |
| **WireGuard** | kernel/wg-go | `wg setconf` / فایل + `wg syncconf` ✅ | `wg show dump` per-peer ✅ | latest_handshake ✅ | کم (الگوی wg-easy) |
| **OpenVPN** | پروسه openvpn | Management Interface + user-pass/cn auth ✅ | status3 bytes (real-time تقریبی) ✅ | status client list ✅ | متوسط |
| **SSH Tunnel** | sshd | system user / Match block | iptables per-UID counters (محدود) | `ss`/`who` | متوسط، Capability محدود |
| **ShadowTLS** | باینری | ندارد (wrapper تک‌سرویس) | ندارد | ندارد | ساده؛ بهتر است به‌عنوان transportِ inbound در sing-box هم در دسترس باشد |
| **SoftEther** | vpnserver | `vpncmd` hub user ✅ | session/NAT table ✅ | session list ✅ | متوسط-زیاد |
| **PPTP/L2TP** | pptpd/xl2tpd+ppp | chap-secrets | ppp/ifconfig | ipsec status | legacy — گزینه‌ی آخر (ناامن) |

---

## ۱۰. اپ موبایل

- **فناوری پیشنهادی: Flutter** (یک کدبیس برای Android + iOS؛ امکان platform channel به native engineها).
- **موتور اتصال یکپارچه: sing-box (libbox)** — پوشش VLESS/VMess/Trojan/Shadowsocks/Hysteria2/TUIC/**WireGuard**/ShadowTLS در یک کتابخانه → به‌جای N کلاینت، یک engine. OpenVPN و SSH کانکتور مجزا می‌گیرند (ics-openvpn / dartssh).
- **لایه‌ها:**
  - `api_client` — Dio با Certificate Pinning + refresh-interceptor
  - `vault` — `flutter_secure_storage` برای refresh token و device_uid؛ **config هرگز persist نمی‌شود**
  - `session` — sealed-payload decrypt در Dart FFI/Platform channel → handoff به engine → wipe
  - `ui` — فقط: نام کانفیگ، پروتکل، وضعیت، انقضا، حجم، روزهای مانده، دکمه Connect
- **Device ID:** UUIDv4 در اولین اجرا + ذخیره در Keychain/Keystore + ثبت سرور در login.

---

## ۱۱. نقشه راه (Phases) با Definition of Done

| فاز | عنوان | DoD | وضعیت |
|---|---|---|---|
| P0 | تحلیل + معماری | این سند | ✅ |
| P1 | Core Abstraction Layer | `app/cores/*` + تست سبز | ✅ (همین مرحله) |
| P2 | **XrayDriver** | port کامل `app/xray` پشت Interface؛ پنل فعلی بدون تغییر رفتار بالا می‌آید | ✅ |
| P2.5 | **SingBoxDriver** | Config-render + restart؛ مترجم Routing/Outbound؛ chain ingress؛ SELF_INSTALL | ✅ |
| P2.6 | تحلیل مرجع + Refactor | سند `REFERENCE-ANALYSIS.md`؛ استخراج `ManagedProcess`/`DeltaTracker`/`SessionUsageTracker`؛ provides/requires + گارد حذف | ✅ |
| P2.7 | **OpenVPNDriver** | mgmt-client-auth (کاربر زنده بدون restart)؛ آمار authoritative hook + interim status؛ Device Detection؛ PKI; SELF_INSTALL | ✅ |
| P3 | دیتابیس | جداول §6 + migration از proxiesها + Repository adapters؛ حذف `xray` از `db/models.py` | ⬅ فاز بعدی |
| P4 | اتصال Manager | EventBus در user CRUD؛ جایگزینی `xray/operations`؛ جاب usage چندکوری + sync reconcile | |
| P5 | Core Settings API + داشبورد | endpointهای §7.1 + صفحه Core Settings در React (فرم خودکار از JSON Schema) | |
| P6 | Client API v1 + امنیت | §7.2 و §7.3 + device limit + audit + rate limit | |
| P7 | اپ موبایل MVP | login/لیست سرویس/connect روی sing-box engine (Xray + WireGuard) | |
| P8 | درایورهای باقی | WireGuard → Hysteria2 → TUIC → SSH → SoftEther → (ShadowTLS/PPTP-L2TP) | |
| P9 | سخت‌سازی | تست integration کامل، monitoring، i18n، CI/CD، مستندات توسعه درایور | |
| P9 | سخت‌سازی | تست integration کامل، monitoring، i18n، CI/CD، مستندات توسعه درایور | |

---

## ۱۲. زیرسیستم‌های مرکزی (معماری نسخه ۲ — Enterprise)

> پیاده‌سازی‌شده در این مرحله: `app/cores/routing/`، `app/cores/outbounds/`، `app/cores/policy/` + گسترش قرارداد Driver و Capability v2 — با **۴۸ تست سبز** در کل پروژه.

### ۱۲.۱ اشتراک یکپارچه و حسابداری مصرف مرکزی

- هر کاربر دقیقاً **یک** `PolicyProfile` و **یک** شمارنده‌ی `used_bytes` دارد — مستقل از تعداد Coreهایی که سرویس دارد.
- هر درایور فقط **دلتا** گزارش می‌دهد (`UsageRecord` با کلید یکتای `(core_id, node_id, account_id)`). جاب مرکزی `UsageRecorder` (فاز ۴) baseline پایدار را در DB نگه می‌دارد تا بعد از restart پنل، دوباره‌شماری (Duplicate Counting) رخ ندهد. تست دلتا در `test_usage_reports_deltas_and_keeps_node_split` این رفتار را قفل می‌کند.
- انقضا نیز جهانی است: جاب مرکزی در لحظه‌ی انقضا رویداد `USER_EXPIRED` منتشر می‌کند و CoreManager روی **همه** Coreها `suspend` را اعمال می‌کند.

### ۱۲.۲ Policy Engine جهانی (`app/cores/policy/`)

- **Pure & Side-effect-free:** `PolicyEngine.evaluate(profile, ctx) -> PolicyDecision` — ورودی: وضعیت مصرف، دستگاه‌های فعال،IP/کشور/ASN کلاینت، ساعت فعلی. خروجی: لیست نقض‌ها (`Violation`).
- محدودیت‌ها: حجم، انقضا، **device_limit جهانی** (اسلات موجود برای دستگاه فعلی دوباره مصرف نمی‌شود)، `max_ips`، `speed_limit_kbps`، `max_session_seconds`، `allowed_hours` (پنجره‌های ساعتی با پشتیبانی **شب‌گذر** و روزهای هفته)، Country Lock (white/blacklist)، ASN Lock.
- **شفافیت اجرایی:** `enforcement_map(profile, capabilities)` به ادمین دقیقاً می‌گوید هر محدودیت کجا اعمال می‌شود: `panel` (همیشه در دسترس) / `core` (native، مثل speed limit روی Hysteria2) / `unsupported-on-core`.
- Geo-Blacklist به‌صورت خودکار به Routing Rule تبدیل می‌شود (`to_block_rules`) تا Coreهایی که `GEO_ROUTING` دارند، سمت خودشان هم بلاک کنند.

### ۱۲.۳ Routing Engine مرکزی (`app/cores/routing/`)

- مدل قانون مستقل از Core: `RoutingRule{ matcher: {domains, domain_suffixes, domain_keywords, domain_regexes, geosites, geoips, ip_cidrs, source_ip_cidrs, ports, port_ranges, process_names, protocols, networks}, action: allow|block|route_to|redirect|dns|fake_dns|dns_override, priority }`.
- **قانون طلایی — بدون حذف سکوت‌آمیز:** هر قانون روی هر Core یا در `applied` است یا در `unsupported` **با دلیل و فیلد مشکل‌دار**. تست `test_deploy_covers_every_rule_on_every_core` این invariant را روی سه Core قفل می‌کند. `report.gaps` مستقیم به بنر هشدار UI می‌رود.
- مثال‌های واقعی ترجمه: `process_names` روی Xray گزارش می‌شود (پشتیبانی ندارد)، قوانین geo روی sing-box بدون `geoip_db/geosite_db` گزارش می‌شوند، `redirect`/`fake_dns` روی sing-box گزارش می‌شود (سطح inbound/DNS است نه route action).

### ۱۲.۴ Outbound Manager + Chain Routing (`app/cores/outbounds/`)

- Outboundهای مرکزی: `direct, block, blackhole, dns, socks, http, vless, vmess, trojan, shadowsocks, wireguard, hysteria2, tuic, openvpn, core`.
- `kind=core` یعنی «خروجی به یک Core دیگر پنل»: Manager با `get_chain_endpoints/ensure_chain_listener` یک listener لوکال (socks/http) روی Core مقصد می‌سازد و Outbound را به صورت مشخص **materialize** می‌کند. مثال: Inbound Xray → Outbound WireGuard با دو خط Outbound ثبت می‌شود.
- **تشخیص چرخه:** گراف لبه‌های core→core در plan مشترک نگه داشته می‌شود و هر لبه‌ای که حلقه می‌بندد (`xray → sing-box → xray`) با خطای `CoreError` کل plan را متوقف می‌کند (تست: `test_self_chain_and_full_cycle_are_rejected`).
- outbound زنجیره‌ای هرگز روی Coreِ مقصد خودش مستقر نمی‌شود (skip + note).

### ۱۲.۵ Capability System v2

| Capability | معنی | Xray | sing-box | OpenVPN |
|---|---|---|---|---|
| ROUTING | قوانین مسیریابی native | ✅ | ✅ | ❌ |
| GEO_ROUTING | geosite/geoip | ✅ | ✅ (نیازمند DB) | ❌ |
| PROCESS_ROUTING | match بر اساس نام پروسس | ❌ | ✅ | ❌ |
| OUTBOUND_MANAGEMENT | خروجی‌های قابل‌برنامه‌ریزی | ✅ | ✅ | ❌ |
| CHAIN_ROUTING | میزبان/هدف زنجیره | ✅ | ✅ | ❌ |
| UDP_SUPPORT | رله UDP | ✅ | ✅ | ✅ (proto udp) |
| SPEED_LIMIT | سقف سرعت native per-user | ❌ | ❌ | ❌ |
| USAGE_ACCOUNTING | آمار per-user | ✅ | ❌ | ✅ (hook + status) |
| ONLINE_TRACKING | نشست‌های آنلاین | ✅ (دلتای آمار) | ❌ | ✅ (status 3) |
| DEVICE_DETECTION | شناسایی دستگاه/کلاینت | ❌ | ❌ | ✅ (IV_PLAT/IV_VER) |
| SELF_INSTALL | نصب خودکار باینری | ❌ | ✅ (GitHub Releases) | ✅ (package manager) |

### ۱۲.۵.۱ درس‌های vpn-ui (جزئیات در `docs/REFERENCE-ANALYSIS.md`)

- **الگوی Bridge**: برای Coreهای بدون شمارنده/احراز native، درایور خودش یک Bridge واقعی ارائه می‌دهد. نمونه‌ی پیاده‌شده: OpenVPN با `management-client-auth` (احراز زنده‌ی handshake بدون restart) + `client-disconnect` hook (فینال authoritative) + `status 3` (interim).
- **provides/requires + گارد حذف**: وابستگی اشتراکی Coreها (مثل strongSwan مشترک IKEv2/L2TP) با `CoreMetadata.provides/requires` و `CoreManager.dependency_report/dependents` مدل شد — حذف provider وقتی consumer دارد مسدود است (`force=`).
- **دقت Session در حسابداری**: `SessionUsageTracker` دو متن (interim/final) را ادغام می‌کند بدون دوباره‌شماری — تستش با سناریوی کامل connect→grow→disconnect قفل شده.

> نکته‌ی صادقانه‌ی معماری: آمار per-user روی sing-box در upstream وجود ندارد؛ پنل این را پنهان نمی‌کند — در Capability و گزارش‌ها شفاف است و در UX به ادمین توضیح داده می‌شود. سهمیه‌ی جهانی روی Coreهایی با آمار بسته می‌شود.

### ۱۲.۶ ثبت دستگاه جهانی (Device Registry) — طراحی فاز ۴

- «اتصال جدید» فقط از مسیر اپ (POST /client/v1/auth/login یا /connect) قابل صدور است → **device_limit در لحظه‌ی Admission** با PolicyEngine سخت‌گیرانه چک می‌شود.
- برای Coreهای raw (بدون اپ)، دستگاه از طریق `get_online_devices` درایورها کشف و به registry ضمیمه می‌شود؛ نقض سیاست → `kick_account` (remove+re-add = قطع نشست بدون حذف کاربر) توسط DeviceService.

---

## ۱۳. الگوها و اصول (نگاشت SOLID)

| الگو/اصل | محل پیاده‌سازی |
|---|---|
| Strategy | هر Driver یک Strategy برای یک Core |
| Factory | `registry.get_driver_class` + ساخت instance در `CoreManager.install_core` |
| Plugin | Auto-register (`__init_subclass__`) + entry_points + `discover_builtin` |
| Repository / Port | `CoreStateStore` (Protocol) در manager؛ آداپتر SQLAlchemy در فاز ۳ |
| Dependency Injection | سازنده‌ی `CoreManager(store, bus, settings_provider)` |
| Observer | `EventBus` و رویدادهای دامنه |
| Command | اکشن‌های start/stop/restart/update به‌صورت متدهای یکتا روی manager |
| Saga (compensation) | `provision_user` چندکوری + `ProvisionResult` + reconcile با `sync_accounts` |
| Open/Closed | Core جدید = فقط یک پوشه‌ی جدید در `drivers/` |
| Interface Segregation | Capabilityها به‌جای Interface حجیم اجباری |
| Single Responsibility | manager=fقط ارکستراسیون؛ driver=فقط یک Core؛ store=فقط persistence |
- **تست:** unit (درایورها با mock)، integration (manager + درایور فیک — ✅)، E2E (در CI با باینری‌های واقعی در کانتینر)

---

## ۱۴. فاز پلتفرم — تکمیل معماری Multi-Core (Enterprise)

> پیاده‌سازی‌شده در این مرحله: ۵ درایور جدید (**WireGuard, Hysteria2, TUIC, SSH, SoftEther**)، ارتقای حسابداری **sing-box** (v2ray StatsService)، سرویس‌های مرکزی **UnifiedQuota / DeviceManager / SessionManager**، fan-out **suspend/resume**، قابلیت **KEY_ROTATION**، ماژول **QR مستقل (Pure-Python, ISO 18004)**، نصب‌کننده‌ی اشتراکی GitHub Releases، تست سناریوهای چندکوری، و تست **Conformance قرارداد پلاگین** برای هر ۸ درایور. **۱۳۳ تست سبز** (هم standalone و هم pytest).

### ۱۴.۱ Refactorهای پیش از توسعه (طبق قانون پروژه)

| مورد | کار |
|---|---|
| `openvpn/driver.py` | حذف `__import__("datetime")` درون‌خطی → import استاندارد؛ برگشت زمان‌های naive به UTC-aware (باگ واقعی در SessionManager) |
| `CoreManager` | افزودن `suspend_user` / `resume_user` (fan-out هم‌زمان روی همه Coreها — تصمیم صرفاً بر مبنای Capability: `SUSPEND_RESUME` → مسیر ارزان native؛ `USER_MANAGEMENT` → `update(enabled=...)`؛ غیره → خطای صادقانه) |
| `BaseCoreDriver` | قابلیت جدید `KEY_ROTATION` + متد `rotate_credentials`؛ مستندسازی قرارداد «درایور می‌تواند credential تولیدشده را **درجا** در `account.settings` بنویسد تا لایه‌ی سرویس پایدارش کند» (پیش‌نیاز WireGuard/TUIC) |
| `singbox/backend+driver` | حذف اسطوره‌ی «sing-box آمار ندارد» → پیاده‌سازی واقعی با v2ray StatsService رسمی؛ استخراج `TrafficStatsSource` به‌عنوان Port (تست‌پذیر بدون grpc) |
| `app/cores/github_install.py` | استخراج نصب‌کننده‌ی GitHub Releases به ماژول مشترک (DRY) — sing-box/hysteria/tuic مصرف‌کننده |
| `setool`/`sshtool`/`wgtool`/`hycfg` | جداسازی منطق خالص (پارس/رندر) از IO در همه‌ی درایورهای جدید |

### ۱۴.۲ ماتریس قابلیت نهایی — ۸ Core

| قابلیت | xray | sing-box | wireguard | openvpn | hysteria2 | tuic | ssh | softether |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| USER_MANAGEMENT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SUSPEND_RESUME | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| USAGE_ACCOUNTING | ✅ | ✅ (v2ray API) | ✅ (wg dump) | ✅ (hook+status) | ✅ (traffic API) | ❌* | ❌* | ✅ (UserGet) |
| ONLINE_TRACKING | ✅ | ✅ (heuristic) | ✅ (handshake) | ✅ (status) | ✅ (/online) | ❌* | ✅ (ps) | ✅ (SessionList) |
| DEVICE_DETECTION | ❌ | ❌ | ❌ | ✅ (IV_PLAT) | ❌ | ❌ | ❌ | ✅ (hostname) |
| HOT_RELOAD | ✅ (gRPC) | ❌ (restart) | ✅ (syncconf) | ✅ (mgmt) | ❌ (restart) | ❌ (restart) | ✅ (usermod) | ✅ (vpncmd) |
| KEY_ROTATION | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SPEED_LIMIT | ❌ | ❌ | ❌ | ❌ | ❌† | ❌ | ❌ | ❌ |
| ROUTING / GEO | ✅/✅ | ✅/✅‡ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| OUTBOUND_MGMT | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CHAIN_ROUTING | ✅ (socks/http) | ✅ (socks/http/mixed) | ✅ (wg peering) | ❌ | ✅ (hy2-in) | ✅ (tuic-in) | ✅ (ssh-in) | ❌ |
| SELF_INSTALL | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌§ |
| SERVICE_CONTROL | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌¶ | ❌¶ |
| CLIENT_CONFIG | ✅ | ✅ | ✅ (+QR) | ✅ | ✅ | ✅ | ✅ | ✅ |
| MULTI_NODE | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| UDP_SUPPORT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ○ (TCP) | ✅ |

\* **صادقانه مستندشده:** TUIC هیچ API آماری در پروتکل ندارد؛ SSH حسابداری درست‌حسابی per-user در ابزار استاندارد ندارد (owner-match iptables فقط egress را و در جهت غلط می‌بیند). UnifiedQuota ترافیک این دو Core را «unaccounted» با هشدار گزارش می‌کند — شبیه‌سازی نمی‌شود.
† SPEED_LIMIT برای hysteria2 از مسیر HTTP-Auth callback (پاسخ `tx` بایت‌برثانیه) فقط وقتی لایه‌ی API پنل endpoint مناسب بدهد (P5) واقعی می‌شود؛ bandwidth سراسری سمت server از تنظیمات قابل ست شدن است.
‡ GEO روی sing-box نیازمند `geoip_db/geosite_db` است؛ بدون آن‌ها قانون صادقانه در `unsupported` گزارش می‌شود.
§ SoftEther بسته‌ی رسمی در مخازن استاندارد ندارد → نصب اسکریپتی فریبکارانه انجام نمی‌شود، مستندسازی ارجاع داده می‌شود.
¶ دایمن متعلق به systemd است؛ درایور اکانت‌ها را مدیریت می‌کند، وضعیت سرویس را **گزارش** می‌دهد نه مالکش.
○ sshd روی TCP است؛ UDP-over-SSH وجود ندارد.

### ۱۴.۳ سناریوهای اثبات Multi-Core (تست‌های `test_multicore_scenarios.py` — ۸ تست)

| سناریو | نتیجه و مکانیزم اثبات |
|---|---|
| S1: کاربر واحد روی ۴ Core | `provision_user` روی xray+sing-box+openvpn+wireguard → `ClientConfig` مستقل با engine متفاوت برای هرکدام |
| S2: سهمیه‌ی یکپارچه | 1GB(xray)+2GB(openvpn)+3GB(wireguard)+4GB(sing-box) ⇒ **دقیقاً 10GB** (۱۰,۷۳۷,۴۱۸,۲۴۰ بایت — بدون خطای اعشار، با اعداد half-GB دقیق در فیکسچر). poll مجدد با همان شمارنده‌ها ⇒ **۰ بایت جدید** (بدون دوباره‌شماری — قفل تستی). رشد +1GB روی wg ⇒ 11GB. رکورد متعلق به حساب ناشناخته ⇒ `DroppedRecord` با دلیل |
| S2b: Multi-Node | رکوردهای یک کاربر از master + node 3 + node 5 ⇒ هرکدام **یک بار** و با `node_id` حفظ‌شده جمع می‌شوند |
| S3: Suspend هم‌زمان | یک فراخوانی `suspend_user` ⇒ xray: حذف (مفهوم کاربر غیرفعال ندارد — حذف یعنی تعلیق)، sing-box: حذف از کانفیگ+restart، openvpn: piece منفی در auth + `kill <cn>` برای نشست زنده، wireguard: حذف peer با syncconf (بدون قطع بقیه) |
| S4: Resume هم‌زمان | بازگردانی روی هر ۴ Core با همان credentialها |
| S5: Delete هم‌زمان | حذف حساب متناظر روی هر ۴ Core + پاک‌سازی baseline حسابداری |
| Device limit جهانی | یک دستگاه (همان IP) روی **دو** Core ⇒ **یک** دستگاه در رجیستری (cores ⊇ هر دو)؛ دستگاه دوم با IP دیگر ⇒ نقض `device_limit=1` تشخیص داده شد |
| Session History | session open/close با duration محاسبه‌شده در `test_session_manager_tracks_open_and_close_with_duration` |
| Fault isolation | بک‌اند معیوب یک Core ⇒ آن Core `success=False` با پیام، بقیه موفق |
| Stress/Concurrency | ۵۰ کاربر × ۴ Core هم‌زمان + ۸ shard موازی اعمال سهمیه ⇒ مجموع دقیق ریاضی؛ < 10s |

### ۱۴.۴ زیرسیستم‌های مرکزی جدید

**UnifiedQuotaService (`app/cores/quota.py`)** — الگوی **Ledger/Port**: درایورها هرگز user_id را نمی‌فهمند؛ نقشه‌ی انتساب `{(core_id, account_id): user_id}` از لایه‌ی Repository می‌آید. هر batch دلتا دقیقاً یک‌بار اعمال می‌شود (`QuotaStore.add` اتمیک؛ آداپتر SQL در P3 در همان تراکنش baseline را هم persist می‌کند). خروجی: `AppliedUsage` (مصرف جدید، مجموع، exceeded) + `DroppedRecord` (حساب‌های یتیم — هرگز بلع سکوت‌آمیز).

**DeviceManager (`app/cores/devices.py`)** — مدل هویت صادقانه: `stable_id` (اپ رسمی header می‌فرستد) > هیوریستیک `(user, ip)` > anon-per-user برای Coreهای بدون IP. همان دستگاه روی چند Core = یک دستگاه (device_id مشترک). خروجی: Device Info با فیلدهای خواسته‌شده (Device ID / Name / Platform / App Version / Last IP / Last Seen / Current Core) + `cores` (همه‌ی Coreهایی که دستگاه رویشان دیده شده).

**SessionManager (`app/cores/sessions.py`)** — diff پولینگ: نشست جدید ⇒ opened؛ ناپدیدشده ⇒ closed با duration و شمارنده‌های نهایی → تاریخچه. درایورها مجبور به event نمی‌شوند (در has APIهای ناهمگن کار نمی‌کند).

### ۱۴.۵ Cross-Core Routing — ماتریس واقعیت (رفع بند ۹)

منابع زنجیره = Coreهایی که OUTBOUND_MANAGEMENT دارند؛ مقصدها = Coreهای میزبان Chain Endpoint:

| مبدأ \ مقصد | xray | sing-box | wireguard | hysteria2 | tuic | ssh | openvpn | softether |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **xray** | — | ✅ socks/http | ✅ wg peering | ❌* | ❌* | ✅ ssh-out | ❌† | ❌‡ |
| **sing-box** | ✅ socks/http | — | ✅ wg peering | ✅ hy2-in | ✅ tuic-in | ❌§ | ❌† | ❌‡ |
| **openvpn** | ❌¶ (OS-scope) | ❌¶ | ❌¶ | ❌¶ | ❌¶ | ❌¶ | — | ❌¶ |
| **wireguard** | ❌¶ | ❌¶ | — | ❌¶ | ❌¶ | ❌¶ | ❌¶ | ❌¶ |

\* xray outbound بومی hysteria2/tuic ندارد → زنجیره از مسیر sing-box (`xray→sing-box→hy2`) با cycle-guard.
† هیچ‌کدام outbound بومی openvpn ندارند → زنجیرهٔ process-level ناممکن؛ مسیر آینده = OS-level TUN bridging (مستند، پیاده نشده — صادقانه).
‡ L2 hub؛ outbound انتخابی ندارد.
§ sing-box ssh outbound ندارد.
¶ منبع زنجیره شدن به مفهوم «انتخاب egress per-connection» در مقیاس این Coreها تعریف نشده است (روتینگ ترافیک کلاینت‌ها سطح OS است) — گزارش صادقانه.

مکانیزم جدید: `ensure_chain_listener(protocol)` برای Coreهای credential-driven یک **System Chain User/Peer** واقعی provision می‌کند (WireGuard: peer واقعی + کلید؛ Hysteria2/TUIC/SSH: کاربر زنجیره‌ای). کلیدهای متادیتا (`_METADATA_KEYS`) قرارداد مشخص بین تولیدکننده‌ی endpoint و مترجم‌های outbound است و در materialize به settings منتقل می‌شود. نقشه‌ی `_ENDPOINT_KIND` اکنون wireguard/hysteria2/tuic/ssh را هم پوشش می‌دهد. وضعیت زنجیره‌ی wg بعد از restart پنل در `chain-peers.json` (۰۶۰۰) پایدار می‌شود.

### ۱۴.۶ WireGuard Driver — پاسخ کامل بند ۲

| خواسته | پیاده‌سازی واقعی |
|---|---|
| Peer Management | desired-state → conf کامل + `wg syncconf` زنده (بدون قطع peerهای دیگر) |
| Key Rotation | `rotate_credentials`: keypair جدید (+PSK) با syncconf لحظه‌ای؛ کلید قدیم بلافاصله می‌میرد (قفل تستی) |
| Usage | `wg show all dump` → transfer-rx/tx تجمعی → DeltaTracker؛ ریست اینترفیس ⇒ clamp به ۰ (مستند) |
| Handshake/Online Detection | `latest-handshake` ≤ آستانه (پیش‌فرض ۱۸۰s) ⇒ آنلاین + endpoint IP؛ stale ⇒ آفلاین |
| Device Detection | **ادعا نمی‌شود** (WG هیچ هویت کلاینتی غیر از pubkey ندارد) — مستند |
| Config Rendering | رندر INI سرور/کلاینت + `wg-quick strip` داخلی (بدون وابستگی wg-quick) |
| QR Generation API | ماژول `app/cores/qr.py` — انکودر کامل ISO/IEC 18004 بدون هیچ وابستگی (byte mode، ECC L/M، نسخه‌های ۱–۴۰، انتخاب mask با penalty استاندارد)؛ **اعتبارسنجی bit-exact در برابر python-qrcode روی ۹ بردار طلایی** (v1 تا v36، interleave چندبلوکی، داده‌ی باینری). خروجی SVG compact + ASCII. API درایور: `client_config_qr(account)` |
| Auto Install | wireguard-tools از apt/dnf/yum/pacman/apk |
| Multi-Node | **ادعا نمی‌شود** — سند: نود = instance مجزای مدیریت‌شده؛ انتقال SSH-backend در roadmap صادقانه است |
| Health Check | RUNNING از `wg show interfaces`؛ DEGRADED روی خطای sync آخر + metrics کلی |

### ۱۴.۷ ماژول QR — تصمیم گرفتن مسئولیت صحت

کتابخانه‌ی تصویری وارد نکردیم (sandbox/preview بدون شبکه). انکودر از مشخصات ISO 18004 با جداول استاندارد (۴۰ نسخه × ۲ سطح ECC، GF(256)، Reed-Solomon، interleaving، ۸ mask + penalty، format/version info BCH) نوشته شد. دو نکته‌ی واقعی پیدا در تست: ترتیب ضرب‌کننده‌ی چندجمله‌ای generator (رفع شد) و ترمیناتور segno که یک بایت `0x00` اضافه می‌نویسد (رفتار مستندِ آن کتابخانه — انکودر ما مطابق متن استاندارد و bit-exact با python-qrcode است).

### ۱۴.۸ طراحی Backend اپ رسمی (بند ۱۱؛ پیاده‌سازی در P6)

```
POST /client/v1/auth/login        {username, password, device_id, app_version}
     → {access_jwt(کوتاه‌عمر), refresh_token(sliding), profile:{name,status,expire_at,
        data_limit, used, remaining}}
GET  /client/v1/profile           → همان profile (+ per-core: [{id:"wg-iran1", protocol:"wireguard", status}])
POST /client/v1/connect/{core_id} → ۱) PolicyEngine.evaluate  ۲) device_limit جهانی (DB transaction)
     ۳) connect_token یک‌بارمصرف (TTL ۳۰s, jti واحد)  ۴) پاسخ: {core, protocol, status}
POST /client/v1/config            {connect_token, device_pubkey(X25519)}
     → Sealed Delivery: X25519-ECDH + HKDF-SHA256("marzban-seal-v1") + AES-256-GCM
     → payload ساخت‌یافته‌ی موتور کلاینت (sing-box/wireguard/openvpn JSON) — فقط حافظه
POST /client/v1/disconnect        ← freed device slot + گزارش مصرف اختیاری کلاینت
GET  /client/v1/events (WS/SSE)   ← suspend/quota-expiry/push config-rotation
```

اصل طلایی: هیچ IP/Port/Domain/UUID/Key/SNI/گواهی در **هیچ** پاسخ JSON عادی نیست — فقط کانال مُهروموم (sealed) که کلیدش با ECDH ساخته می‌شود و در اپ هرگز روی دیسک نوشته نمی‌شود. اطلاعات نمایشی اپ فقط همین‌هاست: نام، پروتکل، وضعیت، انقضا، مصرف، باقی‌مانده. (محدودیت rooted-device مستند در §۸.)

### ۱۴.۹ طراحی Migration از Marzban فعلی (بند ۱۲؛ پیاده‌سازی در P3/P5)

```
alembic revision migrate_to_corehub_v1:
  1. users (+password_hash bcrypt, +device_limit, NULL-safe)        ← users قدیمی
  2. cores دانه: ['xray'] + settings از xray.json فعلی               ← یک‌بار seed
  3. proxies (vmess/vless/trojan/ss) → user_core_accounts
       protocol=type, settings=credentials, account_id=f"{id}.{username}" (سازگار با email قدیمی)
  4. inbounds → core_inbounds(core_id='xray', tag, protocol, settings)
  5. hosts → core_hosts(core_id='xray', inbound_tag, remark, address, sni, ...)
  6. node usages جمع‌شده → usage_records + baseline در user_usage (بدون دوباره‌شماری)
  7. jwt/subscriptions کاربران → user_core_accounts.token (sub token = همان uuid قبلی در فاز گذار)
  8. Configهای قدیمی sub تا N روز گذار باقی می‌مانند (دکمه‌ی Revoke-and-Rotate)
```
قانون‌ها: بدون از دست رفتن داده؛ تبدیل idempotent (دوبار اجرا = همان نتیجه)؛ گزارش dry-run؛ rollback با snapshot اتمیک. سرویس `LegacyImportService` دقیقاً همین نگاشت را پیاده می‌کند و تست آن با دیتابیس نمونه v0.8.4 واقعی اجرا می‌شود.

### ۱۴.۱۰ بازبینی دیتابیس (بند ۱۳) — وضعیت نهایی طراحی

جدول‌ها (مستقل از هر Core — جزئیات در §۶):
`users` (+password_hash, +device_limit) · `user_core_accounts` (credentials_enc AES-GCM؛ کلید از env/KMS) · `cores` · `core_inbounds` · `nodes` · `devices` (+platform/app_version/last_ip/last_seen/current_core) · `sessions` (تاریخچه) + `device_sessions` (زنده) · `usage_records` (idempotent با کلید `(core,node,account,seq)` اتمیک با baseline) · `user_usage` (مجموع جاری) · `policies` · `routing_rules` · `outbounds` · `audit_logs` · `refresh_tokens` · `connect_tokens` (jti یک‌بارمصرف) · `plugins` (entry-point external drivers + نسخه). Health/Events: بدون جدول جدا — `cores.state/health` (آخرین وضعیت) + خروجی EventBus در `audit_logs` (رویدادمحور). نتیجه‌ی بازبینی: ستون `stable_device_id` به devices، و `seq` افزایشی به usage_records اضافه شد.

### ۱۴.۱۱ طراحی داشبورد (بند ۱۴؛ پیاده‌سازی در P5/P7)

```
┌ Overview ─ cards: کاربران | آنلاین | مصرف کل | Alertها
├ Cores ─ grid ۸ Core: state/health/uptime/metrics/router-status/outbound-status + دکمه‌های lifecycle
├ Users ─ مصرف هر کاربر split بر اساس Core (stacked) + devices + سقف‌ها + enforce نتیجه
├ Devices ─ جدول واحد (بند ۷): ID/Name/Platform/AppVersion/LastIP/LastSeen/CurrentCore همه‌ی Coreها
├ Sessions ─ Active (realtime WS) + History (bند ۸) با duration و ترافیک + Core
├ Traffic ─ مصرف تجمیعی (زمان‌بندی) per core + سرعت لحظه‌ای؛ برچسب sessions بدون حسابداری (SSH/TUIC) «unaccounted»
├ Nodes ─ سلامت هر Node (صلاحیت MULTI_NODE فقط xray؛ گزارش صادقانه برای بقیه: single-instance)
├ Routing/Outbounds ─ RouteDeploymentReport.gaps به‌صورت بنر «قوانین اعمال‌نشده با دلیل»
└ Alerts ─ health transitions (EventBus), policy violations, quota >= 90%, core restarts, chain cycles(blocked)
```

### ۱۴.۱۲ تحلیل مجدد vpn-ui برای این فاز (بند ۱۵)

| پروتکل | راهکار vpn-ui | تصمیم ما | دلیل |
|---|---|---|---|
| SSH | `xray_sshoutbound`: اتصال xray ssh outbound به سرور SSH | **پذیرفته‌شده (ایده)** | `OutboundKind.SSH` + مترجم xray ssh outbound + chain ssh-in در SSHDriver — بدون کپی کد |
| WireGuard/Amnezia | matrix «هسته/AWG» + «Setup detects it and tells you rather than failing silently» | الگوی همان **صداقت** تبویب‌شده (بدون AWG) | AWG افسانه‌ای نساختیم؛ معیار: هر ناسازگاری = DEGRADED/unsupported صریح |
| Hysteria2/TUIC/SoftEther | (فقط از مسیر xray patched) => وابستگی به فورک xray | **معیوبِ ردشده** | پیاده‌سازی مستقل با API رسمی هر پروژه (بدون وابستگی 3x-ui/xray) |
| RADIUS accounting | handleAcct→bytes در diver auth | قبلاً به‌صورت Bridge pattern تعمیم داده شد | openvpn hook + hy2/traffic API همان الگو، بدون RADIUS وابستگی |

### ۱۴.۱۳ وضعیت تست‌ها و پوشش (بند ۱۶)

| دسته | فایل | تست |
|---|---|---|
| Multi-Core سناریوها (S1–S5, Quota, Device, Session, Fault, Stress) | `test_multicore_scenarios.py` | ۸ |
| Conformance قرارداد پلاگین (هر ۸ درایور) | `test_driver_contract.py` | ۵ |
| QR (بردارهای طلایی ISO) | `test_qr.py` | ۸ |
| WireGuard | `test_wireguard_driver.py` | ۱۲ |
| Hysteria2 | `test_hysteria2_driver.py` | ۷ |
| TUIC | `test_tuic_driver.py` | ۶ |
| SSH | `test_ssh_driver.py` | ۸ |
| SoftEther | `test_softether_driver.py` | ۷ |
| sing-box (+آمار جدید) | `test_singbox_driver.py` | ۱۴ |
| Xray/OpenVPN/Manager/Routing/Outbounds/Policy/Deps/Process | (از فازهای قبل) | ۵۸ |
| **مجموع** | | **۱۳۳** |

پوشش موردنیاز بند ۱۶ به تفکیک هر درایور: Unit ✅ · Integration (با فیک‌های پروتکلی — معادل معماری integration بدون کانتینر) ✅ · Multi-Node ✅ (xray node split + S2b) · Traffic Aggregation ✅ (S2 + per-driver delta tests) · Device Limit ✅ · Suspend/Resume ✅ (S3/S4 + per-driver) · Routing ✅ (routing tests + translation fidelity) · Chain ✅ (outbounds cycle + per-driver ingress) · Failover ✅ (fault isolation) · Performance ✅ (throughput smoke در conformance + stress) · Concurrency ✅ (S-stress + WG race test). E2E با باینری واقعی = CI جداگانه (کانتینر) — برنامه‌ریزی P8.

### ۱۴.۱۴ Roadmap به‌روزرسانی‌شده

```
P0  Core Abstraction ✅      P4  Usage recorder job + persist baselines   ← بعدی
P1  CoreManager+Plugin ✅    P5  Admin API (/api/cores, settings, migration endpoint)
P2  Xray+sing-box+OpenVPN ✅ P6  Client API /client/v1 + Sealed Delivery + connect-token
P2.7 WireGuard+H2+TUIC+SSH+SE ✅  P7  Flutter app MVP + Dashboard
P2.8 Unified services (quota/devices/sessions) ✅  P8  CI E2E با باینری‌های واقعی
P3  Database (SQLAlchemy + Alembic + migration §14.9)  ← فاز بعدی
P9  Multi-Node node-agent عمومی (همه‌ی Coreها، نه فقط xray)
```

---

## ۱۵. فاز برندینگ و محصول (Zagros) — از Core Platform به محصول کامل

این فاز پروژه را از «پلتفرم چندهسته‌ای» به **محصول مستقل Zagros** تبدیل کرد: Rebrand کامل، لایه‌ی رمزنگاری داخلی، سیستم Delivery عمومی، Subscription Portal، Client API برای اپ، Persistence کامل (P3)، Config Studio، داشبورد حرفه‌ای و UI جدید.

### ۱۵.۱ Rebrand کامل Marzban → Zagros

| سطح | تغییر |
|---|---|
| Repository / Package | `github.com/ZagrosGM/Zagros`؛ تصاویر Docker `zagrosgm/zagros:latest` |
| Backend | FastAPI title «Zagros API» (+ Swagger/Redoc)، نسخه‌ی جدید `1.0.0-rc.1` |
| CLI | `marzban-cli.py` → `zagros-cli.py`؛ env ایجاد ادمین `ZAGROS_ADMIN_PASSWORD` |
| Env Vars | بلاک جدید `ZAGROS_*`: `ZAGROS_DATABASE_URL` (با fallback به legacy)، `ZAGROS_SECRET_KEY`، `ZAGROS_CLIENT_AUTH_MODE`، `ZAGROS_PORTAL_TITLE`، `ZAGROS_APP_NAME` |
| Paths | `/var/lib/zagros`، `/opt/zagros`، loggerهای `zagros.*`، CNهای `zagros-*` |
| UI/Dashboard | عنوان/فوتر/کلیدهای locale (`addNewZagrosNode`)، متن‌های fa/zh |
| Docs/README | بازنویسی کامل fa/en/ru/zh با ارجاع صادقانه به ریشه‌ی پروژه (AGPL) |

مقررات: هرجا «Marzban» باقی مانده صرفاً **provenance** است (سند مهاجرت داده، legacy_reader، LICENSE) — هیچ وابستگی ظاهری/عملکردی به Marzban در محصول نیست. در sweep، دو fixture تست (payload طلایی QR و ps-fixture) که عمداً رشته‌ی Marzban داشتند revert شدند تا بردارهای طلایی دست‌نخورده بمانند.

نکته‌ی معماری مهم: `app/__init__.py` به الگوی **lazy (PEP 562)** بازنویسی شد؛ ساخت اپ FastAPI فقط هنگام دسترسی به `app.app` انجام می‌شود تا Alembic env / CLI / تست‌ها / زیرسیستم cores بدون کشیدن کل استک HTTP (fastapi/apscheduler/xray singletons) import شوند.

### ۱۵.۲ لایه‌ی رمزنگاری داخلی (`app/crypto/`)

وابستگی runtime ایجاب می‌کرد `cryptography` اختیاری بماند؛ بنابراین پیاده‌سازی **Pure-Python ممیزی‌پذیر** با بردارهای استاندارد:

| ماژول | الگوریتم | اعتبارسنجی |
|---|---|---|
| `aesgcm.py` | AES-128/192/256 + GCM (فقط nonce نودوشش‌بیتی) | KATهای FIPS-197 ECB + SP800-38D + ۲۴ кейس cross-check با کتابخانه‌ی `cryptography` |
| `x25519.py` | RFC 7748 ladder | هر دو بردار RFC + fuzz شصت‌وچهارتایی؛ **باگ واقعی MSB-mask** روی u-coordinate دریافتی رفع شد (`received[31] &= 0x7F`) |
| `seal.py` | `X25519-HKDF-SHA256-AES-256-GCM` (Envelope رمزنگاری‌شده به گیرنده) | seal/open round-trip + tamper |
| `passwords.py` | scrypt `n=2¹⁴ r=8 p=1`، فرمت `$zg-scrypt$v1$...`، نیازمند rehash تشخیص‌پذیر | KAT + constant-time compare |

### ۱۵.۳ سیستم Delivery عمومی (`app/cores/delivery.py`)

معکوسِ طراحی‌های driver-specific: **هر Driver خودش اعلام می‌کند چه artifactهایی دارد**؛ Portal فقط render می‌کند.

- انواع artifact: `LINK` (share-link + QR)، `FILE` (دانلود + QR برای ini)، `FIELDS` (کلید/مقدار با masking خودکارِ secret — `public_*` آگاهانه قابل‌مشاهده می‌ماند)، `NOTE` (توضیح صادقانه برای قابلیتِ unsupported).
- `share_url_for_outbound`: تولید vless/vmess/trojan/shadowsocks از روی outboundهای به‌شکل sing-box (reality pbk/sid، ws host/path، quoting استاندارد).
- `BaseCoreDriver.describe_delivery(account, context)` پیش‌فرضِ generic دارد؛ xray (**refactor:** `_compose_outbound` استخراج شد تا build_client_config و delivery از یک منبع حقیقت تغذیه شوند)، wireguard (conf FILE + QR + Address/PublicKey/Endpoint/DNS) و openvpn (ovpn FILE + user/pass + راهنما) override مستقل دارند.
- ماتریس خروجی‌ها در `tests/cores/test_delivery.py` برای **هر ۸ درایور** conformance تست می‌شود؛ هیچ نام coreای در presenter هاردکد نیست.

### ۱۵.۴ Subscription Portal (`app/portal/`)

- **Client Authentication Mode:** `subscription_link` (Mode 1) در برابر `application_login` (Mode 2)، در سطح کل پنل + **override برای هر کاربر** (override کاربر همیشه غلبه دارد).
- Mode 2 صفحه‌ی پورتال را به «دانلود اپلیکیشن رسمی Zagros» تبدیل می‌کند — هیچ لینک/کانفیگ/secretی render نمی‌شود.
- Service لایه: per-driver `try/except` با NOTE صادقانۀ «Temporarily unavailable» (هیچ خطای درایوری کل صفحه را نمی‌شکند).
- Renderer کاملاً self-contained (بدون asset خارجی): توکن‌های طراحی `--zg-*`، dark/light (`localStorage('zagros-theme')` + prefers-color-scheme)، RTL فارسی پیش‌فرض + en، لوگوی کوهستان SVG، دکمه‌ی کپی با fallback، ماسک/نمایش secret، QR به‌صورت SVG اینلاین از `app.cores.qr`، فایل‌ها به‌صورت data URI.
- نمونه‌ی واقعی رندرشده با درایورهای واقعی: `ui/portal-preview.html` (Mode 1) و `ui/app-mode-preview.html` (Mode 2).

### ۱۵.۵ Client API برای اپ (`app/clientapi/`)

اصول طراحی به حکم بند ۸ مسترپرامپت: لاگین فقط با username/password؛ **هیچ secret/raw config از API بیرون نمی‌آید**؛ اعتبار اتصال فقط در لحظه‌ی Connect و از کانال رمزنگاری‌شده (Sealed Delivery).

- احراز: scrypt verify حتی برای username ناشناخته (uniform-cost)، rate-limit «۵ خطا در ۶۰ ثانیه»، خطاهای یکدست (unknown/suspended/wrong-password غیرقابل تفکیک)، statusهای معلق‌کننده `{disabled, expired, limited}`.
- توکن‌ها: `zga.<b64>.<sig>` با HS256-only (بدون alg-confusion)، انواع `access`/`sub`/`refresh`، refresh-rotation با `rotated_to` (replay قابل‌تشخیص)، کلید مشتق از secret اصلی با HKDF (`zagros/client-tokens/v1`).
- Sealed Delivery: `request_connect` یک Connect-Token **یک‌بارمصرف با TTL ٬۳۰ ثانیه** (sha256-hashed، خطاهای unknown/expired/replay یکسان) صادر می‌کند؛ `deliver_config` با کلید عمومی X25519 کلاینت، payload JSON را با envelope §15.2 مهروموم می‌کند. Server در حافظه ذخیره می‌کند؛ API خام را برنمی‌گرداند.
- `get_profile` هیچ secretی ندارد؛ اگر ساخت کانفیگ core شکست بخورد، status آن core صادقانه `unavailable` اعلام می‌شود.

### ۱۵.۶ P3 — Persistence کامل (`app/persistence/`)

- **Repository Pattern:** پورت‌های ClientDataProvider / PortalDataProvider / QuotaStore / BaselineStore / UsageJournal / DeviceStore / SessionStore / SettingsStore / StudioStore / RefreshTokenStore / UserRepository — پیاده‌سازی SQL و InMemory قابل‌تعویض.
- **مدل داده (~۲۰ جدول):** admins, users (+`client_auth_mode`، `app_username`، `app_password_hash`، `device_limit`), cores, core_inbounds, core_hosts, nodes, **user_core_accounts** (credentials رمزنگاری‌شده‌ی ردیفی)، user_usage, usage_baselines, usage_records (`BigInteger().with_variant(Integer,"sqlite")` برای autoincrement در SQLite), devices, device_sessions, policies, routing_rules, outbound_profiles, settings (KV), refresh_tokens, audit_logs, plugins.
- **رمزنگاری در سکون:** AES-256-GCM با AAD ردیفی `user_id:core_id:account_id`، پیشوند نسخه `v1:`، کلید مشتق HKDF (`zagros/db-credentials/v1`) از `ZAGROS_SECRET_KEY` (حداقل ۱۶ کاراکتر).
- **Session factory:** PRAGMA `journal_mode=WAL`، `foreign_keys=ON`، `busy_timeout=5000`؛ انجام FK به‌عنوان feature امنیتی محصول تلقی شد (تست‌ها اصلاح شدند نه DB). Async از طریق `asyncio.to_thread` بدون وابستگی به درایور async — مستندشده.
- **Alembic:** `alembic upgrade head` در env ایزوله اجرا و راستی‌آزمایی شد (۲۰ جدول کاربر + `alembic_version`؛ downgrade→base و re-upgrade سالم). اولویت URL: `ZAGROS_DATABASE_URL` > `SQLALCHEMY_DATABASE_URL` > ini. `verify_schema()` در بوت «fail-fast با پیام دقیق» انجام می‌شود و هیچ‌وقت خودکار schema نمی‌سازد.
- **مهاجرت از Marzban (`legacy_reader` + `migration`):** خواندن `db.sqlite3` نسخه‌ی 0.8.4 با `sqlite3` استاندارد (mode=ro، جداولِ غایب → خالی). users→users، proxies→`user_core_accounts` با `account_id = f"{legacy_user_id}.{username}.{protocol}"` (یک اکانت به‌ازای هر پروتکل — برخورد id با نسخه‌ی قبلی رفع شد)، `core_id="xray"`، settings + excluded inbounds حفظ می‌شوند، hosts/nodes/admins نظیر به نظیر. مصرف legacy جهت‌محور نیست → در `downlink_bytes` import می‌شود و **به‌ازای هر کاربر warning صریح** ثبت می‌گردد؛ on_hold/auto_delete/user_agent به `audit_logs` آرشیو می‌شوند (`legacy.field_archived`)؛ reset-logها → `legacy.usage_reset`؛ کانفیگ inbound در DB نیست → warning ارجاع به Config Studio. Importer **idempotent** است (upsert سراسری)؛ dry_run کامل پشتیبانی می‌شود؛ Rollback = `alembic downgrade`.

### ۱۵.۷ Config Studio (`app/studio/`)

- Patch مطابق **RFC 6902** (شش عمل + unescape ‌`~0`/`~1` + `-` append) و اعتبارسنجی زیرمجموعه‌ی JSON Schema با گزارشِ مسیر دقیق.
- `preview` فقط روی کپی اجرا می‌کند و `unified_diff` برمی‌گرداند — **apply اتمیک** است: هر validation-invalid هرگز روی store نوشته نمی‌شود.
- **Wizard گرافیکی Inbound** (`wizard_add_inbound`): ورودی ساخت‌یافته‌ی InboundSpec (tag/protocol/listen/port/settings) → patch خودکار روی مسیر اعلام‌شده توسط **متادیتای درایور** (`studio_inbounds_path`، مثلاً `/inbounds`) — نه هاردکد. درایور بدون پشتیبانی Export → `WizardUnsupportedError` صادقانه.
- سرویس raw/preview/apply/wizard از طریق FastAPI router در `/api/zagros/studio/...` در دسترس است؛ UI گرافیکی کامل بخش ۳/۴ پرامپت در roadmap (P5) باقی است (backend + قرارداد آماده؛ ویرایشگرهای Drag&Drop مرحله‌ی بعدی).

### ۱۵.۸ داشبورد حرفه‌ای (`app/adminapi/dashboard.py` + `ui/dashboard.html`)

`DashboardService` خروجی `DashboardSnapshot` می‌دهد: کاربران کل/آنلاین/فعال، مصرف کل + **گیج per-core** (up/down)، سلامت Coreها (state/health/version/uptime/accounts/sessions)، سلامت Nodeها، Routing/Outbound Status (به‌تفکیک core + شمارش صادقانه‌ی unsupported)، شمار Device/Session فعال و **Alertها** (مرتب‌شده: critical اول؛ quota≥۹۰٪ با سقف ۱۰). موتورهای Routing/Outbound برای این منظور `last_report` عمومی گرفتند (رفکتور بدون تغییر رفتار — تست‌های قبلی سبز ماندند).

UI جدید `ui/dashboard.html` (self-contained، بدون build step): سیستم طراحی Zagros (توکن‌های `--zg-*` هم‌خانواده با Portal)، dark/light، RTL فارسی + EN، KPIهای زنده، **نمودار sparkline لحظه‌ای throughput** (canvas)، کارت‌های سلامت core/node با pill وضعیت، progress bar مصرف هر core، وضعیت deployment، لیست هشدار — با polling هر ۵ ثانیه از `/api/zagros/dashboard/snapshot` و **fallback شفاف به داده‌ی Demo با نشان آشکار «داده نمایشی»** (بدون تظاهر به live بودن).

### ۱۵.۹ اتصال به اپ اصلی (`app/platform/`)

- `runtime.py`: Composition Root — cipher، repos، CoreManager (+discover_builtin)، موتورها، adapter آنلاین (`SQLOnlineDataAdapter` که هم ClientDataProvider است هم PortalDataProvider؛ فقط coreهای enabled+loaded تحویل داده می‌شوند؛ online = online_at در ۹۰ ثانیه‌ی اخیر) + `boot_cores()` + `verify_schema()`.
- `routers.py`: روتر `zagros_router` با endpointهای کامل: `/client/v1/auth/{login,refresh,logout}`، `/client/v1/profile`، `/client/v1/connect/{core_id}`، `/client/v1/config`، `GET /zagros/sub/{token}` (پورتال)، صدور subscription-token، `GET /api/zagros/dashboard/snapshot`، studio raw/preview/apply/wizard، تنظیمات پورتال GET/PUT، صدور app-credentials و endpoint مهاجرت `/api/zagros/migrate/legacy` (با dry_run).
- در `_build_app()` mount شد؛ راه‌اندازی runtime **guarded** است: نبودِ `ZAGROS_SECRET_KEY` یا schema ناقص → log critical + ادامه‌ی بوت پنل و پاسخ صادقانه‌ی ۵۰۳ از endpointهای Zagros (هرگز کرش). مسیر `/zagros/dashboard` خود UI را serve می‌کند.

### ۱۵.۱۰ وضعیت تست‌ها (پایان این فاز)

| دسته | تست |
|---|---|
| Cores (۸ درایور، قرارداد، routing، outbounds، QR، سناریو) | ۱۴۶ |
| Crypto (AES-GCM، X25519، Seal، Passwords) | ۲۶ |
| Portal | ۱۰ |
| Client API | ۱۵ |
| Persistence (+ Alembic/Migration، بدون نیاز به نصب sqlalchemy — skip-safe) | ۱۵ |
| Config Studio | ۹ |
| Admin API (Dashboard) | ۲ |
| **مجموع** | **۲۲۳ ✅** |

Alembic CLI نیز end-to-end با `sqlite:////tmp` اجرا و تأیید شد. E2E با باینری واقعی همچنان P8 است.

### ۱۵.۱۱ Roadmap نهایی به‌روزرسانی‌شده

```
P0  Core Abstraction ✅                 P4  Usage recorder job مرکزی (بکبه SQLBaselineStore)
P1  CoreManager + Plugin ✅             P5  UI ویرایشگرهای گرافیکی Studio (Drag&Drop/Wizard/Advanced-Diff) + CRUD کاربران
P2  Xray + sing-box + OpenVPN ✅        P6  رویدادهای بلادرنگ WS/SSE + دوکاناله‌کردن Alertها
P2.7 WireGuard+Hy2+TUIC+SSH+SoftEther ✅ P7  اپ Flutter/Zagros Client MVP (روی clientapi موجود)
P2.8 سرویس‌های یکپارچه ✅               P8  CI: E2E با باینری‌های واقعی + ماتریس استرس در کانتینر
P3  Persistence+Alembic+Migration ✅    P9  node-agent عمومی چندهسته‌ای (فراتر از xray)
P3.5 Rebrand+Portal+ClientAPI+Studio+Dashboard ✅ (این فاز)
```

---

## ۱۶. Feature Freeze و آماده‌سازی Alpha (نسخه `1.0.0-alpha.2`)

در این فاز هیچ Feature جدیدی اضافه نشد؛ فقط ثبات، صحت، امنیت و कامل‌سازی UI.

### ۱۶.۱ بازبینی Taxonomy‌ درایورها
تعریف واحد معماری (Driver = محصول سرور مستقل با سه شرط: باینری/چرخه‌حیات مستقل،
سطح مدیریتی متمایز، deployment جدا) در `docs/DRIVER-TAXONOMY.md` تثبیت شد. هر ۸
درایور رأی مثبت گرفتند؛ Hysteria2/TUIC سرورهای مستقلِ با مستندات رسمی هستند (نه
inboundهای sing-box) و هم‌پوشانی صفر است. رفع بدهی: `app/cores/pki.py` (تولید
گواهی مشترک)، حذف تکرار از ۳ backend، صفر چرخه‌ی import در runtime.

### ۱۶.۲ تست با باینری واقعی (tests/e2e، به‌جای mock)
سوئیت gated با `ZAGROS_E2E=1`؛ اجرای واقعی با باینری‌های رسمی GitHub. **۱۳ رخداد
باگ/ناسازگاری واقعی** پیدا و اصلاح شد — فهرست کامل در `docs/REAL-BINARY-NOTES.md`.
مهم‌ترین‌ها: کلید `trafficStats:` در hysteria، ممنوعیت نقطه در کلیدهای userpass،
بوت با users خالی (hysteria/tuic) → bootstrap credential امن پایدار، مهاجرت کانفیگ
sing-box به schema 1.12 (dns server جدید + حذف outbound مستهلک `dns` به نفع
route action `hijack-dns`)، بازسازی ManagedProcess بعد از install، پیاده‌سازی واقعی
SELF_INSTALL برای xray (+سیاست uninstall فقط-با-marker)، قاعده‌ی WAL-checkpoint
برای Backup. محدودیت‌های محیطی (wireguard/openvpn/softether/ssh بدون root؛ xray
start وابسته به runtime پنل) صادقانه مستندند، نه سبزِ جعلی.

### ۱۶.۳ امنیت (docs/SECURITY-REVIEW.md)
بحرانی‌ترین یافته: مسیرهای `/api/zagros/*` بدون auth → روتر ادمین sudo-gated
(fail-closed) + تست دائمی ۱۰ مسیر. Rotation لینک اشتراک اکنون انباتی است (jti در
settings KV). CORS پیش‌فرض same-origin شد. rate-limit ورود اپ، uniform-cost
authentication، connect-token یک‌بارمصرف و Sealed Delivery بازبینی و تأیید شدند.

### ۱۶.۴ تکمیل UI (در چارچوب Freeze)
`ui/studio.html` — Config Studio گرافیکی: Inbound Wizard ساخت‌یافته (بدون JSON؛
مسیر از متادیتای درایور)، ویرایشگر درختی عمومی Routing/Outbounds/DNS-Policy که
خودش JSON-Patch تولید می‌کند، پیش‌نمایش Diff + Validation قبل از Apply، و حالت
Advanced (raw + diff) به‌عنوان غیرپیش‌فرض. هر دو صفحه‌ی UI جریان توکن ادمین
sudo را پشتیبانی می‌کنند (پاسخ ۴۰۱/۴۰۳ → فرم توکن؛ داشبورد در آفلاین با نشانِ
آشکار «داده نمایشی» کار می‌کند).

### ۱۶.۵ Performance
backend رمزنگاری دوگانه: ترجیح `cryptography` (وابستگی موجود) → AES-256-GCM از
~۲۲ms به ~۵µs per 1.4KB (~۴۰۰۰×) و X25519 از ده‌ها میلی‌ثانیه به ~۰٫۰۸ms؛ fallback
خالص‌پایتون برای bootstrap حفظ شد و هر دو مسیر روی همان golden vectors قفل‌اند.
معیارها: share-link ~۵µs، jsonpatch روی سند بزرگ ~۲٫۵ms، scrypt ~۴۸ms (مقصود).

### ۱۶.۶ وضعیت تست Alpha
`python3 -m pytest tests/ -q` → **۲۲۹ پاس + ۷ اسکیپ (e2e gated)**.
`ZAGROS_E2E=1` → **۶ پاس + ۱ اسکیپ مستند** (باینری واقعی).
 وضعیت GitHub در گزارش فاز مکتوب شد (بدون هیچ اقدام حدسی).
