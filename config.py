from decouple import config

from app.env_loader import load_zagros_env

# Single source of truth: ``<project-root>/.env`` (see app/env_loader.py).
# In docker deployments compose only MOUNTS that file into the container —
# nothing is injected into the process environment — so editing the file +
# restarting the container applies every setting, exactly like Marzban.
load_zagros_env()


# ─────────────────────────── Identity / Domain ─────────────────────────── #
# DOMAIN is the public hostname of this panel (e.g. panel.example.com).
# When set, PANEL_BASE_URL / APP_BASE_URL and absolute subscription links
# are derived from it automatically — cheaper than Marzban's manual prefix.
DOMAIN = config("DOMAIN", default="").strip()


def _derive_base_url(domain: str) -> str:
    if not domain:
        return ""
    if domain.startswith(("http://", "https://")):
        return domain.rstrip("/")
    return f"https://{domain}".rstrip("/")


PANEL_BASE_URL = config("PANEL_BASE_URL", default=_derive_base_url(DOMAIN)).rstrip("/")
APP_BASE_URL = config("APP_BASE_URL", default=PANEL_BASE_URL).rstrip("/")


# ------------------------- Zagros platform (P3+) ------------------------- #
# New canonical names live under the ZAGROS_* namespace; legacy names stay
# accepted as fallbacks so existing deployments keep booting.
ZAGROS_DATABASE_URL = config(
    "ZAGROS_DATABASE_URL",
    default=config("SQLALCHEMY_DATABASE_URL", default="sqlite:///zagros.db"),
)
ZAGROS_SECRET_KEY = config("ZAGROS_SECRET_KEY", default="")
ZAGROS_CLIENT_AUTH_MODE = config(
    "ZAGROS_CLIENT_AUTH_MODE", default="subscription_link"
).lower()
ZAGROS_PORTAL_TITLE = config("ZAGROS_PORTAL_TITLE", default="اشتراک من")
ZAGROS_APP_NAME = config("ZAGROS_APP_NAME", default="Zagros")

SQLALCHEMY_DATABASE_URL = config("SQLALCHEMY_DATABASE_URL", default="sqlite:///db.sqlite3")
SQLALCHEMY_POOL_SIZE = config("SQLALCHEMY_POOL_SIZE", cast=int, default=10)
SQLIALCHEMY_MAX_OVERFLOW = config("SQLIALCHEMY_MAX_OVERFLOW", cast=int, default=30)

# ───────────────────────── HTTP bind & TLS ─────────────────────────────── #
# UVICORN_HOST is honored VERBATIM (nothing rewrites it at runtime).
#
# TLS_MODE controls how the panel terminates TLS:
#   auto (default): TLS on when both UVICORN_SSL_CERTFILE/KEYFILE are set,
#                   otherwise plain HTTP on UVICORN_HOST.
#   on            : TLS REQUIRED — refuses to boot without cert+key.
#   off           : force plain HTTP even if cert/key variables are set
#                   (reverse-proxy / LAN setups terminating TLS upstream).
TLS_MODE = config("TLS_MODE", default="auto").lower()
UVICORN_HOST = config("UVICORN_HOST", default="0.0.0.0")
UVICORN_PORT = config("UVICORN_PORT", cast=int, default=8000)
UVICORN_UDS = config("UVICORN_UDS", default=None)
UVICORN_SSL_CERTFILE = config("UVICORN_SSL_CERTFILE", default=None)
UVICORN_SSL_KEYFILE = config("UVICORN_SSL_KEYFILE", default=None)
UVICORN_SSL_CA_CERTFILE = config("UVICORN_SSL_CA_CERTFILE", default=None)
UVICORN_SSL_CA_TYPE = config("UVICORN_SSL_CA_TYPE", default="public").lower()
DASHBOARD_PATH = config("DASHBOARD_PATH", default="/dashboard/")

DEBUG = config("DEBUG", default=False, cast=bool)
DOCS = config("DOCS", default=False, cast=bool)

# Security review (Alpha): never default to "*" — especially not together
# with allow_credentials=True in the app. Empty default = same-origin only;
# operators opt in explicitly per trusted origin.
ALLOWED_ORIGINS = [o.strip() for o in config("ALLOWED_ORIGINS", default="").split(",") if o.strip()]

# HTTP Host-header allow-list (Starlette TrustedHostMiddleware). Empty
# default = the middleware is not installed at all (no behavior change);
# when set, requests with an unlisted Host are rejected with 400.
TRUSTED_HOSTS = [h.strip() for h in config("TRUSTED_HOSTS", default="").split(",") if h.strip()]
TRUSTED_PROXIES = [h.strip() for h in config("TRUSTED_PROXIES", default="").split(",") if h.strip()]
ZAGROS_HSTS = config("ZAGROS_HSTS", default=False, cast=bool)
ZAGROS_REDIRECT_HTTP_TO_HTTPS = config(
    "ZAGROS_REDIRECT_HTTP_TO_HTTPS", default=False, cast=bool)

VITE_BASE_API = f"http://127.0.0.1:{UVICORN_PORT}/api/" \
    if DEBUG and config("VITE_BASE_API", default="/api/") == "/api/" \
    else config("VITE_BASE_API", default="/api/")

XRAY_JSON = config(
    "XRAY_JSON", default="/var/lib/zagros/cores/xray/xray_config.json"
)
XRAY_FALLBACKS_INBOUND_TAG = config("XRAY_FALLBACKS_INBOUND_TAG", cast=str, default="") or config(
    "XRAY_FALLBACK_INBOUND_TAG", cast=str, default=""
)
XRAY_EXECUTABLE_PATH = config(
    "XRAY_EXECUTABLE_PATH", default="/var/lib/zagros/cores/xray/bin/xray"
)
XRAY_ASSETS_PATH = config(
    "XRAY_ASSETS_PATH", default="/var/lib/zagros/cores/xray/assets"
)
XRAY_EXCLUDE_INBOUND_TAGS = config("XRAY_EXCLUDE_INBOUND_TAGS", default='').split()

# ─────────────────────────── Subscription ──────────────────────────────── #
# Canonical names first; the legacy XRAY_* names stay accepted as fallbacks
# so existing deployments keep booting unchanged.
SUBSCRIPTION_URL_PREFIX = config(
    "SUBSCRIPTION_URL_PREFIX",
    default=config("XRAY_SUBSCRIPTION_URL_PREFIX", default=""),
).strip("/")
SUBSCRIPTION_PATH = config(
    "SUBSCRIPTION_PATH",
    default=config("XRAY_SUBSCRIPTION_PATH", default="sub"),
).strip("/")

# Legacy aliases — bound so every pre-existing import site keeps working.
# When the operator only set DOMAIN (no explicit prefix), subscription
# links become absolute against PANEL_BASE_URL automatically.
XRAY_SUBSCRIPTION_URL_PREFIX = SUBSCRIPTION_URL_PREFIX or PANEL_BASE_URL
XRAY_SUBSCRIPTION_PATH = SUBSCRIPTION_PATH

TELEGRAM_API_TOKEN = config("TELEGRAM_API_TOKEN", default="")
TELEGRAM_ADMIN_ID = config(
    'TELEGRAM_ADMIN_ID',
    default="",
    cast=lambda v: [int(i) for i in filter(str.isdigit, (s.strip() for s in v.split(',')))]
)
TELEGRAM_PROXY_URL = config("TELEGRAM_PROXY_URL", default="")
TELEGRAM_LOGGER_CHANNEL_ID = config("TELEGRAM_LOGGER_CHANNEL_ID", cast=int, default=0)
TELEGRAM_DEFAULT_VLESS_FLOW = config("TELEGRAM_DEFAULT_VLESS_FLOW", default="")

JWT_ACCESS_TOKEN_EXPIRE_MINUTES = config("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", cast=int, default=1440)

CUSTOM_TEMPLATES_DIRECTORY = config("CUSTOM_TEMPLATES_DIRECTORY", default=None)
# Canonical name first; legacy SUBSCRIPTION_PAGE_TEMPLATE stays accepted.
SUBSCRIPTION_TEMPLATE = config(
    "SUBSCRIPTION_TEMPLATE",
    default=config("SUBSCRIPTION_PAGE_TEMPLATE", default="subscription/index.html"),
)
SUBSCRIPTION_PAGE_TEMPLATE = SUBSCRIPTION_TEMPLATE
HOME_PAGE_TEMPLATE = config("HOME_PAGE_TEMPLATE", default="home/index.html")

CLASH_SUBSCRIPTION_TEMPLATE = config("CLASH_SUBSCRIPTION_TEMPLATE", default="clash/default.yml")
CLASH_SETTINGS_TEMPLATE = config("CLASH_SETTINGS_TEMPLATE", default="clash/settings.yml")

SINGBOX_SUBSCRIPTION_TEMPLATE = config("SINGBOX_SUBSCRIPTION_TEMPLATE", default="singbox/default.json")
SINGBOX_SETTINGS_TEMPLATE = config("SINGBOX_SETTINGS_TEMPLATE", default="singbox/settings.json")

MUX_TEMPLATE = config("MUX_TEMPLATE", default="mux/default.json")

V2RAY_SUBSCRIPTION_TEMPLATE = config("V2RAY_SUBSCRIPTION_TEMPLATE", default="v2ray/default.json")
V2RAY_SETTINGS_TEMPLATE = config("V2RAY_SETTINGS_TEMPLATE", default="v2ray/settings.json")

USER_AGENT_TEMPLATE = config("USER_AGENT_TEMPLATE", default="user_agent/default.json")
GRPC_USER_AGENT_TEMPLATE = config("GRPC_USER_AGENT_TEMPLATE", default="user_agent/grpc.json")

EXTERNAL_CONFIG = config("EXTERNAL_CONFIG", default="", cast=str)
LOGIN_NOTIFY_WHITE_LIST = [ip.strip() for ip in config("LOGIN_NOTIFY_WHITE_LIST",
                                                       default="", cast=str).split(",") if ip.strip()]

USE_CUSTOM_JSON_DEFAULT = config("USE_CUSTOM_JSON_DEFAULT", default=False, cast=bool)
USE_CUSTOM_JSON_FOR_V2RAYN = config("USE_CUSTOM_JSON_FOR_V2RAYN", default=False, cast=bool)
USE_CUSTOM_JSON_FOR_V2RAYNG = config("USE_CUSTOM_JSON_FOR_V2RAYNG", default=False, cast=bool)
USE_CUSTOM_JSON_FOR_STREISAND = config("USE_CUSTOM_JSON_FOR_STREISAND", default=False, cast=bool)
USE_CUSTOM_JSON_FOR_HAPP = config("USE_CUSTOM_JSON_FOR_HAPP", default=False, cast=bool)

NOTIFY_STATUS_CHANGE = config("NOTIFY_STATUS_CHANGE", default=True, cast=bool)
NOTIFY_USER_CREATED = config("NOTIFY_USER_CREATED", default=True, cast=bool)
NOTIFY_USER_UPDATED = config("NOTIFY_USER_UPDATED", default=True, cast=bool)
NOTIFY_USER_DELETED = config("NOTIFY_USER_DELETED", default=True, cast=bool)
NOTIFY_USER_DATA_USED_RESET = config("NOTIFY_USER_DATA_USED_RESET", default=True, cast=bool)
NOTIFY_USER_SUB_REVOKED = config("NOTIFY_USER_SUB_REVOKED", default=True, cast=bool)
NOTIFY_IF_DATA_USAGE_PERCENT_REACHED = config("NOTIFY_IF_DATA_USAGE_PERCENT_REACHED", default=True, cast=bool)
NOTIFY_IF_DAYS_LEFT_REACHED = config("NOTIFY_IF_DAYS_LEFT_REACHED", default=True, cast=bool)
NOTIFY_LOGIN = config("NOTIFY_LOGIN", default=True, cast=bool)

ACTIVE_STATUS_TEXT = config("ACTIVE_STATUS_TEXT", default="Active")
EXPIRED_STATUS_TEXT = config("EXPIRED_STATUS_TEXT", default="Expired")
LIMITED_STATUS_TEXT = config("LIMITED_STATUS_TEXT", default="Limited")
DISABLED_STATUS_TEXT = config("DISABLED_STATUS_TEXT", default="Disabled")
ONHOLD_STATUS_TEXT = config("ONHOLD_STATUS_TEXT", default="On-Hold")

USERS_AUTODELETE_DAYS = config("USERS_AUTODELETE_DAYS", default=-1, cast=int)
USER_AUTODELETE_INCLUDE_LIMITED_ACCOUNTS = config("USER_AUTODELETE_INCLUDE_LIMITED_ACCOUNTS", default=False, cast=bool)


# USERNAME: PASSWORD
SUDOERS = {config("SUDO_USERNAME"): config("SUDO_PASSWORD")} \
    if config("SUDO_USERNAME", default='') and config("SUDO_PASSWORD", default='') \
    else {}


WEBHOOK_ADDRESS = config(
    'WEBHOOK_ADDRESS',
    default="",
    cast=lambda v: [address.strip() for address in v.split(',')] if v else []
)
WEBHOOK_SECRET = config("WEBHOOK_SECRET", default=None)

# recurrent notifications

# timeout between each retry of sending a notification in seconds
RECURRENT_NOTIFICATIONS_TIMEOUT = config("RECURRENT_NOTIFICATIONS_TIMEOUT", default=180, cast=int)
# how many times to try after ok response not recevied after sending a notifications
NUMBER_OF_RECURRENT_NOTIFICATIONS = config("NUMBER_OF_RECURRENT_NOTIFICATIONS", default=3, cast=int)

# sends a notification when the user uses this much of thier data
NOTIFY_REACHED_USAGE_PERCENT = config(
    "NOTIFY_REACHED_USAGE_PERCENT",
    default="80",
    cast=lambda v: [int(p.strip()) for p in v.split(',')] if v else []
)

# sends a notification when there is n days left of their service
NOTIFY_DAYS_LEFT = config(
    "NOTIFY_DAYS_LEFT",
    default="3",
    cast=lambda v: [int(d.strip()) for d in v.split(',')] if v else []
)

DISABLE_RECORDING_NODE_USAGE = config("DISABLE_RECORDING_NODE_USAGE", cast=bool, default=False)

# headers: profile-update-interval, support-url, profile-title
SUB_UPDATE_INTERVAL = config("SUB_UPDATE_INTERVAL", default="12")
SUB_SUPPORT_URL = config("SUB_SUPPORT_URL", default="https://t.me/")
SUB_PROFILE_TITLE = config("SUB_PROFILE_TITLE", default="Subscription")

# discord webhook log
DISCORD_WEBHOOK_URL = config("DISCORD_WEBHOOK_URL", default="")


# Interval jobs, all values are in seconds
JOB_CORE_HEALTH_CHECK_INTERVAL = config("JOB_CORE_HEALTH_CHECK_INTERVAL", cast=int, default=10)
JOB_RECORD_NODE_USAGES_INTERVAL = config("JOB_RECORD_NODE_USAGES_INTERVAL", cast=int, default=30)
JOB_RECORD_USER_USAGES_INTERVAL = config("JOB_RECORD_USER_USAGES_INTERVAL", cast=int, default=10)
JOB_REVIEW_USERS_INTERVAL = config("JOB_REVIEW_USERS_INTERVAL", cast=int, default=10)
JOB_SEND_NOTIFICATIONS_INTERVAL = config("JOB_SEND_NOTIFICATIONS_INTERVAL", cast=int, default=30)
