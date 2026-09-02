"""Admin-managed subscription page templates.

Marzban let an operator point the panel at a custom template directory —
but only through an environment variable plus shell access to the server.
Here the operator authors an HTML page, uploads it from the panel's
Subscriptions section, and selects it there: no shell, no restart, no
redeploy.

Contract:

* a flat directory under the data dir, sanitized names, ``.html``/``.htm``
  only — an upload can never escape it or shadow a system file;
* templates are Jinja2 and render **the way Marzban renders its
  subscription page**: no auto-escaping, the ``bytesformat`` / ``datetime``
  / ``yaml`` filters and the ``now()`` global are available, and the
  ``user`` object answers the Marzban names (``user.links``,
  ``user.subscription_url``, ``user.used_traffic``, ``user.data_limit``,
  ``user.expire``, ``user.status.value`` ...) next to the Zagros ones — a
  template written for Marzban works unchanged;
* an upload is validated before it is stored: a syntax error, an unknown
  filter or a broken variable reference is rejected with the line number,
  instead of being discovered by a subscriber;
* a template that still fails at serve time NEVER breaks a subscriber's
  page: the built-in page is served, the failure is logged and remembered
  (:func:`last_failure`) so the dashboard can show *why* the built-in page
  is being served. Presentation is the one place where failing open is the
  safe direction.
"""
from __future__ import annotations

import logging
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SUBDIR = "subscription-templates"
MAX_BYTES = 1024 * 1024  # 1 MB — full Tailwind/Alpine single-file pages fit
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EXTENSIONS = (".html", ".htm")

STARTER_TEMPLATE = """{# Zagros subscription page — starter template.

   Edit freely, then upload it in Subscriptions → "subscription page
   template". An upload is validated (syntax + a test render) and becomes
   the active page at once; "preview" shows it with sample data or a real
   user. Templates written for Marzban work unchanged.

   Everything a core delivers is in `sections` — share links (xray,
   sing-box), config files (OpenVPN, WireGuard), credential tables (SSH,
   SoftEther, PPTP, L2TP, SSTP) and notes — so one page shows every
   protocol. Full reference:
   https://zagrosgm.github.io/zagros-docs/examples/subscription-page

   Variables (all optional to use):
     user.username, user.status, user.online, user.note
     used_bytes / data_limit_bytes / remaining_bytes    ints or None
     expire_at                                          datetime or None
     sections   [{protocol, title, engine, note, artifacts[]}]
                artifact: kind ("link"/"file"/"fields"/"note"), label,
                          content, filename, mime, qr, note, fields[]
                field:    key, label, value, secret, copyable
     links      flat [{protocol, title, label, url}]
     files      flat [{protocol, title, label, filename, mime, content, href}]
     subscription_url, subscription_formats {links, clash, sing_box}
     import_links {v2rayng, hiddify, streisand, happ, v2box, shadowrocket,
                   nekobox, karing, sing-box, clash, stash}
     apps [{platform, name, url, primary}], notes [str]
     brand, app_name, support_url, generated_at, lang, direction
   Helpers:
     format_bytes(v), format_date(v), days_left(v)
     qr_svg(text)            inline SVG QR code ("" if empty / too long)
     data_uri(text, mime)    download href for a config file
     filters: bytesformat, datetime, yaml, e (escape) — global: now()
   Marzban names on `user`: links, subscription_url, used_traffic,
     lifetime_used_traffic, data_limit, expire (unix time), status.value,
     data_limit_reset_strategy.value, created_at, online_at
#}
{%- set fa = lang == "fa" -%}
{%- set L = {
  "online": "آنلاین", "offline": "آفلاین", "used": "مصرف", "limit": "حجم کل",
  "remaining": "باقی‌مانده", "unlimited": "نامحدود", "expire": "انقضا",
  "never": "بدون انقضا", "days": "روز مانده", "expired": "منقضی شده",
  "sub": "لینک اشتراک", "copy": "کپی", "copied": "کپی شد", "open": "باز کردن",
  "qr": "کد QR", "download": "دانلود", "show": "نمایش", "hide": "پنهان",
  "import": "افزودن به برنامه", "formats": "فرمت‌های دیگر", "apps": "دانلود برنامه",
  "notes": "نکته‌ها", "support": "پشتیبانی", "engine": "کلاینت پیشنهادی"
} if fa else {
  "online": "online", "offline": "offline", "used": "Used", "limit": "Total",
  "remaining": "Remaining", "unlimited": "Unlimited", "expire": "Expires",
  "never": "Never", "days": "days left", "expired": "expired",
  "sub": "Subscription link", "copy": "Copy", "copied": "Copied", "open": "Open",
  "qr": "QR code", "download": "Download", "show": "Show", "hide": "Hide",
  "import": "Add to app", "formats": "Other formats", "apps": "Download the app",
  "notes": "Notes", "support": "Support", "engine": "recommended client"
} -%}
{%- set app_names = {
  "v2rayng": "v2rayNG", "hiddify": "Hiddify", "streisand": "Streisand",
  "happ": "Happ", "v2box": "V2Box", "shadowrocket": "Shadowrocket",
  "nekobox": "NekoBox", "karing": "Karing", "sing-box": "sing-box",
  "clash": "Clash / Mihomo", "stash": "Stash"
} -%}
{%- set days = days_left(expire_at) -%}
<!doctype html>
<html lang="{{ lang }}" dir="{{ direction }}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{ brand | e }} · {{ user.username | e }}</title>
<style>
  /* ---- customize: colours, radius and font live here ---- */
  :root {
    --accent: #2563eb; --bg: #f4f6fb; --card: #ffffff; --text: #111827;
    --muted: #6b7280; --line: #e5e7eb; --soft: #f3f4f6; --radius: 16px;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #0b0f19; --card: #111827; --text: #f3f4f6; --muted: #9ca3af;
            --line: #1f2937; --soft: #1a2233; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 16px 48px; background: var(--bg); color: var(--text);
         font: 15px/1.7 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 760px; margin: 0 auto; display: grid; gap: 16px; }
  .card { background: var(--card); border: 1px solid var(--line);
          border-radius: var(--radius); padding: 20px; }
  h1 { margin: 0; font-size: 22px; }
  h2 { margin: 0 0 12px; font-size: 16px; }
  .muted { color: var(--muted); font-size: 13px; }
  .top { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px;
           background: var(--soft); color: var(--muted); }
  .badge.active { background: #dcfce7; color: #166534; }
  .badge.limited, .badge.expired, .badge.disabled { background: #fee2e2; color: #991b1b; }
  .badge.on_hold { background: #fef3c7; color: #92400e; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
           gap: 12px; margin-top: 16px; }
  .stat { padding: 12px; border: 1px solid var(--line); border-radius: 12px; }
  .stat b { display: block; font-size: 17px; }
  .bar { height: 8px; background: var(--soft); border-radius: 999px; overflow: hidden; margin-top: 14px; }
  .bar i { display: block; height: 100%; background: var(--accent); }
  .ltr { direction: ltr; text-align: left; unicode-bidi: plaintext; }
  code.url { display: block; padding: 10px 12px; background: var(--soft); border-radius: 10px;
             font-size: 13px; word-break: break-all; }
  .btn { display: inline-flex; align-items: center; gap: 6px; padding: 7px 14px; border-radius: 10px;
         border: 1px solid var(--line); background: var(--card); color: var(--text);
         text-decoration: none; font: inherit; font-size: 13px; line-height: 1.4; cursor: pointer; }
  .btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  .btn.small { padding: 3px 10px; font-size: 12px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .item { padding: 14px 0; border-top: 1px solid var(--line); }
  .item:first-of-type { border-top: 0; padding-top: 4px; }
  .item header { display: flex; justify-content: space-between; align-items: center; gap: 8px;
                 flex-wrap: wrap; margin-bottom: 8px; }
  .item header .actions { margin: 0; }
  details { margin-top: 8px; }
  details summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  .qr { margin-top: 8px; }
  .qr svg { width: 180px; height: 180px; border-radius: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  td { padding: 8px 4px; border-top: 1px solid var(--line); vertical-align: top; }
  td:first-child { color: var(--muted); width: 32%; }
  td .btn { margin-inline-start: 6px; }
  pre.file { max-height: 220px; overflow: auto; padding: 10px 12px; background: var(--soft);
             border-radius: 10px; font-size: 12px; margin: 8px 0 0; }
  .note { padding: 10px 12px; border-radius: 10px; background: #fef9c3; color: #713f12;
          font-size: 13px; margin: 8px 0 0; }
  footer { text-align: center; font-size: 12px; color: var(--muted); }
</style>
</head>
<body>
<main>

  <!-- ===== account ===== -->
  <section class="card">
    <div class="top">
      <div>
        <h1>{{ brand | e }}</h1>
        <div class="muted">{{ user.username | e }}</div>
      </div>
      <div>
        <span class="badge {{ user.status }}">{{ user.status }}</span>
        <span class="badge">{{ L['online'] if online else L['offline'] }}</span>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><span class="muted">{{ L['used'] }}</span><b>{{ format_bytes(used_bytes) }}</b></div>
      <div class="stat"><span class="muted">{{ L['limit'] }}</span>
        <b>{% if data_limit_bytes %}{{ format_bytes(data_limit_bytes) }}{% else %}{{ L['unlimited'] }}{% endif %}</b></div>
      <div class="stat"><span class="muted">{{ L['remaining'] }}</span>
        <b>{% if remaining_bytes is not none %}{{ format_bytes(remaining_bytes) }}{% else %}{{ L['unlimited'] }}{% endif %}</b></div>
      <div class="stat"><span class="muted">{{ L['expire'] }}</span>
        <b>{% if expire_at %}{{ format_date(expire_at) }}{% else %}{{ L['never'] }}{% endif %}</b>
        {% if days is not none %}<span class="muted">{% if days >= 0 %}{{ days }} {{ L['days'] }}{% else %}{{ L['expired'] }}{% endif %}</span>{% endif %}</div>
    </div>
    {% if user.usage_ratio is not none %}
    <div class="bar"><i style="width: {{ (user.usage_ratio * 100) | round(1) }}%"></i></div>
    {% endif %}
    {% if user.note %}<p class="muted">{{ user.note | e }}</p>{% endif %}
  </section>

  <!-- ===== subscription link + one-tap import ===== -->
  {% if subscription_url %}
  <section class="card">
    <h2>{{ L['sub'] }}</h2>
    <code class="url ltr">{{ subscription_url | e }}</code>
    <div class="actions">
      <button class="btn primary" data-copy="{{ subscription_url | e }}" data-done="{{ L['copied'] }}">{{ L['copy'] }}</button>
      {% for app_id, href in import_links.items() %}
      <a class="btn" href="{{ href | e }}">{{ app_names.get(app_id, app_id) }}</a>
      {% endfor %}
    </div>
    <details>
      <summary>{{ L['qr'] }}</summary>
      <div class="qr">{{ qr_svg(subscription_url) }}</div>
    </details>
    <details>
      <summary>{{ L['formats'] }}</summary>
      <code class="url ltr">{{ subscription_formats.clash | e }}</code>
      <code class="url ltr" style="margin-top: 6px">{{ subscription_formats.sing_box | e }}</code>
    </details>
  </section>
  {% endif %}

  <!-- ===== every protocol the cores deliver ===== -->
  {% for section in sections %}
  <section class="card">
    <h2>{{ section.title | e }}{% if section.engine %} <span class="muted">· {{ L['engine'] }}: {{ section.engine | e }}</span>{% endif %}</h2>
    {% if section.note %}<p class="note">{{ section.note | e }}</p>{% endif %}
    {% for a in section.artifacts %}
    <div class="item">
      {% if a.kind == "link" %}
        <header>
          <span>{{ a.label | e }}</span>
          <span class="actions">
            <button class="btn small" data-copy="{{ a.content | e }}" data-done="{{ L['copied'] }}">{{ L['copy'] }}</button>
            <a class="btn small" href="{{ a.content | e }}">{{ L['open'] }}</a>
          </span>
        </header>
        <code class="url ltr">{{ a.content | e }}</code>
        {% if a.qr %}<details><summary>{{ L['qr'] }}</summary><div class="qr">{{ qr_svg(a.content) }}</div></details>{% endif %}

      {% elif a.kind == "file" %}
        <header>
          <span>{{ a.label | e }}</span>
          <span class="actions">
            <a class="btn small primary" href="{{ data_uri(a.content, a.mime) }}" download="{{ a.filename | e }}">{{ L['download'] }} · {{ a.filename | e }}</a>
            <button class="btn small" data-copy="{{ a.content | e }}" data-done="{{ L['copied'] }}">{{ L['copy'] }}</button>
          </span>
        </header>
        <details><summary>{{ L['show'] }}</summary><pre class="file ltr">{{ a.content | e }}</pre></details>
        {% if a.qr %}<details><summary>{{ L['qr'] }}</summary><div class="qr">{{ qr_svg(a.content) }}</div></details>{% endif %}

      {% elif a.kind == "fields" %}
        <header><span>{{ a.label | e }}</span></header>
        <table>
          {% for f in a.fields %}
          <tr>
            <td>{{ f.label | e }}</td>
            <td class="ltr">
              {% if f.secret %}
                <span class="secret" data-secret="{{ f.value | e }}">••••••••</span>
                <button class="btn small" data-reveal data-show="{{ L['show'] }}" data-hide="{{ L['hide'] }}">{{ L['show'] }}</button>
              {% else %}
                <span>{{ f.value | e }}</span>
              {% endif %}
              {% if f.copyable %}<button class="btn small" data-copy="{{ f.value | e }}" data-done="{{ L['copied'] }}">{{ L['copy'] }}</button>{% endif %}
            </td>
          </tr>
          {% endfor %}
        </table>

      {% elif a.kind == "note" %}
        <p class="note">{{ a.note | e }}</p>
      {% endif %}

      {% if a.note and a.kind != "note" %}<p class="muted">{{ a.note | e }}</p>{% endif %}
    </div>
    {% endfor %}
  </section>
  {% endfor %}

  <!-- ===== official apps + notes + support ===== -->
  {% if apps %}
  <section class="card">
    <h2>{{ L['apps'] }}</h2>
    <div class="actions">
      {% for app in apps %}
      <a class="btn{% if app.primary %} primary{% endif %}" href="{{ app.url | e }}">{{ app.name | e }} <span class="muted">({{ app.platform | e }})</span></a>
      {% endfor %}
    </div>
  </section>
  {% endif %}

  {% if notes or support_url %}
  <section class="card">
    {% if notes %}<h2>{{ L['notes'] }}</h2>{% for n in notes %}<p class="note">{{ n | e }}</p>{% endfor %}{% endif %}
    {% if support_url %}<div class="actions"><a class="btn" href="{{ support_url | e }}">{{ L['support'] }}</a></div>{% endif %}
  </section>
  {% endif %}

  <footer>{{ brand | e }} · {{ format_date(generated_at) }}</footer>
</main>

<script>
(function () {
  function legacyCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text; ta.setAttribute("readonly", "");
    ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (err) { /* ignore */ }
    document.body.removeChild(ta);
  }
  function flash(btn) {
    var old = btn.textContent, done = btn.getAttribute("data-done") || "✓";
    btn.textContent = done;
    setTimeout(function () { btn.textContent = old; }, 1200);
  }
  function copyText(text, btn) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { flash(btn); },
        function () { legacyCopy(text); flash(btn); });
    } else { legacyCopy(text); flash(btn); }
  }
  document.addEventListener("click", function (ev) {
    var copyBtn = ev.target.closest("[data-copy]");
    if (copyBtn) { ev.preventDefault(); copyText(copyBtn.getAttribute("data-copy"), copyBtn); return; }
    var revealBtn = ev.target.closest("[data-reveal]");
    if (!revealBtn) { return; }
    var secret = revealBtn.parentNode.querySelector(".secret");
    if (!secret) { return; }
    var shown = secret.getAttribute("data-shown") === "1";
    secret.textContent = shown ? "••••••••" : secret.getAttribute("data-secret");
    secret.setAttribute("data-shown", shown ? "0" : "1");
    revealBtn.textContent = shown ? revealBtn.getAttribute("data-show") : revealBtn.getAttribute("data-hide");
  });
})();
</script>
</body>
</html>
"""


class TemplateError(Exception):
    """Rejected upload / failed render — safe to show the message to an operator."""


def data_dir_for(runtime: Any) -> str:
    """Where managed files live: beside the SQLite DB, else the default."""
    url = str(getattr(runtime, "database_url", "") or "")
    if url.startswith("sqlite:///"):
        from pathlib import Path as _Path

        return str(_Path(url[10:]).parent)
    return "/var/lib/zagros"


def directory(data_dir: str) -> Path:
    return Path(data_dir) / SUBDIR


def safe_name(filename: str) -> str:
    """Basename only, flat, sanitized — never a path, never a traversal."""
    raw = str(filename or "").replace("\\", "/")
    name = Path(raw).name.strip()
    if not name or name in {".", ".."}:
        raise TemplateError("template name is empty")
    if not name.lower().endswith(_EXTENSIONS):
        raise TemplateError("template must be an .html or .htm file")
    name = re.sub(r"[^A-Za-z0-9._-]", "-", name)
    if not _SAFE_NAME.match(name):
        raise TemplateError(
            "template name may only contain letters, digits, dot, dash and underscore")
    return name


# --------------------------------------------------------------------- #
# Jinja2 environment — Marzban parity
# --------------------------------------------------------------------- #

def _bytesformat(value: Any) -> str:
    """Marzban's ``readable_size`` filter; ``None``/undefined → ``∞``."""
    from jinja2 import Undefined

    if value is None or isinstance(value, Undefined):
        return "∞"
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "∞"
    if size <= 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    index = min(int(math.floor(math.log(size, 1024))), len(units) - 1)
    return f"{round(size / math.pow(1024, index), 2)} {units[index]}"


def _datetimeformat(value: Any) -> str:
    """Marzban's ``datetime`` filter; unix timestamps and datetimes alike."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return ""


def _to_yaml(obj: Any) -> str:
    if not obj:
        return ""
    import yaml

    return yaml.dump(obj, allow_unicode=True, indent=2)


def _exclude_keys(obj: Any, *target_keys: str) -> dict:
    return {key: val for key, val in dict(obj).items() if key not in target_keys}


def _only_keys(obj: Any, *target_keys: str) -> dict:
    return {key: val for key, val in dict(obj).items() if key in target_keys}


def _utcnow() -> datetime:
    # Marzban registers ``datetime.utcnow`` (naive UTC); same value, no
    # deprecation warning on Python 3.12.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def build_environment(loader: Any | None = None):
    """The environment operator templates render in.

    Autoescape is OFF on purpose: Marzban renders its subscription page
    without it and its templates place share links inside ``<script>``
    blocks, where HTML entities are not decoded — escaping would corrupt
    every ``&`` in a link. Everything the context exposes is panel- or
    admin-controlled (usernames are regex-constrained, links are
    URL-quoted); the one subscriber-influenced value (the last client
    User-Agent) is escaped by the context itself (see
    :class:`app.portal.render.TemplateUser`).
    """
    from jinja2 import ChainableUndefined, Environment

    env = Environment(loader=loader, autoescape=False,
                      undefined=ChainableUndefined)
    env.filters.update({
        "bytesformat": _bytesformat,
        "datetime": _datetimeformat,
        "yaml": _to_yaml,
        "except": _exclude_keys,
        "only": _only_keys,
    })
    env.globals["now"] = _utcnow
    return env


def _environment_for(data_dir: str):
    from jinja2 import FileSystemLoader

    return build_environment(FileSystemLoader(str(directory(data_dir))))


def _template_line(exc: BaseException) -> int | None:
    """Line inside the template where a render error happened (Jinja rewrites
    tracebacks so template frames carry the template's line numbers)."""
    line = None
    tb = exc.__traceback__
    while tb is not None:
        filename = tb.tb_frame.f_code.co_filename
        if filename == "<template>" or filename.lower().endswith(_EXTENSIONS):
            line = tb.tb_lineno
        tb = tb.tb_next
    return line


def _describe(exc: BaseException) -> tuple[str, int | None]:
    from jinja2 import TemplateSyntaxError, UndefinedError

    if isinstance(exc, TemplateSyntaxError):
        return f"syntax error: {exc.message}", exc.lineno
    line = _template_line(exc)
    if isinstance(exc, UndefinedError):
        return f"{exc} — check the variable names against the documentation", line
    return f"{exc.__class__.__name__}: {exc}", line


def _with_line(message: str, line: int | None) -> str:
    return f"line {line}: {message}" if line else message


def validate_source(source: str, context: dict[str, Any] | None = None,
                    *, data_dir: str | None = None) -> None:
    """Reject a template that cannot render.

    Syntax is always checked; when ``context`` is given the template is
    rendered against it too, so unknown filters, wrong attribute names and
    the like surface now — with a line number — rather than as a silent
    fallback to the built-in page.
    """
    from jinja2 import TemplateSyntaxError

    env = _environment_for(data_dir) if data_dir else build_environment()
    try:
        template = env.from_string(source)
    except TemplateSyntaxError as exc:
        message, line = _describe(exc)
        raise TemplateError(_with_line(message, line)) from exc
    if context is None:
        return
    try:
        template.render(**context)
    except Exception as exc:  # noqa: BLE001 — every failure becomes a message
        message, line = _describe(exc)
        raise TemplateError(_with_line(f"render failed — {message}", line)) from exc


# --------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------- #

def list_templates(data_dir: str) -> list[dict[str, Any]]:
    d = directory(data_dir)
    if not d.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(d.iterdir()):
        if path.is_file() and path.name.lower().endswith(_EXTENSIONS):
            stat = path.stat()
            out.append({"name": path.name, "size": int(stat.st_size),
                        "modified_at": int(stat.st_mtime)})
    return out


def save_template(data_dir: str, filename: str, content: bytes,
                  *, context: dict[str, Any] | None = None) -> str:
    """Validate and store an uploaded template; returns the stored name.

    ``context`` (a sample render context) turns the upload into a test
    render: a template that cannot render is rejected, never stored.
    """
    name = safe_name(filename)
    if not content.strip():
        raise TemplateError("template file is empty")
    if len(content) > MAX_BYTES:
        raise TemplateError(f"template is larger than {MAX_BYTES // 1024} KB")
    try:
        source = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise TemplateError("template must be UTF-8 encoded text") from exc
    d = directory(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    validate_source(source, context, data_dir=data_dir)
    (d / name).write_text(source, encoding="utf-8")
    _forget_failure(name)  # a fixed upload retires the stale diagnosis
    return name


def delete_template(data_dir: str, name: str) -> bool:
    path = directory(data_dir) / safe_name(name)
    if not path.is_file():
        return False
    path.unlink()
    return True


def template_exists(data_dir: str, name: str) -> bool:
    try:
        return (directory(data_dir) / safe_name(name)).is_file()
    except TemplateError:
        return False


def read_template(data_dir: str, name: str) -> str | None:
    try:
        safe = safe_name(name)
    except TemplateError:
        return None
    path = directory(data_dir) / safe
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------- #

# The most recent serve-time failure (single-process runtime). The
# dashboard shows it next to the template picker, so "why am I seeing the
# built-in page?" is answered on the page that caused it.
_LAST_FAILURE: dict[str, Any] | None = None


def last_failure() -> dict[str, Any] | None:
    return dict(_LAST_FAILURE) if _LAST_FAILURE else None


def _remember_failure(name: str, message: str, line: int | None) -> None:
    global _LAST_FAILURE
    _LAST_FAILURE = {"template": name, "error": message, "line": line,
                     "at": int(time.time())}


def _forget_failure(name: str) -> None:
    global _LAST_FAILURE
    if _LAST_FAILURE and _LAST_FAILURE.get("template") == name:
        _LAST_FAILURE = None


def render_template(data_dir: str, name: str, context: dict[str, Any],
                    *, strict: bool = False) -> str | None:
    """Render an uploaded template.

    Default (serve path): ``None`` when it cannot be rendered — a signal,
    not a failure: the caller serves the built-in page so a subscriber is
    never shown a stack trace. ``strict=True`` (preview / validation path):
    raise :class:`TemplateError` with the reason instead.
    """
    try:
        safe = safe_name(name)
    except TemplateError:
        if strict:
            raise
        return None
    if not template_exists(data_dir, safe):
        if strict:
            raise TemplateError(f"template '{safe}' is not on the server")
        _remember_failure(safe, "template file is missing on the server", None)
        return None
    try:
        rendered = _environment_for(data_dir).get_template(safe).render(**context)
    except Exception as exc:  # noqa: BLE001 — presentation must not raise
        message, line = _describe(exc)
        if strict:
            raise TemplateError(_with_line(message, line)) from exc
        _remember_failure(safe, message, line)
        logger.warning("subscription template %r failed to render (%s) — "
                       "falling back to the built-in page", safe,
                       _with_line(message, line))
        return None
    _forget_failure(safe)
    return rendered
