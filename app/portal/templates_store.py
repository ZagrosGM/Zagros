"""Admin-managed subscription page templates (alpha.9.2 item 3).

Marzban let an operator point the panel at a custom template directory —
but only through an environment variable plus shell access to the server.
Here the operator authors an HTML page, uploads it from the panel's
Subscriptions section, and selects it there: no shell, no restart, no
redeploy.

Contract:

* a flat directory under the data dir, sanitized names, ``.html``/.htm``
  only — an upload can never escape it or shadow a system file;
* templates are Jinja2 and render with autoescape ON, because user data
  (usernames, notes, link labels) flows through them;
* a missing, unreadable or broken template NEVER breaks a subscriber's
  page: the built-in page is served instead and the failure is logged.
  Presentation is the one place where failing open is the safe direction.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SUBDIR = "subscription-templates"
MAX_BYTES = 256 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EXTENSIONS = (".html", ".htm")

STARTER_TEMPLATE = """{# Zagros subscription page — starter template.

   Edit freely, upload it in Subscriptions → "subscription page template",
   then select it. Save this file first: `download starter` hands you
   exactly this text.

   Available variables (all escaped unless you use |safe):
     user.username, user.status, user.online
     used_bytes / data_limit_bytes / remaining_bytes   (ints or None)
     expire_at                                         (datetime or None)
     sections        — [{protocol, title, engine, artifacts[], note}]
     links           — flat [{protocol, title, label, url}]
     apps, notes, brand, app_name, support_url, generated_at
     format_bytes(value), format_date(value)           helpers
   A broken template never breaks the page: Zagros serves the built-in
   one instead and logs why.
#}
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ brand }} · {{ user.username }}</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; padding: 24px; font: 15px/1.7 system-ui, sans-serif;
         background: #f6f7f9; color: #16181d; }
  .card { max-width: 720px; margin: 0 auto; background: #fff; border-radius: 16px;
          padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .muted { color: #6b7280; font-size: 13px; }
  .row { display: flex; justify-content: space-between; gap: 12px;
         padding: 10px 0; border-bottom: 1px solid #eef0f3; }
  .row:last-child { border-bottom: 0; }
  a.sub { display: block; direction: ltr; text-align: left; margin: 8px 0;
          padding: 10px 12px; background: #f3f4f6; border-radius: 10px;
          color: #111827; text-decoration: none; font-size: 13px;
          word-break: break-all; }
  footer { max-width: 720px; margin: 16px auto; text-align: center;
           font-size: 12px; color: #9ca3af; }
</style>
</head>
<body>
<div class="card">
  <h1>{{ brand }}</h1>
  <p class="muted">{{ user.username }} · {% if user.online %}آنلاین{% else %}آفلاین{% endif %}</p>

  <div class="row"><span>مصرف</span><b>{{ format_bytes(used_bytes) }}{% if data_limit_bytes %} از {{ format_bytes(data_limit_bytes) }}{% endif %}</b></div>
  <div class="row"><span>باقی‌مانده</span><b>{% if remaining_bytes is not none %}{{ format_bytes(remaining_bytes) }}{% else %}نامحدود{% endif %}</b></div>
  <div class="row"><span>انقضا</span><b>{% if expire_at %}{{ format_date(expire_at) }}{% else %}ندارد{% endif %}</b></div>

  {% for link in links %}
    <a class="sub" href="{{ link.url }}">{{ link.label }}</a>
  {% endfor %}

  {% if support_url %}<p class="muted"><a href="{{ support_url }}">پشتیبانی</a></p>{% endif %}
</div>
<footer>{{ brand }} · {{ generated_at }}</footer>
</body>
</html>
"""


class TemplateError(Exception):
    """Rejected upload — safe to show the message to an operator."""


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


def save_template(data_dir: str, filename: str, content: bytes) -> str:
    """Store an uploaded template; returns the stored (sanitized) name."""
    name = safe_name(filename)
    if not content.strip():
        raise TemplateError("template file is empty")
    if len(content) > MAX_BYTES:
        raise TemplateError(f"template is larger than {MAX_BYTES // 1024} KB")
    d = directory(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(content)
    return name


def delete_template(data_dir: str, name: str) -> bool:
    path = directory(data_dir) / safe_name(name)
    if not path.is_file():
        return False
    path.unlink()
    return True


def read_template(data_dir: str, name: str) -> str | None:
    try:
        safe = safe_name(name)
    except TemplateError:
        return None
    path = directory(data_dir) / safe
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def render_template(data_dir: str, name: str, context: dict[str, Any]) -> str | None:
    """Render an uploaded template, or ``None`` when it cannot be rendered.

    ``None`` is a signal, not a failure: the caller serves the built-in
    page so a subscriber is never shown a stack trace.
    """
    try:
        safe = safe_name(name)
    except TemplateError:
        return None
    if read_template(data_dir, safe) is None:
        return None
    try:
        from jinja2 import Environment, FileSystemLoader

        env = Environment(autoescape=True,
                          loader=FileSystemLoader(str(directory(data_dir))))
        return env.get_template(safe).render(**context)
    except Exception as exc:  # noqa: BLE001 — presentation must not raise
        logger.warning("subscription template %r failed to render (%s) — "
                       "falling back to the built-in page", safe, exc)
        return None
