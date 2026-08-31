# Subscription page templates

An operator can replace the page a subscriber sees when they open their
subscription link in a browser. This is the panel-side equivalent of Marzban's
custom template directory — but the upload and the selection both live in the
dashboard (*Subscriptions → subscription page template*), so no shell access
and no restart are involved.

Introduced in `1.0.0-alpha.9.2`. A Persian guide with ready-to-paste examples
lives next to this file as `subscription-templates.fa.md`.

## What the template does and does not affect

A subscription URL answers two very different callers:

| Caller | Gets | Template applies |
|---|---|---|
| VPN clients (v2rayNG, Streisand, sing-box, Nekoray…) | the link list, or a clash/sing-box document | no |
| A browser (`Accept: text/html` + a browser UA) | the subscription page | **yes** |
| A browser with `?format=clash` / `?format=sing-box` | the client document | no |

So a template changes presentation only. When the panel runs in
`application_login` mode no configuration material is emitted at all: `links`
is empty and `apps` carries the download links instead.

## Using it

1. **Download the starter** (the button in the same card) — a complete, working
   template with the variables documented in a comment.
2. Edit it anywhere.
3. **Upload** it: `.html` / `.htm` only, at most 256 KB. The name is sanitised
   (basename only, odd characters become `-`) and lands in one flat directory
   under the data dir (`<data_dir>/subscription-templates/`).
4. **Select** it and save. The setting stores a file *name*, never a path;
   the renderer resolves it inside that directory, so no value can escape it.
5. Verify with a browser-like request (see *Troubleshooting*).

Templates are Jinja2 and render with **autoescape on**, because usernames,
notes and link labels flow through them.

### The rule that matters

A template that is missing, unreadable, or throws while rendering never breaks
a subscriber's page: the built-in page is served instead and the reason is
logged. Presentation is the one place where failing open is the safe
direction.

## Variables

| Variable | Type | Notes |
|---|---|---|
| `brand`, `app_name` | str | panel branding |
| `support_url` | str \| null | set in portal settings |
| `notes` | list[str] | panel notes (e.g. a core limitation) |
| `generated_at` | datetime | when the page was built |
| `user` | object | see below |
| `used_bytes` | int | |
| `data_limit_bytes` | int \| null | `null` means unlimited |
| `remaining_bytes` | int \| null | `null` when unlimited |
| `expire_at` | datetime \| null | |
| `online` | bool | has a session right now |
| `sections` | list | per-protocol sections, see below |
| `links` | list | flat `{protocol, title, label, url}` for every LINK artifact |
| `apps` | list | `{platform, name, url, primary}` |
| `page` | object | the whole page (adds `lang`, `direction`, `kind`) |

`user` fields: `username`, `status` (`active` / `limited` / `expired` /
`disabled` / `on_hold`), `online`, `used_bytes`, `data_limit_bytes`,
`expire_at`, `remaining_bytes`, `user_id`, `client_auth_mode`.

Helpers:

* `format_bytes(value)` → `1.00 KB`; `∞` for `None`
* `format_date(value)` → `2026/08/30`; `—` for `None`

## Sections and artifacts

```
sections[] = { protocol, title, engine, note, inbound_tag, artifacts[] }
```

Each artifact has a `kind` (`str`, compared against `"link"`, `"file"`,
`"fields"`, `"note"`):

| kind | fields | meaning |
|---|---|---|
| `link` | `content` (the URL), `label` | subscription link to copy |
| `file` | `filename`, `content` (file text), `mime` | downloadable config file |
| `fields` | `fields[] = {key, label, value, secret, copyable}` | credential table |
| `note` | `note` | an explanation or honest limitation |

```jinja
{% for section in sections %}
  <h2>{{ section.title }} <small>{{ section.protocol }}</small></h2>
  {% if section.note %}<p class="muted">{{ section.note }}</p>{% endif %}
  {% for a in section.artifacts %}
    {% if a.kind == "link" %}
      <a href="{{ a.content }}">{{ a.label }}</a>
    {% elif a.kind == "file" %}
      <a download="{{ a.filename }}"
         href="data:{{ a.mime }};charset=utf-8,{{ a.content | urlencode }}">{{ a.filename }}</a>
    {% elif a.kind == "fields" %}
      <dl>{% for f in a.fields %}<dt>{{ f.label }}</dt><dd>{{ f.value }}</dd>{% endfor %}</dl>
    {% elif a.kind == "note" %}
      <p>{{ a.note }}</p>
    {% endif %}
  {% endfor %}
{% endfor %}
```

Files are offered as `data:` URIs so the page stays self-contained. External
assets (fonts, CSS, JS from a CDN) are deliberately unsupported: the page must
render for subscribers who can barely reach the panel itself.

## Quota display, done correctly

Guard the unlimited case — dividing by `None` yields a misleading
`3.00 MB of 0 B (0%)`:

```jinja
{% if data_limit_bytes %}
  {% set pct = (used_bytes / data_limit_bytes * 100) | round(1) %}
  <div class="bar"><span style="width: {{ [pct, 100] | min }}%"></span></div>
  <p>{{ format_bytes(used_bytes) }} of {{ format_bytes(data_limit_bytes) }} ({{ pct }}%)</p>
{% else %}
  <p>{{ format_bytes(used_bytes) }} — unlimited</p>
{% endif %}
```

## Troubleshooting

```bash
# 1. the user's subscription URL
curl -s -H "Authorization: Bearer $TOKEN" https://PANEL/api/user/USERNAME \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['subscription_url'])"

# 2. ask for it exactly like a browser
curl -s -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36" \
     -H "Accept: text/html,application/xhtml+xml" "https://PANEL/sub/TOKEN"
```

If you get the built-in page instead of yours, the template either is not on
the server (the dashboard warns next to the selector) or failed to render:

```bash
docker compose logs zagros | grep -i "subscription template"
```

## Current limitations

* **No QR helper.** The built-in page draws QR codes itself; templates receive
  the link text only (an external QR library would break the no-external-assets
  rule). Ask if you need it — it can be exposed as a variable.
* **One template for everyone.** Selection is panel-wide; branch inside the
  template (`{% if user.status == 'limited' %}`) for per-user differences.
* **No filesystem or network access** from a template — only the variables
  above.
