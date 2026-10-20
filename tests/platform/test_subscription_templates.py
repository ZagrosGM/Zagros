"""Operator-authored subscription page templates (1.0.0 contract).

Marzban needed an env var plus shell access to point the panel at a custom
template. Here the operator uploads an HTML page in the Subscriptions
section and it becomes the active page at once — so the things that must
hold are:

  * an upload can only ever land inside the managed directory, under a
    sanitised name (no traversal, no non-HTML payload);
  * an upload that cannot render is REJECTED with the line number — it is
    never stored, so "uploaded but the built-in page shows" cannot happen
    for a syntax error;
  * templates render the way Marzban renders its subscription page: no
    auto-escaping, Marzban's filters/globals, and the Marzban ``user``
    names — a template written for Marzban works unchanged;
  * a template that still fails at SERVE time never breaks a subscriber's
    page — the built-in page is served and the failure is remembered so
    the dashboard can show why;
  * the application-login page is never replaced by a template.

Run: pytest tests/platform/test_subscription_templates.py -q
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.portal import templates_store  # noqa: E402
from app.portal.models import (  # noqa: E402
    PageKind,
    PortalPage,
    PortalSettings,
    PortalUserView,
)
from app.portal.render import (  # noqa: E402
    render_page_html,
    sample_context,
    sample_page,
    template_context,
)


def _page(**user_overrides) -> PortalPage:
    user = dict(user_id=1, username="alice", used_bytes=2048)
    user.update(user_overrides)
    return PortalPage(kind=PageKind.PORTAL, brand="Zagros",
                      user=PortalUserView(**user),
                      subscription_url="https://panel.example.com/sub/TOKEN")


# ----------------------------------------------------------------- storage --

def test_upload_accepts_html_and_rejects_everything_else(tmp_path):
    assert templates_store.save_template(
        str(tmp_path), "my-page.html", b"<h1>hi</h1>") == "my-page.html"

    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "page.php", b"<?php ?>")
    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "", b"<h1>hi</h1>")
    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "empty.html", b"   ")
    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "binary.html", b"\xff\xfe\x00\x01")


def test_a_traversal_name_can_never_escape_the_directory(tmp_path):
    data_dir = str(tmp_path)
    stored = templates_store.save_template(
        data_dir, "../../etc/passwd.html", b"<h1>hi</h1>")
    assert stored == "passwd.html"
    assert (tmp_path / "etc" / "passwd.html").exists() is False
    assert (templates_store.directory(data_dir) / "passwd.html").is_file()

    with pytest.raises(ValueError):
        PortalSettings(subscription_template="../../etc/passwd.html").normalize()


def test_list_and_delete_round_trip(tmp_path):
    data_dir = str(tmp_path)
    assert templates_store.list_templates(data_dir) == []

    templates_store.save_template(data_dir, "a.html", b"<p>a</p>")
    templates_store.save_template(data_dir, "b.html", b"<p>b</p>")
    listed = templates_store.list_templates(data_dir)
    assert [item["name"] for item in listed] == ["a.html", "b.html"]
    assert listed[0]["size"] == len(b"<p>a</p>")

    assert templates_store.template_exists(data_dir, "a.html") is True
    assert templates_store.delete_template(data_dir, "a.html") is True
    assert templates_store.template_exists(data_dir, "a.html") is False
    assert [item["name"] for item in
            templates_store.list_templates(data_dir)] == ["b.html"]
    assert templates_store.delete_template(data_dir, "a.html") is False


def test_bom_is_stripped_on_upload(tmp_path):
    name = templates_store.save_template(
        str(tmp_path), "bom.html", "\ufeff<p>{{ user.username }}</p>".encode("utf-8"))
    out = templates_store.render_template(str(tmp_path), name, template_context(_page()))
    assert out == "<p>alice</p>"


# ------------------------------------------------------- upload validation --

def test_upload_rejects_a_broken_template_with_the_line_number(tmp_path):
    """The operator learns about the typo at upload time, with the line —
    not by seeing the built-in page and grepping the logs."""
    ctx = sample_context()
    with pytest.raises(templates_store.TemplateError) as info:
        templates_store.save_template(
            str(tmp_path), "broken.html",
            b"<html>\n<body>\n{% if user.online %}\nhi\n</body></html>", context=ctx)
    assert str(info.value).startswith("line 3:")
    assert templates_store.list_templates(str(tmp_path)) == []  # nothing stored

    with pytest.raises(templates_store.TemplateError) as info:
        templates_store.save_template(
            str(tmp_path), "filter.html", b"{{ user.username | nosuchfilter }}", context=ctx)
    assert "nosuchfilter" in str(info.value)

    # a runtime failure during the test render is rejected too
    with pytest.raises(templates_store.TemplateError) as info:
        templates_store.save_template(
            str(tmp_path), "runtime.html", b"a\nb\n{{ user.data_limit / 0 }}", context=ctx)
    assert "line 3" in str(info.value) and "ZeroDivisionError" in str(info.value)


def test_syntax_is_checked_even_without_a_sample_context(tmp_path):
    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "broken.html", b"{% for %}")


# ------------------------------------------------------------- rendering --

def test_selected_template_renders_the_subscription_page(tmp_path):
    templates_store.save_template(
        str(tmp_path), "custom.html",
        b"<html><body>{{ user.username }}:{{ format_bytes(used_bytes) }}</body></html>")
    out = render_page_html(_page(), "custom.html", templates_dir=str(tmp_path))
    assert out == "<html><body>alice:2.00 KB</body></html>"


def test_marzban_template_vocabulary_works_unchanged(tmp_path):
    """The names, filters and globals a Marzban template uses."""
    templates_store.save_template(str(tmp_path), "mz.html", (
        b"{{ user.status.value }}|{{ user.used_traffic | bytesformat }}|"
        b"{% if not user.data_limit %}inf{% else %}{{ user.data_limit | bytesformat }}{% endif %}|"
        b"{% if not user.expire %}noexp{% else %}{{ user.expire | datetime }}{% endif %}|"
        b"{{ user.data_limit_reset_strategy.value }}|{{ user.subscription_url }}|"
        b"{{ user.links | length }}|{{ now().year >= 2026 }}|{{ user.status == 'active' }}|"
        b"{{ user.lifetime_used_traffic }}|{{ user.note }}"))
    expire = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    page = sample_page(subscription_url="https://p.example/sub/T")
    page.user.expire_at = expire
    page.user.data_limit_bytes = 10 * 1024 ** 3
    page.user.used_bytes = 1024 ** 3
    page.user.note = "vip"
    out = render_page_html(page, "mz.html", templates_dir=str(tmp_path))
    parts = out.split("|")
    assert parts[0] == "active"
    assert parts[1] == "1.0 GB"
    assert parts[2] == "10.0 GB"
    assert parts[3].startswith("2030-01-02")
    assert parts[4] == "month"
    assert parts[5] == "https://p.example/sub/T"
    assert int(parts[6]) >= 3            # the sample page carries share links
    assert parts[7] == "True"
    assert parts[8] == "True"
    assert parts[9] == str(19 * 1024 ** 3)
    assert parts[10] == "vip"


def test_links_are_not_html_escaped(tmp_path):
    """Marzban parity: templates place share links inside <script> strings,
    where entities are not decoded — escaping ``&`` would corrupt every link."""
    templates_store.save_template(str(tmp_path), "x.html",
                                  b'<script>const s = "{{ user.links }}"</script>')
    out = render_page_html(sample_page(), "x.html", templates_dir=str(tmp_path))
    assert "&amp;" not in out
    assert "security=reality&encryption=none" in out


def test_the_one_subscriber_controlled_value_is_escaped(tmp_path):
    """No auto-escaping, so the single value a subscriber can influence
    (their client's User-Agent) is escaped by the context itself."""
    templates_store.save_template(str(tmp_path), "ua.html", b"{{ user.sub_last_user_agent }}")
    page = _page(sub_last_user_agent="</script><script>alert(1)</script>")
    out = render_page_html(page, "ua.html", templates_dir=str(tmp_path))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_unknown_attributes_read_as_empty_not_as_errors(tmp_path):
    templates_store.save_template(
        str(tmp_path), "u.html",
        b"[{{ user.nothing.here }}][{{ page.foo.bar }}][{{ user.expire | datetime }}]"
        b"[{{ user.nothing | bytesformat }}][{% if user.nothing %}Y{% else %}N{% endif %}]")
    out = render_page_html(_page(), "u.html", templates_dir=str(tmp_path))
    assert out == "[][][][\u221e][N]"


def test_missing_or_broken_template_serves_the_built_in_page(tmp_path):
    """A subscriber must never be the one who pays for an operator's typo —
    and the dashboard learns WHY through last_failure()."""
    builtin = render_page_html(_page())
    data_dir = str(tmp_path)

    # 1. configured but never uploaded
    assert render_page_html(_page(), "gone.html", templates_dir=data_dir) == builtin
    failure = templates_store.last_failure()
    assert failure and failure["template"] == "gone.html" and "missing" in failure["error"]

    # 2. broke AFTER upload (edited on disk): syntax
    d = templates_store.directory(data_dir); d.mkdir(parents=True, exist_ok=True)
    (d / "broken.html").write_text("ok\n{% for %}", encoding="utf-8")
    assert render_page_html(_page(), "broken.html", templates_dir=data_dir) == builtin
    failure = templates_store.last_failure()
    assert failure["template"] == "broken.html" and failure["line"] == 2

    # 3. raises while rendering
    (d / "boom.html").write_text("{{ user.this_attribute_does_not_exist() }}", encoding="utf-8")
    assert render_page_html(_page(), "boom.html", templates_dir=data_dir) == builtin
    assert templates_store.last_failure()["template"] == "boom.html"

    # 4. a working render clears the diagnosis for that template
    (d / "boom.html").write_text("fine {{ user.username }}", encoding="utf-8")
    assert render_page_html(_page(), "boom.html", templates_dir=data_dir) == "fine alice"
    assert templates_store.last_failure() is None


def test_strict_render_raises_with_the_reason(tmp_path):
    """The preview endpoint must show the reason, never fall back silently."""
    d = templates_store.directory(str(tmp_path)); d.mkdir(parents=True)
    (d / "b.html").write_text("a\nb\n{{ user.data_limit / 0 }}", encoding="utf-8")
    with pytest.raises(templates_store.TemplateError) as info:
        templates_store.render_template(str(tmp_path), "b.html",
                                        template_context(_page(data_limit_bytes=5)), strict=True)
    assert str(info.value).startswith("line 3:")
    with pytest.raises(templates_store.TemplateError):
        templates_store.render_template(str(tmp_path), "absent.html", {}, strict=True)


def test_application_login_page_ignores_the_template(tmp_path):
    """Mode 2 quarantine: not a single byte of configuration material may
    leave the panel, and an operator template cannot be audited for that."""
    templates_store.save_template(str(tmp_path), "t.html", b"LEAK {{ user.links }}")
    page = sample_page()
    page.kind = PageKind.APP_DOWNLOAD
    out = render_page_html(page, "t.html", templates_dir=str(tmp_path))
    assert "LEAK" not in out and "vless://" not in out


def test_starter_template_is_renderable(tmp_path):
    """The file the UI hands out must actually work when uploaded back —
    validated against the same sample context the upload endpoint uses."""
    ctx = sample_context(brand="Acme", subscription_url="https://acme.example/sub/T")
    templates_store.save_template(str(tmp_path), "starter.html",
                                  templates_store.STARTER_TEMPLATE.encode("utf-8"),
                                  context=ctx)
    out = templates_store.render_template(str(tmp_path), "starter.html", ctx)
    assert out is not None
    assert "sample_user" in out and "https://acme.example/sub/T" in out and "Acme" in out


def test_sample_page_covers_every_artifact_kind():
    from app.cores.delivery import ArtifactKind

    kinds = {a.kind for s in sample_page().sections for a in s.artifacts}
    assert kinds == set(ArtifactKind)


# ------------------------------------------- multi-protocol template helpers --

def _render(source: str, ctx: dict) -> str:
    return templates_store.build_environment().from_string(source).render(**ctx)


def test_every_protocol_is_reachable_through_sections():
    """A template must be able to show what EVERY core delivers — not just
    the xray/sing-box share links: OpenVPN and WireGuard files, SSH-style
    credential tables and notes are all in ``sections`` with string kinds
    a template can compare against."""
    ctx = template_context(sample_page())
    out = _render(
        "{% for s in sections %}{{ s.protocol }}:"
        "{% for a in s.artifacts %}{{ a.kind }}{% if not loop.last %}+{% endif %}{% endfor %} "
        "{% endfor %}", ctx)
    assert "wireguard:file" in out and "ovpn:file" in out      # the OpenVPN driver's real protocol id
    assert "ssh:fields+note" in out and "vless:link+link" in out
    # kind compares as a plain string, the way the docs tell operators to
    assert _render("{% for s in sections %}{% for a in s.artifacts %}"
                   "{% if a.kind == 'file' %}{{ a.filename }} {% endif %}"
                   "{% endfor %}{% endfor %}", ctx) == "sample_user.conf sample_user.ovpn "


def test_files_view_carries_a_ready_download_href():
    ctx = template_context(sample_page())
    files = {f["protocol"]: f for f in ctx["files"]}
    assert set(files) == {"wireguard", "ovpn"}
    wg = files["wireguard"]
    assert wg["filename"] == "sample_user.conf" and wg["content"].startswith("[Interface]")
    assert wg["href"].startswith("data:text/plain;base64,")
    assert files["ovpn"]["href"].startswith("data:application/x-openvpn-profile;base64,")
    # a template can build the same href itself from any artifact
    out = _render("{{ data_uri(files[0].content, files[0].mime) }}", ctx)
    assert out == wg["href"]


def test_qr_svg_is_inline_and_never_raises():
    ctx = template_context(sample_page(subscription_url="https://p.example/sub/T"))
    svg = _render("{{ qr_svg(subscription_url) }}", ctx)
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "<img" not in svg and "chart.googleapis" not in svg     # inline, no external service
    # empty / missing / far too long → empty string, not an exception
    assert _render("[{{ qr_svg('') }}][{{ qr_svg(none) }}][{{ qr_svg(nothing) }}]", ctx) == "[][][]"
    assert _render("{{ qr_svg('x' * 5000) }}", ctx) == ""
    # module size and border are tunable
    small = _render("{{ qr_svg(subscription_url, size=2, border=0) }}", ctx)
    assert len(small) < len(svg) and 'width="' in small


def test_days_left_accepts_datetimes_and_unix_times():
    from datetime import timedelta

    soon = datetime.now(timezone.utc) + timedelta(days=10, hours=1)
    ctx = template_context(_page(expire_at=soon))
    assert _render("{{ days_left(expire_at) }}", ctx) == "10"
    assert _render("{{ days_left(user.expire) }}", ctx) == "10"     # Marzban epoch
    assert _render("{{ days_left(none) }}|{{ days_left('junk') }}", ctx) == "None|None"
    gone = datetime.now(timezone.utc) - timedelta(days=3, hours=1)
    assert int(_render("{{ days_left(expire_at) }}", template_context(_page(expire_at=gone)))) < 0
    assert _render("{{ days_left(expire_at) }}", template_context(_page())) == "None"


def test_import_links_and_formats_derive_from_the_page_url():
    ctx = template_context(_page())
    fmts = ctx["subscription_formats"]
    assert fmts == {
        "links": "https://panel.example.com/sub/TOKEN",
        "clash": "https://panel.example.com/sub/TOKEN?format=clash-meta",
        "sing_box": "https://panel.example.com/sub/TOKEN?format=sing-box",
    }
    links = ctx["import_links"]
    assert links["v2rayng"] == "v2rayng://install-config?url=https%3A%2F%2Fpanel.example.com%2Fsub%2FTOKEN"
    assert links["hiddify"] == "hiddify://import/https://panel.example.com/sub/TOKEN"
    assert links["shadowrocket"].startswith("sub://")
    # clash-family and sing-box clients get their own ?format= profile
    assert "clash-meta" in links["clash"] and "clash-meta" in links["stash"]
    assert "format%3Dsing-box" in links["sing-box"]
    # no URL (page fetched some other way) → nothing to import, no crash
    bare = PortalPage(kind=PageKind.PORTAL, user=PortalUserView(user_id=1, username="bob"))
    bare_ctx = template_context(bare)
    assert bare_ctx["import_links"] == {} and bare_ctx["subscription_formats"]["clash"] == ""
    assert _render("{% for k, v in import_links.items() %}{{ k }}{% endfor %}-", bare_ctx) == "-"


def test_starter_template_shows_every_protocol_with_downloads_and_qr():
    """The starter is the multi-protocol reference: links with QR, files
    with a download button, credential tables with masked secrets, notes,
    and one-tap import buttons — in both page languages."""
    for lang in ("fa", "en"):
        ctx = template_context(sample_page(lang=lang, subscription_url="https://p.example/sub/T"))
        out = _render(templates_store.STARTER_TEMPLATE, ctx)
        assert 'download="sample_user.conf"' in out and 'download="sample_user.ovpn"' in out
        assert 'href="data:application/x-openvpn-profile;base64,' in out
        assert out.count("<svg") >= 4                       # sub URL + 3 links
        assert "v2rayng://install-config" in out and "hiddify://import/" in out
        assert 'data-secret="s4mpl3-p4ss"' in out and "s4mpl3-p4ss</span>" not in out
        assert "UDP is not tunnelled over SSH" in out
        assert "built-in method" not in out                 # dict.copy() leak guard


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
