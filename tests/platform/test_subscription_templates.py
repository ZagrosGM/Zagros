"""Operator-authored subscription page templates (alpha.9.2 item 3).

Marzban needed an env var plus shell access to point the panel at a custom
template. Here the operator uploads an HTML page and picks it in the
Subscriptions section — so the two things that must hold are:

  * an upload can only ever land inside the managed directory, under a
    sanitised name (no traversal, no non-HTML payload);
  * a template that is missing or broken NEVER breaks a subscriber's page —
    the built-in page is served instead.

Run: pytest tests/platform/test_subscription_templates.py -q
"""
from __future__ import annotations

import sys
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


def _page() -> PortalPage:
    return PortalPage(kind=PageKind.PORTAL, brand="Zagros",
                      user=PortalUserView(user_id=1, username="alice",
                                          used_bytes=2048))


def test_upload_accepts_html_and_rejects_everything_else(tmp_path):
    assert templates_store.save_template(
        str(tmp_path), "my-page.html", b"<h1>hi</h1>") == "my-page.html"

    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "page.php", b"<?php ?>")
    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "", b"<h1>hi</h1>")
    with pytest.raises(templates_store.TemplateError):
        templates_store.save_template(str(tmp_path), "empty.html", b"   ")


def test_a_traversal_name_can_never_escape_the_directory(tmp_path):
    """The name is sanitised, not trusted: ../../etc/passwd.html becomes a
    flat file inside the managed directory (and .html is required anyway)."""
    data_dir = str(tmp_path)
    stored = templates_store.save_template(
        data_dir, "../../etc/passwd.html", b"<h1>hi</h1>")
    assert stored == "passwd.html"
    assert (tmp_path / "etc" / "passwd.html").exists() is False
    assert (templates_store.directory(data_dir) / "passwd.html").is_file()

    # a settings value is validated too, so a path can never be selected
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

    assert templates_store.delete_template(data_dir, "a.html") is True
    assert [item["name"] for item in
            templates_store.list_templates(data_dir)] == ["b.html"]
    assert templates_store.delete_template(data_dir, "a.html") is False


def test_selected_template_renders_the_subscription_page(tmp_path):
    from app.portal.render import render_page_html

    templates_store.save_template(
        str(tmp_path), "custom.html",
        b"<html><body>{{ user.username }}:{{ format_bytes(used_bytes) }}</body></html>")
    out = render_page_html(_page(), "custom.html", templates_dir=str(tmp_path))
    # exactly the operator's document: their markup, their variables, and
    # none of the built-in page wrapped around it
    assert out == "<html><body>alice:2.00 KB</body></html>"


def test_missing_or_broken_template_serves_the_built_in_page(tmp_path):
    """A subscriber must never be the one who pays for an operator's typo."""
    from app.portal.render import render_page_html

    builtin = render_page_html(_page())

    # 1. configured but never uploaded
    assert render_page_html(_page(), "gone.html",
                            templates_dir=str(tmp_path)) == builtin
    # 2. uploaded but syntactically broken
    templates_store.save_template(str(tmp_path), "broken.html",
                                  b"{% for %}")
    assert render_page_html(_page(), "broken.html",
                            templates_dir=str(tmp_path)) == builtin
    # 3. uploaded but it raises while rendering
    templates_store.save_template(
        str(tmp_path), "boom.html",
        b"{{ user.this_attribute_does_not_exist() }}")
    assert render_page_html(_page(), "boom.html",
                            templates_dir=str(tmp_path)) == builtin


def test_template_values_are_escaped(tmp_path):
    """Autoescape is ON: user-controlled text cannot inject markup."""
    from app.portal.render import render_page_html

    templates_store.save_template(str(tmp_path), "x.html", b"{{ user.username }}")
    page = _page()
    page.user.username = "<script>alert(1)</script>"
    out = render_page_html(page, "x.html", templates_dir=str(tmp_path))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_starter_template_is_renderable(tmp_path):
    """The file the UI hands out must actually work when uploaded back."""
    templates_store.save_template(str(tmp_path), "starter.html",
                                  templates_store.STARTER_TEMPLATE.encode("utf-8"))
    out = templates_store.render_template(str(tmp_path), "starter.html",
                                          {"user": _page().user, "links": [],
                                           "used_bytes": 1024,
                                           "data_limit_bytes": None,
                                           "remaining_bytes": None,
                                           "expire_at": None, "online": False,
                                           "brand": "Zagros",
                                           "generated_at": "now",
                                           "format_bytes": lambda n: f"{n} B",
                                           "format_date": lambda v: "-"})
    assert out is not None
    assert "alice" in out


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
