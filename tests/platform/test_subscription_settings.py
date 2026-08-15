"""Subscription public-origin/path/TLS settings regressions."""
from __future__ import annotations

import pytest

from app.portal.models import PortalSettings
from app.portal.service import PortalService
from app.portal.settings_store import InMemorySettingsStore


def test_public_domain_subdomain_port_and_force_https_normalize_one_origin() -> None:
    settings = PortalSettings(
        public_domain="example.com", custom_subdomain="sub",
        public_scheme="http", public_port=8443, force_https=True,
        subscription_path="clients", qr_base_url="https://edge.example.com/",
    ).normalize()
    assert settings.public_scheme == "https"
    assert settings.public_base_url() == "https://sub.example.com:8443"
    assert settings.subscription_url_prefix == "https://sub.example.com:8443"
    assert settings.qr_base_url == "https://edge.example.com"


def test_legacy_prefix_survives_when_structured_domain_is_absent() -> None:
    settings = PortalSettings(
        subscription_url_prefix="https://legacy.example/subroot/",
        subscription_path="sub",
    ).normalize()
    assert settings.public_base_url() == "https://legacy.example/subroot"
    assert settings.subscription_url_prefix == "https://legacy.example/subroot"


def test_delivery_context_uses_qr_override_then_subscription_origin() -> None:
    settings = PortalSettings(
        public_domain="example.com", custom_subdomain="sub",
        qr_base_url="https://edge.example.com",
    ).normalize()
    ctx = PortalService._delivery_context(settings, "request.example")
    assert ctx.public_host == "edge.example.com"
    settings = settings.model_copy(update={"qr_base_url": None})
    ctx = PortalService._delivery_context(settings, "request.example")
    assert ctx.public_host == "sub.example.com"


def test_url_generation_shape_covers_portal_clash_singbox_and_qr_origin() -> None:
    settings = PortalSettings(
        public_domain="example.com", custom_subdomain="sub",
        subscription_path="clients", public_scheme="https",
    ).normalize()
    subscription = settings.canonical_url()
    assert subscription == "https://sub.example.com/clients/<token>"
    assert (subscription + "?format=clash-meta").endswith("?format=clash-meta")
    assert (subscription + "?format=sing-box").endswith("?format=sing-box")
    ctx = PortalService._delivery_context(settings, None)
    assert ctx.public_host == "sub.example.com"


@pytest.mark.parametrize("field,value", [
    ("subscription_path", "bad/path"),
    ("subscription_path", "dashboard"),
    ("subscription_path", "statics"),
    ("public_domain", "https://bad.example"),
    ("qr_base_url", "ftp://bad.example"),
])
def test_invalid_public_link_settings_fail_closed(field, value) -> None:
    with pytest.raises(ValueError):
        PortalSettings(**{field: value}).normalize()
