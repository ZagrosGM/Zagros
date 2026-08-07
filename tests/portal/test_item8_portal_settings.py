"""Regression tests for α7.1 item 8:
Subscription Settings → Access Mode = Application → Save must not 422.

Root cause (alpha.7): the dashboard posted ``client_auth_mode: "app_login"``
plus ``app_name`` / ``subscription_path`` / ``subscription_url_prefix`` to
PUT /zagros/settings/portal.  The backend enum only knew
``application_login`` and the schema owned none of the identity fields, so
the save died 422 (and the identity fields could never persist).

The fix is at the schema root: alias-tolerant enum coercion, first-class
fields with real validation (PathValidator → 422 not 500), dynamic serving
on the configured segment with the canonical /sub/ alias kept forever.
"""
from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from app.portal.models import ClientAuthMode, PortalSettings
from app.portal.settings_store import InMemorySettingsStore


# --------------------------------------------------------------------- #
# enum contract
# --------------------------------------------------------------------- #

def test_app_login_alias_coerces_to_application_login():
    s = PortalSettings.model_validate({"client_auth_mode": "app_login"})
    assert s.client_auth_mode is ClientAuthMode.APPLICATION_LOGIN


def test_canonical_values_still_accepted():
    for raw in ("subscription_link", "application_login"):
        s = PortalSettings.model_validate({"client_auth_mode": raw})
        assert s.client_auth_mode.value == raw


def test_garbage_auth_mode_still_rejected():
    with pytest.raises(ValidationError):
        PortalSettings.model_validate({"client_auth_mode": "let-me-in"})


# --------------------------------------------------------------------- #
# new identity fields: validate + normalize
# --------------------------------------------------------------------- #

def test_normalize_strips_path_slashes_and_prefix_slash():
    s = PortalSettings(subscription_path="/my-sub/",
                       subscription_url_prefix="https://cdn.example.com/").normalize()
    assert s.subscription_path == "my-sub"
    assert s.subscription_url_prefix == "https://cdn.example.com"


def test_blank_prefix_becomes_none_and_blank_app_name_defaults():
    s = PortalSettings(subscription_url_prefix="", app_name="   ").normalize()
    assert s.subscription_url_prefix is None
    assert s.app_name == "Zagros"


def test_invalid_subscription_paths_rejected_at_normalize():
    for bad in ("sub/../x", "UPPER", "with space"):
        with pytest.raises(ValueError):
            PortalSettings(subscription_path=bad).normalize()


def test_blank_path_falls_back_to_default_segment():
    for blank in ("", "/", "  "):
        # a cleared field means "use the default", never an error
        assert PortalSettings(subscription_path=blank).normalize().subscription_path == "sub"


def test_valid_subscription_paths_accepted():
    for ok in ("sub", "vpn", "sub.v2", "s-1_x", "a" * 32):
        assert PortalSettings(subscription_path=ok).normalize().subscription_path == ok


# --------------------------------------------------------------------- #
# store round-trip (what the UI does: GET → edit → PUT)
# --------------------------------------------------------------------- #

def test_inmemory_store_round_trips_the_full_alpha7_form():
    store = InMemorySettingsStore()
    saved = asyncio.run(store.save_portal_settings(PortalSettings.model_validate({
        # EXACTLY what the alpha.7 dashboard posted when it got 422:
        "portal_title": "اشتراک من",
        "app_name": "Zagros VPN",
        "client_auth_mode": "app_login",
        "subscription_path": "vpn",
        "subscription_url_prefix": "https://panel.example.com/",
    })))
    got = asyncio.run(store.get_portal_settings())
    assert got.client_auth_mode is ClientAuthMode.APPLICATION_LOGIN
    assert got.app_name == "Zagros VPN"
    assert got.subscription_path == "vpn"
    assert got.subscription_url_prefix == "https://panel.example.com"
    assert saved.app_name == "Zagros VPN"


def test_old_persisted_json_without_new_fields_still_loads():
    # backward compatibility: alpha.7 rows lack the new keys entirely
    s = PortalSettings.model_validate({"brand": "Z", "portal_title": "t",
                                       "client_auth_mode": "subscription_link"})
    assert s.app_name == "Zagros" and s.subscription_path == "sub"
