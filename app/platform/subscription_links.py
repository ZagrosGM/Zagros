"""Public subscription link shape — ONE source of truth for every serializer.

The dashboard's Subscription page persists ``PortalSettings`` (public domain,
scheme, port, subscription path, listener mode) in the platform database.
``UserResponse.subscription_url`` — the field bots and scripts (Mirza and
friends) show to buyers — used to be built from ``config.py`` alone, i.e. from
``SUBSCRIPTION_URL_PREFIX`` / ``PANEL_BASE_URL``. Nothing bridged the saved
settings into it, so a panel whose subscriptions live on a dedicated
domain/port still handed out links on the panel address.

This module resolves the *effective* public base URL synchronously (the
legacy serializers are plain Pydantic validators) with a short TTL cache, so
a ``GET /api/users`` listing hundreds of users costs one settings read.

Resolution order:

1. ``portal.settings`` row in the platform database (what the dashboard
   saved) — when it yields a public base URL;
2. the environment (``SUBSCRIPTION_URL_PREFIX`` → ``PANEL_BASE_URL`` derived
   from ``DOMAIN``), exactly as before;
3. nothing — the link stays relative (``/sub/<token>``) and clients absolutize
   it against the address they reached the panel on.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

_TTL_SECONDS = 5.0
_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "value": None}


def _runtime():
    try:
        import app as _app

        return getattr(getattr(_app, "app", None).state, "zagros", None)
    except Exception:  # noqa: BLE001 - the legacy stack may not be built yet
        return None


def _read_portal_settings(runtime):
    """Synchronous read of the saved ``PortalSettings`` (or ``None``)."""
    from app.persistence.models import SettingModel
    from app.persistence.repositories import _PORTAL_SETTINGS_KEY
    from app.portal.models import PortalSettings

    with runtime.session_factory() as session:
        row = session.get(SettingModel, _PORTAL_SETTINGS_KEY)
    if row is None or not row.value_json:
        return None
    settings = PortalSettings.model_validate(row.value_json)
    try:
        return settings.normalize()
    except ValueError:
        # a half-saved/legacy row: still honour whatever base it can express
        return settings


def _env_prefix() -> str:
    """``SUBSCRIPTION_URL_PREFIX`` (or the ``PANEL_BASE_URL`` derivation config.py
    already performs) — the pre-1.0.3 source of the link."""
    from config import XRAY_SUBSCRIPTION_URL_PREFIX

    return (XRAY_SUBSCRIPTION_URL_PREFIX or "").strip().rstrip("/")


def invalidate() -> None:
    """Forget the cached shape (called after the Subscription page saves)."""
    with _lock:
        _cache["at"] = 0.0
        _cache["value"] = None


def link_shape(*, force: bool = False) -> dict[str, Any]:
    """``{"base": "https://sub.example.com:2096" | None, "path": "sub",
    "source": "portal" | "environment" | "none"}`` — cached for a few seconds."""
    now = time.monotonic()
    with _lock:
        cached = _cache["value"]
        if cached is not None and not force and now - _cache["at"] < _TTL_SECONDS:
            return cached

    shape: dict[str, Any] | None = None
    runtime = _runtime()
    if runtime is not None:
        try:
            settings = _read_portal_settings(runtime)
        except Exception as exc:  # noqa: BLE001 - never break a user response
            logger.debug("portal settings unavailable for link shape: %s", exc)
            settings = None
        if settings is not None:
            base = (settings.public_base_url() or "").rstrip("/") or None
            path = (settings.subscription_path or "sub").strip().strip("/") or "sub"
            if base:
                shape = {"base": base, "path": path, "source": "portal"}
            else:
                # no public identity saved: the env may still supply one, but
                # the operator's chosen path segment always applies
                shape = {"base": None, "path": path, "source": "none"}
    if shape is None or shape["base"] is None:
        env_base = _env_prefix()
        path = shape["path"] if shape else "sub"
        if env_base:
            shape = {"base": env_base, "path": path, "source": "environment"}
        else:
            shape = {"base": None, "path": path, "source": "none"}

    with _lock:
        _cache["at"] = now
        _cache["value"] = shape
    return shape


def subscription_url(token: str) -> str:
    """The public subscription URL for *token* (absolute when the panel knows
    its public identity, else the relative canonical path)."""
    import secrets

    shape = link_shape()
    path = f"/{shape['path']}/{token}"
    base = shape["base"]
    if not base:
        return path
    if "*" in base:
        # legacy wildcard prefix: a random label per link (Marzban behaviour)
        base = base.replace("*", secrets.token_hex(8))
    return f"{base}{path}"
