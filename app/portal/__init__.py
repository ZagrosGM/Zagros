"""Zagros Subscription Portal — dynamic, driver-agnostic subscription pages.

The portal renders a modern per-user page whose sections are built *only*
from drivers' :class:`~app.cores.delivery.DeliveryProfile` descriptors —
no protocol or core name is ever hardcoded here. Two page kinds exist,
gated by the panel's Client Authentication Mode (and a per-user override):

* ``SUBSCRIPTION_LINK`` → the full portal (profiles, configs, QRs, files).
* ``APPLICATION_LOGIN`` → app-download page only; no configuration material
  of any kind is emitted (users connect via the official Zagros app through
  the sealed client API).
"""
from app.portal.models import (
    AppDownload,
    ClientAuthMode,
    PageKind,
    PortalPage,
    PortalSettings,
    PortalUserView,
)
from app.portal.service import PortalDataProvider, PortalService, SubscriptionContext
from app.portal.settings_store import InMemorySettingsStore, SettingsStore
from app.portal.render import render_page_html

__all__ = [
    "AppDownload",
    "ClientAuthMode",
    "PageKind",
    "PortalPage",
    "PortalSettings",
    "PortalUserView",
    "PortalDataProvider",
    "PortalService",
    "SubscriptionContext",
    "SettingsStore",
    "InMemorySettingsStore",
    "render_page_html",
]
