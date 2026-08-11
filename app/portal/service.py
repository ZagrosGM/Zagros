"""PortalService — assembles subscription pages from live driver descriptors."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

from app.cores.base import BaseCoreDriver
from app.cores.delivery import (
    ArtifactKind,
    DeliveryArtifact,
    DeliveryContext,
    DeliverySection,
)
from app.cores.types import UserAccount
from app.portal.hostengine import HostSettingsEngine, delivery_variables
from app.portal.models import (
    ClientAuthMode,
    PageKind,
    PortalPage,
    PortalUserView,
)
from app.portal.settings_store import SettingsStore

logger = logging.getLogger(__name__)


@dataclass
class SubscriptionContext:
    """Everything the portal needs about one subscriber."""

    user: PortalUserView
    accounts: list[tuple[BaseCoreDriver, UserAccount]]


class PortalDataProvider(Protocol):
    """Hexagonal port: the service never touches ORM/HTTP directly."""

    async def get_subscription_context(self, user_id: int) -> SubscriptionContext | None:
        """Return the user view + (driver, account) pairs, or None if unknown."""


class PortalService:
    """Builds :class:`PortalPage` respecting mode gates and honest failures."""

    def __init__(self, provider: PortalDataProvider, settings: SettingsStore,
                 *, host_store: Any | None = None) -> None:
        self._provider = provider
        self._settings = settings
        # alpha.7.2 (item 13): optional Host-Settings store — when absent
        # (tests, minimal boots) profiles pass through byte-identically.
        self._host_store = host_store
        self._host_engine = HostSettingsEngine()

    @staticmethod
    def _delivery_context(settings, request_host: str | None) -> DeliveryContext:
        from urllib.parse import urlsplit

        configured = str(settings.subscription_url_prefix or "").strip()
        host = ""
        if configured:
            parsed = urlsplit(configured if "://" in configured
                              else f"//{configured}")
            host = parsed.hostname or ""
        if not host:
            host = str(request_host or "").strip()
        return DeliveryContext(brand=settings.brand,
                               public_host=host or None)

    async def _expand_hosts(self, core_id: str, profile, variables):
        """Widen one delivery profile through the admin's Host Settings
        (item 13).  The built-in xray core is SKIPPED — its links are
        already expanded per legacy host entry by the driver itself
        (Marzban-parity path); layering core_hosts over it would double
        every link.  Cores without entries pass through unchanged."""
        if self._host_store is None or core_id == "xray":
            return profile
        entries = await self._host_store.list_grouped(core_id)
        if not entries:
            return profile
        return self._host_engine.expand(profile, entries, variables)

    async def build_page(self, user_id: int, *, lang: str | None = None,
                         public_host: str | None = None) -> PortalPage | None:
        ctx = await self._provider.get_subscription_context(user_id)
        if ctx is None:
            return None
        settings = await self._settings.get_portal_settings()
        page_lang = (lang or settings.default_lang or "fa").split("-")[0]
        direction = "rtl" if page_lang in ("fa", "ar", "he") else "ltr"

        mode = ctx.user.client_auth_mode or settings.client_auth_mode
        if mode is ClientAuthMode.APPLICATION_LOGIN:
            # Mode 2: not a single byte of configuration material is emitted.
            return PortalPage(
                kind=PageKind.APP_DOWNLOAD,
                brand=settings.brand,
                app_name=settings.app_name,
                title=settings.portal_title,
                lang=page_lang, direction=direction,
                user=ctx.user.model_copy(update={"client_auth_mode": mode}),
                sections=[],
                apps=list(settings.app_downloads),
                support_url=settings.support_url,
            )

        sections: list[DeliverySection] = []
        notes: list[str] = []
        variables = delivery_variables(ctx.user)
        delivery_context = self._delivery_context(settings, public_host)
        for driver, account in ctx.accounts:
            try:
                profile = await driver.describe_delivery(account, delivery_context)
                profile = await self._expand_hosts(driver.metadata.id, profile, variables)
            except Exception as exc:  # noqa: BLE001 — honesty: show, don't crash the page
                logger.warning("delivery description failed for core %s: %s",
                               driver.metadata.id, exc)
                sections.append(DeliverySection(
                    protocol=account.protocol,
                    title=driver.metadata.name,
                    engine="",
                    artifacts=[DeliveryArtifact(
                        kind=ArtifactKind.NOTE,
                        label="Temporarily unavailable",
                        note="This service is temporarily unavailable; the panel "
                             "could not assemble its configuration right now.",
                    )],
                    note=f"Reported honestly instead of hidden: {exc.__class__.__name__}",
                ))
                continue
            for section in profile.sections:
                section.title = f"{settings.brand} · {section.title}" if not section.title.startswith(settings.brand) else section.title
            sections.extend(profile.sections)
            if profile.note:
                notes.append(profile.note)

        return PortalPage(
            kind=PageKind.PORTAL,
            brand=settings.brand,
            app_name=settings.app_name,
            title=settings.portal_title,
            lang=page_lang, direction=direction,
            user=ctx.user,
            sections=sections,
            apps=list(settings.app_downloads),
            support_url=settings.support_url,
            notes=notes,
        )

    async def build_links(self, user_id: int, *,
                          public_host: str | None = None) -> tuple[list[str], list[str]] | None:
        """Every share-link the user's cores can produce — the multi-core
        subscription payload for non-browser clients (v2rayNG, Streisand,
        sing-box for Android...).

        Returns ``(links, notes)`` — every LINK artifact across ALL
        (driver, account) pairs. FILE/FIELDS artifacts (ovpn/wireguard
        configs and L2TP/SSTP credentials) have no standard URL form; they
        stay on the HTML portal instead of being fabricated into pseudo
        links, and the drivers' honest notes are returned so the caller can
        state why (never silently dropped).
        """
        ctx = await self._provider.get_subscription_context(user_id)
        if ctx is None:
            return None
        settings = await self._settings.get_portal_settings()
        mode = ctx.user.client_auth_mode or settings.client_auth_mode
        if mode is ClientAuthMode.APPLICATION_LOGIN:
            # Mode 2 quarantine: not a single byte of configuration material —
            # same gate as the portal page, enforced on the raw list too.
            return [], []
        links: list[str] = []
        notes: list[str] = []
        variables = delivery_variables(ctx.user)
        delivery_context = self._delivery_context(settings, public_host)
        for driver, account in ctx.accounts:
            if not account.enabled:
                continue
            try:
                profile = await driver.describe_delivery(account, delivery_context)
                profile = await self._expand_hosts(driver.metadata.id, profile, variables)
            except Exception as exc:  # noqa: BLE001 — honest, never crash the list
                notes.append(f"{account.protocol}: temporarily unavailable ({exc.__class__.__name__})")
                continue
            for section in profile.sections:
                for artifact in section.artifacts:
                    if artifact.kind is ArtifactKind.LINK and artifact.content:
                        links.append(artifact.content)
                    elif artifact.note:
                        notes.append(f"{section.title}: {artifact.note}")
            if profile.note:
                notes.append(profile.note)
        return links, notes
