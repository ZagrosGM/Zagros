"""PortalService — assembles subscription pages from live driver descriptors."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from app.cores.base import BaseCoreDriver
from app.cores.delivery import ArtifactKind, DeliveryArtifact, DeliverySection
from app.cores.types import UserAccount
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

    def __init__(self, provider: PortalDataProvider, settings: SettingsStore) -> None:
        self._provider = provider
        self._settings = settings

    async def build_page(self, user_id: int, *, lang: str | None = None) -> PortalPage | None:
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
                title=settings.portal_title,
                lang=page_lang, direction=direction,
                user=ctx.user.model_copy(update={"client_auth_mode": mode}),
                sections=[],
                apps=list(settings.app_downloads),
                support_url=settings.support_url,
            )

        sections: list[DeliverySection] = []
        notes: list[str] = []
        for driver, account in ctx.accounts:
            try:
                profile = await driver.describe_delivery(account)
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
            title=settings.portal_title,
            lang=page_lang, direction=direction,
            user=ctx.user,
            sections=sections,
            apps=list(settings.app_downloads),
            support_url=settings.support_url,
            notes=notes,
        )

    async def build_links(self, user_id: int) -> tuple[list[str], list[str]] | None:
        """Every share-link the user's cores can produce — the multi-core
        subscription payload for non-browser clients (v2rayNG, Streisand,
        sing-box for Android...).

        Returns ``(links, notes)`` — every LINK artifact across ALL
        (driver, account) pairs. FILE/FIELDS artifacts (ovpn/wireguard
        configs, l2tp/sstp/pptp credentials) have no standard URL form; they
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
        for driver, account in ctx.accounts:
            if not account.enabled:
                continue
            try:
                profile = await driver.describe_delivery(account)
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
