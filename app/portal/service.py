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
        # (item 13): optional Host-Settings store — when absent
        # (tests, minimal boots) profiles pass through byte-identically.
        self._host_store = host_store
        self._host_engine = HostSettingsEngine()

    @staticmethod
    def delivery_context(settings, request_host: str | None) -> DeliveryContext:
        from urllib.parse import urlsplit

        # QR/client profiles may use an explicit public base, otherwise every
        # delivered endpoint follows the same normalized subscription origin.
        configured = str(settings.qr_base_url or settings.subscription_url_prefix or "").strip()
        host = ""
        if configured:
            parsed = urlsplit(configured if "://" in configured
                              else f"//{configured}")
            host = parsed.hostname or ""
        if not host:
            host = str(request_host or "").strip()
        return DeliveryContext(brand=settings.brand,
                               public_host=host or None)

    @staticmethod
    def _delivery_context(settings, request_host: str | None) -> DeliveryContext:
        """Compatibility alias for existing callers and tests."""
        return PortalService.delivery_context(settings, request_host)

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
        delivery_context = self.delivery_context(settings, public_host)
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

    async def describe_file(self, user_id: int, core_id: str, tag: str, *,
                            public_host: str | None = None
                            ) -> tuple[str, str, str] | None:
        """One FILE artifact's (content, filename, mime) — or None.

        Serves the ``zagros-file:`` markers ``build_links`` emits: same
        account set, same delivery profiles, matched on the raw
        ``inbound_tag`` (matching pre-host-expansion keeps multi-host cores
        at one file per listener). Application-login users get nothing —
        same quarantine as the link list.
        """
        ctx = await self._provider.get_subscription_context(user_id)
        if ctx is None:
            return None
        settings = await self._settings.get_portal_settings()
        mode = ctx.user.client_auth_mode or settings.client_auth_mode
        if mode is ClientAuthMode.APPLICATION_LOGIN:
            return None
        delivery_context = self.delivery_context(settings, public_host)
        for driver, account in ctx.accounts:
            if driver.metadata.id != core_id or not account.enabled:
                continue
            try:
                profile = await driver.describe_delivery(account, delivery_context)
            except Exception:  # noqa: BLE001 — 404, same as missing
                return None
            for section_index, section in enumerate(profile.sections):
                want = section.inbound_tag or f"section-{section_index}"
                if want != tag:
                    continue
                for artifact in section.artifacts:
                    if (artifact.kind is ArtifactKind.FILE
                            and artifact.content):
                        return (artifact.content,
                                artifact.filename or f"{core_id}-{tag}.bin",
                                artifact.mime or "application/octet-stream")
            return None
        return None

    async def build_links(self, user_id: int, *,
                          public_host: str | None = None,
                          token: str | None = None,
                          bypass_mode_gate: bool = False,
                          ) -> tuple[list[str], list[str]] | None:
        """Every share-link the user's cores can produce — the multi-core
        subscription payload for non-browser clients (v2rayNG, Streisand,
        sing-box for Android...).

        Returns ``(links, notes)`` — every LINK artifact across ALL
        (driver, account) pairs. FIELDS artifacts (L2TP/SSTP credentials)
        have no standard URL form; they stay on the HTML portal instead of
        being fabricated into pseudo links, and the drivers' honest notes
        are returned so the caller can state why (never silently dropped).
        FILE artifacts (OpenVPN/WireGuard profiles) are served by the
        per-file download endpoint; when the caller's subscription
        ``token`` is known, one ``zagros-file:`` marker note per file is
        emitted (a same-server relative path the Zagros app resolves and
        fetches; generic clients read it as a comment and the
        clash/sing-box renderers strip it).
        """
        from urllib.parse import quote

        ctx = await self._provider.get_subscription_context(user_id)
        if ctx is None:
            return None
        settings = await self._settings.get_portal_settings()
        mode = ctx.user.client_auth_mode or settings.client_auth_mode
        if mode is ClientAuthMode.APPLICATION_LOGIN and not bypass_mode_gate:
            # Mode 2 quarantine: not a single byte of configuration material —
            # same gate as the portal page, enforced on the raw list too.
            # The QR enrollment page passes bypass_mode_gate=True: a
            # reseller/admin-issued activation ticket is an explicit,
            # audited, TTL-bounded delivery decision for exactly one user,
            # which the ambient-subscription quarantine must not swallow.
            return [], []
        links: list[str] = []
        notes: list[str] = []
        variables = delivery_variables(ctx.user)
        delivery_context = self.delivery_context(settings, public_host)
        for driver, account in ctx.accounts:
            if not account.enabled:
                continue
            try:
                profile = await driver.describe_delivery(account, delivery_context)
                profile = await self._expand_hosts(driver.metadata.id, profile, variables)
            except Exception as exc:  # noqa: BLE001 — honest, never crash the list
                # Name alone ("CoreError") tells an operator nothing; carry a
                # short reason so "why is this protocol missing?" is answerable
                # from the subscription itself. Kept short: this text is
                # user-visible.
                detail = str(exc).strip().replace("\n", " ")
                reason = f" — {detail[:160]}" if detail else ""
                notes.append(
                    f"{account.protocol}: temporarily unavailable "
                    f"({exc.__class__.__name__}){reason}")
                continue
            for section_index, section in enumerate(profile.sections):
                for artifact in section.artifacts:
                    if artifact.kind is ArtifactKind.LINK and artifact.content:
                        links.append(artifact.content)
                    elif (artifact.kind is ArtifactKind.FILE and token
                            and artifact.content):
                        tag = section.inbound_tag or f"section-{section_index}"
                        notes.append(
                            "zagros-file: "
                            f"/sub/file/{token}/{driver.metadata.id}/"
                            f"{quote(str(tag), safe='')}")
                    elif artifact.note:
                        notes.append(f"{section.title}: {artifact.note}")
            if profile.note:
                notes.append(profile.note)
        return links, notes
