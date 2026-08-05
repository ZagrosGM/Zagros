"""Subscription Portal tests — service gating, renderer output, security.

Covers: Client Authentication Mode (panel setting + per-user override),
honest per-core failure reporting, HTML escaping, secret masking, QR
embedding, file data-URIs, and the app-download page never leaking
configuration material.

Run: pytest tests/portal/test_portal.py -v   OR   python tests/portal/test_portal.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import traceback
import types as _types
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores.delivery import (  # noqa: E402
    ArtifactKind,
    DeliveryArtifact,
    DeliveryField,
    DeliveryProfile,
    DeliverySection,
)
from app.cores.exceptions import CoreError  # noqa: E402
from app.cores.types import UserAccount  # noqa: E402
from app.portal.models import (  # noqa: E402
    AppDownload,
    ClientAuthMode,
    PageKind,
    PortalSettings,
    PortalUserView,
)
from app.portal.service import PortalService, SubscriptionContext  # noqa: E402
from app.portal.settings_store import InMemorySettingsStore  # noqa: E402
from app.portal.render import render_page_html  # noqa: E402

# ---------------------------------------------------------------------- #
# fixtures
# ---------------------------------------------------------------------- #

_SECRET = "uuid-secret-1234"


class _FakeDriverOk:
    class _Meta:
        id = "fakebox"
        name = "FakeBox"
    metadata = _Meta()

    async def describe_delivery(self, account, context=None) -> DeliveryProfile:
        return DeliveryProfile(
            core_id="fakebox",
            sections=[DeliverySection(
                protocol="vless", title="FakeBox VLESS", engine="sing-box",
                artifacts=[
                    DeliveryArtifact(kind=ArtifactKind.LINK, label="Main link",
                                     content=f"vless://{_SECRET}@h.example.com:443?security=tls#x",
                                     qr=True),
                    DeliveryArtifact(kind=ArtifactKind.FIELDS, label="Details",
                                     fields=[DeliveryField(key="password", label="Password",
                                                           value=_SECRET, secret=True)]),
                    DeliveryArtifact(kind=ArtifactKind.FILE, label="Config",
                                     content="[Interface]\n...", filename="alice.conf"),
                ],
            )],
        )


class _FakeDriverBroken:
    class _Meta:
        id = "brokenbox"
        name = "BrokenBox"
    metadata = _Meta()

    async def describe_delivery(self, account, context=None) -> DeliveryProfile:
        raise CoreError("core is stopped")


class _Provider:
    def __init__(self, user: PortalUserView | None, drivers: list | None = None):
        self._user = user
        self._drivers = drivers if drivers is not None else [_FakeDriverOk()]
        self.calls: list[int] = []

    async def get_subscription_context(self, user_id: int):
        self.calls.append(user_id)
        if self._user is None:
            return None
        accounts = [
            (d, UserAccount(user_id=user_id, username=self._user.username,
                            account_id=f"{user_id}.{self._user.username}", protocol="vless"))
            for d in self._drivers
        ]
        return SubscriptionContext(user=self._user, accounts=accounts)


def _user(**over) -> PortalUserView:
    base: dict[str, Any] = dict(
        user_id=7, username="alice", status="active",
        used_bytes=1_500_000_000, data_limit_bytes=10_000_000_000,
        expire_at=None,
    )
    base.update(over)
    return PortalUserView(**base)


def _service(user, settings=None, drivers=None) -> tuple[PortalService, _Provider]:
    provider = _Provider(user, drivers)
    store = InMemorySettingsStore(settings or PortalSettings())
    return PortalService(provider, store), provider


def test_mode_subscription_link_renders_full_portal() -> None:
    service, _ = _service(_user())
    page = asyncio.run(service.build_page(7))
    assert page is not None and page.kind is PageKind.PORTAL
    assert len(page.sections) == 1
    html = render_page_html(page)
    assert "FakeBox VLESS" in html and "vless://" in html
    assert _SECRET in html                         # portal mode MAY show it (masked)
    assert 'dir="rtl"' in html and 'lang="fa"' in html
    assert "<svg" in html                           # inline QR present
    assert "data:text/plain;base64," in html        # file download data URI
    assert "Zagros" in html


def test_mode_application_login_hides_everything() -> None:
    settings = PortalSettings(
        client_auth_mode=ClientAuthMode.APPLICATION_LOGIN,
        app_downloads=[AppDownload(platform="android", name="Zagros Android",
                                   url="https://apps.example.com/zagros.apk", primary=True)],
    )
    service, _ = _service(_user(), settings=settings)
    page = asyncio.run(service.build_page(7))
    assert page is not None and page.kind is PageKind.APP_DOWNLOAD
    assert page.sections == []
    html = render_page_html(page)
    assert _SECRET not in html                      # not one byte of config leaks
    assert "https://apps.example.com/zagros.apk" in html
    assert "vless://" not in html


def test_per_user_override_beats_panel_default() -> None:
    # panel = subscription link, user override = app login
    user = _user(client_auth_mode=ClientAuthMode.APPLICATION_LOGIN)
    service, _ = _service(user)
    page = asyncio.run(service.build_page(7))
    assert page is not None and page.kind is PageKind.APP_DOWNLOAD

    # panel = app login, user override = subscription link
    settings = PortalSettings(client_auth_mode=ClientAuthMode.APPLICATION_LOGIN)
    service2, _ = _service(_user(client_auth_mode=ClientAuthMode.SUBSCRIPTION_LINK),
                           settings=settings)
    page2 = asyncio.run(service2.build_page(7))
    assert page2 is not None and page2.kind is PageKind.PORTAL


def test_unknown_user_returns_none() -> None:
    service, provider = _service(None)
    assert asyncio.run(service.build_page(999)) is None
    assert provider.calls == [999]


def test_broken_core_reports_honestly_not_silently() -> None:
    service, _ = _service(_user(), drivers=[_FakeDriverOk(), _FakeDriverBroken()])
    page = asyncio.run(service.build_page(7))
    assert page is not None
    assert len(page.sections) == 2
    broken = next(s for s in page.sections if s.title == "BrokenBox")
    assert broken.artifacts[0].kind is ArtifactKind.NOTE
    assert "unavailable" in (broken.artifacts[0].note or "").lower()
    html = render_page_html(page)
    assert "BrokenBox" in html and "FakeBox VLESS" in html  # page survives


def test_secrets_masked_but_present_and_copyable() -> None:
    service, _ = _service(_user())
    page = asyncio.run(service.build_page(7))
    html = render_page_html(page)
    assert 'data-masked="1"' in html                  # mask applied at render time
    assert "••" in html                               # mask bullets visible
    assert "p@ss" not in html
    # the copy payload is URL-encoded so special characters survive
    assert "zgCopy" in html and "decodeURIComponent" in html


def test_html_escaping_of_user_controlled_values() -> None:
    evil = '<script>alert("x")</script>'
    user = _user(username=evil)
    service, _ = _service(user)
    page = asyncio.run(service.build_page(7))
    html = render_page_html(page)
    assert evil not in html
    assert "&lt;script&gt;" in html


def test_expiring_and_unlimited_views() -> None:
    import datetime
    soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5, hours=1)
    service, _ = _service(_user(expire_at=soon))
    page = asyncio.run(service.build_page(7))
    html = render_page_html(page)
    assert "days left" in html or "روز باقی‌مانده" in html

    service2, _ = _service(_user(data_limit_bytes=None))
    html2 = render_page_html(asyncio.run(service2.build_page(7)))
    assert "∞" in html2 or "نامحدود" in html2


def test_english_locale_renders_ltr() -> None:
    service, _ = _service(_user())
    page = asyncio.run(service.build_page(7, lang="en"))
    assert page is not None
    html = render_page_html(page)
    assert 'dir="ltr"' in html and 'lang="en"' in html
    assert "Show QR" in html and "Details" in html  # English i18n strings


def test_settings_store_roundtrip_and_mode_switch() -> None:
    async def run():
        store = InMemorySettingsStore()
        assert (await store.get_portal_settings()).client_auth_mode is ClientAuthMode.SUBSCRIPTION_LINK
        new = PortalSettings(client_auth_mode=ClientAuthMode.APPLICATION_LOGIN, brand="Zagros X")
        await store.save_portal_settings(new)
        got = await store.get_portal_settings()
        assert got.client_auth_mode is ClientAuthMode.APPLICATION_LOGIN
        assert got.brand == "Zagros X"
        # mutation isolation: caller-side changes must not leak into the store
        got.brand = "mutated"
        assert (await store.get_portal_settings()).brand == "Zagros X"
    asyncio.run(run())


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
