"""Host Settings at the portal service edge (alpha.7.2, item 13).

Pins the integration contract: PortalService widens delivery through the
host store when entries exist, behaves byte-identically when they don't,
never double-expands the built-in xray (legacy hosts path stays the only
source there), and the expanded links flow through the real format
converters. Also pins the SQL store round-trip via the real model.
"""
from __future__ import annotations

# NOTE: sync tests driving coroutines through asyncio.run — the suite-wide
# convention (the repo pins NO pytest-asyncio dependency; CI installs only
# requirements.txt + pytest). Bare ``async def test_`` + pytest.mark.asyncio
# only "works" on machines that happen to have the plugin and fails on a
# clean runner with "async def functions are not natively supported".
import asyncio
import datetime as dt

from app.cores.delivery import (
    ArtifactKind,
    DeliveryArtifact,
    DeliveryProfile,
    DeliverySection,
)
from app.portal.hostengine import HostEntry
from app.portal.models import PortalUserView
from app.portal.service import PortalService
from app.portal.settings_store import InMemorySettingsStore
from app.persistence.repositories import InMemoryCoreHostStore


def _user():
    return PortalUserView(
        user_id=7, username="alice", status="active",
        used_bytes=10 * 2**30, data_limit_bytes=100 * 2**30,
        expire_at=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))


class _FakeDriver:
    class metadata:  # noqa: D106 — test double
        id = "hysteria2"
        name = "Fake HY2"

    def __init__(self, link: str, core_id: str = "hysteria2"):
        self.metadata.id = core_id
        self._link = link

    async def describe_delivery(self, account, context=None):
        return DeliveryProfile(core_id=self.metadata.id, sections=[
            DeliverySection(protocol="hysteria2", title="Fake HY2",
                            engine="sing-box", inbound_tag="hy2-in",
                            artifacts=[DeliveryArtifact(
                                kind=ArtifactKind.LINK, label="base",
                                content=self._link, qr=True)])])


class _Account:
    def __init__(self, protocol="hysteria2", enabled=True):
        self.protocol = protocol
        self.enabled = enabled


class _Provider:
    def __init__(self, pairs, user=None):
        self._pairs = pairs
        self._user = user or _user()

    async def get_subscription_context(self, user_id):
        from app.portal.service import SubscriptionContext

        return SubscriptionContext(user=self._user, accounts=self._pairs)


HY2_LINK = "hy2://pw@h2.example.com:443?sni=h2.example.com#base"


def test_build_links_expands_with_host_entries():
    async def run():
        store = InMemoryCoreHostStore()
        await store.replace_tags("hysteria2", {"hy2-in": [
            HostEntry(remark="DC1 {USERNAME}", address="dc1.example.com"),
            HostEntry(remark="DC2", address="dc2.example.com", port=8443),
        ]})
        svc = PortalService(_Provider([(_FakeDriver(HY2_LINK), _Account())]),
                            InMemorySettingsStore(), host_store=store)
        links, notes = await svc.build_links(7)
        assert links is not None
        assert len(links) == 2
        assert "dc1.example.com:443" in links[0]
        assert "dc2.example.com:8443" in links[1]
        assert links[0].endswith("#" + "DC1%20alice")
    asyncio.run(run())


def test_build_links_without_entries_is_identical():
    async def run():
        store = InMemoryCoreHostStore()
        svc = PortalService(_Provider([(_FakeDriver(HY2_LINK), _Account())]),
                            InMemorySettingsStore(), host_store=store)
        links, _ = await svc.build_links(7)
        assert links == [HY2_LINK]
    asyncio.run(run())


def test_no_host_store_is_identical_backcompat():
    async def run():
        svc = PortalService(_Provider([(_FakeDriver(HY2_LINK), _Account())]),
                            InMemorySettingsStore())
        links, _ = await svc.build_links(7)
        assert links == [HY2_LINK]
    asyncio.run(run())


def test_builtin_xray_is_never_double_expanded():
    async def run():
        store = InMemoryCoreHostStore()
        await store.replace_tags("xray", {"V-WS": [HostEntry(address="dup.example.com")]})
        xray_link = "vless://u@orig.example.com:443?type=tcp&security=none#L1"
        driver = _FakeDriver(xray_link, core_id="xray")
        svc = PortalService(_Provider([(driver, _Account("vless"))]),
                            InMemorySettingsStore(), host_store=store)
        links, _ = await svc.build_links(7)
        assert links == [xray_link]
        assert not any("dup.example.com" in l for l in links)
    asyncio.run(run())


def test_expanded_links_flow_into_clash_and_singbox_formats():
    async def run():
        from app.platform.sub_formats import to_clash_meta, to_sing_box

        store = InMemoryCoreHostStore()
        await store.replace_tags("hysteria2", {"hy2-in": [
            HostEntry(remark="DC2", address="dc2.example.com", sni="cdn.example.com"),
        ]})
        svc = PortalService(_Provider([(_FakeDriver(HY2_LINK), _Account())]),
                            InMemorySettingsStore(), host_store=store)
        links, notes = await svc.build_links(7)
        clash, _ = to_clash_meta(links, notes)
        sb, _ = to_sing_box(links, notes)
        assert "dc2.example.com" in clash and "cdn.example.com" in clash
        assert "dc2.example.com" in sb and "cdn.example.com" in sb
        assert "DC2" in clash and "DC2" in sb
    asyncio.run(run())


def test_build_page_expands_sections():
    async def run():
        store = InMemoryCoreHostStore()
        await store.replace_tags("hysteria2", {"hy2-in": [
            HostEntry(remark="Portal DC", address="dc-p.example.com"),
        ]})
        svc = PortalService(_Provider([(_FakeDriver(HY2_LINK), _Account())]),
                            InMemorySettingsStore(), host_store=store)
        page = await svc.build_page(7)
        assert page is not None
        contents = [a.content for s in page.sections for a in s.artifacts]
        assert any("dc-p.example.com" in c for c in contents)
    asyncio.run(run())


# --------------------------------------------------------------------- #
# SQL store round-trip (exercises the real CoreHostModel mapping)
# --------------------------------------------------------------------- #

def test_default_host_lifecycle_is_per_inbound_and_cleans_deleted_tags():
    async def run():
        from app.portal.hostengine import DEFAULT_ADDRESS, DEFAULT_REMARK, reconcile_default_hosts

        store = InMemoryCoreHostStore()
        grouped = await reconcile_default_hosts(store, "wireguard", ["wg-a"])
        assert grouped["wg-a"][0].remark == DEFAULT_REMARK
        assert grouped["wg-a"][0].address == DEFAULT_ADDRESS
        # A second inbound gets an independent object/row.
        grouped = await reconcile_default_hosts(store, "wireguard", ["wg-a", "wg-b"])
        assert set(grouped) == {"wg-a", "wg-b"}
        await store.replace_tags("wireguard", {
            "wg-a": [HostEntry(remark="custom", address="a.example")],
        })
        grouped = await reconcile_default_hosts(store, "wireguard", ["wg-a", "wg-b"])
        assert grouped["wg-a"][0].remark == "custom"  # no blind overwrite
        grouped = await reconcile_default_hosts(store, "wireguard", ["wg-b"])
        assert set(grouped) == {"wg-b"}  # deleted inbound's hosts cleaned

    asyncio.run(run())


def test_sql_core_host_store_roundtrip(tmp_path):
    async def run():
        from app.persistence import create_schema, create_session_factory
        from app.persistence.repositories import SQLCoreHostStore

        sf = create_session_factory(f"sqlite:///{tmp_path}/hosts.db")
        create_schema(sf)
        store = SQLCoreHostStore(sf)

        grouped = await store.list_grouped("wireguard")
        assert grouped == {}

        await store.replace_tags("wireguard", {"wireguard": [
            HostEntry(remark="DC1-{USERNAME}", address="dc1.example.com", port=51830),
            HostEntry(remark="full", address="dc2.example.com",
                      allowinsecure=True, is_disabled=True,
                      mux_enable=True, fragment_setting="1-3,1-3,tlshello",
                      noise_setting="none", random_user_agent=True,
                      use_sni_as_host=True),
            HostEntry(remark="extras", address="dc3.example.com",
                      extras={"vpn_mark": 7}),
        ]})
        grouped = await store.list_grouped("wireguard")
        e1, e2, e3 = grouped["wireguard"]
        assert (e1.remark, e1.address, e1.port) == ("DC1-{USERNAME}", "dc1.example.com", 51830)
        assert e2.is_disabled is True and e2.allowinsecure is True
        assert e2.mux_enable is True and e2.fragment_setting == "1-3,1-3,tlshello"
        assert e2.noise_setting == "none" and e2.random_user_agent is True
        assert e2.use_sni_as_host is True
        assert e3.extras.get("vpn_mark") == 7          # unrecognized attrs preserved

        # replace ONLY the listed tag: a second tag keeps its rows
        await store.replace_tags("wireguard", {"wg-alt": [HostEntry(address="alt.example.com")]})
        grouped = await store.list_grouped("wireguard")
        assert [e.address for e in grouped["wireguard"]] == \
            ["dc1.example.com", "dc2.example.com", "dc3.example.com"]
        assert [e.address for e in grouped["wg-alt"]] == ["alt.example.com"]

        # explicit empty list clears a tag
        await store.replace_tags("wireguard", {"wg-alt": []})
        grouped = await store.list_grouped("wireguard")
        assert "wg-alt" not in grouped or grouped["wg-alt"] == []
        assert len(grouped["wireguard"]) == 3

        # priority = list order (sort column)
        await store.replace_tags("wireguard", {"wireguard": [
            HostEntry(remark="z-last", address="z.example.com"),
            HostEntry(remark="a-first", address="a.example.com"),
        ]})
        grouped = await store.list_grouped("wireguard")
        assert [e.address for e in grouped["wireguard"]] == \
            ["z.example.com", "a.example.com"]
    asyncio.run(run())
