"""Subscription Portal per-core UX content (alpha.7.2, item 15).

Pins the portal-facing delivery contract per core, end to end at the
driver edge (the portal renderer is fully generic and consumes exactly
this shape):

  * xray / sing-box: one QR-able LINK section per selected inbound, every
    section naming its inbound_tag (Host Settings engine keys on it).
  * OpenVPN: downloadable .ovpn FILE + username/password + CA/TLS security
    facts (fingerprint derived from the real CA DER).
  * WireGuard: QR-able .conf + peer/key details (address, server public
    key, endpoint, DNS, MTU, Allowed IPs, keepalive, peer identity, PSK
    when provisioned) — private key never a field.
  * SSH: host/port/username/password per granted listener.
  * SoftEther: one section PER compat transport (L2TP/IPsec + PSK, SSTP,
    PPTP, OpenVPN clone) with full connection facts; missing server-side
    facts surface as honest NOTE artifacts, never a failed delivery; the
    filter whitelists/blacklists by catalog tag (l2tp/sstp/pptp/softether).
"""
from __future__ import annotations

import asyncio
import hashlib
import ssl
import tempfile

import pytest

from app.cores.delivery import ArtifactKind
from app.cores.types import UserAccount


def _acct(user: int, name: str, protocol: str, settings: dict | None = None) -> UserAccount:
    return UserAccount(
        user_id=user, username=name, account_id=f"{user}.{name}",
        protocol=protocol, settings=settings or {})


def _fields(profile, section_index: int = 0) -> dict:
    """field key → field, across every FIELDS artifact of a section."""
    out: dict = {}
    for art in profile.sections[section_index].artifacts:
        if art.kind is ArtifactKind.FIELDS:
            for f in art.fields:
                out[f.key] = f
    return out


# ---------------------------------------------------------------------- #
# xray (built-in) — one link per inbound                                 #
# ---------------------------------------------------------------------- #

def test_xray_delivery_links_per_inbound() -> None:
    from tests.cores.test_delivery import _xray_profile  # real 2-inbound fixture

    profile = asyncio.run(_xray_profile())
    links = [a for s in profile.sections for a in s.artifacts
             if a.kind is ArtifactKind.LINK]
    assert len(links) == 2
    assert all(a.qr for a in links)                      # every link is QR-able
    assert all(a.content.startswith(("vless://", "vmess://", "trojan://",
                                     "ss://", "hy2://", "tuic://")) for a in links)


# ---------------------------------------------------------------------- #
# sing-box — sections per (tag, inbound), inbound_tag pinned             #
# ---------------------------------------------------------------------- #

def test_singbox_sections_pin_inbound_tag_and_keep_note_tagless() -> None:
    from app.cores.consolidation import translate_entry
    from app.cores.drivers.singbox import SingBoxDriver
    from tests.cores.fakes import FakeSingBoxBackend, FakeV2RayStats

    driver = SingBoxDriver(
        {"work_dir": tempfile.mkdtemp(prefix="it15sb-"),
         "advertise_host": "203.0.113.10"},
        backend=FakeSingBoxBackend(), stats=FakeV2RayStats())

    async def main():
        entries = [
            translate_entry("hysteria2", {
                "tag": "hy2-main", "port": 443, "sni": "cdn.example.com",
                "obfs": "obfs-secret"}),
            translate_entry("hysteria2", {
                "tag": "hy2-alt", "port": 8443, "sni": "cdn2.example.com",
                "obfs": "obfs-secret"}),
        ]
        await driver.apply_studio_document({"inbounds": entries})
        account = _acct(1, "alice", "hysteria2")
        await driver.create_account(account)
        return await driver.describe_delivery(account), account

    profile, account = asyncio.run(main())
    assert account.settings["password"]                  # minted (item 10)
    assert [s.inbound_tag for s in profile.sections] == ["hy2-main", "hy2-alt"]
    for section in profile.sections:
        assert section.artifacts[0].kind is ArtifactKind.LINK
        assert section.artifacts[0].qr
        assert "hy2://" in section.artifacts[0].content
        assert section.inbound_tag in section.artifacts[0].content
    # grants filter by tag, sections follow the grant
    async def granted():
        acc = _acct(2, "bob", "hysteria2", {"inbound_tags": ["hy2-alt"]})
        await driver.create_account(acc)
        return await driver.describe_delivery(acc)

    narrowed = asyncio.run(granted())
    assert [s.inbound_tag for s in narrowed.sections] == ["hy2-alt"]


# ---------------------------------------------------------------------- #
# openvpn — .ovpn file + credentials + CA/TLS security facts             #
# ---------------------------------------------------------------------- #

def test_openvpn_delivery_security_facts_and_real_ca_fingerprint() -> None:
    from app.cores.drivers.openvpn import OpenVPNDriver
    from tests.cores.fakes import TEST_CA_CRT, FakeOpenVPNBackend

    driver = OpenVPNDriver(backend=FakeOpenVPNBackend())

    async def main():
        await driver.apply_studio_document({"inbounds": [
            {"tag": "ovpn-main", "protocol": "ovpn", "port": 1194},
            {"tag": "ovpn-alt", "protocol": "ovpn", "port": 1443,
             "transport": "tcp", "subnet": "10.9.0.0"},
        ]})
        await driver.start()
        account = _acct(1, "alice", "ovpn", {"password": "pw-alice"})
        await driver.create_account(account)
        return await driver.describe_delivery(account)

    profile = asyncio.run(main())
    assert [s.inbound_tag for s in profile.sections] == ["ovpn-main", "ovpn-alt"]
    expected_fp = hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(TEST_CA_CRT)).hexdigest()[:16].upper()
    for index, section in enumerate(profile.sections):
        kinds = [a.kind for a in section.artifacts]
        assert kinds[:3] == [ArtifactKind.FILE, ArtifactKind.FIELDS,
                             ArtifactKind.FIELDS]
        fields = _fields(profile, index)
        # user/pass present, password secret
        assert fields["username"].value == "1.alice"
        assert fields["password"].value == "pw-alice" and fields["password"].secret
        # server & security facts
        assert fields["server"].value.split(":")[-1] in {"1194", "1443"}
        assert fields["transport"].value in {"UDP", "TCP"}
        assert "AES-256-GCM" in fields["cipher"].value
        assert "tls-crypt" in fields["tls"].value
        assert fields["ca_fingerprint"].value == expected_fp
        # the .ovpn file carries the CA inline
        file_art = section.artifacts[0]
        assert "BEGIN CERTIFICATE" in file_art.content
        assert "remote-cert-tls server" in file_art.content


# ---------------------------------------------------------------------- #
# wireguard — config + QR + peer / keys                                  #
# ---------------------------------------------------------------------- #

def test_wireguard_delivery_peer_and_key_details() -> None:
    from app.cores.drivers.wireguard import WireGuardDriver
    from tests.cores.fakes import FakeWireGuardBackend

    driver = WireGuardDriver(
        {"work_dir": tempfile.mkdtemp(prefix="it15wg-"),
         "use_preshared_keys": True},
        backend=FakeWireGuardBackend())

    async def main():
        await driver.start()
        account = _acct(1, "alice", "wireguard")
        await driver.create_account(account)
        return await driver.describe_delivery(account), account

    profile, account = asyncio.run(main())
    section = profile.sections[0]
    assert section.inbound_tag == "wireguard"
    kinds = [a.kind for a in section.artifacts]
    assert kinds == [ArtifactKind.FILE, ArtifactKind.FIELDS, ArtifactKind.NOTE]
    file_art = section.artifacts[0]
    assert file_art.qr and "[Interface]" in file_art.content
    fields = _fields(profile)
    assert {"address", "public_key", "endpoint", "dns",
            "allowed_ips", "keepalive"} <= set(fields)
    # peer identity + provisioned PSK shown (secret), private key never
    assert fields["client_public_key"].value == account.settings["public_key"]
    assert fields["preshared_key"].secret
    assert fields["preshared_key"].value == account.settings["preshared_key"]
    labels = {f.label for f in section.artifacts[1].fields}
    assert not any("Private" in label for label in labels)


def test_wireguard_delivery_without_psk_omits_the_field_honestly() -> None:
    from app.cores.drivers.wireguard import WireGuardDriver
    from tests.cores.fakes import FakeWireGuardBackend

    driver = WireGuardDriver(
        {"work_dir": tempfile.mkdtemp(prefix="it15wg2-"),
         "use_preshared_keys": False},  # default is True — disable explicitly
        backend=FakeWireGuardBackend())

    async def main():
        await driver.start()
        account = _acct(1, "alice", "wireguard")
        await driver.create_account(account)
        return await driver.describe_delivery(account)

    profile = asyncio.run(main())
    assert "preshared_key" not in _fields(profile)       # absent, not blank


# ---------------------------------------------------------------------- #
# ssh — host/port/username/password per granted listener                 #
# ---------------------------------------------------------------------- #

def test_ssh_delivery_per_listener_credentials() -> None:
    from app.cores.drivers.ssh import SSHTunnelDriver
    from tests.cores.fakes import FakeSSHBackend

    driver = SSHTunnelDriver(
        {"advertise_host": "203.0.113.20",
         "listeners": [{"tag": "ssh-a", "port": 2222},
                       {"tag": "ssh-b", "port": 2223}]},
        backend=FakeSSHBackend())

    async def main():
        account = _acct(1, "alice", "ssh", {"password": "s3cret"})
        await driver.create_account(account)
        return await driver.describe_delivery(account)

    profile = asyncio.run(main())
    assert [s.inbound_tag for s in profile.sections] == ["ssh-a", "ssh-b"]
    for index, section in enumerate(profile.sections):
        fields = _fields(profile, index)
        assert fields["host"].value == "203.0.113.20"
        assert fields["port"].value == str(2222 + index)
        assert fields["password"].secret and fields["password"].value == "s3cret"
        notes = [a for a in section.artifacts if a.kind is ArtifactKind.NOTE]
        assert notes and "ssh -p" in notes[0].note


# ---------------------------------------------------------------------- #
# softether — one section per compat transport, honestly                 #
# ---------------------------------------------------------------------- #

def test_softether_delivery_all_transports_with_psk_and_notes() -> None:
    from app.cores.drivers.softether import SoftEtherDriver
    from tests.cores.fakes import FakeSEBackend

    driver = SoftEtherDriver(
        {"ipsec_psk": "test-psk", "advertise_host": "vpn.example.com"},
        backend=FakeSEBackend())

    async def main():
        account = _acct(1, "alice", "l2tp", {"password": "pw-alice"})
        await driver.create_account(account)
        return await driver.describe_delivery(account)

    profile = asyncio.run(main())
    assert [s.inbound_tag for s in profile.sections] == [
        "l2tp", "sstp", "pptp", "softether"]
    assert [s.protocol for s in profile.sections] == [
        "l2tp", "sstp", "pptp", "ovpn"]
    for index, section in enumerate(profile.sections):
        fields = _fields(profile, index)
        assert fields["host"].value == "vpn.example.com"
        assert fields["username"].value == "1.alice"
        assert fields["password"].secret and fields["password"].value == "pw-alice"
        assert fields["hub"].value == "DEFAULT"
    # per-transport ports grounded in the hub document
    assert _fields(profile, 0)["port"].value == "UDP 500 · 4500 · 1701"
    assert _fields(profile, 1)["port"].value == "443/tcp"
    assert _fields(profile, 2)["port"].value == "1723/tcp"
    assert _fields(profile, 3)["port"].value == "1194/tcp"
    # PSK rides the L2TP section only, secret
    l2tp = _fields(profile, 0)
    assert l2tp["ipsec_psk"].value == "test-psk" and l2tp["ipsec_psk"].secret
    assert "ipsec_psk" not in _fields(profile, 1)
    # feature flags are OFF on a fresh hub → honest NOTE per transport; the
    # OpenVPN-clone section carries the EXTERNAL-MANAGEMENT note instead
    # (vpncmd 5.02 has no toggle verb — alpha.7.5 item 7)
    for section in profile.sections:
        notes = [a.note for a in section.artifacts if a.kind is ArtifactKind.NOTE]
        if section.protocol == "ovpn":
            assert any("Server Manager" in (n or "") and "no" in (n or "")
                       for n in notes)
        else:
            assert any("feature is currently OFF" in (n or "") for n in notes)


def test_softether_delivery_missing_facts_are_notes_not_errors() -> None:
    from app.cores.drivers.softether import SoftEtherDriver
    from tests.cores.fakes import FakeSEBackend

    # no ipsec_psk, no advertise_host, ovpn ports customized
    driver = SoftEtherDriver(
        {"advertise_host": "", "ovpn_ports": "55443"},
        backend=FakeSEBackend())

    async def main():
        account = _acct(1, "alice", "l2tp")
        await driver.create_account(account)             # mints password
        return await driver.describe_delivery(account), account

    profile, account = asyncio.run(main())
    assert account.settings["password"]                  # item-10 mint
    l2tp_notes = [a.note for a in profile.sections[0].artifacts
                  if a.kind is ArtifactKind.NOTE]
    assert any("pre-shared key" in n for n in l2tp_notes)
    assert any("server address is not configured" in n for n in l2tp_notes)
    assert _fields(profile, 0)["password"].value == account.settings["password"]
    # non-L2TP sections never mention the PSK
    sstp_notes = [a.note for a in profile.sections[1].artifacts
                  if a.kind is ArtifactKind.NOTE]
    assert not any("pre-shared key" in (n or "") for n in sstp_notes)
    assert _fields(profile, 3)["port"].value == "55443/tcp"


def test_softether_delivery_grants_and_empty_state() -> None:
    from app.cores.drivers.softether import SoftEtherDriver
    from tests.cores.fakes import FakeSEBackend

    driver = SoftEtherDriver({"ipsec_psk": "k"}, backend=FakeSEBackend())

    async def main():
        only = _acct(1, "alice", "l2tp",
                     {"password": "x", "inbound_tags": ["sstp"]})
        await driver.create_account(only)
        narrowed = await driver.describe_delivery(only)
        assert [s.inbound_tag for s in narrowed.sections] == ["sstp"]

        excluded = _acct(2, "bob", "sstp",
                         {"password": "x", "excluded_inbounds": ["sstp"]})
        await driver.create_account(excluded)
        sans = await driver.describe_delivery(excluded)
        assert "sstp" not in [s.inbound_tag for s in sans.sections]

        nothing = _acct(3, "carol", "pptp",
                        {"password": "x",
                         "inbound_tags": ["sstp"],
                         "excluded_inbounds": ["sstp"]})
        await driver.create_account(nothing)
        empty = await driver.describe_delivery(nothing)
        assert len(empty.sections) == 1
        assert empty.sections[0].artifacts[0].kind is ArtifactKind.NOTE
        assert "No SoftEther transport" in empty.sections[0].artifacts[0].note

    asyncio.run(main())
