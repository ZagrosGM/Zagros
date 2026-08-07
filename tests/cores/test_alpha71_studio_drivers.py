"""α7.1 driver-level studio contracts — every core's apply path, pinned
against the wizard blueprint (validated in parallel by the binary matrix
probes: Xray 26.3.27 `xray run -test`, sing-box 1.12.4 `sing-box check`).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import types
from pathlib import Path

import pytest

from app.cores.exceptions import CoreError
from app.cores.types import UserAccount


def _acct(name: str, protocol: str, **settings) -> UserAccount:
    return UserAccount(user_id=1, username=name, account_id=f"1.{name}",
                       protocol=protocol, enabled=True, settings=settings)


# ===================================================================== #
# sing-box
# ===================================================================== #

class _SBFakeBackend:
    def __init__(self):
        self.applied: list[dict] = []
        self.restarts = 0
        self._running = True

    def apply_config(self, config):
        self.applied.append(config)

    def is_running(self):
        return self._running

    def restart(self):
        self.restarts += 1


def _singbox(tmp_path, **settings) -> "object":
    from app.cores.drivers.singbox.driver import SingBoxDriver

    backend = _SBFakeBackend()
    d = SingBoxDriver(settings={"work_dir": str(tmp_path), **settings}, backend=backend)
    d._studio_doc = {"inbounds": []}
    return d


def _sb_translate(driver, **entry):
    base = {"tag": "t1", "listen": "0.0.0.0", "port": 1443}
    base.update(entry)
    return driver._studio_entry_to_native(base)


def test_singbox_socks_mixed_never_carry_tls(tmp_path):
    d = _singbox(tmp_path)
    for proto in ("socks", "mixed"):
        with pytest.raises(CoreError, match="do not carry a TLS section"):
            _sb_translate(d, protocol=proto, security="tls")
    ib = _sb_translate(d, protocol="mixed", security="none",
                       username="u1", password="p1")
    assert ib["users"] == [{"username": "u1", "password": "p1"}]
    assert ib["type"] == "mixed"


def test_singbox_naive_requires_users_and_tls_is_forced(tmp_path):
    d = _singbox(tmp_path)
    with pytest.raises(CoreError, match="username\+password"):
        _sb_translate(d, protocol="naive", port=1443, security="tls")
    ib = _sb_translate(d, protocol="naive", port=1443, security="tls",
                       sni="cdn.example.com", username="bob", password="pw")
    assert ib["type"] == "naive" and ib.get("tls", {}).get("enabled")
    # naive has physically no transport struct — nothing rendered
    assert "transport" not in ib


def test_singbox_anytls_requires_password(tmp_path):
    d = _singbox(tmp_path)
    with pytest.raises(CoreError, match="listener password"):
        _sb_translate(d, protocol="anytls", security="tls", sni="s.example.com")
    ib = _sb_translate(d, protocol="anytls", security="tls", sni="s.example.com",
                       password="secret", padding_scheme="stop=8\n100-500")
    assert ib["users"][0]["password"] == "secret"
    assert ib["padding_scheme"] == ["stop=8", "100-500"]
    assert "transport" not in ib  # anytls has no transport field physically


def test_singbox_shadowsocks_has_no_transport_or_tls(tmp_path):
    d = _singbox(tmp_path)
    with pytest.raises(CoreError, match="no transport field"):
        _sb_translate(d, protocol="shadowsocks", transport="ws")
    with pytest.raises(CoreError, match="do not carry a TLS section"):
        _sb_translate(d, protocol="shadowsocks", security="tls")
    ib = _sb_translate(d, protocol="shadowsocks", method="aes-256-gcm")
    assert ib["method"] == "aes-256-gcm"
    assert ib["type"] == "shadowsocks"


def test_singbox_reality_only_vless_trojan(tmp_path):
    d = _singbox(tmp_path)
    with pytest.raises(CoreError, match="VLESS/Trojan"):
        _sb_translate(d, protocol="vmess", security="reality", sni="x.com")
    ib = _sb_translate(d, protocol="vless", transport="ws", security="reality",
                       sni="dl.google.com", path="/w")
    assert ib["transport"]["type"] == "ws"
    tls = ib["tls"]
    assert tls["reality"]["enabled"] and tls["reality"]["handshake"]["server"] == "dl.google.com"
    # panel-side metadata is carried in-band until the merge strips it
    assert ib["_reality_public_key"]


def test_singbox_quic_transport_requires_tls(tmp_path):
    d = _singbox(tmp_path)
    with pytest.raises(CoreError, match="QUIC transport requires TLS"):
        _sb_translate(d, protocol="vless", transport="quic", security="none")
    ib = _sb_translate(d, protocol="trojan", transport="quic", security="tls",
                       sni="s.example.com")
    assert ib["transport"] == {"type": "quic"}


def test_singbox_unknown_fields_fail_loudly(tmp_path):
    d = _singbox(tmp_path)
    with pytest.raises(CoreError, match="not translatable"):
        _sb_translate(d, protocol="vless", xhttp_mode="stream-one")


def test_singbox_ss_method_whitelist(tmp_path):
    d = _singbox(tmp_path)
    with pytest.raises(CoreError, match="does not implement"):
        d._ss_checked_method("2022-blake3-chacha20-poly1305")  # Xray-only
    with pytest.raises(CoreError, match="does not implement"):
        d._ss_checked_method("aes-128-cfb")
    assert d._ss_checked_method("2022-blake3-aes-256-gcm")


def test_singbox_ss2022_ipsk_persisted_0600(tmp_path):
    d = _singbox(tmp_path, ss_method="2022-blake3-aes-256-gcm")
    psk1 = d._ss_server_psk()
    assert len(base64.b64decode(psk1)) == 32
    assert d._ss_server_psk() == psk1          # persisted — never re-minted
    path = tmp_path / ".ss-2022-psk-32"
    assert path.exists()
    assert path.stat().st_mode & 0o777 == 0o600
    # classic methods need no iPSK
    d2 = _singbox(tmp_path / "classic", ss_method="aes-128-gcm")
    assert d2._ss_server_psk() is None


def test_singbox_ss2022_user_psk_normalized_deterministically(tmp_path):
    d = _singbox(tmp_path, ss_method="2022-blake3-aes-128-gcm")
    account = _acct("u1", "shadowsocks", password="legacy-token_urlsafe-secret")
    norm = d._normalize_account(account)
    assert norm is not account                     # frozen → NEW object
    psk = norm.settings["password"]
    assert len(base64.b64decode(psk)) == 16        # proper 2022 uPSK size
    expected = base64.b64encode(
        hashlib.sha256(b"legacy-token_urlsafe-secret").digest()[:16]).decode()
    assert psk == expected                          # pure function of the secret
    assert d._normalize_account(norm) is norm       # already-valid PSK untouched
    # classic method leaves the free-form password alone
    d2 = _singbox(tmp_path / "cl", ss_method="aes-128-gcm")
    assert d2._normalize_account(account) is account


def test_singbox_tuic_account_uuid_and_shape(tmp_path):
    from app.cores.drivers.singbox.driver import SingBoxDriver

    account = _acct("t", "tuic", id="legacy-uuid-1", password="pw")
    d = SingBoxDriver(settings={"work_dir": str(tmp_path)}, backend=_SBFakeBackend())
    # legacy `id` migrates to `uuid` at the ingest boundary
    norm = d._normalize_account(account)
    assert norm.settings["uuid"] == "legacy-uuid-1"
    entry = SingBoxDriver._user_entry(norm)
    assert entry == {"uuid": "legacy-uuid-1", "password": "pw"}   # NO name


def test_singbox_create_account_requires_credentials_when_enabled(tmp_path):
    from app.cores.drivers.singbox.driver import SingBoxDriver

    d = SingBoxDriver(settings={"work_dir": str(tmp_path)}, backend=_SBFakeBackend())
    with pytest.raises(CoreError, match="missing credentials"):
        asyncio.run(d.create_account(_acct("empty", "trojan")))


def test_singbox_merge_strips_private_marker_keys(tmp_path):
    from app.cores.drivers.singbox.driver import SingBoxDriver

    d = SingBoxDriver(settings={"work_dir": str(tmp_path)}, backend=_SBFakeBackend())
    d._accounts[_acct("bob", "vless", id="uuid-1").account_id] = _acct(
        "bob", "vless", id="uuid-1")
    d._studio_doc = {"inbounds": [{
        "tag": "r1", "protocol": "vless", "transport": "tcp",
        "security": "reality", "sni": "dl.google.com", "port": 1443}]}
    rendered = d.render_config()
    ib = rendered["inbounds"][0]
    assert not any(k.startswith("_") for k in ib), ib          # never rendered
    meta = d._studio_link_meta["r1"]
    assert meta["_reality_public_key"]                          # kept for delivery
    assert ib["users"] == [{"name": "1.bob", "uuid": "uuid-1"}]


def test_singbox_apply_writes_and_restarts_when_running(tmp_path):
    from app.cores.drivers.singbox.driver import SingBoxDriver

    d = SingBoxDriver(settings={"work_dir": str(tmp_path)}, backend=_SBFakeBackend())
    backend = d._backend
    d._accounts[_acct("bob", "vless", id="uuid-1").account_id] = _acct(
        "bob", "vless", id="uuid-1")
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "tag": "w1", "protocol": "vless", "transport": "tcp",
        "security": "none", "port": 1443}]}))
    assert backend.applied and backend.restarts == 1
    assert backend.applied[-1]["inbounds"][0]["listen_port"] == 1443
    # stopped backend: config written, no restart
    backend2 = _SBFakeBackend()
    backend2._running = False
    d2 = SingBoxDriver(settings={"work_dir": str(tmp_path / "s")}, backend=backend2)
    asyncio.run(d2.apply_studio_document({"inbounds": [{
        "tag": "w1", "protocol": "vless", "transport": "tcp",
        "security": "none", "port": 1443}]}))
    assert backend2.applied and backend2.restarts == 0


# ===================================================================== #
# wireguard
# ===================================================================== #

class _WGFakeBackend:
    def __init__(self):
        self.written_key: str | None = None
        self.syncs: list[str] = []

    def public_from_private(self, private):
        return f"PUB({private})"

    def write_server_private_key(self, private):
        self.written_key = private

    def sync(self, config):
        self.syncs.append(config)

    def is_running(self):
        return True


def _wg_driver(tmp_path, **settings):
    from app.cores.drivers.wireguard.driver import WireGuardDriver

    return WireGuardDriver(
        settings={"work_dir": str(tmp_path), **settings}, backend=_WGFakeBackend())


def test_wireguard_export_has_all_wizard_fields_and_no_private_key(tmp_path):
    d = _wg_driver(tmp_path, mtu=1400, dns_servers=["1.1.1.1", "9.9.9.9"],
                   subnet="10.77.0.0/24", advertise_host="vpn.example.com",
                   peer_allowed_ips=["0.0.0.0/0"], peer_keepalive=30,
                   use_preshared_keys=True)
    doc = d.export_config_document()
    ib = doc["inbounds"][0]
    assert ib["protocol"] == "wireguard" and ib["mtu"] == 1400
    assert ib["dns"] == "1.1.1.1, 9.9.9.9"
    assert ib["address"] == "10.77.0.0/24"
    assert ib["endpoint"] == "vpn.example.com"
    assert ib["allowed_ips"] == "0.0.0.0/0"
    assert ib["persistent_keepalive"] == 30 and ib["preshared_keys"] is True
    assert "private_key" not in ib            # write-only wizard field


def test_wireguard_apply_maps_settings_and_writes_custom_key(tmp_path):
    d = _wg_driver(tmp_path)
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "protocol": "wireguard", "port": 51820, "mtu": 1380,
        "dns": "1.1.1.1, 8.8.8.8", "address": "10.99.0.0/24",
        "endpoint": "vpn.example.org", "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 21, "preshared_keys": False,
        "private_key": "CUSTOM_PRIVATE_KEY_" + "A" * 20}]}))
    s = d.settings
    assert s["port"] == 51820 and s["mtu"] == 1380
    assert s["dns_servers"] == ["1.1.1.1", "8.8.8.8"]
    assert s["subnet"] == "10.99.0.0/24" and s["advertise_host"] == "vpn.example.org"
    assert s["peer_allowed_ips"] == ["0.0.0.0/0"] and s["peer_keepalive"] == 21
    assert s["use_preshared_keys"] is False
    backend = d._backend
    assert backend.written_key.startswith("CUSTOM_PRIVATE_KEY_")
    assert d._server_public.startswith("PUB(CUSTOM_PRIVATE_KEY_")
    # re-apply with the same key: idempotent — written only once
    backend.written_key = None
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "protocol": "wireguard",
        "private_key": d._server_private}]}))
    assert backend.written_key is None


def test_wireguard_apply_rejects_multi_document_and_wrong_protocol(tmp_path):
    d = _wg_driver(tmp_path)
    with pytest.raises(CoreError, match="exactly ONE interface"):
        asyncio.run(d.apply_studio_document({"inbounds": [{}, {}]}))
    with pytest.raises(CoreError, match="cannot host"):
        asyncio.run(d.apply_studio_document({"inbounds": [{"protocol": "shadowsocks"}]}))


def test_wireguard_client_profile_uses_peer_defaults(tmp_path):
    from app.cores.drivers.wireguard.wgtool import render_client as wc

    text = wc(private_key="CPRIV", address="10.77.0.2/32",
              server_public_key="SERVERPUB", endpoint_host="vpn.example.com",
              endpoint_port=51820, dns=["1.1.1.1"], mtu=1400,
              allowed_ips=("10.0.0.0/8",), persistent_keepalive=17)
    assert "AllowedIPs = 10.0.0.0/8" in text
    assert "PersistentKeepalive = 17" in text
    assert "PrivateKey = CPRIV" in text and "MTU = 1400" in text


# ===================================================================== #
# openvpn
# ===================================================================== #

class _OVPNFakeBackend:
    def __init__(self):
        self.running = False
        self.configs: list[str] = []
        self.restarts = 0

    def is_running(self):
        return self.running

    def apply_config(self, text):
        self.configs.append(text)

    def restart(self):
        self.restarts += 1

    def install_hook_script(self, text):
        return "/tmp/openvpn-disconnect.sh"


def _ovpn_driver(tmp_path, **settings):
    from app.cores.drivers.openvpn.driver import OpenVPNDriver

    return OpenVPNDriver(
        settings={"work_dir": str(tmp_path / "ovpn"), **settings},
        backend=_OVPNFakeBackend())


def test_openvpn_apply_maps_wizard_fields(tmp_path):
    d = _ovpn_driver(tmp_path)
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "protocol": "ovpn", "port": 1195, "transport": "tcp",
        "topology": "net30", "cipher": "AES-128-GCM",
        "cipher_fallback": "AES-128-CBC", "auth": "SHA384",
        "compression": "lz4-v2", "dns": "1.1.1.1",
        "redirect_gateway": False, "extra_directives": "keepalive 10 60"}]}))
    s = d.settings
    assert s["port"] == 1195 and s["proto"] == "tcp" and s["topology"] == "net30"
    assert s["cipher"] == "AES-128-GCM" and s["cipher_fallback"] == "AES-128-CBC"
    assert s["auth_digest"] == "SHA384" and s["compression"] == "lz4-v2"
    assert s["dns_servers"] == ["1.1.1.1"] and s["redirect_gateway"] is False
    assert s["extra_directives"] == "keepalive 10 60"


def test_openvpn_rejects_bad_transport_topology_compression(tmp_path):
    d = _ovpn_driver(tmp_path)
    with pytest.raises(CoreError, match="udp or tcp"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"protocol": "ovpn", "transport": "quic"}]}))
    with pytest.raises(CoreError, match="topology"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"protocol": "ovpn", "topology": "mesh"}]}))
    with pytest.raises(CoreError, match="compression"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"protocol": "ovpn", "compression": "gzip"}]}))


def test_openvpn_static_auth_requires_and_installs_creds(tmp_path):
    # missing creds → the install step raises instead of bricking the server
    d = _ovpn_driver(tmp_path, static_user="", static_pass="")
    with pytest.raises(CoreError, match="username AND password"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"protocol": "ovpn", "auth_mode": "static"}]}))
    # creds provided → script 0700, creds file 0600 with exact content
    d2 = _ovpn_driver(tmp_path)
    asyncio.run(d2.apply_studio_document({"inbounds": [
        {"protocol": "ovpn", "auth_mode": "static",
         "username": "office", "password": "s3cret-pass"}]}))
    wd = Path(d2.settings["work_dir"])
    script = Path(d2._static_auth_script_path())
    assert script.exists() and script.stat().st_mode & 0o777 == 0o700
    creds = wd / ".ovpn-static-auth"
    assert creds.stat().st_mode & 0o777 == 0o600
    assert creds.read_text() == "office:s3cret-pass"
    # injection guard: ':' or newline credentials are rejected
    d3 = _ovpn_driver(tmp_path / "bad", static_user="a:b", static_pass="x")
    with pytest.raises(CoreError, match="':' or newlines"):
        asyncio.run(d3.apply_studio_document({"inbounds": [
            {"protocol": "ovpn", "auth_mode": "static"}]}))


def test_openvpn_pki_upload_validated_and_matching_pair_written(tmp_path):
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    d = _ovpn_driver(tmp_path)
    # mismatched cert/key pair → rejected BEFORE anything is written
    from app.utils.crypto import generate_certificate
    pair_a, pair_b = generate_certificate(), generate_certificate()
    with pytest.raises(CoreError):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"protocol": "ovpn", "certificate": pair_a["cert"],
             "certificate_key": pair_b["key"]}]}))
    wd = Path(d.settings["work_dir"])
    assert not list(wd.glob("*.crt")) and not list(wd.glob("*.key"))
    # half pair → same class of guard
    with pytest.raises(CoreError, match="together"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"protocol": "ovpn", "certificate": pair_a["cert"]}]}))
    # matching pair → written once, idempotent
    asyncio.run(d.apply_studio_document({"inbounds": [
        {"protocol": "ovpn", "ca_certificate": pair_a["cert"],
         "certificate": pair_a["cert"], "certificate_key": pair_a["key"]}]}))
    keys = list(wd.glob("*.key"))
    assert keys and "PRIVATE KEY" in keys[0].read_text()
    first_mtime = keys[0].stat().st_mtime_ns
    asyncio.run(d.apply_studio_document({"inbounds": [
        {"protocol": "ovpn",
         "certificate": pair_a["cert"], "certificate_key": pair_a["key"]}]}))
    assert keys[0].stat().st_mtime_ns == first_mtime


def test_openvpn_render_reflects_auth_mode_and_push_options(tmp_path):
    d = _ovpn_driver(tmp_path, auth_mode="static", static_user="off", static_pass="pw",
                     compression="lz4-v2", topology="net30")
    conf = d.render_server_conf("hook.sh")
    assert "auth-user-pass-verify" in conf
    assert "topology net30" in conf
    assert "lz4-v2" in conf
    d2 = _ovpn_driver(tmp_path, auth_mode="management")
    conf2 = d2.render_server_conf("hook.sh")
    assert "management-client-auth" in conf2


# ===================================================================== #
# ssh
# ===================================================================== #

class _SSHFakeBackend:
    def __init__(self):
        self.users: dict[str, str] = {}
        self.service_calls = 0
        self.authorized: list[tuple[str, str]] = []

    def ensure_service(self):
        self.service_calls += 1
        return "fake-drop-in reload"

    def user_exists(self, username):
        return username in self.users

    def authorize_key(self, username, public_key):
        self.authorized.append((username, public_key))


def _ssh_driver(tmp_path, **settings) -> "object":
    from app.cores.drivers.ssh.driver import SSHTunnelDriver

    return SSHTunnelDriver(settings=settings or {}, backend=_SSHFakeBackend())


def test_ssh_apply_maps_authentication_and_settings(tmp_path):
    d = _ssh_driver(tmp_path)
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "protocol": "ssh", "port": 2022, "authentication": "both",
        "shell": "/bin/bash", "sftp": False, "max_sessions": 5,
        "banner": "Welcome", "password": "pw"}]}))
    s = d.settings
    assert s["port"] == 2022
    assert s["password_auth"] is True and s["pubkey_auth"] is True
    assert s["shell"] == "/bin/bash" and s["sftp"] is False
    assert s["max_sessions"] == 5 and s["banner"] == "Welcome"
    assert s["default_password"] == "pw"
    assert d._backend.service_calls == 1   # pushed through ensure_service


def test_ssh_never_both_auth_off_guard(tmp_path):
    d = _ssh_driver(tmp_path, password_auth=False, pubkey_auth=False)
    with pytest.raises(CoreError, match="BOTH password AND public-key"):
        asyncio.run(d.apply_studio_document({"inbounds": [{"protocol": "ssh"}]}))
    assert d._backend.service_calls == 0


def test_ssh_public_key_propagates_to_existing_accounts(tmp_path):
    d = _ssh_driver(tmp_path, default_password="pw")
    backend = d._backend
    unix_name = d._unix_name(_acct("alice", "ssh"))
    backend.users[unix_name] = "pw"
    d._accounts["1.alice"] = _acct("alice", "ssh")
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "protocol": "ssh", "public_key": "ssh-ed25519 AAAA...comment"}]}))
    assert d.settings["default_authorized_key"] == "ssh-ed25519 AAAA...comment"
    assert backend.authorized == [(unix_name, "ssh-ed25519 AAAA...comment")]


def test_ssh_local_backend_authorize_key(tmp_path, monkeypatch):
    from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

    keys_dir = str(tmp_path / "keys")
    monkeypatch.setattr(LocalSystemSSHBackend, "_keys_dir", keys_dir)
    backend = LocalSystemSSHBackend({"dropin_path": str(tmp_path / "dropin.conf")})
    with pytest.raises(CoreError):
        backend.authorize_key("bob", "not-a-real-key-prefix AAAAB3")
    backend.authorize_key("bob", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBobKey")
    key_file = Path(keys_dir) / "bob"
    assert key_file.exists()
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert "ssh-ed25519" in key_file.read_text()
    # idempotent
    backend.authorize_key("bob", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBobKey")
    # drop-in carries the panel-owned AuthorizedKeysFile chain (keys dir + %u)
    text = backend.render_dropin()
    assert f"AuthorizedKeysFile .ssh/authorized_keys {keys_dir}/%u" in text
    # delete_user removes the key file too (userdel stubbed — no host mutation)
    monkeypatch.setattr(LocalSystemSSHBackend, "_run",
                        staticmethod(lambda *a, **k: ""))
    backend.delete_user("bob")
    assert not key_file.exists()


def test_ssh_dropin_keeps_port_22_always(tmp_path):
    from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

    backend = LocalSystemSSHBackend({"port": 2022, "dropin_path": str(tmp_path / "d.conf")})
    text = backend.render_dropin()
    assert "Port 22" in text and "Port 2022" in text


# ===================================================================== #
# hysteria2 / tuic / softether
# ===================================================================== #

def test_hysteria2_apply_maps_settings_and_rejects_two(tmp_path):
    from app.cores.drivers.hysteria2.driver import Hysteria2Driver

    backend = types.SimpleNamespace(
        apply_config=lambda cfg: None,
        is_running=lambda: False,
        restart=lambda: None,
    )
    d = Hysteria2Driver(settings={"work_dir": str(tmp_path)}, backend=backend)
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "protocol": "hysteria2", "port": 4431, "sni": "cdn.example.com",
        "masquerade": "https://www.bing.com", "up_mbps": 100,
        "down_mbps": 200, "obfs": "obfspass"}]}))
    s = d.settings
    assert s["port"] == 4431
    assert s["advertise_sni"] == "cdn.example.com"
    with pytest.raises(CoreError, match="exactly ONE listener"):
        asyncio.run(d.apply_studio_document({"inbounds": [{}, {}]}))


def test_tuic_apply_maps_zero_rtt_and_lists(tmp_path):
    from app.cores.drivers.tuic.driver import TUICDriver

    backend = types.SimpleNamespace(
        apply_config=lambda cfg: None,
        is_running=lambda: False,
        restart=lambda: None,
    )
    d = TUICDriver(settings={"work_dir": str(tmp_path)}, backend=backend)
    asyncio.run(d.apply_studio_document({"inbounds": [{
        "protocol": "tuic", "port": 5443, "zero_rtt": True,
        "congestion_control": "bbr", "ipv6": True}]}))
    s = d.settings
    assert s["port"] == 5443 and s["zero_rtt_handshake"] is True
    assert s["congestion_control"] == "bbr"
    with pytest.raises(CoreError, match="exactly ONE listener"):
        asyncio.run(d.apply_studio_document({"inbounds": [{}, {}]}))


def test_tuic_export_round_trips_zero_rtt(tmp_path):
    from app.cores.drivers.tuic.driver import TUICDriver

    backend = types.SimpleNamespace(
        apply_config=lambda cfg: None,
        is_running=lambda: False,
        restart=lambda: None,
    )
    d = TUICDriver(settings={"work_dir": str(tmp_path),
                             "zero_rtt_handshake": True}, backend=backend)
    doc = d.export_config_document()
    assert doc["inbounds"][0]["zero_rtt"] is True


class _SEFakeBackend:
    def __init__(self, reachable=True):
        self._reachable = reachable
        self.cmds: list[str] = []

    def reachable(self):
        return self._reachable

    def _cmd(self, command, csv=None):
        self.cmds.append(command)
        return ""


def test_softether_requires_reachability_first(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    d = SoftEtherDriver(settings={}, backend=_SEFakeBackend(reachable=False))
    with pytest.raises(CoreError, match="not reachable"):
        asyncio.run(d.apply_studio_document({"inbounds": [{"protocol": "l2tp", "ipsec_psk": "x"}]}))


def test_softether_vpncmd_convergence(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    backend = _SEFakeBackend()
    d = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=backend)
    asyncio.run(d.apply_studio_document({"inbounds": [
        {"protocol": "l2tp", "ipsec_psk": "my-psk"},
        {"protocol": "ovpn", "ports": "995"}]}))
    flat = " | ".join(backend.cmds)
    assert "IPsecEnable /L2TP:yes" in flat and "/PSK:my-psk" in flat
    assert "/DEFAULTHUB:DEFAULT" in flat
    assert "OpenVPNEnable yes /PORTS:995" in flat
    # not-wanted features converge OFF (deleted listeners)
    assert "ListenerDelete 443" in flat and "ListenerDelete 1723" in flat
    # positive: sstp wanted → idempotent create
    backend2 = _SEFakeBackend()
    d2 = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=backend2)
    asyncio.run(d2.apply_studio_document({"inbounds": [{"protocol": "sstp"}]}))
    assert "ListenerCreate 443" in " | ".join(backend2.cmds)
    assert "OpenVPNEnable no" in " | ".join(backend2.cmds) or \
        "IPsecEnable /L2TP:no" in " | ".join(backend2.cmds)


def test_softether_l2tp_requires_psk(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    d = SoftEtherDriver(settings={"hub": "DEFAULT", "ipsec_psk": ""},
                        backend=_SEFakeBackend())
    with pytest.raises(CoreError, match="pre-shared key"):
        asyncio.run(d.apply_studio_document({"inbounds": [{"protocol": "l2tp"}]}))


def test_softether_empty_feature_set_rejected(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    d = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=_SEFakeBackend())
    with pytest.raises(CoreError, match="at least one feature"):
        asyncio.run(d.apply_studio_document({"inbounds": []}))
