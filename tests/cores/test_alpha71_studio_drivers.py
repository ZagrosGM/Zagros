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
    assert entry == {"name": "1.t", "uuid": "legacy-uuid-1", "password": "pw"}
    # The name is not decoration: vendored sing-box's StatsService keys TUIC
    # counters by it, exactly like Hysteria2/VLESS users.


def test_singbox_explicit_hy2_tuic_listen_before_first_grant(tmp_path):
    driver = _singbox(tmp_path)
    driver._studio_doc = {"inbounds": [
        {"tag": "hy-empty", "protocol": "hysteria2", "port": 38443,
         "transport": "quic", "security": "tls"},
        {"tag": "tu-empty", "protocol": "tuic", "port": 38444,
         "transport": "quic", "security": "tls"},
    ]}
    rendered = driver.render_config()["inbounds"]
    assert [(item["type"], item["listen_port"], item["users"])
            for item in rendered] == [
                ("hysteria2", 38443, []), ("tuic", 38444, []),
            ]


def test_singbox_create_account_provisions_credentials_when_missing(tmp_path):
    """alpha.7.2 (batch item 10): no provision may fail for missing
    credentials — the driver mints cryptographically random material INTO
    the passed settings dict (the provisioning flow persists it back)."""
    from app.cores.drivers.singbox.driver import SingBoxDriver

    d = SingBoxDriver(settings={"work_dir": str(tmp_path)}, backend=_SBFakeBackend())
    cases = {"trojan": "password", "shadowsocks": "password",
             "hysteria2": "password", "vless": "id", "vmess": "id"}
    for protocol, key in cases.items():
        account = _acct("empty-" + protocol, protocol)
        assert not account.settings.get(key)
        asyncio.run(d.create_account(account))
        value = account.settings[key]
        assert isinstance(value, str) and len(value) >= 16, (protocol, key)
        stored = d._accounts[account.account_id]
        assert stored.settings.get(key) or stored.settings.get("password")
    # tuic mints uuid AND password
    account = _acct("empty-tuic", "tuic")
    asyncio.run(d.create_account(account))
    assert account.settings.get("uuid") and account.settings.get("password")


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
    def __init__(self, settings=None, family=None):
        self.settings = settings or {"interface": "mzwg0"}
        self.interface = self.settings.get("interface", "mzwg0")
        self.written_key: str | None = None
        self.syncs: list[str] = []
        self.up_calls: list[str] = []
        self.down_calls = 0
        self.running = True
        self.family = family if family is not None else []
        self.family.append(self)

    def for_listener(self, settings):
        return _WGFakeBackend(settings, self.family)

    def ensure_server_keys(self):
        suffix = self.interface[-4:]
        return (f"SERVER_PRIVATE_{suffix}", f"SERVER_PUBLIC_{suffix}")

    def public_from_private(self, private):
        return f"PUB({private})"

    def write_server_private_key(self, private):
        self.written_key = private

    def sync(self, config):
        self.syncs.append(config)

    def down(self):
        self.down_calls += 1
        self.running = False

    def up(self, config):
        self.up_calls.append(config)
        self.running = True

    def wait_ready(self, _port):
        return None

    def is_running(self):
        return self.running


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


def test_wireguard_apply_materializes_multiple_interfaces_and_rejects_wrong_protocol(tmp_path):
    d = _wg_driver(tmp_path)
    asyncio.run(d.apply_studio_document({"inbounds": [
        {"tag": "wg-a", "protocol": "wireguard", "port": 51820,
         "address": "10.90.0.0/24", "endpoint": "a.example.com"},
        {"tag": "wg-b", "protocol": "wireguard", "port": 51821,
         "address": "10.91.0.0/24", "endpoint": "b.example.com"},
    ]}))
    listeners = d.settings["listeners"]
    assert [listener["tag"] for listener in listeners] == ["wg-a", "wg-b"]
    assert [listener["port"] for listener in listeners] == [51820, 51821]
    assert len({listener["interface"] for listener in listeners}) == 2
    assert len(d._backends) == 2
    assert all(backend.running for backend in d._backends.values())
    assert "ListenPort = 51820" in d._backends["wg-a"].up_calls[-1]
    assert "Address = 10.91.0.1/24" in d._backends["wg-b"].up_calls[-1]

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

    def disconnect_log_path(self, tag: str) -> str:
        return f"/tmp/ovpn-listeners/{tag}/disconnect-log.jsonl"

    def configure(self, specs):
        # materialized listener set — keep the rendered confs for assertions
        self.configs = [str(s["server_conf"]) for s in specs]
        self._specs = list(specs)

    def set_auth_handler(self, handler):
        self.auth_handler = handler

    def restart(self):
        self.restarts += 1


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
    # A real OpenVPN server pair needs KU digitalSignature + EKU serverAuth
    # and must be signed by the supplied CA (remote-cert-tls server enforces it).
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca_cert = (_x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key()).serial_number(_x509.random_serial_number())
               .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
               .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
               .add_extension(_x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "server")])
    server_cert = (_x509.CertificateBuilder().subject_name(server_name).issuer_name(ca_name)
                   .public_key(server_key.public_key()).serial_number(_x509.random_serial_number())
                   .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                   .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
                   .add_extension(_x509.KeyUsage(digital_signature=True, content_commitment=False,
                        key_encipherment=True, data_encipherment=False, key_agreement=False,
                        key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
                   .add_extension(_x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(ca_key, hashes.SHA256()))
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    asyncio.run(d.apply_studio_document({"inbounds": [
        {"protocol": "ovpn", "ca_certificate": ca_pem,
         "certificate": cert_pem, "certificate_key": key_pem}]}))
    server_key_path = wd / "server.key"
    assert server_key_path.exists() and "PRIVATE KEY" in server_key_path.read_text()
    first_mtime = server_key_path.stat().st_mtime_ns
    asyncio.run(d.apply_studio_document({"inbounds": [
        {"protocol": "ovpn", "ca_certificate": ca_pem,
         "certificate": cert_pem, "certificate_key": key_pem}]}))
    assert server_key_path.stat().st_mtime_ns == first_mtime


def test_openvpn_render_reflects_auth_mode_and_push_options(tmp_path):
    def _render(d):
        listener = d._listeners()[0]
        return d.render_server_conf(
            listener, hook_path="/wd/hook.sh", mgmt_port=17506,
            log_path="/wd/listeners/openvpn/disconnect-log.jsonl")

    d = _ovpn_driver(tmp_path, auth_mode="static", static_user="off", static_pass="pw",
                     compression="lz4-v2", topology="net30")
    conf = _render(d)
    assert "auth-user-pass-verify" in conf
    assert "verify-client-cert none" in conf
    assert "topology net30" in conf
    assert "lz4-v2" in conf
    assert "management 127.0.0.1 17506" in conf
    d2 = _ovpn_driver(tmp_path, auth_mode="management")
    conf2 = _render(d2)
    assert "management-client-auth" in conf2
    # shared PKI referenced by absolute path (per-listener cwd)
    assert f"ca {tmp_path}/ovpn/ca.crt" in conf2


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
# softether (hysteria2/tuic standalone-driver tests retired in alpha.7.2 —
# both protocols now translate/apply through the sing-box studio path,
# covered by the 26-cell matrix and tests/cores/test_consolidation.py)
# ===================================================================== #

class _SEFakeBackend:
    def __init__(self, reachable=True, ipsec=None):
        from app.cores.drivers.softether.setool import IPsecServices

        self._reachable = reachable
        self.cmds: list[str] = []
        self.ipsec_state = ipsec or IPsecServices(
            l2tp=False, l2tp_raw=False, etherip=False, psk="", default_hub="")

    def reachable(self):
        return self._reachable

    def _cmd(self, command, csv=None, hub=True):
        assert hub is False, "feature switches require entire-server admin context"
        self.cmds.append(command)
        return ""

    def ipsec_get(self):
        self.cmds.append("IPsecGet")
        if isinstance(self.ipsec_state, Exception):
            raise self.ipsec_state
        return self.ipsec_state

    def secure_nat_ensure(self):
        self.cmds.append("SecureNatEnable+DhcpEnable+DhcpGet")

    def ipsec_services_set(self, *, l2tp, l2tp_raw, etherip, psk, default_hub):
        from app.cores.drivers.softether.setool import IPsecServices

        # mirror of LocalSoftEtherBackend's local preflight: the full
        # 5-argument command is only built from non-empty psk + hub, so a
        # test asserting the arg string also asserts the validation
        assert psk and default_hub, "preflight: empty psk/hub must never reach vpncmd"
        yn = lambda b: "yes" if b else "no"  # noqa: E731
        psk_arg = f'"{psk}"' if any(ch.isspace() for ch in psk) else psk
        self.cmds.append(
            f"IPsecEnable /L2TP:{yn(l2tp)} /L2TPRAW:{yn(l2tp_raw)} "
            f"/ETHERIP:{yn(etherip)} /PSK:{psk_arg} /DEFAULTHUB:{default_hub}")
        self.ipsec_state = IPsecServices(
            l2tp=l2tp, l2tp_raw=l2tp_raw, etherip=etherip,
            psk=psk, default_hub=default_hub)


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
        {"protocol": "sstp"}]}))
    flat = " | ".join(backend.cmds)
    assert "IPsecGet" in backend.cmds
    assert "SecureNatEnable+DhcpEnable+DhcpGet" in backend.cmds
    assert ("IPsecEnable /L2TP:yes /L2TPRAW:no /ETHERIP:no "
            "/PSK:my-psk /DEFAULTHUB:DEFAULT") in flat
    # SSTP is a real protocol switch plus a TCP listener. It is never
    # represented as PPTP and never asks for the L2TP PSK.
    assert "SstpEnable yes" in flat and "ListenerCreate 443" in flat
    assert "PPTP" not in flat and "ListenerCreate 1723" not in flat

    backend2 = _SEFakeBackend()
    d2 = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=backend2)
    asyncio.run(d2.apply_studio_document({"inbounds": [{"protocol": "sstp"}]}))
    flat2 = " | ".join(backend2.cmds)
    assert "SstpEnable yes" in flat2 and "ListenerCreate 443" in flat2
    assert "IPsecEnable" not in flat2
    assert "pre-shared key" not in flat2.lower()


def test_softether_custom_sstp_port_is_materialized_and_delivered(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    backend = _SEFakeBackend()
    driver = SoftEtherDriver(
        settings={"hub": "DEFAULT", "advertise_host": "vpn.example.com"},
        backend=backend)
    asyncio.run(driver.apply_studio_document({"inbounds": [{
        "tag": "sstp-custom", "protocol": "sstp", "port": 46704,
    }]}))
    flat = " | ".join(backend.cmds)
    assert "SstpEnable yes" in flat
    assert "ListenerCreate 46704" in flat
    assert driver.settings["sstp_port"] == 46704
    assert driver.export_config_document()["inbounds"][0] == {
        "tag": "sstp-custom", "protocol": "sstp", "port": 46704,
    }
    account = _acct(
        "sstp", "sstp", password="pw", inbound_tags=["sstp-custom"])
    profile = asyncio.run(driver.describe_delivery(account))
    port_field = next(
        field.value
        for artifact in profile.sections[0].artifacts
        for field in artifact.fields
        if field.key == "port"
    )
    assert port_field == "46704/tcp"
    config = asyncio.run(driver.build_client_config(account))
    assert config.payload["port"] == 46704


def test_softether_legacy_fake_l2tp_port_normalizes_to_standard(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    backend = _SEFakeBackend()
    driver = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=backend)
    document = {"inbounds": [{
        "tag": "l2tp-old", "protocol": "l2tp", "port": 19592,
        "ipsec_psk": "valid-psk",
    }]}
    asyncio.run(driver.apply_studio_document(document))
    assert document["inbounds"][0]["port"] == 1701
    assert driver.export_config_document()["inbounds"][0]["port"] == 1701
    assert not any("19592" in command for command in backend.cmds)


def test_softether_l2tp_raw_preserves_wizard_tag(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    backend = _SEFakeBackend()
    driver = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=backend)
    asyncio.run(driver.apply_studio_document({"inbounds": [{
        "tag": "raw-custom-1701", "protocol": "l2tp_raw", "port": 1701,
    }]}))
    assert driver.settings["feature_l2tp_raw"] is True
    assert driver.settings["feature_tags"]["l2tp_raw"] == "raw-custom-1701"
    assert driver.export_config_document()["inbounds"][0]["tag"] == "raw-custom-1701"
    assert "/L2TP:no /L2TPRAW:yes /ETHERIP:no" in " | ".join(backend.cmds)
    assert "SecureNatEnable+DhcpEnable+DhcpGet" in backend.cmds


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


def test_softether_disable_preserves_server_psk_and_hub(tmp_path):
    """The item-7 regression (alpha.7.4 rc=38): disabling L2TP must still
    send the FULL 5-argument command built from the server's CURRENT
    PSK + hub (never a /PSK:-less string), and the settings store is not
    clobbered by the disable."""
    from app.cores.drivers.softether.driver import SoftEtherDriver
    from app.cores.drivers.softether.setool import IPsecServices

    state = IPsecServices(l2tp=True, l2tp_raw=False, etherip=True,
                          psk="srv-psk", default_hub="MAIN")
    backend = _SEFakeBackend(ipsec=state)
    d = SoftEtherDriver(settings={"hub": "DEFAULT", "ipsec_psk": "stored"},
                        backend=backend)
    asyncio.run(d.apply_studio_document({"inbounds": [{"protocol": "sstp"}]}))
    flat = " | ".join(backend.cmds)
    assert ("IPsecEnable /L2TP:no /L2TPRAW:no /ETHERIP:no "
            "/PSK:srv-psk /DEFAULTHUB:MAIN") in flat
    assert d.settings["ipsec_psk"] == "stored"  # untouched by the disable
    assert d.settings["feature_l2tp"] is False


def test_softether_enable_psk_preference_order(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver
    from app.cores.drivers.softether.setool import IPsecServices

    state = IPsecServices(l2tp=False, l2tp_raw=False, etherip=False,
                          psk="server-psk", default_hub="HUBX")
    # Without fresh wizard input, IPsecGet is authoritative over a stale
    # persisted value (the field bug showed "vpn" while the server used a
    # different key); hub also comes from IPsecGet.
    backend = _SEFakeBackend(ipsec=state)
    d = SoftEtherDriver(settings={"hub": "DEFAULT", "ipsec_psk": "stored"},
                        backend=backend)
    asyncio.run(d.apply_studio_document({"inbounds": [{"protocol": "l2tp"}]}))
    assert "/PSK:server-psk /DEFAULTHUB:HUBX" in " | ".join(backend.cmds)
    assert d.settings["ipsec_psk"] == "server-psk"
    # with no stored PSK the server's own PSK is reused
    backend2 = _SEFakeBackend(ipsec=state)
    d2 = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=backend2)
    asyncio.run(d2.apply_studio_document({"inbounds": [{"protocol": "l2tp"}]}))
    assert "/PSK:server-psk /DEFAULTHUB:HUBX" in " | ".join(backend2.cmds)


def test_softether_stable_openvpn_switch_and_pptp_honesty(tmp_path):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    d = SoftEtherDriver(settings={"hub": "DEFAULT"}, backend=_SEFakeBackend())
    asyncio.run(d.apply_studio_document(
        {"inbounds": [{"protocol": "ovpn", "port": 995}]}))
    assert "OpenVpnEnable yes /PORTS:995" in d._backend.cmds
    assert d.settings["feature_ovpn"] is True

    with pytest.raises(CoreError, match="does not implement PPTP"):
        asyncio.run(d.apply_studio_document(
            {"inbounds": [{"protocol": "pptp"}]}))


def test_softether_ipsec_backend_local_preflight(monkeypatch):
    """LocalSoftEtherBackend.ipsec_services_set — the exact rc=38 guard:
    an EMPTY psk must die locally (never reaching vpncmd), whitespace PSKs
    get quoted for shlex.split, and parse_ipsec_get consumes real tables."""
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend
    from app.cores.drivers.softether.setool import parse_ipsec_get

    backend = LocalSoftEtherBackend({"hub": "DEFAULT"})
    sent: list[str] = []
    monkeypatch.setattr(
        backend, "_cmd",
        lambda command, csv=False, hub=True: (
            (_ for _ in ()).throw(AssertionError("IPsec must be server-scoped"))
            if hub else sent.append(command) or ""
        ),
    )

    backend.ipsec_services_set(l2tp=False, l2tp_raw=False, etherip=False,
                               psk="abc123", default_hub="DEFAULT")
    assert sent == ["IPsecEnable /L2TP:no /L2TPRAW:no /ETHERIP:no "
                    "/PSK:abc123 /DEFAULTHUB:DEFAULT"]
    for bad in ("", "   ", None):
        with pytest.raises(CoreError, match="pre-shared key"):
            backend.ipsec_services_set(l2tp=False, l2tp_raw=False, etherip=False,
                                       psk=bad, default_hub="DEFAULT")
    assert len(sent) == 1  # nothing reached vpncmd for the refused calls
    with pytest.raises(CoreError, match="default hub"):
        backend.ipsec_services_set(l2tp=True, l2tp_raw=False, etherip=False,
                                   psk="x", default_hub="")
    with pytest.raises(CoreError, match="quote/newline"):
        backend.ipsec_services_set(l2tp=True, l2tp_raw=False, etherip=False,
                                   psk='a"b', default_hub="DEFAULT")
    backend.ipsec_services_set(l2tp=True, l2tp_raw=False, etherip=False,
                               psk="my pass phrase", default_hub="DEFAULT")
    assert sent[-1] == ('IPsecEnable /L2TP:yes /L2TPRAW:no /ETHERIP:no '
                        '/PSK:"my pass phrase" /DEFAULTHUB:DEFAULT')

    table = (
        "SoftEther VPN Command Line Management Utility (vpncmd command) Version 5.02\n"
        "Connected to VPN Server \"localhost\".\n\n"
        "Item                              |Value\n"
        "----------------------------------+---------\n"
        "L2TP over IPsec Server Function   |Yes\n"
        "Raw L2TP Server Function          |No\n"
        "EtherIP / L2TPv3 over IPsec Server Function |No\n"
        "Pre-Shared Key                    |secret-psk\n"
        "Default Virtual HUB               |DEFAULT\n\n"
        "The command completed successfully.\n"
    )
    svc = parse_ipsec_get(table)
    assert (svc.l2tp, svc.l2tp_raw, svc.etherip) == (True, False, False)
    assert svc.psk == "secret-psk" and svc.default_hub == "DEFAULT"
    assert svc.any_enabled
    empty = parse_ipsec_get("")
    assert not empty.any_enabled and empty.psk == "" and empty.default_hub == ""


# --------------------------------------------------------------------- #
# alpha.7.5 item 10 — controlled / cached / observable source build
# --------------------------------------------------------------------- #

def test_softether_build_jobs_bounded(monkeypatch):
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({})
    monkeypatch.setattr("os.cpu_count", lambda: 64)
    monkeypatch.delenv("ZAGROS_SOFTETHER_BUILD_JOBS", raising=False)
    assert backend._build_jobs() == 4  # capped, never full-throttle
    monkeypatch.setattr("os.cpu_count", lambda: 2)
    assert backend._build_jobs() == 2
    monkeypatch.setenv("ZAGROS_SOFTETHER_BUILD_JOBS", "8")
    assert backend._build_jobs() == 8
    monkeypatch.setenv("ZAGROS_SOFTETHER_BUILD_JOBS", "999")
    assert backend._build_jobs() == 16  # hard ceiling on the override too
    monkeypatch.setenv("ZAGROS_SOFTETHER_BUILD_JOBS", "junk")
    assert backend._build_jobs() == 2  # invalid override → safe default


def test_softether_run_streamed_progress_and_errors(monkeypatch, caplog):
    import logging

    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({})
    out = backend._run_streamed(
        ["/bin/sh", "-c", "printf '[ 10%%] Building C object x\\n[ 95%%] Linking\\nBuilt target vpnserver\\n'"],
        timeout=30)
    with caplog.at_level(logging.INFO, logger="zagros.cores.drivers.softether"):
        backend._run_streamed(
            ["/bin/sh", "-c", "printf '[ 10%%] Building C object x\\n'"],
            timeout=30)
    assert any("softether build: [ 10%] Building C object x" in r.message
               for r in caplog.records)
    assert "Built target vpnserver" in out
    with pytest.raises(CoreError, match="rc=1"):
        backend._run_streamed(
            ["/bin/sh", "-c", "echo make: Error 2 >&2; exit 1"], timeout=30)
    with pytest.raises(CoreError, match="timed out"):
        backend._run_streamed(["/bin/sh", "-c", "sleep 3"], timeout=0.3)


def test_softether_install_from_source_cached_and_targeted(tmp_path, monkeypatch):
    """Item 10: the source build (a) is targeted (no client/bridge/vpntest),
    (b) is bounded-parallel, (c) caches the source tree so a RETRY resumes
    without re-downloading, (d) reports the tag honestly on success."""
    import io
    import tarfile

    from app.cores import github_install
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    cache = tmp_path / "cache"
    install_root = tmp_path / "installroot"
    monkeypatch.setenv("ZAGROS_SOFTETHER_SRC_CACHE", str(cache))
    monkeypatch.delenv("ZAGROS_SOFTETHER_BUILD_JOBS", raising=False)
    monkeypatch.setattr("os.cpu_count", lambda: 32)

    backend = LocalSoftEtherBackend({})
    monkeypatch.setattr(backend, "_INSTALL_ROOT", str(install_root))
    monkeypatch.setattr(backend, "_ensure_build_deps", lambda: None)
    monkeypatch.setattr(backend, "_link_on_path", lambda root: None)
    monkeypatch.setattr(
        github_install, "fetch_latest_release",
        lambda repo: {"tag_name": "5.02.5187", "assets": []})

    # a minimal but valid "source tree" tarball
    src_bytes = io.BytesIO()
    with tarfile.open(fileobj=src_bytes, mode="w:gz") as tar:
        data = b"cmake_minimum_required(VERSION 3.10)\n"
        info = tarfile.TarInfo("SoftEtherVPN-5.02.5187/CMakeLists.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    downloads: list[str] = []
    monkeypatch.setattr(
        backend, "_download",
        lambda url, dest, timeout=900.0: (
            downloads.append(url),
            open(dest, "wb").write(src_bytes.getvalue()),
        )[-1])

    ran: list[list[str]] = []

    def fake_run(argv, *, timeout=120.0):
        ran.append(argv)
        return ""

    def fake_streamed(argv, *, timeout):
        ran.append(argv)
        build_dir = argv[2]
        import os as _os
        _os.makedirs(build_dir, exist_ok=True)  # the real configure step creates it
        for name in ("vpnserver", "vpncmd", "hamcore.se2"):
            open(_os.path.join(build_dir, name), "wb").write(b"bin")
        return ""

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr(backend, "_run_streamed", fake_streamed)

    first = backend._install_from_source()
    assert "5.02.5187" in first
    build_calls = [a for a in ran if a[:2] == ["cmake", "--build"]]
    assert len(build_calls) == 1
    argv = build_calls[0]
    assert "--parallel" in argv and argv[argv.index("--parallel") + 1] == "4"
    targets = argv[argv.index("--target") + 1:]
    assert targets == ["cedar", "mayaqua", "hamcore-archive-build",
                       "vpnserver", "vpncmd"]
    # NOT built: the panel never installs the client/bridge/test binaries
    assert all(t not in targets for t in ("vpnclient", "vpnbridge", "vpntest"))
    assert (install_root / "vpnserver").exists()
    assert (cache / "5.02.5187" / ".complete").exists()

    # retry: NO re-download, configure+build resume from the cached tree
    ran.clear()
    second = backend._install_from_source()
    assert downloads and len(downloads) == 1
    assert "5.02.5187" in second
    assert [a for a in ran if a[:2] == ["cmake", "--build"]]  # resumed build


# ===================================================================== #
# alpha.7.5 item 4 + 6 — headers depth & certificate path mode
# ===================================================================== #

def _xray(tmp_path):
    from app.cores.drivers.xray.driver import XrayDriver

    return XrayDriver(settings={"cert_dir": str(tmp_path / "certs")})


def _xr_translate(driver, **entry):
    base = {"tag": "t1", "listen": "0.0.0.0", "port": 1443}
    base.update(entry)
    return driver._studio_entry_to_native(base)


# ---- xray: ws headers / grpc multiMode / RAW-TCP http camouflage ----

def test_xray_ws_arbitrary_headers_merge_with_host(tmp_path):
    d = _xray(tmp_path)
    ib = _xr_translate(d, protocol="vless", transport="ws", security="none",
                       path="/w", host="cdn.example.com",
                       headers="Accept: */*\nX-Trace: 42\nHost: ignored.example.com")
    ss = ib["streamSettings"]["wsSettings"]
    assert ss["path"] == "/w"
    # the explicit Host field wins over the pasted Host line; the rest lands
    assert ss["headers"] == {"Accept": "*/*", "X-Trace": "42",
                             "Host": "cdn.example.com"}


def test_xray_ws_invalid_header_line_fails_loudly(tmp_path):
    d = _xray(tmp_path)
    with pytest.raises(CoreError, match="no 'Name: value'"):
        _xr_translate(d, protocol="vless", transport="ws", security="none",
                      headers="NotAHeader")


def test_xray_grpc_multi_mode_maps_to_multiMode(tmp_path):
    d = _xray(tmp_path)
    ib = _xr_translate(d, protocol="vless", transport="grpc", security="none",
                       service_name="svc", multi_mode=True)
    grpc = ib["streamSettings"]["grpcSettings"]
    assert grpc["serviceName"] == "svc" and grpc["multiMode"] is True
    # absent → key omitted (no phantom defaults)
    ib2 = _xr_translate(d, protocol="vless", transport="grpc", security="none",
                        service_name="svc")
    assert "multiMode" not in ib2["streamSettings"]["grpcSettings"]


def test_xray_tcp_http_camouflage_full_object(tmp_path):
    d = _xray(tmp_path)
    ib = _xr_translate(
        d, protocol="vless", transport="tcp", security="none",
        header_type="http", http_method="post", path="/api,/v2",
        host="static.example.com",
        request_headers="Accept: */*\nAccept: text/html",  # last wins per name
        response_status=404, response_reason="Not Found",
        response_headers="Server: nginx")
    hdr = ib["streamSettings"]["tcpSettings"]["header"]
    assert hdr["type"] == "http"
    assert hdr["request"]["method"] == "POST"
    assert hdr["request"]["path"] == ["/api", "/v2"]
    assert hdr["request"]["headers"]["Host"] == "static.example.com"
    assert hdr["request"]["headers"]["Accept"] == "text/html"
    assert hdr["response"] == {"version": "1.1", "status": "404",
                               "reason": "Not Found",
                               "headers": {"Server": "nginx"}}


def test_xray_tcp_camouflage_guards(tmp_path):
    d = _xray(tmp_path)
    # http facts with header_type=none → named contradiction
    with pytest.raises(CoreError, match="require header_type=http"):
        _xr_translate(d, protocol="vless", transport="tcp", security="none",
                      http_method="GET")
    # unknown header type → loud
    with pytest.raises(CoreError, match="not an xray RAW header"):
        _xr_translate(d, protocol="vless", transport="tcp", security="none",
                      header_type="udp")
    # reality + http header → handshake breaker, refused upfront
    with pytest.raises(CoreError, match="REALITY already camouflages"):
        _xr_translate(d, protocol="vless", transport="tcp", security="reality",
                      sni="www.microsoft.com", header_type="http")
    # plain tcp stays clean — no tcpSettings at all
    ib = _xr_translate(d, protocol="vless", transport="tcp", security="none")
    assert "tcpSettings" not in ib["streamSettings"]


# ---- xray: certificate path mode + upload validation unification ----

def _pem_pair(tmp_path, name="a"):
    from app.utils.crypto import generate_certificate

    p = generate_certificate()
    (tmp_path / f"{name}.crt").write_text(p["cert"])
    (tmp_path / f"{name}.key").write_text(p["key"])
    return p, str(tmp_path / f"{name}.crt"), str(tmp_path / f"{name}.key")


def test_xray_tls_certificate_path_mode_references_files_in_place(tmp_path):
    d = _xray(tmp_path)
    _p, crt, key = _pem_pair(tmp_path)
    ib = _xr_translate(d, protocol="vless", transport="tcp", security="tls",
                       sni="example.com", certificate_path=crt,
                       certificate_key_path=key)
    tls = ib["streamSettings"]["tlsSettings"]
    # referenced IN PLACE — never copied into the core cert dir
    assert tls["certificates"][0] == {"certificateFile": crt, "keyFile": key}


def test_xray_tls_rejects_bad_path_mismatched_and_garbage_pairs(tmp_path):
    d = _xray(tmp_path)
    _pa, ca, ka = _pem_pair(tmp_path, "a")
    _pb, cb, kb = _pem_pair(tmp_path, "b")
    with pytest.raises(CoreError, match="not found"):
        _xr_translate(d, protocol="vless", transport="tcp", security="tls",
                      sni="e.com", certificate_path=str(tmp_path / "nope.crt"),
                      certificate_key_path=ka)
    with pytest.raises(CoreError, match="do NOT match"):
        _xr_translate(d, protocol="vless", transport="tcp", security="tls",
                      sni="e.com", certificate_path=ca, certificate_key_path=kb)
    # pasted garbage now fails validation too (unified rules — was: written
    # to disk blind, died at core start)
    with pytest.raises(CoreError, match="not a valid PEM"):
        _xr_translate(d, protocol="vless", transport="tcp", security="tls",
                      sni="e.com", certificate="garbage",
                      certificate_key=_pa["key"])


# ---- sing-box: ws/http headers + http method + cert path mode ----

def test_singbox_ws_headers_text_parse_and_host_precedence(tmp_path):
    d = _singbox(tmp_path)
    ib = _sb_translate(d, protocol="vless", transport="ws", security="none",
                       path="/w", host="cdn.example.com",
                       headers="Accept: */*\nHost: overridden.example.com")
    assert ib["transport"] == {
        "type": "ws", "path": "/w",
        "headers": {"Accept": "*/*", "Host": "cdn.example.com"}}


def test_singbox_http_transport_method_and_headers(tmp_path):
    d = _singbox(tmp_path)
    ib = _sb_translate(d, protocol="vless", transport="http", security="none",
                       path="/h", host="a.example.com", http_method="PUT",
                       headers="X-Tenant: blue")
    tr = ib["transport"]
    assert tr["type"] == "http" and tr["path"] == "/h"
    assert tr["method"] == "PUT"
    assert tr["host"] == ["a.example.com"]
    assert tr["headers"] == {"X-Tenant": "blue"}


def test_singbox_tls_certificate_path_mode(tmp_path):
    d = _singbox(tmp_path)
    _p, crt, key = _pem_pair(tmp_path)
    ib = _sb_translate(d, protocol="vless", transport="tcp", security="tls",
                       sni="example.com", certificate_path=crt,
                       certificate_key_path=key)
    assert ib["tls"]["certificate_path"] == crt
    assert ib["tls"]["key_path"] == key
    # mismatched pair → precise CoreError, no files touched
    _p2, _c2, k2 = _pem_pair(tmp_path, "b")
    with pytest.raises(CoreError, match="do NOT match"):
        _sb_translate(d, protocol="vless", transport="tcp", security="tls",
                      sni="example.com", certificate_path=crt,
                      certificate_key_path=k2)
