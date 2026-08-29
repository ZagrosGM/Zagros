"""Server-identity federation — the material a client uses to trust the SERVER.

A multi-node panel is only usable if a profile keeps working when its address
is switched from the master to a node. That needs three things to travel to
the node: the inbound document, the accounts, and the SERVER IDENTITY (CA /
server keypair / IPsec PSK). This file pins the identity contract:

  * a core with no server identity exports nothing (and never raises)
  * WireGuard exports its persisted keypair and adopts a foreign one
  * WireGuard refuses a malformed key instead of writing it
  * OpenVPN exports the PKI and rejects a bundle whose cert does not match
  * SoftEther exports the IPsec PSK and pushes it to a live daemon
  * the base contract rejects material for a core that cannot hold any
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from app.cores.exceptions import CoreError  # noqa: E402


def _wg_driver(tmp: str, **extra):
    from app.cores.drivers.wireguard.backend import LocalWireGuardBackend
    from app.cores.drivers.wireguard.driver import WireGuardDriver

    settings = {"work_dir": tmp, "advertise_host": "127.0.0.1",
                "allow_loopback_advertise": True}
    settings.update(extra)
    backend = LocalWireGuardBackend(settings)
    return WireGuardDriver(settings, backend=backend), backend


# --------------------------------------------------------------------------- #
# the contract: cores without server identity
# --------------------------------------------------------------------------- #
def test_core_without_identity_exports_nothing_and_rejects_material():
    from app.cores.base import BaseCoreDriver
    from app.cores.drivers.xray.driver import XrayDriver

    driver = object.__new__(XrayDriver)
    assert driver.export_identity() == {}
    assert driver.import_identity({}) == []
    try:
        driver.import_identity({"server.key": "abc"})
    except NotImplementedError as exc:
        assert "xray" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("material must be rejected for a core with no identity")


def test_xray_has_no_identity_to_federate():
    """xray users travel inside the document; the server has no key material."""
    from app.cores.drivers.xray.driver import XrayDriver

    driver = object.__new__(XrayDriver)
    assert XrayDriver.export_identity(driver) == {}


# --------------------------------------------------------------------------- #
# WireGuard
# --------------------------------------------------------------------------- #
def test_wireguard_round_trips_its_server_keypair():
    with tempfile.TemporaryDirectory() as tmp:
        driver, backend = _wg_driver(tmp)
        private, public = backend.ensure_server_keys()

        exported = driver.export_identity()
        assert exported == {"server.key": private}

        # a second host (the node) adopts it and ends up with the same PUBLIC key
        with tempfile.TemporaryDirectory() as node_tmp:
            node_driver, node_backend = _wg_driver(node_tmp)
            node_private, node_public = node_backend.ensure_server_keys()
            assert node_public != public  # generated independently

            applied = node_driver.import_identity(exported)
            assert applied == ["server.key"]

            node_private2, node_public2 = node_backend.ensure_server_keys()
            assert node_public2 == public  # the federated identity
            assert node_private2 == private


def test_wireguard_rejects_a_malformed_identity():
    with tempfile.TemporaryDirectory() as tmp:
        driver, backend = _wg_driver(tmp)
        backend.ensure_server_keys()
        before = backend.read_server_private_key()
        try:
            driver.import_identity({"server.key": "not-a-wg-key"})
        except CoreError:
            pass
        else:  # pragma: no cover
            raise AssertionError("a malformed private key must be refused")
        assert backend.read_server_private_key() == before  # untouched


def test_wireguard_export_is_read_only():
    """An unconfigured core has no identity — export must NOT generate one."""
    with tempfile.TemporaryDirectory() as tmp:
        driver, backend = _wg_driver(tmp)
        assert driver.export_identity() == {}
        assert not os.path.exists(os.path.join(tmp, "server.key"))


# --------------------------------------------------------------------------- #
# OpenVPN
# --------------------------------------------------------------------------- #
def _openvpn_driver(tmp: str):
    from app.cores.drivers.openvpn.driver import OpenVPNDriver

    settings = {"work_dir": tmp, "listen": "127.0.0.1", "port": 11940,
                "proto": "tcp", "subnet": "10.9.0.0",
                "netmask": "255.255.255.0", "management_port": 17555,
                "advertise_host": "127.0.0.1", "allow_loopback_advertise": True}
    return OpenVPNDriver(settings, backend=_FakeOpenVPNBackend())


class _FakeOpenVPNBackend:
    def ensure_pki(self):
        return {"ca_crt": "CA", "tls_crypt": "TA"}

    def missing_dependencies(self):
        return {}

    def is_installed(self):
        return True


def test_openvpn_exports_and_adopts_its_pki():
    with tempfile.TemporaryDirectory() as tmp:
        driver = _openvpn_driver(tmp)
        driver._pki = None
        # seed a minimal, valid PKI the way ensure_pki would
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zagros-ovpn-ca")])
        now = datetime.datetime.now(datetime.timezone.utc)
        ca = (x509.CertificateBuilder()
              .subject_name(name).issuer_name(name)
              .public_key(ca_key.public_key()).serial_number(1)
              .not_valid_before(now - datetime.timedelta(days=1))
              .not_valid_after(now + datetime.timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                             critical=True)
              .sign(ca_key, hashes.SHA256()))
        srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        srv = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(
                   NameOID.COMMON_NAME, "zagros-ovpn-server")]))
               .issuer_name(ca.subject).public_key(srv_key.public_key())
               .serial_number(2)
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.KeyUsage(True, False, False, False, False,
                                            False, False, False, False),
                              critical=True)
               .add_extension(x509.ExtendedKeyUsage(
                   [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
               .sign(ca_key, hashes.SHA256()))

        def pem(obj, key=False):
            return (obj.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption())
                    if key else
                    obj.public_bytes(serialization.Encoding.PEM)).decode()

        for name_, text, mode in (
                ("ca.crt", pem(ca), 0o644),
                ("ca.key", pem(ca_key, True), 0o600),
                ("server.crt", pem(srv), 0o644),
                ("server.key", pem(srv_key, True), 0o600),
                ("ta.key", "TLS-CRYPT-KEY", 0o600)):
            path = os.path.join(tmp, name_)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(path, mode)

        exported = driver.export_identity()
        assert set(exported) >= {"ca.crt", "server.crt", "server.key", "ta.key"}

        # a node adopts it — the CA a client already trusts is now served there
        with tempfile.TemporaryDirectory() as node_tmp:
            node = _openvpn_driver(node_tmp)
            applied = node.import_identity(exported)
            assert "ca.crt" in applied and "server.key" in applied
            with open(os.path.join(node_tmp, "ca.crt"), encoding="utf-8") as fh:
                assert fh.read() == exported["ca.crt"]
            assert oct(os.stat(os.path.join(node_tmp, "server.key")).st_mode)[-3:] == "600"


def test_openvpn_refuses_a_mismatched_identity_bundle():
    with tempfile.TemporaryDirectory() as tmp:
        driver = _openvpn_driver(tmp)
        try:
            driver.import_identity({"ca.crt": "-----BEGIN CERTIFICATE-----\nnope\n"
                                              "-----END CERTIFICATE-----\n"})
        except CoreError:
            pass
        else:  # pragma: no cover
            raise AssertionError("an invalid CA must be refused before writing")


# --------------------------------------------------------------------------- #
# SoftEther
# --------------------------------------------------------------------------- #
class _FakeSoftEtherBackend:
    def __init__(self):
        from app.cores.drivers.softether.setool import IPsecServices

        self.current = IPsecServices(l2tp=True, l2tp_raw=False, etherip=False,
                                     psk="old-psk", default_hub="DEFAULT")
        self.ipsec_set_calls: list[str] = []

    def ipsec_get(self):
        return self.current

    def ipsec_services_set(self, *, l2tp, l2tp_raw, etherip, psk, default_hub):
        self.ipsec_set_calls.append(psk)
        self.current = type(self.current)(l2tp=l2tp, l2tp_raw=l2tp_raw,
                                          etherip=etherip, psk=psk,
                                          default_hub=default_hub)
        return self.current


def _softether_driver(backend):
    from app.cores.drivers.softether.driver import SoftEtherDriver

    settings = {"hub": "DEFAULT", "ipsec_psk": "master-psk"}
    driver = SoftEtherDriver(settings, backend=backend)
    return driver


def test_softether_exports_and_pushes_the_master_psk():
    backend = _FakeSoftEtherBackend()
    driver = _softether_driver(backend)

    exported = driver.export_identity()
    assert exported == {"ipsec_psk": "master-psk"}

    # node side: same driver, but the daemon came up with its own PSK
    node_backend = _FakeSoftEtherBackend()
    node = _softether_driver(node_backend)
    node.settings["ipsec_psk"] = "node-generated"

    applied = asyncio.run(node.import_identity(exported))
    assert applied == ["ipsec_psk"]
    assert node.settings["ipsec_psk"] == "master-psk"
    # pushed live, so no restart is needed for clients to connect
    assert node_backend.ipsec_set_calls == ["master-psk"]


def test_softether_tolerates_a_down_daemon():
    class _Down:
        def ipsec_get(self):
            raise CoreError("vpncmd is not running")

    node = _softether_driver(_Down())
    applied = asyncio.run(node.import_identity({"ipsec_psk": "master-psk"}))
    assert applied == ["ipsec_psk"]
    assert node.settings["ipsec_psk"] == "master-psk"  # applied on next start
