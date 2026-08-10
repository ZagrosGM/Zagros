"""WireGuard driver tests — real protocol fixtures:

  * actual `wg show all dump` text parsing (interfaces + peers)
  * `wg-quick strip` equivalence for syncconf payloads
  * lowest-free IP allocation (+ exhaustion, server reservation)
  * live peer add/remove/suspend/resume via syncconf (never restart)
  * usage deltas from cumulative rx/tx incl. counter-reset clamping
  * online detection via latest-handshake threshold
  * key rotation (old key dies, new key works)
  * client profile rendering + QR determinism
  * chain ingress peer provisioning + state persistence across restarts
  * concurrent provisioning race safety

Run: pytest tests/cores/test_wireguard_driver.py -v   OR   python tests/cores/test_wireguard_driver.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
import traceback
import types as _types
from pathlib import Path

import pytest
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import Capability, CoreError  # noqa: E402
from app.cores.drivers.wireguard import (  # noqa: E402
    WireGuardDriver,
    allocate_address,
    is_valid_key,
    parse_wg_dump,
    render_interface,
    server_address,
    strip_config,
)
from app.cores.types import HealthStatus, UserAccount  # noqa: E402

KEY_ALICE = "ALICE" + "A" * 38 + "="
KEY_BOB = "BOBBOB" + "B" * 37 + "="
KEY_SERVER = "SERVER" + "C" * 37 + "="
PSK_ALICE = "PSKPSK" + "D" * 37 + "="
KEY_CHAIN = "CHAINN" + "E" * 37 + "="

NOW = int(time.time())

# Real-shaped `wg show all dump` (interface line + two peers, one offline)
DUMP_SAMPLE = (
    "mzwg0\tServerPriv\t{srv}\t51820\toff\n"
    "mzwg0\t{alice}\t{psk}\t198.51.100.7:60123\t10.66.66.2/32\t{hs}\t1048576\t2097152\t0\n"
    "mzwg0\t{bob}\t(none)\t(none)\t10.66.66.3/32\t0\t0\t0\t0\n"
).format(srv=KEY_SERVER, alice=KEY_ALICE, psk=PSK_ALICE, bob=KEY_BOB, hs=NOW - 42)

DUMP_ALICE_GREW = DUMP_SAMPLE.replace("\t1048576\t2097152\t", "\t1572864\t2097152\t")
DUMP_ALICE_RESET = DUMP_SAMPLE.replace("\t1048576\t2097152\t", "\t1000\t1000\t")


class FakeWireGuardBackend:
    """Fake WireGuardBackend: canned keys, recorded up/sync/down, queued dumps."""

    def __init__(self, dump_text: str = DUMP_SAMPLE):
        self.dump_text = dump_text
        self.synced: list[str] = []
        self.up_calls: list[str] = []
        self.down_calls = 0
        self.running = True
        self._key_counter = 0

    # setup ---------------------------------------------------------- #
    def is_installed(self) -> bool:
        return True

    def install_packages(self) -> str:
        return "installed-fake"

    def ensure_server_keys(self) -> tuple[str, str]:
        return ("SERVER_PRIVATE", KEY_SERVER)

    def generate_keypair(self) -> tuple[str, str]:
        self._key_counter += 1
        pub = ("K%d" % self._key_counter).ljust(43, "K") + "="
        return (f"private-{self._key_counter}", pub)

    def generate_preshared(self) -> str:
        return "P".ljust(43, "S") + "="

    # lifecycle ------------------------------------------------------ #
    def up(self, config_text: str) -> None:
        self.up_calls.append(config_text)
        self.running = True

    def sync(self, config_text: str) -> None:
        self.synced.append(config_text)

    def down(self) -> None:
        self.down_calls += 1
        self.running = False

    def is_running(self) -> bool:
        return self.running

    # telemetry ------------------------------------------------------ #
    def dump(self):
        return parse_wg_dump(self.dump_text)

    def version(self) -> str | None:
        return "v1.0.20210914"

    def logs(self, tail: int = 200):
        return ["wireguard: fake log"]

    def metrics(self):
        from app.cores.types import CoreMetrics

        return CoreMetrics(active_accounts=len(self.dump().peers))


def _account(user: int, name: str, enabled: bool = True, settings: dict | None = None) -> UserAccount:
    return UserAccount(
        user_id=user, username=name, account_id=f"{user}.{name}",
        protocol="wireguard", enabled=enabled, settings=settings or {},
    )


def _driver(tmp: str | None = None, dump: str = DUMP_SAMPLE) -> tuple[WireGuardDriver, FakeWireGuardBackend]:
    backend = FakeWireGuardBackend(dump)
    settings: dict[str, Any] = {"work_dir": tmp or tempfile.mkdtemp(prefix="mzwg-test-")}
    return WireGuardDriver(settings, backend=backend), backend


# ---------------------------------------------------------------------- #
# pure parsing / rendering helpers                                       #
# ---------------------------------------------------------------------- #

def test_parse_wg_dump_real_shape() -> None:
    dump = parse_wg_dump(DUMP_SAMPLE)
    assert dump.interfaces == ("mzwg0",)
    assert dump.listen_ports == {"mzwg0": 51820}
    assert len(dump.peers) == 2

    alice, bob = dump.peers
    assert alice.public_key == KEY_ALICE
    assert alice.preshared_key == PSK_ALICE
    assert alice.endpoint == "198.51.100.7:60123"
    assert alice.allowed_ips == ("10.66.66.2/32",)
    assert alice.latest_handshake == NOW - 42
    assert (alice.transfer_rx, alice.transfer_tx) == (1048576, 2097152)

    assert bob.preshared_key is None
    assert bob.endpoint is None
    assert bob.latest_handshake == 0


def test_strip_config_matches_wgquick_semantics() -> None:
    full = render_interface(
        private_key="PRIV", address="10.66.66.1/24", listen_port=51820,
        peers=[
            __import__("app.cores.drivers.wireguard.wgtool", fromlist=["DesiredPeer"]).DesiredPeer(
                comment="1.alice", public_key=KEY_ALICE,
                allowed_ips=("10.66.66.2/32",), preshared_key=PSK_ALICE),
        ],
    )
    stripped = strip_config(full)
    assert "Address" not in stripped and "Table" not in stripped
    assert "# 1.alice" not in stripped  # comments dropped
    assert "PrivateKey = PRIV" in stripped
    assert "ListenPort = 51820" in stripped
    assert f"PublicKey = {KEY_ALICE}" in stripped
    assert f"PresharedKey = {PSK_ALICE}" in stripped
    assert "AllowedIPs = 10.66.66.2/32" in stripped


def test_render_interface_forwarding_nat_hooks() -> None:
    """alpha.7.5 item 12: full-path rendering — forwarding + MASQUERADE.

    The server interface must carry the wg-quick PostUp/PostDown hook block
    when the driver default (enable_nat=True) holds, must skip it for a
    bare-link operator choice, and `wg syncconf` payloads must NEVER carry
    the hooks (strip semantics keep live updates non-disruptive)."""
    from app.cores.drivers.wireguard.wgtool import DesiredPeer

    peer = DesiredPeer(comment="1.alice", public_key=KEY_ALICE,
                       allowed_ips=("10.66.66.2/32",), preshared_key=None)
    with_hooks = render_interface(
        private_key="PRIV", address="10.66.66.1/24", listen_port=51820,
        peers=[peer], forward_nat=True)
    # Forwarding is a pre-start environment check, never a PostUp sysctl:
    # host-network Docker mounts /proc/sys read-only.
    assert "sysctl" not in with_hooks and "/proc/sys" not in with_hooks
    assert "PostUp = iptables -C FORWARD -i %i -j ACCEPT" in with_hooks
    assert "iptables -t nat -C POSTROUTING -s 10.66.66.0/24" in with_hooks
    assert "MASQUERADE" in with_hooks
    # runtime default-route discovery — no hardcoded interface name
    assert "ip route show default" in with_hooks and "eth0" not in with_hooks
    assert "PostDown = iptables -D FORWARD -i %i -j ACCEPT" in with_hooks
    without = render_interface(
        private_key="PRIV", address="10.66.66.1/24", listen_port=51820,
        peers=[peer], forward_nat=False)
    assert "PostUp" not in without and "MASQUERADE" not in without
    stripped = strip_config(with_hooks)
    assert "PostUp" not in stripped and "sysctl" not in stripped
    # syncconf payload keeps exactly the interface/peer crypto keys
    assert "PrivateKey = PRIV" in stripped and "ListenPort = 51820" in stripped


def test_driver_render_carries_hooks_by_default(monkeypatch) -> None:
    async def run() -> None:
        driver, backend = _driver()
        await driver.start()
        conf = backend.up_calls[0]
        assert "sysctl" not in conf and "/proc/sys" not in conf
        assert "MASQUERADE" in conf

    asyncio.run(run())


def test_driver_render_nat_disabled_omits_hooks() -> None:
    async def run() -> None:
        driver, backend = _driver()
        driver.settings["enable_nat"] = False
        await driver.start()
        conf = backend.up_calls[0]
        assert "MASQUERADE" not in conf and "PostUp" not in conf

    asyncio.run(run())


def test_ip_allocation_lowest_free_and_exhaustion() -> None:
    assert server_address("10.66.66.0/24") == "10.66.66.1/24"
    first = allocate_address("10.66.66.0/24", set())
    assert first == "10.66.66.2/32", first
    second = allocate_address("10.66.66.0/24", {first})
    assert second == "10.66.66.3/32"
    # /30: hosts .1 (server) and .2 → exactly one free peer address
    assert allocate_address("10.66.66.0/30", set()) == "10.66.66.2/32"
    try:
        allocate_address("10.66.66.0/30", {"10.66.66.2/32"})
        raise AssertionError("exhausted subnet must raise ValueError")
    except ValueError:
        pass


def test_key_validation_shape() -> None:
    assert is_valid_key(KEY_ALICE)
    assert not is_valid_key("short")
    assert not is_valid_key("A" * 44)          # missing '=' padding
    assert not is_valid_key("A" * 43 + "==")   # wrong length


# ---------------------------------------------------------------------- #
# driver behaviour (fake backend)                                        #
# ---------------------------------------------------------------------- #

def test_lifecycle_creates_server_config_and_marks_healthy() -> None:
    async def run() -> None:
        driver, backend = _driver()
        await driver.start()
        assert backend.up_calls, "wg-quick up must be invoked on start"
        conf = backend.up_calls[0]
        assert "ListenPort = 51820" in conf and "Address = 10.66.66.1/24" in conf
        assert not backend.synced

        status = await driver.status()
        assert status.health == HealthStatus.HEALTHY
        assert status.core_version == "v1.0.20210914"
        assert status.metrics and status.metrics.active_accounts == 2

        await driver.stop()
        assert backend.down_calls == 1

    asyncio.run(run())


def test_peer_management_live_sync() -> None:
    async def run() -> None:
        dump_offline = "mzwg0\tp\t{srv}\t51820\toff\n".format(srv=KEY_SERVER)
        driver, backend = _driver(dump=dump_offline)
        await driver.start()

        account = _account(1, "alice")
        await driver.create_account(account)
        # keys were generated *in place* (panel persists the account after this)
        assert is_valid_key(account.settings["public_key"])
        assert account.settings["private_key"].startswith("private-")
        assert account.settings["preshared_key"]
        assert account.settings["address"] == "10.66.66.2/32"
        assert len(backend.synced) == 1 and "[Peer]" in backend.synced[0]

        # suspend → peer disappears via sync (no restart)
        await driver.suspend_account(account.account_id)
        assert "[Peer]" not in backend.synced[-1]

        # resume with generated settings → peer returns
        resumed = account.model_copy(update={"enabled": True})
        await driver.resume_account(resumed)
        assert "[Peer]" in backend.synced[-1]

        # delete → peer gone
        await driver.delete_account(account.account_id)
        assert "[Peer]" not in backend.synced[-1]
        assert backend.down_calls == 0  # all live, never a restart

    asyncio.run(run())


def test_usage_deltas_and_reset_clamp() -> None:
    async def run() -> None:
        driver, backend = _driver()
        await driver.start()
        settings = {"public_key": KEY_ALICE, "private_key": "p", "address": "10.66.66.2/32"}
        await driver.create_account(_account(1, "alice", settings=dict(settings)))
        await driver.create_account(_account(2, "bob", settings={
            "public_key": KEY_BOB, "private_key": "p2", "address": "10.66.66.3/32"}))

        records = await driver.get_usage()
        by_id = {r.account_id: r for r in records}
        assert by_id["1.alice"].uplink_bytes == 1048576   # rx = client→server
        assert by_id["1.alice"].downlink_bytes == 2097152  # tx = server→client
        assert by_id["2.bob"].uplink_bytes == 0

        # cumulative counters grow → only the delta is reported
        backend.dump_text = DUMP_ALICE_GREW
        records = await driver.get_usage()
        by_id = {r.account_id: r for r in records}
        assert by_id["1.alice"].uplink_bytes == 1572864 - 1048576
        assert by_id["1.alice"].downlink_bytes == 0
        assert by_id["2.bob"].downlink_bytes == 0  # no re-report

        # interface restarted → counters reset → clamp to 0, never negative
        backend.dump_text = DUMP_ALICE_RESET
        records = await driver.get_usage()
        by_id = {r.account_id: r for r in records}
        assert by_id["1.alice"].uplink_bytes == 0

        # unknown peers are never billed to users
        assert all(r.account_id in {"1.alice", "2.bob"} for r in records)

    asyncio.run(run())


def test_online_detection_handshake_threshold() -> None:
    async def run() -> None:
        driver, backend = _driver()
        # handshake freshness must be measured against the EXECUTION clock,
        # not import time — the import-baked NOW drifts with suite length
        # (longer suites pushed the age past the old tolerance and flaked).
        backend.dump_text = DUMP_SAMPLE.replace(
            str(NOW - 42), str(int(time.time()) - 42))
        await driver.start()
        await driver.create_account(_account(1, "alice", settings={
            "public_key": KEY_ALICE, "private_key": "p", "address": "10.66.66.2/32"}))
        await driver.create_account(_account(2, "bob", settings={
            "public_key": KEY_BOB, "private_key": "p2", "address": "10.66.66.3/32"}))

        sessions = await driver.get_online_devices()
        assert len(sessions) == 1  # only alice (bob never handshook)
        session = sessions[0]
        assert session.account_id == "1.alice"
        assert session.ip == "198.51.100.7"
        assert session.metadata["endpoint"] == "198.51.100.7:60123"
        age = session.metadata["latest_handshake_age_seconds"]
        assert 42 <= age <= 42 + 10  # fresh timestamp: only runtime drift

        # handshake older than threshold → offline (honestly unknown ≠ online)
        stale = DUMP_SAMPLE.replace(str(NOW - 42), str(NOW - 3600))
        backend.dump_text = stale
        assert await driver.get_online_devices() == []

    asyncio.run(run())


def test_key_rotation_kills_old_key() -> None:
    async def run() -> None:
        driver, backend = _driver()
        await driver.start()
        account = _account(1, "alice", settings={
            "public_key": KEY_ALICE, "private_key": "old-priv", "address": "10.66.66.2/32",
            "preshared_key": PSK_ALICE})
        await driver.create_account(account)

        rotated = await driver.rotate_credentials(account)
        assert rotated.settings["public_key"] != KEY_ALICE
        assert rotated.settings["private_key"] != "old-priv"
        assert rotated.settings["preshared_key"] != PSK_ALICE
        assert KEY_ALICE not in backend.synced[-1]
        assert rotated.settings["public_key"] in backend.synced[-1]
        # usage baseline of the old key is forgotten; the rotated account is
        # not in the dump any more, and the stale alice key is now a foreign
        # peer — it must be filtered out, never billed
        assert await driver.get_usage() == []
        try:
            await driver.rotate_credentials(_account(9, "ghost"))
            assert False
        except CoreError:
            pass

    asyncio.run(run())


def test_client_profile_and_qr_rendering() -> None:
    async def run() -> None:
        driver, _ = _driver()
        await driver.start()
        account = _account(1, "alice", settings={
            "public_key": KEY_ALICE, "private_key": "CLIENTPRIV", "address": "10.66.66.2/32",
            "preshared_key": PSK_ALICE})
        await driver.create_account(account)

        profile = driver.render_client_profile(account)
        assert "PrivateKey = CLIENTPRIV" in profile
        assert f"PublicKey = {KEY_SERVER}" in profile
        assert f"PresharedKey = {PSK_ALICE}" in profile
        assert "Endpoint = 127.0.0.1:51820" in profile
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in profile

        svg1 = driver.client_config_qr(account)
        svg2 = driver.client_config_qr(account)
        assert svg1 == svg2 and svg1.startswith("<svg") and svg1.endswith("</svg>")
        assert len(svg1) > 200  # quiet-zone-wrapped full symbol

        config = await driver.build_client_config(account)
        assert config.payload["format"] == "ini"
        # secrets never leak into the redacted repr
        assert "CLIENTPRIV" not in repr(config) and "CLIENTPRIV" not in str(config)

    asyncio.run(run())


def test_chain_ingress_real_peering_and_persistence() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="mzwg-chain-") as tmp:
            driver, backend = _driver(tmp=tmp)
            await driver.start()

            try:
                await driver.ensure_chain_listener("socks", 40000)
                assert False, "non-wireguard chain ingress must be refused honestly"
            except CoreError:
                pass

            endpoint = await driver.ensure_chain_listener("wireguard", 0)
            assert endpoint.protocol == "wireguard"
            assert endpoint.port == 51820
            assert endpoint.requires_credentials
            md = endpoint.metadata
            assert md["peer_public_key"] == KEY_SERVER
            assert md["private_key"].startswith("private-")
            assert md["local_address"] == ["10.66.66.2/32"]
            assert md["allowed_ips"] == ["0.0.0.0/0", "::/0"]
            # chain peer was synced into the live config & persisted on disk
            assert "_zg-chain" in backend.synced[-1]
            assert os.path.exists(os.path.join(tmp, "chain-peers.json"))

            # panel restart → same chain peer/credentials (sources stay valid)
            driver2, _ = _driver(tmp=tmp)
            await driver2.start()
            endpoints = await driver2.get_chain_endpoints()
            assert len(endpoints) == 1
            assert endpoints[0].metadata["private_key"] == md["private_key"]
            assert endpoints[0].metadata["local_address"] == md["local_address"]

    asyncio.run(run())


def test_concurrent_provisioning_is_race_safe() -> None:
    async def run() -> None:
        driver, backend = _driver(dump="mzwg0\tp\t{s}\t51820\toff\n".format(s=KEY_SERVER))
        await driver.start()
        accounts = [_account(i, f"u{i}") for i in range(1, 26)]
        await asyncio.gather(*(driver.create_account(a) for a in accounts))
        peers = driver._desired_peers()
        assert len(peers) == 25
        addrs = {p.allowed_ips[0] for p in peers}
        assert len(addrs) == 25, "every peer needs a unique tunnel address"
        assert len(backend.synced) >= 25  # each publish pushed live state

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# alpha.7.2 — offline wizard + pure-python key material                  #
# ---------------------------------------------------------------------- #

def test_pure_key_material_matches_rfc7748_vector():
    """public_from_private_pure == X25519 (RFC 7748 §6.1 vector) — the exact
    math `wg pubkey` performs (X25519 clamps the scalar internally), now
    computed without the binary so configuring needs no installed tools."""
    import base64 as _b64

    from app.cores.drivers.wireguard.backend import (
        generate_keypair_pure,
        generate_preshared_pure,
        public_from_private_pure,
    )

    scalar = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    expected_pub = bytes.fromhex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    got = _b64.b64decode(
        public_from_private_pure(_b64.b64encode(scalar).decode()))
    assert got == expected_pub

    priv, pub = generate_keypair_pure()
    assert is_valid_key(priv) and is_valid_key(pub)
    assert public_from_private_pure(priv) == pub
    assert is_valid_key(generate_preshared_pure())
    assert generate_keypair_pure()[0] != priv  # real randomness

    try:
        public_from_private_pure("not-a-key")
        raise AssertionError("invalid key accepted")
    except CoreError as exc:
        assert "private key" in str(exc)


def test_local_backend_key_material_needs_no_wg_binary(monkeypatch=None):
    """LocalWireGuardBackend keys are pure python: no `wg` on PATH, no
    subprocess — the configure path works on a bare host."""
    import base64 as _b64

    from app.cores.drivers.wireguard.backend import (
        LocalWireGuardBackend, is_valid_key as _ivk, public_from_private_pure)

    tmp = tempfile.mkdtemp(prefix="mzwg-keys-")
    backend = LocalWireGuardBackend({"work_dir": tmp, "executable_wg": "definitely-not-wg"})
    priv, pub = backend.generate_keypair()
    assert _ivk(priv) and _ivk(pub)
    assert public_from_private_pure(priv) == pub
    # persisted identity round-trips (pubkey re-derived offline)
    priv2, pub2 = backend.ensure_server_keys()
    assert (priv2, pub2) == backend.ensure_server_keys()
    scalar = _b64.b64encode(bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).decode()
    backend.write_server_private_key(scalar)
    assert backend.ensure_server_keys()[0] == scalar


def test_wizard_apply_on_stopped_core_needs_no_daemon():
    """Item: building a WireGuard inbound via the studio must NOT require a
    running core — apply persists settings, materializes the server
    identity, and pushes NOTHING to the kernel while the daemon is down."""
    async def run():
        driver, backend = _driver()
        backend.running = False
        driver._server_private = None  # simulate never-started core
        driver._server_public = None
        doc = {"inbounds": [{
            "tag": "wireguard", "protocol": "wireguard", "port": 51822,
            "address": "10.77.0.0/24", "endpoint": "vpn.example.com",
            "persistent_keepalive": 30,
        }]}
        await driver.apply_studio_document(doc)
        assert driver.settings["port"] == 51822
        assert driver.settings["subnet"] == "10.77.0.0/24"
        assert driver.settings["advertise_host"] == "vpn.example.com"
        assert driver.settings["peer_keepalive"] == 30
        assert driver._server_private == "SERVER_PRIVATE"  # identity now known
        assert backend.synced == [] and backend.up_calls == []   # zero pushes
        # bring-up renders exactly the stored document
        await driver.start()
        assert backend.running and len(backend.up_calls) == 1
        assert "ListenPort = 51822" in backend.up_calls[0]
        assert "Address = 10.77.0.1/24" in backend.up_calls[0]
    asyncio.run(run())


def test_account_provisioning_on_stopped_core():
    """Peers created while the daemon is down persist and appear in the
    interface config at start (no sync attempts against a dead kernel if)."""
    async def run():
        driver, backend = _driver()
        backend.running = False
        driver._server_private = None
        driver._server_public = None
        account = _account(1, "offliner")
        await driver.create_account(account)
        assert account.settings.get("public_key") and account.settings.get("private_key")
        assert str(account.settings.get("address") or "").startswith("10.66.66.")
        assert backend.synced == []
        await driver.start()
        assert account.settings["public_key"] in backend.up_calls[0]
    asyncio.run(run())


def test_local_backend_forwarding_preflight_is_environment_aware(tmp_path, monkeypatch):
    """Docker/read-only proc fails before interface creation; direct-host mode
    uses sysctl and verifies the resulting kernel value."""
    from app.cores.drivers.wireguard.backend import LocalWireGuardBackend

    backend = LocalWireGuardBackend({"work_dir": str(tmp_path)})
    monkeypatch.setattr(backend, "_forwarding_enabled", lambda: False)
    monkeypatch.setattr(backend, "_in_container", lambda: True)
    with pytest.raises(CoreError, match="Docker HOST"):
        backend._ensure_forwarding()
    assert not (tmp_path / "mzwg0.conf").exists()

    states = iter([False, True])
    commands: list[list[str]] = []
    monkeypatch.setattr(backend, "_in_container", lambda: False)
    monkeypatch.setattr(backend, "_forwarding_enabled", lambda: next(states))
    monkeypatch.setattr("shutil.which", lambda name: "/usr/sbin/sysctl" if name == "sysctl" else None)
    monkeypatch.setattr(backend, "_run", lambda argv, **kw: commands.append(argv) or "")
    backend._ensure_forwarding()
    assert commands == [["/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1"]]


# ---------------------------------------------------------------------- #
# standalone + pytest runner                                             #
# ---------------------------------------------------------------------- #

def _run_standalone() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(_run_standalone())
