"""SoftEther driver tests — real vpncmd fixtures:

  * UserGet key|value parsing (unicast+broadcast totals, both directions)
  * UserList / SessionList CSV parsing (header-driven)
  * live user management (no restarts — honest HOT_RELOAD)
  * expire-based suspend + session disconnect
  * usage deltas via native counters
  * L2TP/IPsec sealed payload rules
  * honest SELF_INSTALL absence (locked)

Run: pytest tests/cores/test_softether_driver.py -v  OR  python tests/cores/test_softether_driver.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import os
import subprocess
import traceback
import types as _types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import Capability, CoreError  # noqa: E402
from app.cores.drivers.softether import (  # noqa: E402
    SoftEtherDriver,
    parse_session_get,
    parse_session_list,
    parse_user_get,
    parse_user_list,
)
from app.cores.drivers.softether.setool import (  # noqa: E402
    SESession,
    SessionStatistics,
    UserStatistics,
)
from app.cores.types import UserAccount  # noqa: E402

REAL_USER_GET = """\
SoftEther VPN Command Line Management Utility (vpncmd command)
Connected to VPN Server "localhost".

Item                                    |Value
----------------------------------------|--------------------------------
User Name                               |1.alice
Group Name                              |
Real Name                               |alice
Description                             |panel
Number of Logins                        |42
Expiration Date                         |2100/01/01 00:00:00
Incoming Unicast Total Size             |1,073,741,824 bytes
Incoming Broadcast Total Size           |0 bytes
Outgoing Unicast Total Size             |2,147,483,648 bytes
Outgoing Broadcast Total Size           |1,024 bytes

The command completed successfully.
"""

REAL_USER_LIST_CSV = """\
"User Name","Group name","Real name","note","Number of Logins","Last Login"
"1.alice","","alice","panel","42","2026/08/03 11:59:01"
"2.bob","","bob","panel","7","2026/08/03 10:00:00"
"""

REAL_SESSION_LIST_CSV = """\
"Session Name","Status","User Name","Source Host Name","Hostname","Session Mode"
"SID-1.alice-42","Established","1.alice","DESKTOP-AB12 (203.0.113.5)","DESKTOP-AB12","Client/Bridge"
"SID-2.bob-9","Established","2.bob","iPhone-X (198.51.100.9)","iPhone-X","Client/Bridge"
"""

REAL_SESSION_GET = """\
Item                                      |Value
------------------------------------------+----------------------------------------
User Name (Authentication)                |1.alice
User Name (Database)                      |1.alice
Session Name                              |SID-1.alice-42
Outgoing Data Size                        |24,059 bytes
Incoming Data Size                        |5,397,726 bytes
The command completed successfully.
"""


class FakeSEBackend:
    """Fake SoftEtherBackend: user/session tables as dicts, recorded calls."""

    def __init__(self):
        self.users: dict[str, str] = {}
        self.expires: dict[str, str | None] = {}
        self.stats: dict[str, tuple[int, int]] = {}
        self.sessions: list[SESession] = []
        self.session_stats: dict[str, tuple[int, int]] = {}
        self.disconnected: list[str] = []
        self._reachable = True

    def reachable(self): return self._reachable
    def client_binary(self): return "/persistent/vpnclient"
    def user_create(self, username, note=""): self.users.setdefault(username, "")
    def user_delete(self, username): self.users.pop(username, None)
    def user_password_set(self, username, password): self.users[username] = password
    def user_expires_set(self, username, expires): self.expires[username] = expires
    def suspend_user(self, username): self.expires[username] = "2000/01/01 00:00:00"
    def user_get(self, username):
        if username not in self.users:
            raise CoreError("no such user")
        inc, out = self.stats.get(username, (0, 0))
        return UserStatistics(username=username, incoming_bytes=inc, outgoing_bytes=out)
    def user_list(self): return sorted(self.users)
    def session_list(self): return list(self.sessions)
    def session_get(self, session_name):
        session = next(s for s in self.sessions if s.session_name == session_name)
        incoming, outgoing = self.session_stats.get(session_name, (0, 0))
        return SessionStatistics(
            session_name=session_name, username=session.username,
            incoming_bytes=incoming, outgoing_bytes=outgoing)
    def session_disconnect(self, session_name):
        self.disconnected.append(session_name)
        self.sessions = [s for s in self.sessions if s.session_name != session_name]
    def ipsec_psk(self): return None
    def secure_nat_ensure(self): self.secure_nat = True


def _driver(settings: dict | None = None, backend: FakeSEBackend | None = None
            ) -> tuple[SoftEtherDriver, FakeSEBackend]:
    backend = backend or FakeSEBackend()
    merged = {"ipsec_psk": "test-psk"}
    merged.update(settings or {})
    return SoftEtherDriver(merged, backend=backend), backend


def _account(user: int, name: str, enabled: bool = True, password: str = "s3cret") -> UserAccount:
    return UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                       protocol="l2tp", enabled=enabled, settings={"password": password})


# ---------------------------------------------------------------------- #

def test_parse_real_vpncmd_fixtures() -> None:
    stats = parse_user_get(REAL_USER_GET)
    assert stats.username == "1.alice"
    assert stats.incoming_bytes == 1_073_741_824          # unicast + broadcast
    assert stats.outgoing_bytes == 2_147_483_648 + 1_024  # unicast + broadcast
    assert stats.num_logins == 42

    users = parse_user_list(REAL_USER_LIST_CSV)
    assert [u.username for u in users] == ["1.alice", "2.bob"]
    assert users[0].logins == 42

    sessions = parse_session_list(REAL_SESSION_LIST_CSV)
    assert len(sessions) == 2
    assert sessions[0].session_name == "SID-1.alice-42"
    assert sessions[0].username == "1.alice"
    assert "DESKTOP-AB12" in sessions[0].source_host

    live = parse_session_get(REAL_SESSION_GET)
    assert live.session_name == "SID-1.alice-42"
    assert live.username == "1.alice"
    assert live.incoming_bytes == 5_397_726
    assert live.outgoing_bytes == 24_059


def test_start_reconciles_numbered_routed_tap_after_daemon_restart(
    monkeypatch,
) -> None:
    """A recreated TAP is not usable until its host IP/UP state is restored."""
    driver, _backend = _driver()
    driver._policy_source = {  # noqa: SLF001 - persisted in-process route intent
        "interface": "tap_zge2e",
        "subnet": "192.168.87.0/24",
        "gateway": "192.168.87.254",
    }
    restored: list[str] = []

    def disable(source_id: str | None = None) -> None:
        assert source_id == "hub:DEFAULT"
        restored.append("disable")
        driver._policy_source = None  # noqa: SLF001

    def ensure(source_id: str | None = None) -> dict[str, str]:
        assert source_id == "hub:DEFAULT"
        restored.append("ensure")
        driver._policy_source = {  # noqa: SLF001
            "interface": "tap_zge2e",
            "subnet": "192.168.87.0/24",
            "gateway": "192.168.87.254",
        }
        return dict(driver._policy_source)  # noqa: SLF001

    monkeypatch.setattr(driver, "disable_policy_source", disable)
    monkeypatch.setattr(driver, "ensure_policy_source", ensure)

    asyncio.run(driver.start())

    assert restored == ["disable", "ensure"]


def test_disable_policy_source_deletes_stale_panel_owned_tap(monkeypatch) -> None:
    import shutil
    import subprocess

    driver, backend = _driver({"policy_tap_device": "zge2e"})
    driver._policy_source = {  # noqa: SLF001
        "interface": "tap_zge2e",
        "subnet": "192.168.87.0/24",
        "gateway": "192.168.87.254",
    }
    disabled: list[str] = []
    backend.routed_tap_disable = lambda *, device, hub_name=None: disabled.append(
        f"{hub_name}:{device}")
    commands: list[list[str]] = []
    monkeypatch.setattr(shutil, "which", lambda name: "/sbin/ip" if name == "ip" else None)
    monkeypatch.setattr(
        subprocess, "run",
        lambda argv, **_kwargs: commands.append(list(argv)) or type("P", (), {"returncode": 0})(),
    )

    driver.disable_policy_source()

    assert disabled == ["DEFAULT:zge2e"]
    assert commands == [["/sbin/ip", "link", "delete", "dev", "tap_zge2e"]]
    assert driver.policy_source() is None


def test_managed_policy_hub_lifecycle_is_isolated_and_secret_free() -> None:
    class LifecycleBackend(FakeSEBackend):
        def __init__(self):
            super().__init__()
            self.hubs = {"DEFAULT"}
            self.hub_users: dict[str, set[str]] = {"DEFAULT": {"production-user"}}
            self.deleted: list[str] = []

        def hub_create(self, hub_name, password):
            assert password and password not in repr(self.hubs)
            if hub_name in self.hubs:
                raise CoreError("already exists")
            self.hubs.add(hub_name)
            self.hub_users[hub_name] = set()

        def hub_delete(self, hub_name):
            self.hubs.discard(hub_name)
            self.hub_users.pop(hub_name, None)
            self.deleted.append(hub_name)

        def hub_user_create(self, hub_name, username, password):
            assert password == "unit-user-password"
            self.hub_users[hub_name].add(username)

        def hub_user_delete(self, hub_name, username):
            self.hub_users.get(hub_name, set()).discard(username)

    backend = LifecycleBackend()
    driver, _ = _driver(backend=backend)
    created = driver.create_policy_hub(
        hub="ZAGROS-E2E-unit", inbound_tag="softether-e2e-unit",
        tap_device="zge2eunit", subnet="192.168.87.0/24",
        gateway="192.168.87.254", username="e2e-user",
        user_password="unit-user-password",
    )

    assert backend.hubs == {"DEFAULT", "ZAGROS-E2E-unit"}
    assert backend.hub_users["DEFAULT"] == {"production-user"}
    assert backend.hub_users["ZAGROS-E2E-unit"] == {"e2e-user"}
    assert created["managed_by_zagros"] is True
    assert "password" not in created
    assert "unit-user-password" not in repr(driver.settings)
    specs = driver.routing_source_specs()
    managed = next(spec for spec in specs if spec["managed_by_zagros"])
    assert managed["tags"] == ["softether-e2e-unit"]
    assert managed["subnet"] == "192.168.87.0/24"

    driver.delete_policy_hub("ZAGROS-E2E-unit")
    assert backend.hubs == {"DEFAULT"}
    assert backend.hub_users["DEFAULT"] == {"production-user"}
    assert driver.settings["policy_hubs"] == []
    assert backend.deleted == ["ZAGROS-E2E-unit"]


def test_managed_policy_hub_overlap_fails_before_vpncmd_mutation() -> None:
    class NoMutationBackend(FakeSEBackend):
        def hub_create(self, *_args):
            raise AssertionError("overlap must fail before HubCreate")

        def hub_user_create(self, *_args):
            raise AssertionError("overlap must fail before UserCreate")

        def hub_delete(self, *_args):
            raise AssertionError("overlap must fail before HubDelete")

    driver, _ = _driver(backend=NoMutationBackend())
    with pytest.raises(CoreError, match="subnets must not overlap"):
        driver.create_policy_hub(
            hub="ZAGROS-E2E-overlap", inbound_tag="softether-e2e-overlap",
            tap_device="zge2eov", subnet="192.168.30.0/25",
            gateway="192.168.30.126", username="e2e-user",
            user_password="unit-user-password",
        )


def test_managed_policy_hub_uses_its_own_hub_tap_and_cleanup(monkeypatch) -> None:
    import shutil
    import subprocess

    driver, backend = _driver({
        "policy_hubs": [{
            "hub": "ZAGROS-E2E-unit", "inbound_tag": "softether-e2e-unit",
            "tap_device": "zge2eunit", "subnet": "192.168.87.0/24",
            "gateway": "192.168.87.254", "username": "e2e-user",
            "managed_by_zagros": True,
        }],
    })
    calls: list[tuple[str, str]] = []
    backend.routed_tap_ensure = lambda *, device, subnet, gateway, hub_name: (
        calls.append(("ensure", f"{hub_name}:{device}:{subnet}:{gateway}"))
        or f"tap_{device}")
    backend.routed_tap_disable = lambda *, device, hub_name: calls.append(
        ("disable", f"{hub_name}:{device}"))
    commands: list[list[str]] = []
    monkeypatch.setattr(
        shutil, "which",
        lambda name: {"ip": "/sbin/ip", "iptables": "/sbin/iptables"}.get(name),
    )

    def command(argv, **_kwargs):
        commands.append(list(argv))
        missing = argv[0] == "/sbin/iptables" and "-C" in argv
        return type("P", (), {
            "returncode": 1 if missing else 0, "stdout": "", "stderr": "",
        })()

    monkeypatch.setattr(subprocess, "run", command)
    source = driver.ensure_policy_source("hub:ZAGROS-E2E-unit")
    assert source["hub"] == "ZAGROS-E2E-unit"
    assert source["subnet"] == "192.168.87.0/24"
    assert calls[0] == (
        "ensure", "ZAGROS-E2E-unit:zge2eunit:192.168.87.0/24:192.168.87.254")
    assert ["/sbin/ip", "address", "replace", "192.168.87.254/24",
            "dev", "tap_zge2eunit"] in commands
    assert ["/sbin/iptables", "-I", "FORWARD", "1", "-i",
            "tap_zge2eunit", "-s", "192.168.87.0/24", "-j", "ACCEPT"] in commands
    assert ["/sbin/iptables", "-I", "FORWARD", "1", "-o",
            "tap_zge2eunit", "-d", "192.168.87.0/24", "-m", "conntrack",
            "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"] in commands

    driver.disable_policy_source("hub:ZAGROS-E2E-unit")
    assert calls[-1] == ("disable", "ZAGROS-E2E-unit:zge2eunit")
    assert ["/sbin/iptables", "-D", "FORWARD", "-i", "tap_zge2eunit",
            "-s", "192.168.87.0/24", "-j", "ACCEPT"] in commands
    assert ["/sbin/ip", "link", "delete", "dev", "tap_zge2eunit"] in commands
    assert driver.policy_sources() == []


def test_softether_start_waits_for_real_daemon_warmup(monkeypatch) -> None:
    backend = FakeSEBackend()
    probes = 0
    started = []

    def reachable():
        nonlocal probes
        probes += 1
        return probes >= 25  # beyond the removed 20-probe/10-second gate

    backend.reachable = reachable
    backend.server_binary = lambda: "/persistent/vpnserver"
    backend.server_start = lambda: started.append(True)

    async def no_wait(_seconds):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_wait)
    driver, _ = _driver(backend=backend)
    asyncio.run(driver.start())
    assert started == [True]
    assert probes == 25


def test_live_user_management_no_restart() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        assert backend.users["1.alice"] == "s3cret"
        assert backend.expires["1.alice"] is None

        # password change → update + session kick
        backend.sessions = [SESession("SID-1.alice-42", "1.alice", "host", {})]
        await driver.update_account(_account(1, "alice", password="n3w"))
        assert backend.users["1.alice"] == "n3w"
        assert backend.disconnected == ["SID-1.alice-42"]

        # wrong protocol refused honestly
        try:
            await driver.create_account(
                UserAccount(user_id=2, username="x", account_id="2.x", protocol="wireguard",
                            settings={"password": "p"}))
            raise AssertionError("unknown protocol must raise")
        except CoreError:
            pass

    asyncio.run(run())


def test_expire_based_suspend_and_resume() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        backend.sessions = [SESession("SID-1.alice-42", "1.alice", "host", {})]

        await driver.suspend_account("1.alice")
        assert backend.expires["1.alice"] == "2000/01/01 00:00:00"
        assert backend.disconnected == ["SID-1.alice-42"]
        assert not driver._accounts["1.alice"].enabled

        await driver.resume_account(_account(1, "alice"))
        assert backend.expires["1.alice"] is None
        assert driver._accounts["1.alice"].enabled

        await driver.delete_account("1.alice")
        assert "1.alice" not in backend.users

    asyncio.run(run())


def test_active_sstp_defers_management_poll_without_losing_cumulative_source() -> None:
    async def run():
        driver, backend = _driver()
        await driver.create_account(_account(1, "alice"))
        backend.sstp_sessions_active = lambda: True
        backend.user_get = lambda _username: (_ for _ in ()).throw(
            AssertionError("vpncmd UserGet must not run during SSTP"))
        assert await driver.get_usage() == []

    asyncio.run(run())


def test_usage_deltas_from_native_counters() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        await driver.create_account(_account(2, "bob"))
        backend.stats = {"1.alice": (1_073_741_824, 2_147_483_648), "2.bob": (100, 100)}

        first = await driver.get_usage()
        by_id = {r.account_id: r for r in first}
        # SoftEther counters are server-oriented: outgoing = client upload,
        # incoming = client download.
        assert by_id["1.alice"].uplink_bytes == 2_147_483_648
        assert by_id["1.alice"].downlink_bytes == 1_073_741_824
        assert by_id["2.bob"].uplink_bytes == 100

        backend.stats["1.alice"] = (1_073_742_824, 2_147_483_648)  # +1000 download
        second = await driver.get_usage()
        by_id = {r.account_id: r for r in second}
        assert by_id["1.alice"].uplink_bytes == 0
        assert by_id["1.alice"].downlink_bytes == 1000

    asyncio.run(run())


def test_softether_accounting_delta_test() -> None:
    """Completed UserGet + live SessionGet is monotonic and exactly-once.

    Pins the real L2TP behavior: UserGet stays unchanged during a 50 MB
    session, then absorbs SessionGet counters at disconnect. Panel restart
    with a persisted baseline must emit neither zero traffic nor the same
    session twice.
    """
    async def run():
        driver, backend = _driver()
        await driver.start()
        account = _account(1, "alice")
        await driver.create_account(account)
        backend.stats["1.alice"] = (0, 0)
        backend.sessions = [
            SESession("SID-1.alice-live", "1.alice", "198.51.100.4", {})]
        backend.session_stats["SID-1.alice-live"] = (5_000_000, 50_000_000)

        first = (await driver.get_usage())[0]
        assert (first.uplink_bytes, first.downlink_bytes) == (50_000_000, 5_000_000)

        # SoftEther's delayed UserGet refresh catches up while the session is
        # STILL connected. Those same 55 MB must not be emitted twice.
        backend.stats["1.alice"] = (5_000_000, 50_000_000)
        caught_up = (await driver.get_usage())[0]
        assert (caught_up.uplink_bytes, caught_up.downlink_bytes) == (0, 0)

        # Five more MB while the same PPP session remains connected.
        backend.session_stats["SID-1.alice-live"] = (5_500_000, 54_500_000)
        second = (await driver.get_usage())[0]
        assert (second.uplink_bytes, second.downlink_bytes) == (4_500_000, 500_000)

        # Disconnect commits the live totals into UserGet. Effective totals
        # stay identical, therefore this poll must not double count them.
        backend.stats["1.alice"] = (5_500_000, 54_500_000)
        backend.sessions = []
        committed = (await driver.get_usage())[0]
        assert (committed.uplink_bytes, committed.downlink_bytes) == (0, 0)

        # A new driver process receives the persisted account baseline.
        snapshot = driver.usage_tracker_snapshot()
        restarted, restarted_backend = _driver()
        await restarted.start()
        await restarted.create_account(account)
        restarted_backend.stats["1.alice"] = (5_500_000, 54_500_000)
        restarted.restore_usage_baselines(snapshot)
        after_restart = (await restarted.get_usage())[0]
        assert (after_restart.uplink_bytes, after_restart.downlink_bytes) == (0, 0)

    asyncio.run(run())


def test_restart_does_not_replay_delayed_userget_behind_billed_live_total() -> None:
    async def run():
        driver, backend = _driver()
        await driver.create_account(_account(1, "alice"))
        backend.sessions = [SESession("SID-live", "1.alice", "client", {})]
        backend.session_stats["SID-live"] = (10, 100)
        first = (await driver.get_usage())[0]
        assert (first.uplink_bytes, first.downlink_bytes) == (100, 10)

        # Disconnect commits slightly less than SessionGet had exposed. This
        # is real SoftEther lag, not a provider counter reset.
        backend.sessions = []
        backend.stats["1.alice"] = (9, 90)
        committed = (await driver.get_usage())[0]
        assert committed.uplink_bytes + committed.downlink_bytes == 0
        state = driver.usage_tracker_snapshot(["1.alice"])

        restarted, restarted_backend = _driver()
        await restarted.create_account(_account(1, "alice"))
        restarted_backend.stats["1.alice"] = (9, 90)
        restarted.restore_usage_baselines(state)
        after = (await restarted.get_usage())[0]
        assert (after.uplink_bytes, after.downlink_bytes) == (0, 0)

        # Once UserGet moves beyond the covered position, only true growth is
        # emitted and the delayed overlap is absorbed.
        restarted_backend.stats["1.alice"] = (11, 101)
        grown = (await restarted.get_usage())[0]
        assert (grown.uplink_bytes, grown.downlink_bytes) == (1, 1)

    asyncio.run(run())


def test_online_sessions_with_device_identity() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        backend.sessions = [
            SESession("SID-1.alice-42", "1.alice", "DESKTOP-AB12 (203.0.113.5)", {}),
            SESession("SID-nonuser-1", "not-managed", "x", {}),
        ]
        sessions = await driver.get_online_devices()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.ip == "DESKTOP-AB12 (203.0.113.5)"
        assert s.metadata["stable_id"] == "se-1.alice-DESKTOP-AB12 (203.0.113.5)"
        assert s.metadata["session_name"] == "SID-1.alice-42"

    asyncio.run(run())


def test_l2tp_payload_rules_and_unreachable_server() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        config = await driver.build_client_config(driver._accounts["1.alice"])
        p = config.payload
        assert p["format"] == "l2tp-ipsec"
        assert p["ipsec_psk"] == "test-psk"
        assert p["username"] == "1.alice" and p["password"] == "s3cret"
        assert "test-psk" not in repr(config)

        # without a PSK the payload cannot be built — honest error, not a guess
        driver_no_psk, _ = _driver(settings={"ipsec_psk": ""})
        await driver_no_psk.start()
        await driver_no_psk.create_account(_account(1, "alice"))
        try:
            await driver_no_psk.build_client_config(driver_no_psk._accounts["1.alice"])
            raise AssertionError("missing PSK must raise")
        except CoreError as exc:
            assert "ipsec_psk" in str(exc)

        # unreachable hub fails start honestly
        dead, backend2 = _driver(backend=FakeSEBackend())
        backend2._reachable = False
        try:
            await dead.start()
            raise AssertionError("unreachable hub must fail start")
        except CoreError:
            pass

    asyncio.run(run())


def test_l2tp_raw_client_config_never_requires_or_leaks_ipsec_psk() -> None:
    driver, _ = _driver(settings={
        "ipsec_psk": "", "advertise_host": "vpn.example.com",
        "feature_l2tp_raw": True,
        "feature_tags": {"l2tp_raw": "raw-custom"},
    })
    account = UserAccount(
        user_id=5, username="raw", account_id="5.raw",
        protocol="l2tp_raw", settings={"password": "pw"},
    )
    config = asyncio.run(driver.build_client_config(account))
    assert config.payload["format"] == "l2tp-raw"
    assert config.payload["port"] == 1701
    assert "ipsec_psk" not in config.payload
    assert "no IPsec encryption" in config.payload["warning"]


def test_honest_capability_surface_locked() -> None:
    driver, _ = _driver()
    assert driver.supports(Capability.HOT_RELOAD)          # vpncmd is live
    assert driver.supports(Capability.USAGE_ACCOUNTING)
    assert driver.supports(Capability.DEVICE_DETECTION)
    # alpha.7 fix: the Install button no longer sits dead — the driver claims
    # SELF_INSTALL and actually performs it (apt package, else the official
    # GitHub release). What stays UNCLAIMED is what the engine still cannot do.
    assert driver.supports(Capability.SELF_INSTALL)
    for cap in (Capability.ROUTING, Capability.CHAIN_ROUTING, Capability.MULTI_NODE):
        assert not driver.supports(cap), f"{cap.value} must NOT be claimed for softether"


def test_softether_install_runs_package_strategies(monkeypatch) -> None:
    """install() delegates to the backend's real package strategies and then
    performs a first daemon start so the hub answers right away."""
    driver, backend = _driver()
    calls: list[str] = []

    backend.reachable = lambda: "vpncmd" in calls
    backend.install_packages = lambda: calls.append("vpncmd") or "installed via fake"
    backend.server_start = lambda: calls.append("start")

    async def run():
        await driver.install()

    asyncio.run(run())
    assert calls[:1] == ["vpncmd"], calls


# ---------------------------------------------------------------------- #
# alpha.7.2 — 3-stage installer chain (pkg → GitHub latest → source)     #
# ---------------------------------------------------------------------- #

def _se_backend():
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend
    return LocalSoftEtherBackend({})


def test_vpncmd_transports_all_credentials_over_private_pty_not_argv(monkeypatch) -> None:
    """Admin and profile secrets are never placed in process argv."""
    import app.cores.routing.softether_client as channel
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    admin_secret = "dummy-admin-secret"
    psk_secret = "dummy-ipsec-secret"
    backend = LocalSoftEtherBackend({
        "admin_password": admin_secret, "server": "localhost", "hub": "TEST_HUB",
    })
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    calls = []

    def run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return "The command completed successfully.\n"

    monkeypatch.setattr(channel, "run_vpncmd_pty", run)
    command = f"IPsecEnable /PSK:{psk_secret} /DEFAULTHUB:TEST_HUB"
    backend._cmd(command, csv=True, hub=False)
    argv, kwargs = calls[0]
    assert argv == ["/vpncmd", "localhost:5555", "/SERVER", "/CSV"]
    assert admin_secret not in " ".join(argv)
    assert psk_secret not in " ".join(argv)
    assert kwargs["administrator_password"] == admin_secret
    assert kwargs["commands"] == [command]
    assert kwargs["prompt"] == "VPN Server"


def test_vpncmd_primary_hub_csv_strips_login_preamble(monkeypatch) -> None:
    """Real vpncmd PTY output has a human banner before the /CSV header.

    Treating that banner as row zero makes UserList parse as empty and turns
    an idempotent account reconcile into a duplicate UserCreate (error 66).
    """
    import app.cores.routing.softether_client as channel
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({
        "admin_password": "server-admin", "hub": "DEFAULT",
    })
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    raw = (
        "SoftEther VPN Command Line Management Utility\n"
        "Connected to VPN Server localhost.\n"
        "VPN Server/DEFAULT> UserList\n"
        "User Name,Full Name,Group Name,Description,Auth Method,Num Logins\n"
        "1.alice.softether,alice,-,panel,Password Authentication,0\n"
        "VPN Server/DEFAULT>\n"
    )
    monkeypatch.setattr(channel, "run_vpncmd_pty", lambda *args, **kwargs: raw)

    assert backend.user_list() == ["1.alice.softether"]
    cleaned = backend._cmd("UserList", csv=True)
    assert cleaned.startswith("User Name,Full Name")
    assert "Command Line Management" not in cleaned


def test_sstp_socket_probe_ignores_loopback_management(monkeypatch) -> None:
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({})
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/ss" if name == "ss" else None)
    monkeypatch.setattr(
        backend, "_run",
        lambda *args, **kwargs: (
            "0 0 127.0.0.1:443 127.0.0.1:50000\n"
            "0 0 109.248.161.249:443 172.61.0.2:42000\n"
        ),
    )
    assert backend.sstp_sessions_active() is True
    monkeypatch.setattr(
        backend, "_run",
        lambda *args, **kwargs: "0 0 127.0.0.1:443 127.0.0.1:50000\n",
    )
    assert backend.sstp_sessions_active() is False


def test_usage_batch_reads_many_users_in_one_management_session(monkeypatch) -> None:
    import app.cores.routing.softether_client as channel
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({
        "admin_password": "server-admin", "hub": "DEFAULT",
    })
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    calls = []
    transcript = (
        "VPN Server/DEFAULT>UserGet 1.alice\n"
        "User Name |1.alice\n"
        "Outgoing Unicast Total Size|1,000 bytes\n"
        "Outgoing Broadcast Total Size|20 bytes\n"
        "Incoming Unicast Total Size|2,000 bytes\n"
        "Incoming Broadcast Total Size|30 bytes\n"
        "VPN Server/DEFAULT>UserGet 2.bob\n"
        "User Name |2.bob\n"
        "Outgoing Unicast Total Size|3,000 bytes\n"
        "Outgoing Broadcast Total Size|40 bytes\n"
        "Incoming Unicast Total Size|4,000 bytes\n"
        "Incoming Broadcast Total Size|50 bytes\n"
        "VPN Server/DEFAULT>\n"
    )

    def run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return transcript

    monkeypatch.setattr(channel, "run_vpncmd_pty", run)
    result = backend.users_get(["1.alice", "2.bob"])
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == ["/vpncmd", "localhost:5555", "/SERVER", "/HUB:DEFAULT"]
    assert kwargs["commands"] == ["UserGet 1.alice", "UserGet 2.bob"]
    assert result["1.alice"].outgoing_bytes == 1020
    assert result["1.alice"].incoming_bytes == 2030
    assert result["2.bob"].outgoing_bytes == 3040
    assert result["2.bob"].incoming_bytes == 4050


def test_bulk_account_replay_uses_one_live_inventory_session(monkeypatch) -> None:
    """Discovery and mutations share one authenticated PTY — no login storm."""
    import app.cores.routing.softether_client as channel
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({
        "admin_password": "server-admin", "hub": "DEFAULT",
    })
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    calls = []
    transcript = (
        "SoftEther VPN Command Line Management Utility\n"
        "User Name,Full Name,Group Name,Description,Auth Method,Num Logins\n"
        "1.existing.softether,existing,-,panel,Password Authentication,0\n"
        "1.stale.softether,stale,-,panel,Password Authentication,0\n"
        "VPN Server/DEFAULT>\n"
    )

    def run(argv, **kwargs):
        followups = list(kwargs["followup_factory"](transcript))
        calls.append((list(argv), kwargs, followups))
        return transcript

    monkeypatch.setattr(channel, "run_vpncmd_pty", run)
    backend.users_reconcile([
        ("1.existing.softether", "existing", "existing-password", True),
        ("2.missing.l2tp", "missing", "missing-password", False),
    ], ["1.stale.softether"])

    assert len(calls) == 1
    argv, kwargs, commands = calls[0]
    assert argv == ["/vpncmd", "localhost:5555", "/SERVER", "/HUB:DEFAULT", "/CSV"]
    assert kwargs["commands"] == ["UserList"]
    assert kwargs["administrator_password"] == "server-admin"
    assert set(kwargs["secrets"]) == {"existing-password", "missing-password"}
    assert commands[0] == "UserDelete 1.stale.softether"
    assert not any(command.startswith("UserCreate 1.existing.softether")
                   for command in commands)
    assert any(command.startswith("UserCreate 2.missing.l2tp ")
               for command in commands)
    assert "UserPasswordSet 1.existing.softether /PASSWORD:existing-password" in commands
    assert "UserExpiresSet 1.existing.softether /EXPIRES:none" in commands
    assert ('UserExpiresSet 2.missing.l2tp '
            '/EXPIRES:"2000/01/01 00:00:00"') in commands


def test_existing_live_user_reconciles_without_duplicate_usercreate() -> None:
    """Fresh driver memory + existing SoftEther state is a normal replay/edit.

    Reconciliation must discover the live user, rotate credentials if needed,
    and remain duplicate-save safe without swallowing real backend failures.
    """
    class StrictBackend(FakeSEBackend):
        def __init__(self):
            super().__init__()
            self.create_calls: list[str] = []
            self.delete_calls: list[str] = []

        def user_create(self, username, note=""):
            self.create_calls.append(username)
            if username in self.users:
                raise CoreError("UserCreate failed (error code 66)")
            self.users[username] = ""

        def user_delete(self, username):
            self.delete_calls.append(username)
            super().user_delete(username)

    async def run():
        backend = StrictBackend()
        account = _account(1, "alice", password="first-password")

        # Missing live account: create exactly once.
        initial, _ = _driver(backend=backend)
        await initial.create_account(account)
        assert backend.create_calls == ["1.alice"]

        # Restart/fresh driver memory: live account exists, so replay must not
        # issue UserCreate. Password rotation still applies normally.
        restarted, _ = _driver(backend=backend)
        rotated = _account(1, "alice", password="rotated-password")
        await restarted.update_account(rotated)
        assert backend.create_calls == ["1.alice"]
        assert backend.users["1.alice"] == "rotated-password"

        # Duplicate Save and full account replay stay idempotent.
        await restarted.update_account(rotated)
        replayed, _ = _driver(backend=backend)
        await replayed.sync_accounts([rotated])
        assert backend.create_calls == ["1.alice"]

        await replayed.delete_account("1.alice")
        assert backend.delete_calls == ["1.alice"]
        assert "1.alice" not in backend.users

        # Mid-provision failure is retry-safe: the first UserCreate may have
        # committed before password setup failed. A retry discovers that live
        # user and continues without creating a duplicate.
        partial_backend = StrictBackend()
        real_password_set = partial_backend.user_password_set
        attempts = 0

        def fail_password_once(username, password):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise CoreError("injected password-stage failure")
            real_password_set(username, password)

        partial_backend.user_password_set = fail_password_once
        partial, _ = _driver(backend=partial_backend)
        bob = _account(2, "bob")
        with pytest.raises(CoreError, match="injected password-stage failure"):
            await partial.create_account(bob)
        assert partial_backend.create_calls == ["2.bob"]
        await partial.create_account(bob)
        assert partial_backend.create_calls == ["2.bob"]
        assert partial_backend.users["2.bob"] == "s3cret"

        # A genuine lookup failure still propagates; the fix is not an error-66
        # suppressor and does not blindly retry UserCreate.
        failed, failed_backend = _driver()
        failed_backend.user_list = lambda: (_ for _ in ()).throw(
            CoreError("real vpncmd transport failure"))
        with pytest.raises(CoreError, match="transport failure"):
            await failed.create_account(_account(3, "carol"))

    asyncio.run(run())


def test_vpncmd_managed_hub_uses_server_auth_then_hub_switch(monkeypatch) -> None:
    import app.cores.routing.softether_client as channel
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    admin_secret = "server-admin-secret"
    backend = LocalSoftEtherBackend({
        "admin_password": admin_secret, "server": "localhost", "hub": "DEFAULT",
    })
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    calls = []
    monkeypatch.setattr(
        channel, "run_vpncmd_pty",
        lambda argv, **kwargs: (calls.append((list(argv), kwargs)) or
                                "The command completed successfully.\n"),
    )
    backend._cmd("UserList", hub_name="ZAGROS-E2E-unit")
    argv, kwargs = calls[0]
    assert argv == ["/vpncmd", "localhost:5555", "/SERVER"]
    assert not any(item.startswith("/HUB:") for item in argv)
    assert kwargs["administrator_password"] == admin_secret
    assert kwargs["commands"] == ["Hub ZAGROS-E2E-unit", "UserList"]


def test_vpncmd_managed_hub_csv_strips_selection_preamble(monkeypatch) -> None:
    import app.cores.routing.softether_client as channel
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({"admin_password": "server-admin"})
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    raw = (
        'The Virtual Hub "ZAGROS-E2E-unit" has been selected.\n'
        'Session Name,User Name,Source Host Name\n'
        'SID-test,e2e-user,192.0.2.4\n'
    )
    monkeypatch.setattr(channel, "run_vpncmd_pty", lambda *args, **kwargs: raw)
    result = backend._cmd("SessionList", csv=True, hub_name="ZAGROS-E2E-unit")
    assert result.startswith("Session Name,User Name")
    assert "has been selected" not in result


def test_vpncmd_rejects_newline_protocol_injection(monkeypatch) -> None:
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    backend = LocalSoftEtherBackend({"admin_password": "bad\npassword"})
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    with pytest.raises(CoreError, match="password contains a newline"):
        backend._cmd("ServerInfoGet")

    backend.password = "safe"
    with pytest.raises(CoreError, match="command contains a newline"):
        backend._cmd("ServerInfoGet\nServerStatusGet")


def test_persistent_runtime_resolves_after_container_recreation(tmp_path, monkeypatch) -> None:
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend

    monkeypatch.setattr("shutil.which", lambda _name: None)
    root = tmp_path / "persistent-runtime"
    root.mkdir()
    for name in ("vpnserver", "vpncmd"):
        path = root / name
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    backend = LocalSoftEtherBackend({
        "install_root": str(root), "executable_path": "vpncmd",
    })
    assert backend.server_binary() == str(root / "vpnserver")
    assert backend.vpncmd_binary() == str(root / "vpncmd")


def test_fresh_server_password_recovery_requires_blank_authority(monkeypatch) -> None:
    backend = _se_backend()
    backend.password = "persisted-admin"
    calls: list[tuple[str, str]] = []

    def command(value, **_kwargs):
        calls.append((backend.password, value))
        return "ok"

    monkeypatch.setattr(backend, "_cmd", command)
    monkeypatch.setattr(backend, "reachable", lambda: True)
    assert backend.recover_fresh_server_password() is True
    assert calls == [
        ("", "ServerInfoGet"),
        ("", "ServerPasswordSet persisted-admin"),
    ]
    assert backend.password == "persisted-admin"


def test_start_repairs_missing_runtime_without_manual_reinstall() -> None:
    class UpgradeBackend(FakeSEBackend):
        def __init__(self):
            super().__init__()
            self._reachable = False
            self.binary = None
            self.repairs = 0
            self.starts = 0

        def server_binary(self): return self.binary
        def install_packages(self):
            self.repairs += 1
            self.binary = "/persistent/softether/vpnserver"
            return "restored from persistent stable cache"
        def server_start(self):
            self.starts += 1
            self._reachable = True

    backend = UpgradeBackend()
    driver, _ = _driver(backend=backend)
    asyncio.run(driver.start())
    assert backend.repairs == 1 and backend.starts == 1
    assert backend.reachable() is True


def test_second_install_short_circuits_without_download_or_build(tmp_path) -> None:
    from unittest import mock

    backend = _se_backend()
    calls: list[list[str]] = []
    with mock.patch.dict(os.environ, {"ZAGROS_SOFTETHER_SRC_CACHE": str(tmp_path / "cache")}), \
         mock.patch.object(backend, "_run",
                           lambda argv, timeout=120.0: (calls.append(list(argv)), "ok")[1]), \
         mock.patch.object(backend, "_install_from_github",
                           lambda: (_ for _ in ()).throw(AssertionError("must not download"))), \
         mock.patch.object(backend, "server_binary",
                           lambda: "/usr/local/softether/vpnserver"), \
         mock.patch.object(backend, "client_binary",
                           lambda: "/usr/local/softether/vpnclient"):
        out = backend.install_packages()
    assert "already installed" in out
    assert calls == []


def test_official_stable_bundle_precedes_package_and_source(tmp_path) -> None:
    import shutil
    from unittest import mock

    backend = _se_backend()
    calls: list[list[str]] = []
    with mock.patch.dict(os.environ, {"ZAGROS_SOFTETHER_SRC_CACHE": str(tmp_path / "cache")}), \
         mock.patch.object(shutil, "which", lambda name: "/usr/bin/apt-get"), \
         mock.patch.object(backend, "server_binary", lambda: None), \
         mock.patch.object(backend, "_run",
                           lambda argv, timeout=120.0: (calls.append(list(argv)), "ok")[1]), \
         mock.patch.object(backend, "_install_from_github",
                           lambda: "installed SoftEther v4.44 stable bundle"):
        out = backend.install_packages()
    assert "v4.44 stable bundle" in out
    assert calls == [], "the fast official bundle must win before apt/source work"


def test_install_source_build_last_resort_uses_live_tag() -> None:
    import shutil
    import tarfile
    import urllib.request
    from io import BytesIO
    from unittest import mock

    import app.cores.github_install as gh

    backend = _se_backend()
    calls: list[list[str]] = []
    urls: list[str] = []

    # real tiny tarball fixture: <tag>/Makefile
    tar_buf = BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        import io as _io
        info = tarfile.TarInfo("SoftEtherVPN-9.9.9-test/Makefile")
        payload = b"all:\n\ttrue\n"
        info.size = len(payload)
        tar.addfile(info, _io.BytesIO(payload))
    tar_bytes = tar_buf.getvalue()

    class _Resp:
        """Streaming fake honouring the chunked-download contract:
        read(size) returns successive ≤size slices, then b''."""
        def __init__(self): self._pos = 0
        def read(self, size=-1):
            if self._pos >= len(tar_bytes): return b""
            end = len(tar_bytes) if size is None or size < 0 \
                else min(len(tar_bytes), self._pos + size)
            out = tar_bytes[self._pos:end]; self._pos = end
            return out
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(request, timeout=0):
        urls.append(request.full_url)
        return _Resp()

    def fake_run(argv, timeout=120.0):
        calls.append(list(argv))
        if argv and argv[0] == "apt-get":
            raise CoreError("no candidate")
        return "ok"

    def fake_run_streamed(argv, timeout=0.0):
        # the item-10 streamed build path: cmake --build <dir> --parallel N
        # --target … — artifacts land directly in the build dir
        calls.append(list(argv))
        assert argv[:2] == ["cmake", "--build"], argv
        assert "--parallel" in argv and "--target" in argv
        build_dir = argv[2]
        Path(build_dir).mkdir(parents=True, exist_ok=True)
        for name in ("vpnserver", "vpnclient", "vpncmd", "hamcore.se2"):
            Path(build_dir, name).write_text("binary")
        return "built"

    root = tempfile.mkdtemp(prefix="se-src-root-")
    with mock.patch.object(shutil, "which",
                           lambda n: "/usr/bin/apt-get" if n == "apt-get" else None), \
         mock.patch.object(backend, "_run", fake_run), \
         mock.patch.object(backend, "_run_streamed", fake_run_streamed), \
         mock.patch.object(backend, "_ensure_build_deps", lambda: None), \
         mock.patch.object(backend, "_install_from_github",
                           lambda: (_ for _ in ()).throw(CoreError("no stable asset"))), \
         mock.patch.object(gh, "fetch_latest_release",
                           lambda repo, timeout=30.0: {"tag_name": "v9.9.9-test"}), \
         mock.patch.object(urllib.request, "urlopen", fake_urlopen), \
         mock.patch.dict(os.environ,
                         {"ZAGROS_SOFTETHER_SRC_CACHE":
                          tempfile.mkdtemp(prefix="se-src-cache-")}), \
         mock.patch.object(backend, "_link_on_path", lambda r: None):
        backend._INSTALL_ROOT = root
        out = backend.install_packages()
    # zero hardcoding: the URL carries the LIVE-resolved tag
    assert any("v9.9.9-test" in url for url in urls)
    assert out == "built SoftEther v9.9.9-test from source (cmake)"
    assert any(c[:2] == ["cmake", "-S"] for c in calls)
    assert any(c[:2] == ["cmake", "--build"] for c in calls)
    for name in ("vpnserver", "vpnclient", "vpncmd", "hamcore.se2"):
        assert Path(root, name).exists()
    assert (Path(root, "vpnserver").stat().st_mode & 0o111) != 0


def test_install_reports_every_failed_stage(tmp_path) -> None:
    import shutil
    from unittest import mock

    import app.cores.github_install as gh

    backend = _se_backend()
    with mock.patch.object(shutil, "which", lambda n: None), \
         mock.patch.object(backend, "server_binary", lambda: None), \
         mock.patch.object(backend, "_install_from_github",
                           lambda: (_ for _ in ()).throw(CoreError("gh down"))), \
         mock.patch.object(gh, "fetch_latest_release",
                           lambda repo, timeout=30.0: {"tag_name": "v1"}), \
         mock.patch.object(backend, "_ensure_build_deps",
                           lambda: (_ for _ in ()).throw(CoreError("no toolchain"))):
        # Hermetic: _install_from_github prepares self._INSTALL_ROOT with a
        # REAL makedirs before the (stubbed) download, so the default
        # /usr/local/softether both leaks into the host filesystem and makes
        # the outcome depend on ambient permissions (root locally, EACCES on
        # CI runners). Point it at tmp so each stage fails ONLY from the
        # injected fault — the thing this test actually pins.
        backend._INSTALL_ROOT = str(tmp_path / "softether")
        try:
            backend.install_packages()
            raise AssertionError("install must fail when every stage fails")
        except CoreError as exc:
            msg = str(exc)
            assert "stable-bundle:" in msg and "source-build:" in msg
            assert "gh down" in msg and "no toolchain" in msg


def test_secure_nat_ensure_is_idempotent_and_requires_complete_pool(monkeypatch) -> None:
    backend = _se_backend()
    calls: list[tuple[str, bool]] = []
    pool = """
Virtual DHCP Server Function | Enabled
Start IP Address | 192.168.30.10
End IP Address | 192.168.30.200
Subnet Mask | 255.255.255.0
Default Gateway | 192.168.30.1
DNS Server 1 | 1.1.1.1
"""

    def command(value, *, csv=False, hub=True, hub_name=None):
        calls.append((value, bool(hub_name) if hub_name is not None else hub))
        if value in ("SecureNatEnable", "DhcpEnable"):
            raise CoreError(f"{value}: already enabled")
        return pool

    monkeypatch.setattr(backend, "_cmd", command)
    backend.secure_nat_ensure()
    assert calls == [("SecureNatEnable", True), ("DhcpEnable", True),
                     ("DhcpGet", True)]

    monkeypatch.setattr(backend, "_cmd",
                        lambda value, **kw: "Start IP Address | 192.168.30.10")
    with pytest.raises(CoreError, match="complete lease pool"):
        backend.secure_nat_ensure()


def test_vpncmd_errors_redact_psk_and_password() -> None:
    backend = _se_backend()
    secret = "NeverLog9"
    rendered = backend._safe_command(
        f"IPsecEnable /PSK:{secret} /PASSWORD:{secret} /L2TP:yes")
    positional = backend._safe_command(f"ServerPasswordSet {secret}")
    assert secret not in rendered and secret not in positional
    assert rendered.count("<redacted>") == 2
    assert positional == "ServerPasswordSet <redacted>"


def test_hub_list_parses_csv_without_switching_primary_context(monkeypatch) -> None:
    backend = _se_backend()
    raw = (
        '"Virtual Hub Name","Status","Type"\n'
        '"DEFAULT","Online","Standalone"\n'
        '"ZAGROS-E2E-unit","Online","Standalone"\n'
    )
    seen: list[tuple[str, bool]] = []

    def command(value, *, csv=False, hub=True, hub_name=None):
        seen.append((value, hub))
        return raw

    monkeypatch.setattr(backend, "_cmd", command)
    assert backend.hub_list() == ["DEFAULT", "ZAGROS-E2E-unit"]
    assert seen == [("HubList", False)]


def test_vpncmd_error_line_redacts_managed_hub_password(monkeypatch) -> None:
    import app.cores.routing.softether_client as channel

    backend = _se_backend()
    secret = "ManagedHubSecret9"
    monkeypatch.setattr(backend, "vpncmd_binary", lambda: "/vpncmd")
    monkeypatch.setattr(
        channel, "run_vpncmd_pty",
        lambda *args, **kwargs: (_ for _ in ()).throw(CoreError(
            f"Error occurred: HubCreate ZAGROS-E2E-unit /PASSWORD:{secret}")),
    )
    with pytest.raises(CoreError) as caught:
        backend._cmd(
            f"HubCreate ZAGROS-E2E-unit /PASSWORD:{secret}", hub=False)
    assert secret not in str(caught.value)
    assert "<redacted>" in str(caught.value)


def test_build_deps_per_manager_and_absence_error() -> None:
    import shutil
    from unittest import mock

    backend = _se_backend()
    calls: list[list[str]] = []
    with mock.patch.object(shutil, "which",
                           lambda n: "/usr/bin/dnf" if n == "dnf" else None), \
         mock.patch.object(backend, "_run",
                           lambda argv, timeout=120.0: (calls.append(list(argv)), "ok")[1]):
        backend._ensure_build_deps()
    assert calls and calls[0][0] == "dnf"
    assert "cmake" in calls[0] and "gcc" in calls[0]

    with mock.patch.object(shutil, "which", lambda n: None):
        try:
            backend._ensure_build_deps()
            raise AssertionError("missing toolchain manager must raise")
        except CoreError as exc:
            assert "no supported package manager" in str(exc)


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
