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
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import Capability, CoreError  # noqa: E402
from app.cores.drivers.softether import (  # noqa: E402
    SoftEtherDriver,
    parse_session_list,
    parse_user_get,
    parse_user_list,
)
from app.cores.drivers.softether.setool import SESession, UserStatistics  # noqa: E402
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


class FakeSEBackend:
    """Fake SoftEtherBackend: user/session tables as dicts, recorded calls."""

    def __init__(self):
        self.users: dict[str, str] = {}
        self.expires: dict[str, str | None] = {}
        self.stats: dict[str, tuple[int, int]] = {}
        self.sessions: list[SESession] = []
        self.disconnected: list[str] = []
        self._reachable = True

    def reachable(self): return self._reachable
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
    def session_disconnect(self, session_name):
        self.disconnected.append(session_name)
        self.sessions = [s for s in self.sessions if s.session_name != session_name]
    def ipsec_psk(self): return None


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


def test_usage_deltas_from_native_counters() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        await driver.create_account(_account(2, "bob"))
        backend.stats = {"1.alice": (1_073_741_824, 2_147_483_648), "2.bob": (100, 100)}

        first = await driver.get_usage()
        by_id = {r.account_id: r for r in first}
        assert by_id["1.alice"].uplink_bytes == 1_073_741_824
        assert by_id["1.alice"].downlink_bytes == 2_147_483_648
        assert by_id["2.bob"].uplink_bytes == 100

        backend.stats["1.alice"] = (1_073_742_824, 2_147_483_648)   # +1000 up
        second = await driver.get_usage()
        by_id = {r.account_id: r for r in second}
        assert by_id["1.alice"].uplink_bytes == 1000
        assert by_id["1.alice"].downlink_bytes == 0

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


def test_honest_capability_surface_locked() -> None:
    driver, _ = _driver()
    assert driver.supports(Capability.HOT_RELOAD)          # vpncmd is live
    assert driver.supports(Capability.USAGE_ACCOUNTING)
    assert driver.supports(Capability.DEVICE_DETECTION)
    for cap in (Capability.SELF_INSTALL, Capability.ROUTING,
                Capability.CHAIN_ROUTING, Capability.MULTI_NODE):
        assert not driver.supports(cap), f"{cap.value} must NOT be claimed for softether"

    async def run():
        driver, _ = _driver()
        try:
            await driver.install()                          # no self-install, honestly
            raise AssertionError("install must raise CapabilityNotSupportedError")
        except Exception as exc:
            assert "self_install" in str(exc)

    asyncio.run(run())


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
