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


def test_install_pkg_manager_first_success_short_circuits() -> None:
    import shutil
    from unittest import mock

    backend = _se_backend()
    calls: list[list[str]] = []
    with mock.patch.object(shutil, "which",
                           lambda n: "/usr/bin/apt-get" if n == "apt-get" else None), \
         mock.patch.object(backend, "_run",
                           lambda argv, timeout=120.0: (calls.append(list(argv)), "ok")[1]), \
         mock.patch.object(backend, "server_binary",
                           lambda: "/usr/lib/softether/vpnserver"):
        out = backend.install_packages()
    assert "apt-get" in out
    assert calls[0] == ["apt-get", "update"]            # refresh first
    assert calls[1] == ["apt-get", "install", "-y", "softether-vpnserver"]
    # first success wins — no GitHub, no source stage


def test_install_tries_every_manager_then_github(monkeypatch=None) -> None:
    import shutil
    from unittest import mock

    import app.cores.github_install as gh

    backend = _se_backend()
    calls: list[list[str]] = []

    def which(name):
        return {"apt-get": "/usr/bin/apt-get", "dnf": "/usr/bin/dnf"}.get(name)

    def failing(argv, timeout=120.0):
        calls.append(list(argv))
        if argv[0] == "apt-get" and argv[1] == "update":
            return "ok"
        raise CoreError("no candidate")

    root = tempfile.mkdtemp(prefix="se-gh-")
    for name in ("vpnserver", "vpncmd", "hamcore.se2"):
        Path(root, name).write_text("x")
    with mock.patch.object(shutil, "which", which), \
         mock.patch.object(backend, "_run", failing), \
         mock.patch.object(gh, "install_from_github",
                           lambda **kw: "v5.02.5187"), \
         mock.patch.object(backend, "_link_on_path", lambda r: None):
        backend._INSTALL_ROOT = root
        out = backend.install_packages()
    assert out == "installed SoftEther v5.02.5187 from GitHub releases"
    attempted = {c[0] for c in calls}
    assert {"apt-get", "dnf"} <= attempted  # NOT apt-only anymore


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
        for name in ("vpnserver", "vpncmd", "hamcore.se2"):
            Path(build_dir, name).write_text("binary")
        return "built"

    root = tempfile.mkdtemp(prefix="se-src-root-")
    with mock.patch.object(shutil, "which",
                           lambda n: "/usr/bin/apt-get" if n == "apt-get" else None), \
         mock.patch.object(backend, "_run", fake_run), \
         mock.patch.object(backend, "_run_streamed", fake_run_streamed), \
         mock.patch.object(backend, "_ensure_build_deps", lambda: None), \
         mock.patch.object(gh, "install_from_github",
                           lambda **kw: (_ for _ in ()).throw(CoreError("no asset"))), \
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
    assert urls and "v9.9.9-test" in urls[0]
    assert out == "built SoftEther v9.9.9-test from source (cmake)"
    assert any(c[:2] == ["cmake", "-S"] for c in calls)
    assert any(c[:2] == ["cmake", "--build"] for c in calls)
    for name in ("vpnserver", "vpncmd", "hamcore.se2"):
        assert Path(root, name).exists()
    assert (Path(root, "vpnserver").stat().st_mode & 0o111) != 0


def test_install_reports_every_failed_stage(tmp_path) -> None:
    import shutil
    from unittest import mock

    import app.cores.github_install as gh

    backend = _se_backend()
    with mock.patch.object(shutil, "which", lambda n: None), \
         mock.patch.object(gh, "install_from_github",
                           lambda **kw: (_ for _ in ()).throw(CoreError("gh down"))), \
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
            assert "github-release:" in msg and "source-build:" in msg
            assert "gh down" in msg and "no toolchain" in msg


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
