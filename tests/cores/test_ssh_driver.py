"""SSH tunnel driver tests — real `ps` fixtures:

  * ps -eo parsing (tunnels vs interactive vs root priv-stage rows)
  * username sanitization (panel prefixing, unsafe chars, length)
  * useradd/lock/unlock/userdel command flow + password changes
  * suspend kills sessions; sshd-down lifecycle honesty
  * chain account provisioning
  * honest no-usage capability (locked)

Run: pytest tests/cores/test_ssh_driver.py -v  OR  python tests/cores/test_ssh_driver.py
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
from app.cores.drivers.ssh import SSHTunnelDriver, parse_ps_sshd, sanitize_username  # noqa: E402
from app.cores.drivers.ssh.sshtool import SSHSession  # noqa: E402
from app.cores.types import UserAccount  # noqa: E402

# real-shaped `ps -eo user=,pid=,etimes=,args=` (alice has a tunnel + a shell)
PS_SAMPLE = """\
root        900  36000 sshd: root [priv] [net]
alice      4209    125 sshd: alice [priv] [net]
alice      4210    125 sshd: alice@notty
alice      4300     40 sshd: alice@pts/0
bob        4400   1000 sshd: bob@notty
carol     5000  80000 -bash
"""


class FakeSSHBackend:
    def __init__(self, sessions: list[SSHSession] | None = None, sshd: bool = True):
        self._sessions = sessions or []
        self._sshd = sshd
        self.users: dict[str, str] = {}         # name → password
        self.locked: set[str] = set()
        self.deleted: list[str] = []
        self.killed: list[str] = []

    def user_exists(self, username): return username in self.users
    def create_user(self, username, password, shell, create_home):
        self.users[username] = password
    def set_password(self, username, password): self.users[username] = password
    def lock_user(self, username): self.locked.add(username)
    def unlock_user(self, username): self.locked.discard(username)
    def delete_user(self, username):
        self.users.pop(username, None)
        self.deleted.append(username)
    def sessions(self): return list(self._sessions)
    def kill_sessions(self, username):
        before = len(self._sessions)
        self._sessions = [s for s in self._sessions if s.user != username]
        self.killed.append(username)
        return before - len(self._sessions)
    def sshd_running(self): return self._sshd
    def logs(self, tail: int = 200): return []
    def install_packages(self): return "installed"


def _driver(backend: FakeSSHBackend | None = None) -> tuple[SSHTunnelDriver, FakeSSHBackend]:
    backend = backend or FakeSSHBackend()
    return SSHTunnelDriver(backend=backend), backend


def _account(user: int, name: str, enabled: bool = True, password: str = "s3cret") -> UserAccount:
    return UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                       protocol="ssh", enabled=enabled, settings={"password": password})


# ---------------------------------------------------------------------- #

def test_parse_ps_real_shape() -> None:
    sessions = parse_ps_sshd(PS_SAMPLE)
    assert len(sessions) == 3                     # notty alice + pts alice + notty bob
    by = {(s.user, s.terminal): s for s in sessions}
    assert by[("alice", "notty")].pid == 4210
    assert by[("alice", "notty")].elapsed_seconds == 125
    assert by[("alice", "pts/0")].pid == 4300
    assert by[("bob", "notty")].elapsed_seconds == 1000
    assert all(s.user != "root" for s in sessions)  # priv-stage rows skipped


def test_username_sanitization() -> None:
    assert sanitize_username("1.alice") == "zg-1-alice"
    assert sanitize_username("42.Bob_Smith") == "zg-42-bob_smith"
    assert sanitize_username("a" * 64).startswith("zg-")
    assert len(sanitize_username("a" * 64)) == 32
    assert sanitize_username("zg-chain") == "zg-chain"


def test_user_lifecycle_commands() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        account = _account(1, "alice")
        await driver.create_account(account)
        assert backend.users["zg-1-alice"] == "s3cret"
        assert "zg-1-alice" not in backend.locked

        # password change → set_password + session kill (force re-auth)
        await driver.update_account(_account(1, "alice", password="n3wpass"))
        assert backend.users["zg-1-alice"] == "n3wpass"
        assert "zg-1-alice" in backend.killed

        # missing password is a real error, not a silent skip
        try:
            await driver.create_account(
                UserAccount(user_id=9, username="nopw", account_id="9.nopw",
                            protocol="ssh", settings={}))
            raise AssertionError("password-less account must raise")
        except CoreError:
            pass

    asyncio.run(run())


def test_suspend_locks_and_kills_resume_unlocks() -> None:
    async def run():
        backend = FakeSSHBackend(sessions=[
            SSHSession(user="zg-1-alice", pid=4210, elapsed_seconds=125, terminal="notty")])
        driver, _ = _driver(backend)
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        await driver.suspend_account("1.alice")
        assert "zg-1-alice" in backend.locked
        assert backend.sessions() == []                # live tunnel killed
        sessions = await driver.get_online_devices()
        assert sessions == []

        await driver.resume_account(_account(1, "alice"))
        assert "zg-1-alice" not in backend.locked

        await driver.delete_account("1.alice")
        assert "zg-1-alice" in backend.deleted
        assert "zg-1-alice" not in backend.users

    asyncio.run(run())


def test_online_sessions_report_terminal_kind() -> None:
    async def run():
        backend = FakeSSHBackend(sessions=[
            SSHSession(user="zg-1-alice", pid=4210, elapsed_seconds=125, terminal="notty"),
            SSHSession(user="zg-1-alice", pid=4300, elapsed_seconds=40, terminal="pts/0"),
            SSHSession(user="someone-else", pid=5000, elapsed_seconds=9, terminal="notty"),
        ])
        driver, _ = _driver(backend)
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        sessions = await driver.get_online_devices()
        assert len(sessions) == 2                     # foreign users ignored
        kinds = {s.metadata["session_kind"] for s in sessions}
        assert kinds == {"tunnel", "interactive"}
        assert all(s.ip is None for s in sessions)    # sshd gives no IPs: honest

    asyncio.run(run())


def test_sshd_down_surfaces_honestly() -> None:
    async def run():
        driver, backend = _driver(FakeSSHBackend(sshd=False))
        try:
            await driver.start()
            raise AssertionError("start must fail when sshd is down")
        except CoreError as exc:
            assert "sshd" in str(exc)
        status = await driver.status()
        from app.cores.types import HealthStatus
        assert status.health == HealthStatus.UNHEALTHY

    asyncio.run(run())


def test_chain_account_and_no_usage_honesty() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        endpoint = await driver.ensure_chain_listener("ssh", 0)
        md = endpoint.metadata
        assert md["username"] == "zg-chain" and len(md["password"]) == 16
        assert backend.users["zg-chain"] == md["password"]
        endpoint2 = await driver.ensure_chain_listener("ssh", 0)
        assert endpoint2.metadata["password"] == md["password"]

        # usage is honestly NOT claimed (locked so a future regression trips CI)
        assert not driver.supports(Capability.USAGE_ACCOUNTING)
        assert not driver.supports(Capability.DEVICE_DETECTION)
        try:
            await driver.get_usage()
            raise AssertionError("usage must raise CapabilityNotSupportedError")
        except Exception as exc:
            assert "usage_accounting" in str(exc)

    asyncio.run(run())


def test_client_config_sealed_payload() -> None:
    async def run():
        driver, _ = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        config = await driver.build_client_config(driver._accounts["1.alice"])
        assert config.payload["format"] == "ssh"
        assert config.payload["username"] == "zg-1-alice"
        assert "s3cret" not in repr(config)

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
