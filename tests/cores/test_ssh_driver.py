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
    def __init__(self, sessions: list[SSHSession] | None = None, sshd: bool = True,
                 acct_reason: str | None = None):
        self._sessions = sessions or []
        self._sshd = sshd
        self.users: dict[str, str] = {}         # name → password
        self.locked: set[str] = set()
        self.deleted: list[str] = []
        self.killed: list[str] = []
        # alpha.7.4 accounting simulation (kernel chain): uid per zg-* user,
        # cumulative byte counters, last-converged rule set
        self.counters: dict[int, int] = {}
        self.sftp_counters: dict[int, tuple[int, int]] = {}
        self.synced_uids: set[int] = set()
        self._acct_reason = acct_reason        # non-None = forwarding accounting unavailable

    # accounting surface mirrors LocalSystemSSHBackend
    def sftp_acct_start(self): return "/tmp/fake-ssh-accounting.sock"
    def sftp_acct_stop(self): pass
    def sftp_acct_read(self): return dict(self.sftp_counters)
    def acct_available(self): return self._acct_reason
    def acct_ensure(self): pass
    def acct_sync_users(self, uids): self.synced_uids = set(uids)
    def acct_read(self): return dict(self.counters)
    def acct_teardown(self): pass
    def uid_of(self, username):
        if username not in self.users:
            return None
        return 1000 + (sum(map(ord, username)) % 500)

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
    # mirrors LocalSystemSSHBackend.ensure_service's contract: start() must
    # fail loudly (CoreError) when sshd is down instead of reporting RUNNING
    def ensure_service(self):
        if not self._sshd:
            raise CoreError("sshd is not running and could not be started — "
                            "enable the system ssh service")
        return "fake (already running)"
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

        # alpha.7.2: a password-less account NEVER fails provisioning —
        # the panel mints a secure random password in place
        nopw = UserAccount(user_id=9, username="nopw", account_id="9.nopw",
                           protocol="ssh", settings={})
        await driver.create_account(nopw)
        minted = str(nopw.settings.get("password") or "")
        assert len(minted) >= 20 and minted != "s3cret"
        assert backend.users["zg-9-nopw"] == minted
        # stable across calls — no silent churn
        await driver.create_account(nopw)
        assert nopw.settings["password"] == minted

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


def test_chain_account_and_usage_degrade_honesty() -> None:
    async def run():
        # backend without usable iptables → the chain cannot exist
        driver, backend = _driver(FakeSSHBackend(
            acct_reason="iptables unavailable inside this container — grant NET_ADMIN"))
        await driver.start()
        endpoint = await driver.ensure_chain_listener("ssh", 0)
        md = endpoint.metadata
        assert md["username"] == "zg-chain" and len(md["password"]) == 16
        assert backend.users["zg-chain"] == md["password"]
        endpoint2 = await driver.ensure_chain_listener("ssh", 0)
        assert endpoint2.metadata["password"] == md["password"]

        # Owner-match can degrade while the decrypted SFTP accounting source
        # remains real. Capability stays available, status names the partial
        # gap, and no fabricated forwarding bytes are returned.
        assert driver.supports(Capability.USAGE_ACCOUNTING)
        assert not driver.supports(Capability.DEVICE_DETECTION)
        assert await driver.get_usage() == []
        state = await driver.status()
        assert state.health.value == "degraded"
        assert "NET_ADMIN" in (state.message or "")
    asyncio.run(run())


def test_usage_accounting_combines_forwarding_and_sftp_directions() -> None:
    """Kernel forwarding uplink + decrypted SFTP up/down become restart-safe
    per-tick deltas; deleted accounts are forgotten."""
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        await driver.create_account(_account(2, "bob"))
        uid_a = backend.uid_of("zg-1-alice")
        uid_b = backend.uid_of("zg-2-bob")
        assert uid_a != uid_b

        # tick 1: kernel counters appear → full counter counts as the delta
        backend.counters[uid_a] = 1000
        backend.counters[uid_b] = 500
        backend.sftp_counters[uid_a] = (200, 700)
        backend.sftp_counters[uid_b] = (100, 300)
        r1 = {r.account_id: (r.uplink_bytes, r.downlink_bytes)
              for r in await driver.get_usage()}
        assert r1 == {"1.alice": (1200, 700), "2.bob": (600, 300)}
        assert backend.synced_uids == {uid_a, uid_b}      # rules converged

        # tick 2: grow one counter → only the growth is billed (no double count)
        backend.counters[uid_a] = 1400
        backend.sftp_counters[uid_a] = (350, 900)
        r2 = {r.account_id: (r.uplink_bytes, r.downlink_bytes)
              for r in await driver.get_usage()}
        assert r2 == {"1.alice": (550, 200), "2.bob": (0, 0)}

        # counter reset (fresh chain) never produces a negative bill
        backend.counters[uid_a] = 50
        r3 = {r.account_id: (r.uplink_bytes, r.downlink_bytes)
              for r in await driver.get_usage()}
        assert r3["1.alice"] == (0, 0)

        # deleted account: forgotten from tracker + out of the rule set
        await driver.delete_account("2.bob")
        r4 = {r.account_id: (r.uplink_bytes, r.downlink_bytes)
              for r in await driver.get_usage()}
        assert "2.bob" not in r4
        assert backend.synced_uids == {uid_a}
    asyncio.run(run())

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
# alpha.7.2 — multi-inbound (xray-style)                                 #
# ---------------------------------------------------------------------- #

def test_multi_inbound_apply_and_dropin() -> None:
    """Two ssh inbounds (distinct tags/ports) land in settings AND in the
    drop-in as two `Port` lines — exactly like xray's multi-inbound."""
    from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

    async def run():
        driver, backend = _driver()
        await driver.apply_studio_document({"inbounds": [
            {"tag": "ssh-main", "protocol": "ssh", "port": 2022,
             "authentication": "both"},
            {"tag": "ssh-alt", "protocol": "ssh", "port": 2222},
        ]})
        assert driver.settings["listeners"] == [
            {"tag": "ssh-main", "port": 2022},
            {"tag": "ssh-alt", "port": 2222},
        ]
        assert driver.settings["port"] == 2022  # legacy mirror = first
        # export reflects BOTH entries
        doc = driver.export_config_document()
        assert [e["tag"] for e in doc["inbounds"]] == ["ssh-main", "ssh-alt"]
        assert [e["port"] for e in doc["inbounds"]] == [2022, 2222]
    asyncio.run(run())

    # the REAL drop-in renders both listeners (pure string render)
    backend_real = LocalSystemSSHBackend({
        "dropin_path": "/nonexistent-dir/zagros.conf",
        "listeners": [
            {"tag": "ssh-main", "port": 2022},
            {"tag": "ssh-alt", "port": 2222, "listen": "10.0.0.5"},
        ],
    })
    text = backend_real.render_dropin()
    assert "Port 22" in text.splitlines()[1]      # operator access kept
    assert "Port 2022" in text and "Port 2222" in text
    assert "ListenAddress 10.0.0.5" in text


def test_multi_inbound_validation_errors() -> None:
    async def run():
        driver, _ = _driver()
        # duplicate tag
        try:
            await driver.apply_studio_document({"inbounds": [
                {"tag": "a", "protocol": "ssh", "port": 2022},
                {"tag": "a", "protocol": "ssh", "port": 2023},
            ]})
            raise AssertionError("duplicate tag accepted")
        except CoreError as exc:
            assert "duplicate" in str(exc) and "'a'" in str(exc)
        # duplicate port (both named in the message)
        try:
            await driver.apply_studio_document({"inbounds": [
                {"tag": "a", "protocol": "ssh", "port": 2022},
                {"tag": "b", "protocol": "ssh", "port": 2022},
            ]})
            raise AssertionError("duplicate port accepted")
        except CoreError as exc:
            assert "2022" in str(exc) and "'b'" in str(exc)
        # reserved operator port
        try:
            await driver.apply_studio_document({"inbounds": [
                {"tag": "a", "protocol": "ssh", "port": 22},
            ]})
            raise AssertionError("port 22 accepted")
        except CoreError as exc:
            assert "reserved" in str(exc)
        # conflicting daemon-wide knob → named field + both tags, no leak
        try:
            await driver.apply_studio_document({"inbounds": [
                {"tag": "a", "protocol": "ssh", "port": 2022, "max_sessions": 5},
                {"tag": "b", "protocol": "ssh", "port": 2023, "max_sessions": 9},
            ]})
            raise AssertionError("conflicting max_sessions accepted")
        except CoreError as exc:
            assert "max_sessions" in str(exc)
            assert "'a'" in str(exc) and "'b'" in str(exc)
        # identical values across entries are fine
        await driver.apply_studio_document({"inbounds": [
            {"tag": "a", "protocol": "ssh", "port": 2022, "max_sessions": 5},
            {"tag": "b", "protocol": "ssh", "port": 2023, "max_sessions": "5"},
        ]})
        assert driver.settings["max_sessions"] == 5
        # nothing half-applied by the failed attempts above
    asyncio.run(run())


def test_multi_inbound_delivery_honors_grants() -> None:
    async def run():
        driver, backend = _driver()
        await driver.apply_studio_document({"inbounds": [
            {"tag": "ssh-main", "protocol": "ssh", "port": 2022},
            {"tag": "ssh-alt", "protocol": "ssh", "port": 2222},
        ]})
        account = _account(1, "alice")
        await driver.create_account(account)
        profile = await driver.describe_delivery(driver._accounts["1.alice"])
        assert len(profile.sections) == 2
        ports = {f.value for s in profile.sections
                 for a in s.artifacts if a.fields
                 for f in a.fields if f.key == "port"}
        assert ports == {"2022", "2222"}
        # whitelist narrows to the granted inbound
        account2 = _account(2, "bob")
        account2.settings["inbound_tags"] = ["ssh-alt"]
        await driver.create_account(account2)
        profile2 = await driver.describe_delivery(driver._accounts["2.bob"])
        assert [s.title for s in profile2.sections] == ["ssh-alt · SSH Tunnel"]
        # exclusion wins over the whitelist
        account2.settings["excluded_inbounds"] = ["ssh-alt"]
        profile3 = await driver.describe_delivery(driver._accounts["2.bob"])
        assert profile3.sections == []
        try:
            await driver.build_client_config(driver._accounts["2.bob"])
            raise AssertionError("client config for excluded inbound")
        except CoreError:
            pass
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
