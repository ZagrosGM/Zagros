"""Shared fake backends for multi-core scenario & conformance tests.

Each fake implements exactly the backend Protocol of its driver and records
calls — the same pattern the per-driver unit tests use, consolidated here so
cross-core scenario tests can focus on behaviour, not plumbing.
"""
from __future__ import annotations

import time
from typing import Any

from app.cores.drivers.openvpn.mgmt import StatusClient, parse_status3
from app.cores.drivers.wireguard import parse_wg_dump
from app.cores.drivers.xray.backend import XrayUsageStat  # noqa: F401  (re-export)
from app.cores.exceptions import CoreError
from app.cores.types import CoreMetrics


# ---------------------------------------------------------------------- #
# xray                                                                   #
# ---------------------------------------------------------------------- #

class FakeXrayBackend:
    INBOUND = {"VLESS_TCP": {"protocol": "vless", "network": "tcp", "tls": "none",
                             "header_type": "", "port": 443}}

    def __init__(self, stats: list | None = None, online: list | None = None):
        self._stats = stats if stats is not None else []
        self._online = online if online is not None else []
        self.added: list[tuple] = []
        self.removed: list[tuple] = []
        self.running = True

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): pass
    def is_running(self): return self.running
    def version(self): return "1.8.23"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def inbounds(self): return dict(self.INBOUND)
    def host_options(self, tag: str): return []
    def add_user(self, tag, protocol, email, settings): self.added.append((tag, protocol, email, settings))
    def remove_user(self, tag, email): self.removed.append((tag, email))
    def usage(self, reset: bool = False): return list(self._stats)
    def online_accounts(self): return list(self._online)
    def set_routing_rules(self, rules): pass
    def set_outbounds(self, outbounds): pass
    def ensure_listener(self, protocol, port): pass


# ---------------------------------------------------------------------- #
# sing-box                                                               #
# ---------------------------------------------------------------------- #

class FakeSingBoxBackend:
    def __init__(self, running: bool = True):
        self.configs: list[dict] = []
        self.running = running
        self.restarts = 0

    def apply_config(self, config: dict[str, Any]) -> None:
        self.configs.append(config)
    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.restarts += 1
    def is_running(self): return self.running
    def version(self): return "1.11.4"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []


class FakeV2RayStats:
    """Feeds cumulative {user: (up, down)} like the v2ray StatsService."""

    def __init__(self, counters: dict[str, tuple[int, int]] | None = None):
        self.counters = counters or {}

    def query_user_counters(self) -> dict[str, tuple[int, int]]:
        return dict(self.counters)


# ---------------------------------------------------------------------- #
# openvpn                                                                #
# ---------------------------------------------------------------------- #

class FakeOpenVPNBackend:
    disconnect_log = "disconnect-log.jsonl"

    def __init__(self, status_text: str = ""):
        self.status_text = status_text
        self.killed: list[str] = []
        self.auth_handler = None
        self.running = True
        self.disconnects: list = []
        self.config = ""

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.running = True
    def is_running(self): return self.running
    def version(self): return "2.6.10"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def management_alive(self): return True
    def install_packages(self): return "ok"

    def ensure_pki(self) -> dict[str, str]:
        return {"ca_crt": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
                "tls_crypt": "TLS-KEY"}
    def apply_config(self, server_conf: str) -> None: self.config = server_conf
    def install_hook_script(self, script: str) -> str: return "/tmp/hook.sh"
    def set_auth_handler(self, handler) -> None: self.auth_handler = handler
    def status_clients(self) -> list[StatusClient]: return parse_status3(self.status_text)
    def kill_client(self, common_name: str) -> bool:
        self.killed.append(common_name)
        return True
    def read_disconnect_log(self) -> list:
        out, self.disconnects = self.disconnects, []
        return out


# ---------------------------------------------------------------------- #
# wireguard                                                              #
# ---------------------------------------------------------------------- #

class FakeWireGuardBackend:
    def __init__(self, dump_text: str = "", server_pub: str = "SRVPUB" + "S" * 37 + "="):
        self.dump_text = dump_text
        self.server_pub = server_pub
        self.synced: list[str] = []
        self.running = True
        self._counter = 0

    def is_installed(self): return True
    def install_packages(self): return "ok"
    def ensure_server_keys(self): return ("SRVPRIV", self.server_pub)

    def generate_keypair(self):
        self._counter += 1
        return (f"priv-{self._counter}", ("%02d" % self._counter).ljust(43, "K") + "=")

    def generate_preshared(self): return "P" * 43 + "="

    def up(self, config_text: str):
        self.synced.append(config_text)
        self.running = True
    def sync(self, config_text: str): self.synced.append(config_text)
    def down(self): self.running = False
    def is_running(self): return self.running
    def dump(self): return parse_wg_dump(self.dump_text)
    def version(self): return "v1.0.20210914"
    def logs(self, tail: int = 200): return []
    def metrics(self): return CoreMetrics()


def wg_dump(server_pub: str, peers: list[tuple[str, str | None, int, int, int]]) -> str:
    """Build `wg show all dump` text: (pubkey, endpoint, handshake_age_s, rx, tx)."""
    now = int(time.time())
    lines = [f"mzwg0\tSRVPRIV\t{server_pub}\t51820\toff"]
    for key, endpoint, age, rx, tx in peers:
        hs = now - age if age >= 0 else 0
        lines.append(f"mzwg0\t{key}\t(none)\t{endpoint or '(none)'}\t10.66.66.2/32\t{hs}\t{rx}\t{tx}\t0")
    return "\n".join(lines) + "\n"


class FailingBackend(FakeXrayBackend):
    """Backend whose user ops always fail — for fan-out isolation tests."""

    def __init__(self, exc: Exception | None = None):
        super().__init__()
        self.exc = exc or CoreError("simulated backend outage")

    def add_user(self, tag, protocol, email, settings):
        raise self.exc

    def remove_user(self, tag, email):
        raise self.exc


# ---------------------------------------------------------------------- #
# hysteria2                                                              #
# ---------------------------------------------------------------------- #

class FakeHy2Backend:
    def __init__(self):
        self.configs: list[str] = []
        self.running = False
        self.restarts = 0
        self._traffic: dict[str, tuple[int, int]] = {}
        self._online: dict[str, int] = {}
        self.kicked: list[list[str]] = []

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.restarts += 1
    def is_running(self): return self.running
    def version(self): return "v2.6.1"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def install_binary(self): return "v2.6.1"
    def ensure_tls(self, cn: str): return ("/fake/server.crt", "/fake/server.key")
    def apply_config(self, yaml_text: str): self.configs.append(yaml_text)
    def traffic(self): return dict(self._traffic)
    def online(self): return dict(self._online)
    def kick(self, users): self.kicked.append(list(users))


# ---------------------------------------------------------------------- #
# tuic                                                                   #
# ---------------------------------------------------------------------- #

class FakeTUICBackend:
    def __init__(self):
        self.configs: list[dict] = []
        self.running = False
        self.restarts = 0

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.restarts += 1
    def is_running(self): return self.running
    def version(self): return "tuic-server 1.0.0"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def install_binary(self): return "1.0.0"
    def ensure_tls(self, cn: str): return ("/fake/tuic.crt", "/fake/tuic.key")
    def apply_config(self, config): self.configs.append(config)


# ---------------------------------------------------------------------- #
# ssh                                                                    #
# ---------------------------------------------------------------------- #

class FakeSSHBackend:
    def __init__(self, sshd: bool = True):
        self._sessions: list = []
        self._sshd = sshd
        self.users: dict[str, str] = {}
        self.locked: set[str] = set()
        self.deleted: list[str] = []
        self.killed: list[str] = []

    def user_exists(self, username): return username in self.users
    def create_user(self, username, password, shell, create_home): self.users[username] = password
    def set_password(self, username, password): self.users[username] = password
    def lock_user(self, username): self.locked.add(username)
    def unlock_user(self, username): self.locked.discard(username)
    def delete_user(self, username):
        self.users.pop(username, None); self.deleted.append(username)
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


# ---------------------------------------------------------------------- #
# softether                                                              #
# ---------------------------------------------------------------------- #

class FakeSEBackend:
    def __init__(self):
        self.users: dict[str, str] = {}
        self.expires: dict[str, str | None] = {}
        self.stats: dict[str, tuple[int, int]] = {}
        self.sessions: list = []
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
        from app.cores.drivers.softether.setool import UserStatistics
        inc, out = self.stats.get(username, (0, 0))
        return UserStatistics(username=username, incoming_bytes=inc, outgoing_bytes=out)
    def user_list(self): return sorted(self.users)
    def session_list(self): return list(self.sessions)
    def session_disconnect(self, session_name):
        self.disconnected.append(session_name)
        self.sessions = [s for s in self.sessions if s.session_name != session_name]
    def ipsec_psk(self): return None
