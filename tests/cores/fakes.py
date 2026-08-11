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

# Real self-signed test CA (openssl req -x509, CN=Zagros Test CA) — the
# driver's describe_delivery derives the CA fingerprint from real DER, so a
# fake "CA" blob is no longer a valid fixture (alpha.7.2, item 15).
TEST_CA_CRT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDEzCCAfugAwIBAgIUYULfBbJOkPLeIiRrEi/j0GbsGPQwDQYJKoZIhvcNAQEL\n"
    "BQAwGTEXMBUGA1UEAwwOWmFncm9zIFRlc3QgQ0EwHhcNMjYwODA3MjI0MTEyWhcN\n"
    "MzYwODA0MjI0MTEyWjAZMRcwFQYDVQQDDA5aYWdyb3MgVGVzdCBDQTCCASIwDQYJ\n"
    "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMULa8BLxMw6vshNPbA+nCTqn48JEE8s\n"
    "ercHIrEOelKYb4WZjH2bAZmCCIIOwaOLuZkoizrTr1yJwSqABLIDaO1l35B5R8vP\n"
    "VCUouYoxR/2LK1xedhlNo/LHsOxhiyA3AxuLDwVD5Id9Xw0ajsYdBPUq4/Etvryz\n"
    "4OLM4FPFb2u34wL4GJVLDB2msVTyP3BECmABqoAzhVXqFAfPVfy1G8MMtjladVbX\n"
    "1CI5nyTwZcBxunyBYBDf6GdUT1cdoCmQmonmCAsNQ7/Qfi6HxWOrR/+WV82wNRNP\n"
    "ohc0I7jqPe7HXNr3DaP/b9CKEBCql6pFW/XztSUHq4AO+FjqSdcTousCAwEAAaNT\n"
    "MFEwHQYDVR0OBBYEFJBIR37iqVOenMiHlSV2iVNfsf88MB8GA1UdIwQYMBaAFJBI\n"
    "R37iqVOenMiHlSV2iVNfsf88MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n"
    "BQADggEBACCSXd+9Yo1SBCUG/KU+7ucO/PZ/9muobdla/zFNdLWDBKfDNkEwOod/\n"
    "AJIdbsG9EPSxn/SYbW5uhRySGdsy2YmktIRTdIuIuW2joJ3Wh5CXGqihmTJC7gl6\n"
    "kEAguDybf264JO9HCVrVIsT6goLXwm2NxDxRecF0yeJB7cq780ltzWjeLEDl9sI9\n"
    "KdHOwXNWMaE1w8NZZia0IjeIgY2nH9SmUcBAbmc+Jp5W2ctV0joS2aKYARlQcMhK\n"
    "fJ8oeYSSG2O71SKCY6vZFHmAWiSUAcU0kyiVK49y375aPs1gq27N0k+4Wszx+SPh\n"
    "zaJ2oIKBQtMHmV5zCJHbgwTCIgUQXBA=\n"
    "-----END CERTIFICATE-----\n"
)


class FakeOpenVPNBackend:
    """Multi-listener fake (alpha.7.2): mirrors LocalOpenVPNBackend's
    configure() contract — one server.conf + hook per tag."""

    def __init__(self, status_text: str = ""):
        self.status_text = status_text
        self.killed: list[str] = []
        self.auth_handler = None
        self.running = True
        self.disconnects: list = []
        self.configs: dict[str, str] = {}
        self.hooks: dict[str, str] = {}
        self.mgmt_ports: dict[str, int] = {}
        self.configure_calls = 0

    def disconnect_log_path(self, tag: str) -> str:
        return f"/wd/listeners/{tag}/disconnect-log.jsonl"

    def configure(self, specs: list[dict[str, Any]]) -> None:
        self.configure_calls += 1
        self.configs = {str(s["tag"]): str(s["server_conf"]) for s in specs}
        self.hooks = {str(s["tag"]): str(s["hook_script"]) for s in specs}
        self.mgmt_ports = {str(s["tag"]): int(s["mgmt_port"]) for s in specs}

    @property
    def config(self) -> str:
        """Convenience single-listener view (legacy assertions)."""
        return next(iter(self.configs.values()), "")

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.running = True
    def is_running(self): return self.running
    def version(self): return "2.6.10"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def management_alive(self): return True
    def install_packages(self): return "ok"
    def command(self, cmd, timeout=30.0, *, tag=None): return ""

    def ensure_pki(self) -> dict[str, str]:
        return {"ca_crt": TEST_CA_CRT,
                "tls_crypt": "TLS-KEY"}
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

    def public_from_private(self, private):
        from app.cores.drivers.wireguard.backend import public_from_private_pure
        return public_from_private_pure(private)

    def write_server_private_key(self, private):
        self.server_private_written = private

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
    def secure_nat_ensure(self): self.secure_nat = True
    def ipsec_get(self):
        from app.cores.drivers.softether.setool import IPsecServices
        return getattr(self, "_ipsec", IPsecServices(
            l2tp=False, l2tp_raw=False, etherip=False, psk="", default_hub="DEFAULT"))
    def ipsec_services_set(self, *, l2tp, l2tp_raw, etherip, psk, default_hub):
        from app.cores.drivers.softether.setool import IPsecServices
        self._ipsec = IPsecServices(l2tp=l2tp, l2tp_raw=l2tp_raw,
                                    etherip=etherip, psk=psk,
                                    default_hub=default_hub)
