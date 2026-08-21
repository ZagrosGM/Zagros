"""OpenVPN driver tests — real protocol fixtures:
  * actual ``status 3`` output parsing (header-driven)
  * management-client-auth handshake sessions (allow/deny/reauth)
  * interim (status) + final (disconnect hook) accounting without double counting
  * live user management (kill on delete/suspend/password change)

Run: pytest tests/cores/test_openvpn_driver.py -v   OR   python tests/cores/test_openvpn_driver.py
"""
from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time
import traceback
import types as _types
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import Capability, CoreError  # noqa: E402
from app.cores.drivers.openvpn import (  # noqa: E402
    AuthRequest,
    DisconnectRecord,
    ManagementClient,
    OpenVPNDriver,
    parse_status3,
)
from app.cores.types import CoreMetrics, HealthStatus, UsageRecord, UserAccount  # noqa: E402

# Real-shape ``status 3`` output (two connected users, one dual row alice)
STATUS3_SAMPLE = (
    "TITLE\tOpenVPN 2.5.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD]\n"
    "TIME\tMon Aug  3 12:00:00 2026\t1785758400\n"
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n"
    "CLIENT_LIST\t1.alice\t203.0.113.5:51234\t10.8.0.6\t\t1000\t500\tMon Aug  3 11:59:01 2026\t1785758341\t1.alice\t5\t0\tAES-256-GCM\n"
    "CLIENT_LIST\t2.bob\t198.51.100.9:44102\t10.8.0.10\t\t4096\t8192\tMon Aug  3 11:45:12 2026\t1785757512\t2.bob\t6\t1\tAES-256-GCM\n"
    "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\n"
    "ROUTING_TABLE\t10.8.0.6\t1.alice\t203.0.113.5:51234\tMon Aug  3 11:59:55 2026\t1785758395\n"
    "GLOBAL_STATS\tMax bcast/mcast queue length\t0\n"
    "END"
)

STATUS3_ALICE_GREW = STATUS3_SAMPLE.replace("\t1000\t500\t", "\t1600\t500\t")

# Real self-signed test CA (CN=Zagros Test CA) — describe_delivery derives
# the CA fingerprint from actual DER, so fake "CA" text is invalid (7.2/15).
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


class FakeBackend:
    """Fake OpenVPNBackend: canned status, queued disconnect finals, recorded calls.
    Multi-listener contract (alpha.7.2): configure() receives the rendered set."""

    def __init__(self, status_text: str = STATUS3_SAMPLE):
        self.status_text = status_text
        self.disconnects: list[DisconnectRecord] = []
        self.configs: dict[str, str] = {}
        self.hooks: dict[str, str] = {}
        self.network_hooks: dict[str, str] = {}
        self.mgmt_ports: dict[str, int] = {}
        self.pki = {"ca_crt": TEST_CA_CRT,
                    "tls_crypt": "-----BEGIN OpenVPN Static key V1-----\nFAKE-TA\n-----END OpenVPN Static key V1-----"}
        self.auth_handler = None
        self.killed: list[str] = []
        self.running = False
        self.installed = False
        self.connected_mgmt = False

    # process
    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.stop(); self.start()
    def is_running(self): return self.running
    def version(self): return "2.5.9"
    def metrics(self): return CoreMetrics(cpu_percent=1.0, memory_bytes=30_000_000)
    def logs(self, tail=200): return ["ovpn log"] * min(tail, 1)

    # setup
    def ensure_pki(self): return self.pki
    def disconnect_log_path(self, tag: str) -> str:
        return f"/wd/listeners/{tag}/disconnect-log.jsonl"
    def configure(self, specs):
        self.configs = {str(s["tag"]): str(s["server_conf"]) for s in specs}
        self.hooks = {str(s["tag"]): str(s["hook_script"]) for s in specs}
        self.network_hooks = {str(s["tag"]): str(s["network_hook_script"]) for s in specs}
        self.mgmt_ports = {str(s["tag"]): int(s["mgmt_port"]) for s in specs}
    @property
    def config(self):    # single-listener convenience view
        return next(iter(getattr(self, "configs", {}).values()), None)
    @property
    def hook(self):
        return next(iter(getattr(self, "hooks", {}).values()), None)
    def install_packages(self): self.installed = True; return "apt ok"

    # mgmt
    def connect_management(self, timeout=15.0): self.connected_mgmt = True
    def management_alive(self): return True
    def command(self, cmd, timeout=30.0): return "SUCCESS: ok"
    def status_clients(self): return parse_status3(self.status_text)
    def kill_client(self, cn): self.killed.append(cn); return True
    def set_auth_handler(self, handler): self.auth_handler = handler

    # accounting
    def read_disconnect_log(self):
        out, self.disconnects = self.disconnects, []
        return out

    # test helper: pretend a handshake arrived
    def simulate_auth(self, cn, password, meta=None):
        return self.auth_handler(cn, password, meta or {})


def _driver(status_text: str = STATUS3_SAMPLE) -> tuple[OpenVPNDriver, FakeBackend]:
    backend = FakeBackend(status_text)
    return OpenVPNDriver(backend=backend), backend


def _account(**over) -> UserAccount:
    base = dict(user_id=1, username="alice", account_id="1.alice",
                protocol="ovpn", settings={"password": "s3cret"})
    base.update(over)
    return UserAccount(**base)


# --------------------------------------------------------------------------- #
# protocol fixtures
# --------------------------------------------------------------------------- #

def test_status3_parsing_real_output() -> None:
    clients = parse_status3(STATUS3_SAMPLE)
    assert len(clients) == 2
    alice = clients[0]
    assert alice.common_name == "1.alice" and alice.real_ip == "203.0.113.5"
    assert alice.real_port == 51234 and alice.virtual_address == "10.8.0.6"
    assert alice.bytes_received == 1000 and alice.bytes_sent == 500
    assert alice.cipher == "AES-256-GCM" and alice.username == "1.alice"
    assert alice.session_key == ("1.alice", "Mon Aug  3 11:59:01 2026", "203.0.113.5")


def test_management_client_command_roundtrip() -> None:
    sent: list[str] = []
    client = ManagementClient(writer=sent.append)
    result_box: dict[str, Any] = {}

    def run_command():
        result_box["out"] = client.command("status 3", timeout=5)

    thread = threading.Thread(target=run_command)
    thread.start()
    client._feed_line("TITLE\tOpenVPN 2.5.9 ...")
    client._feed_line("CLIENT_LIST\t1.alice\t...")
    client._feed_line("END")
    thread.join(timeout=5)
    assert sent == ["status 3"]
    assert "CLIENT_LIST" in result_box["out"]


def test_management_reader_survives_idle_longer_than_connect_timeout() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def server() -> None:
        conn, _ = listener.accept()
        with conn:
            assert conn.recv(128).strip() == b"pid"
            # Longer than the connect timeout: alpha.7.8 left that timeout on
            # recv(), killed the reader, and deadlocked later PUSH_REQUESTs.
            time.sleep(0.2)
            conn.sendall(b"SUCCESS: pid=123\n")

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    client = ManagementClient()
    try:
        client.connect("127.0.0.1", port, timeout=0.05)
        assert client.command("pid", timeout=1) == "SUCCESS: pid=123"
    finally:
        client.close()
        listener.close()
    thread.join(timeout=1)


def test_management_client_auth_session_allow_deny_reauth() -> None:
    sent: list[str] = []
    client = ManagementClient(writer=sent.append)
    client.set_auth_handler(lambda req: req.password == "good")

    feed = client._feed_line
    # alice: good password -> client-auth + END
    for line in ("CLIENT:CONNECT,5,0", "CLIENT:ENV,username=1.alice",
                 "CLIENT:ENV,password=good", "CLIENT:ENV,IV_PLAT=android",
                 "CLIENT:ENV,IV_VER=3.5.1", "CLIENT:ENV,END"):
        feed(">" + line)
    # bob: bad -> client-deny (single line)
    for line in ("CLIENT:CONNECT,6,0", "CLIENT:ENV,username=2.bob",
                 "CLIENT:ENV,password=bad", "CLIENT:ENV,END"):
        feed(">" + line)
    # alice reauth -> client-auth-nt (single line)
    for line in ("CLIENT:REAUTH,5,1", "CLIENT:ENV,username=1.alice",
                 "CLIENT:ENV,password=good", "CLIENT:ENV,END"):
        feed(">" + line)

    assert sent == [
        "client-auth 5 0", "END",
        'client-deny 6 0 "denied"',
        "client-auth-nt 5 1",
    ]


def test_missing_auth_handler_denies_instead_of_push_request_deadlock() -> None:
    sent: list[str] = []
    client = ManagementClient(writer=sent.append)
    for line in ("CLIENT:CONNECT,8,0", "CLIENT:ENV,username=1.x",
                 "CLIENT:ENV,password=p", "CLIENT:ENV,END"):
        client._feed_line(">" + line)
    assert sent == [
        'client-deny 8 0 "authentication handler unavailable"'
    ]


def test_auth_handler_crash_denies_instead_of_hanging() -> None:
    sent: list[str] = []
    client = ManagementClient(writer=sent.append)

    def boom(_req):
        raise RuntimeError("db down")

    client.set_auth_handler(boom)
    for line in ("CLIENT:CONNECT,9,0", "CLIENT:ENV,username=1.x",
                 "CLIENT:ENV,password=p", "CLIENT:ENV,END"):
        client._feed_line(">" + line)
    assert sent == ['client-deny 9 0 "denied"']


# --------------------------------------------------------------------------- #
# driver behaviour
# --------------------------------------------------------------------------- #

def test_auth_callback_is_registered_before_listener_socket_opens() -> None:
    driver, backend = _driver()
    events: list[str] = []
    original_set = backend.set_auth_handler

    def set_handler(handler):
        events.append("auth-handler")
        original_set(handler)

    def start():
        events.append("listener-start")
        backend.running = True

    backend.set_auth_handler = set_handler
    backend.start = start
    asyncio.run(driver.start())
    assert events == ["auth-handler", "listener-start"]


def test_server_config_has_management_auth_hook_and_tls() -> None:
    driver, backend = _driver()

    async def main():
        await driver.create_account(_account())
        await driver.start()

    asyncio.run(main())
    conf = backend.config or ""
    assert "management-client-auth" in conf
    assert "username-as-common-name" in conf
    # alpha.7.5 item 11: OpenVPN 2.6 refuses to start with the REMOVED
    # directive 'client-cert-not-required' — the modern replacement (valid
    # since 2.4; the fake backend reports 2.5.9) is rendered instead
    assert "verify-client-cert none" in conf
    assert "client-cert-not-required" not in conf
    assert "client-disconnect /wd/listeners/openvpn/client-disconnect.sh" in conf
    assert "management 127.0.0.1 17506" in conf  # base 17505 + portal offset
    # shared PKI via absolute paths (per-listener cwd since alpha.7.2)
    assert "tls-crypt /var/lib/zagros/cores/openvpn/ta.key" in conf
    assert "ca /var/lib/zagros/cores/openvpn/ca.crt" in conf
    # PUSH_REQUEST can only complete when server mode has a pool and a real
    # PUSH_REPLY payload (route/DNS/keepalive). Pin the exact server side.
    assert "topology subnet" in conf
    assert "server 10.8.0.0 255.255.255.0" in conf
    assert 'push "redirect-gateway def1 bypass-dhcp"' in conf
    assert 'push "dhcp-option DNS 1.1.1.1"' in conf
    assert "keepalive 10 60" in conf
    assert "script-security 2" in conf
    assert "up /wd/listeners/openvpn/network-hook.sh" in conf
    network = backend.network_hooks["openvpn"]
    assert "-s 10.8.0.0/24" in network and "MASQUERADE" in network
    assert "script_type" in network and "down)" in network


def test_live_user_management_with_kill_semantics() -> None:
    driver, backend = _driver()

    async def main():
        await driver.start()
        await driver.create_account(_account())
        # suspend = immediately kicked
        await driver.suspend_account("1.alice")
        assert backend.killed[-1] == "1.alice"
        # and auth is denied while suspended
        assert backend.simulate_auth("1.alice", "s3cret") is False
        # resume -> allowed again (no restart anywhere!)
        await driver.resume_account(_account())
        assert backend.simulate_auth("1.alice", "s3cret", {"platform": "android", "client_version": "3.5.1"}) is True
        # wrong password -> deny
        assert backend.simulate_auth("1.alice", "nope") is False
        # password change -> active session killed (force re-auth)
        await driver.update_account(_account(settings={"password": "newpw"}))
        assert backend.killed[-1] == "1.alice"
        assert backend.simulate_auth("1.alice", "newpw") is True
        # delete -> removed + killed
        await driver.delete_account("1.alice")
        assert backend.simulate_auth("1.alice", "newpw") is False

    asyncio.run(main())


def test_usage_interims_plus_authoritative_finals_no_double_count() -> None:
    driver, backend = _driver()

    async def main():
        await driver.start()
        await driver.create_account(_account())

        # interim #1: alice at 1000/500 in status
        first = await driver.get_usage(account_ids=["1.alice"])
        assert [(r.uplink_bytes, r.downlink_bytes) for r in first] == [(1000, 500)]

        # interim #2: grew to 1600/500
        backend.status_text = STATUS3_ALICE_GREW
        second = await driver.get_usage(account_ids=["1.alice"])
        assert [(r.uplink_bytes, r.downlink_bytes) for r in second] == [(600, 0)]

        # disconnect: hook reports authoritative finals 1700/550
        backend.disconnects.append(DisconnectRecord(
            common_name="1.alice", bytes_received=1700, bytes_sent=550,
            duration_seconds=420, ended_at=1785758999,
        ))
        backend.status_text = STATUS3_SAMPLE.replace(
            "CLIENT_LIST\t1.alice\t203.0.113.5:51234\t10.8.0.6\t\t1000\t500\tMon Aug  3 11:59:01 2026\t1785758341\t1.alice\t5\t0\tAES-256-GCM\n", "")
        third = await driver.get_usage(account_ids=["1.alice"])
        assert [(r.uplink_bytes, r.downlink_bytes) for r in third] == [(100, 50)]

        # nothing left to report; persist a zero tombstone so a future panel
        # restart cannot restore this closed session's old cursor.
        assert [(r.uplink_bytes, r.downlink_bytes) for r in await driver.get_usage(account_ids=["1.alice"])] == []
        assert driver.usage_tracker_snapshot(["1.alice"]) == {"1.alice": (0, 0)}

    asyncio.run(main())


def test_live_session_baseline_survives_driver_restart() -> None:
    async def main():
        driver, _backend = _driver()
        await driver.create_account(_account())
        first = await driver.get_usage(account_ids=["1.alice"])
        assert [(r.uplink_bytes, r.downlink_bytes) for r in first] == [(1000, 500)]
        snapshot = driver.usage_tracker_snapshot(["1.alice"])
        assert snapshot == {"1.alice": (1000, 500)}

        restarted, _backend2 = _driver()
        await restarted.create_account(_account())
        restarted.restore_usage_baselines(snapshot)
        same = await restarted.get_usage(account_ids=["1.alice"])
        assert [(r.uplink_bytes, r.downlink_bytes) for r in same] == [(0, 0)]

    asyncio.run(main())


def test_usage_direction_and_filtering() -> None:
    driver, backend = _driver()

    async def main():
        records = await driver.get_usage()  # both users
        by_acct = {r.account_id: (r.uplink_bytes, r.downlink_bytes) for r in records}
        # bytes_received (client->server) == UPLINK, bytes_sent == DOWNLINK
        assert by_acct["1.alice"] == (1000, 500)
        assert by_acct["2.bob"] == (4096, 8192)
        # filter works
        only_bob = await driver.get_usage(account_ids=["2.bob"])
        assert {r.account_id for r in only_bob} == {"2.bob"}

    asyncio.run(main())


def test_online_devices_include_device_detection_metadata() -> None:
    driver, backend = _driver()

    async def main():
        await driver.start()
        await driver.create_account(_account())
        backend.simulate_auth("1.alice", "s3cret", {"platform": "android", "client_version": "3.5.1"})
        sessions = await driver.get_online_devices()
        alice = next(s for s in sessions if s.account_id == "1.alice")
        assert alice.ip == "203.0.113.5"
        assert alice.metadata["virtual_ip"] == "10.8.0.6"
        assert alice.metadata["platform"] == "android"
        assert alice.metadata["app_version"] == "3.5.1"
        assert alice.metadata["cipher"] == "AES-256-GCM"

    asyncio.run(main())


def test_client_profile_sealed_and_complete() -> None:
    driver, backend = _driver()

    async def main():
        await driver.start()
        await driver.create_account(_account())
        return await driver.build_client_config(_account())

    cfg = asyncio.run(main())
    profile = cfg.payload["profile"]
    assert cfg.engine == "openvpn" and cfg.payload["format"] == "ovpn"
    assert cfg.payload["username"] == "1.alice"
    assert cfg.payload["password"] == "s3cret"
    assert "remote 127.0.0.1 1194" in profile
    assert "auth-user-pass" in profile
    # Username/password-only client auth is explicit for OpenVPN Connect;
    # server identity still uses the real CA/server certificate chain.
    assert "setenv CLIENT_CERT 0" in profile
    assert "<cert>" not in profile and "<key>" not in profile
    assert "<ca>" in profile and "BEGIN CERTIFICATE" in profile
    assert "<tls-crypt>" in profile and "FAKE-TA" in profile
    server = driver.render_server_conf(driver._listeners()[0], "/tmp/disconnect", 17505, "/tmp/status")
    assert "verify-client-cert none" in server
    assert "management-client-auth" in server
    blob = repr(cfg) + repr(cfg.public_view())
    assert "BEGIN CERTIFICATE" not in blob and "remote 127.0.0.1" not in blob


def test_validation_and_capability_honesty() -> None:
    driver, _ = _driver()

    async def main():
        try:
            await driver.create_account(_account(protocol="wireguard"))
            raise AssertionError("non-ovpn protocol must be rejected")
        except CoreError:
            pass
        # alpha.7.2: a password-less account NEVER fails provisioning —
        # the panel mints a secure random password in place
        bare = _account(settings={})
        await driver.create_account(bare)
        minted = str(bare.settings.get("password") or "")
        assert len(minted) >= 20
        await driver.create_account(bare)
        assert bare.settings["password"] == minted  # stable — no churn

    asyncio.run(main())
    # honest capability matrix: none of these are claimed
    for cap in (Capability.ROUTING, Capability.HOT_RELOAD, Capability.SPEED_LIMIT,
                Capability.PROCESS_ROUTING, Capability.GEO_ROUTING):
        assert not driver.supports(cap), f"{cap} must NOT be claimed by openvpn"
    for cap in (Capability.USER_MANAGEMENT, Capability.USAGE_ACCOUNTING,
                Capability.ONLINE_TRACKING, Capability.DEVICE_DETECTION,
                Capability.UDP_SUPPORT):
        assert driver.supports(cap)


def test_status_reports_degraded_when_mgmt_dead_and_install_passthrough() -> None:
    driver, backend = _driver()

    async def main():
        await driver.install()
        assert backend.installed
        await driver.start()
        status = await driver.status()
        assert status.health == HealthStatus.HEALTHY and status.core_version == "2.5.9"
        backend.management_alive = lambda: False
        assert (await driver.status()).health == HealthStatus.DEGRADED

    asyncio.run(main())


# ---------------------------------------------------------------------- #
# alpha.7.2 — multi-inbound (xray-style: one process per port)           #
# ---------------------------------------------------------------------- #

def test_multi_inbound_apply_renders_each_listener() -> None:
    """Two openvpn inbounds → two rendered server.confs with distinct
    ports/protos/subnets AND distinct management ports (one process each)."""
    driver, backend = _driver()

    async def main():
        await driver.apply_studio_document({"inbounds": [
            {"tag": "ovpn-udp", "protocol": "ovpn", "port": 1194,
             "transport": "udp", "subnet": "10.8.0.0"},
            {"tag": "ovpn-tcp", "protocol": "ovpn", "port": 443,
             "transport": "tcp", "subnet": "10.9.0.0", "cipher": "AES-128-GCM"},
        ]})
        await driver.start()

    asyncio.run(main())
    assert set(backend.configs) == {"ovpn-udp", "ovpn-tcp"}
    udp, tcp = backend.configs["ovpn-udp"], backend.configs["ovpn-tcp"]
    assert "port 1194" in udp and "proto udp" in udp
    assert "port 443" in tcp and "proto tcp" in tcp
    assert "server 10.8.0.0 255.255.255.0" in udp
    assert "server 10.9.0.0 255.255.255.0" in tcp
    # per-listener cipher (wizard) + template fallback from flat settings
    assert "data-ciphers AES-128-GCM:AES-128-GCM" in tcp
    # distinct management channels (base 17505 + ordinal)
    assert backend.mgmt_ports == {"ovpn-udp": 17506, "ovpn-tcp": 17507}
    assert "management 127.0.0.1 17506" in udp
    assert "management 127.0.0.1 17507" in tcp
    # export mirrors the set
    doc = driver.export_config_document()
    assert [e["tag"] for e in doc["inbounds"]] == ["ovpn-udp", "ovpn-tcp"]
    assert doc["inbounds"][1]["transport"] == "tcp"
    # wizard fields on flat settings mirror the FIRST listener
    assert driver.settings["port"] == 1194 and driver.settings["proto"] == "udp"


def test_multi_inbound_validation_names_offenders() -> None:
    driver, backend = _driver()

    async def main():
        # same (port, proto)
        try:
            await driver.apply_studio_document({"inbounds": [
                {"tag": "a", "protocol": "ovpn", "port": 1194},
                {"tag": "b", "protocol": "ovpn", "port": 1194},
            ]})
            raise AssertionError("duplicate endpoint accepted")
        except CoreError as exc:
            assert "'a'" in str(exc) and "'b'" in str(exc) and "1194" in str(exc)
        # same port is fine across udp/tcp (same as xray udp+tcp share)
        await driver.apply_studio_document({"inbounds": [
            {"tag": "a", "protocol": "ovpn", "port": 1194, "transport": "udp"},
            {"tag": "b", "protocol": "ovpn", "port": 1194, "transport": "tcp",
             "subnet": "10.9.0.0"},
        ]})
        # same tunnel subnet on two listeners → routing conflict
        try:
            await driver.apply_studio_document({"inbounds": [
                {"tag": "a", "protocol": "ovpn", "port": 1194,
                 "subnet": "10.8.0.0"},
                {"tag": "b", "protocol": "ovpn", "port": 1195,
                 "subnet": "10.8.0.0"},
            ]})
            raise AssertionError("duplicate subnet accepted")
        except CoreError as exc:
            assert "subnet" in str(exc) and "'b'" in str(exc)
        # conflicting core-wide auth knobs → named field + both tags
        try:
            await driver.apply_studio_document({"inbounds": [
                {"tag": "a", "protocol": "ovpn", "port": 1194,
                 "auth_mode": "management"},
                {"tag": "b", "protocol": "ovpn", "port": 1195,
                 "subnet": "10.9.0.0", "auth_mode": "static"},
            ]})
            raise AssertionError("conflicting auth_mode accepted")
        except CoreError as exc:
            assert "auth_mode" in str(exc) and "'a'" in str(exc) and "'b'" in str(exc)

    asyncio.run(main())
    # exactly ONE configure() happened — the successful udp+tcp doc; every
    # rejected document failed BEFORE touching the backend
    assert sorted(backend.configs) == ["a", "b"]


def test_multi_inbound_delivery_per_listener_and_grants() -> None:
    driver, backend = _driver()

    async def main():
        await driver.apply_studio_document({"inbounds": [
            {"tag": "ovpn-main", "protocol": "ovpn", "port": 1194},
            {"tag": "ovpn-alt", "protocol": "ovpn", "port": 1443,
             "transport": "tcp", "subnet": "10.9.0.0"},
        ]})
        await driver.start()
        account = _account()
        await driver.create_account(account)
        profile = await driver.describe_delivery(account)
        assert [s.title for s in profile.sections] == [
            "ovpn-main · OpenVPN", "ovpn-alt · OpenVPN"]
        files = [a for s in profile.sections for a in s.artifacts
                 if a.kind.value == "file"]
        assert files[0].filename == "alice-ovpn-main.ovpn"
        assert files[1].filename == "alice-ovpn-alt.ovpn"
        assert "remote 127.0.0.1 1194" in files[0].content
        assert "proto udp" in files[0].content
        assert "remote 127.0.0.1 1443" in files[1].content
        assert "proto tcp" in files[1].content
        # both sections share the same per-user credentials
        for section in profile.sections:
            fields = [f for a in section.artifacts if a.fields for f in a.fields]
            assert any(f.key == "username" and f.value == "1.alice" for f in fields)
        # whitelist narrows delivery to the granted inbound
        granted = _account()
        granted.settings["inbound_tags"] = ["ovpn-alt"]
        await driver.create_account(granted)
        narrowed = await driver.describe_delivery(granted)
        assert [s.title for s in narrowed.sections] == ["ovpn-alt · OpenVPN"]
        config = await driver.build_client_config(granted)
        assert config.display_name == "OpenVPN · ovpn-alt"
        assert "remote 127.0.0.1 1443" in config.payload["profile"]
        # exclusion wins
        granted.settings["excluded_inbounds"] = ["ovpn-alt"]
        empty = await driver.describe_delivery(granted)
        assert empty.sections == []
        try:
            await driver.build_client_config(granted)
            raise AssertionError("client config for a fully excluded account")
        except CoreError:
            pass

    asyncio.run(main())


def test_removed_listener_config_materializes_offline() -> None:
    """Studio apply on a STOPPED core materializes the set (offline-first,
    alpha.7.2): files land now, processes come up at Start."""
    driver, backend = _driver()

    async def main():
        assert not backend.is_running()
        await driver.apply_studio_document({"inbounds": [
            {"tag": "solo", "protocol": "ovpn", "port": 1294},
        ]})
        assert list(backend.configs) == ["solo"]   # configured while stopped
        await driver.start()
        assert backend.is_running()
        assert "port 1294" in backend.configs["solo"]

    asyncio.run(main())


def test_client_cert_directive_version_gating() -> None:
    """item 11: version-detected gate, modern default, operator override."""
    driver, backend = _driver()
    assert driver._client_cert_directive() == "verify-client-cert none"  # 2.5.9
    backend.version = lambda: "2.6.12"
    assert driver._client_cert_directive() == "verify-client-cert none"
    backend.version = lambda: "2.3.18"
    assert driver._client_cert_directive() == "client-cert-not-required"
    backend.version = lambda: "not-an-openvpn"
    # unparsable/unknown probe → modern default (distros ship ≥2.5 today)
    assert driver._client_cert_directive() == "verify-client-cert none"
    backend.version = lambda: None
    assert driver._client_cert_directive() == "verify-client-cert none"
    # operator override beats the binary probe
    backend.version = lambda: "2.6.12"
    overridden = OpenVPNDriver(settings={"openvpn_version": "2.3.99"},
                               backend=backend)
    assert overridden._client_cert_directive() == "client-cert-not-required"


def test_legacy_binary_renders_legacy_directive() -> None:
    driver, backend = _driver()
    backend.version = lambda: "2.3.18"

    async def main():
        await driver.create_account(_account())
        await driver.start()

    asyncio.run(main())
    conf = backend.config or ""
    assert "client-cert-not-required" in conf
    assert "verify-client-cert none" not in conf


def _run_all() -> None:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except BaseException:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    _run_all()
