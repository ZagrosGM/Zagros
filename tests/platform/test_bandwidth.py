from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from app.platform.bandwidth import (
    BandwidthLimiter,
    SoftEtherEndpoint,
    UserLimit,
    action_index,
    mark_for_user,
    marks_for_user,
)


class FakeRunner:
    def __init__(self):
        self.calls: list[tuple[list[str], str | None, bool]] = []
        self.has_clsact = False

    def __call__(self, argv, *, input_text=None, check=True):
        argv = list(argv)
        self.calls.append((argv, input_text, check))
        stdout = ""
        if argv[:4] == ["tc", "qdisc", "show", "dev"]:
            stdout = ("qdisc clsact ffff: parent ffff:fff1\n"
                      if self.has_clsact else "qdisc fq 0: root\n")
        if argv[:4] == ["tc", "qdisc", "add", "dev"]:
            self.has_clsact = True
        return subprocess.CompletedProcess(argv, 0, stdout, "")


class DummyRuntime:
    pass


def test_marks_and_action_ids_are_stable_and_disjoint():
    one = marks_for_user(7)
    two = marks_for_user(8)
    assert one["base"] == mark_for_user(7)
    assert len(set(one.values())) == 4
    assert set(one.values()).isdisjoint(two.values())
    assert action_index(7, "up") != action_index(7, "down")
    assert action_index(7, "down") != action_index(8, "up")


def test_shared_police_action_is_bound_to_both_packet_directions(tmp_path, monkeypatch):
    runner = FakeRunner()
    limiter = BandwidthLimiter(DummyRuntime(), runner=runner)
    limiter._state = {"version": 1, "users": {}, "created_clsact": False}
    monkeypatch.setattr("app.platform.bandwidth.STATE_PATH", tmp_path / "state.json")
    desired = {
        7: UserLimit(7, "alice", upload_mbps=20, download_mbps=100,
                     inner_sources={"10.66.66.7", "2001:db8::7"}, ssh_uids={1007},
                     softether_accounts={"7.alice.sstp"}),
    }
    limiter._endpoints[("198.51.100.7", 51234, 443, "tcp")] = SoftEtherEndpoint(
        "7.alice.sstp", "198.51.100.7", 51234, 443, "tcp")
    limiter._owners = {"7.alice.sstp": 7}
    limiter._desired = lambda: desired
    limiter._ensure_softether_routed = lambda _desired: None

    result = limiter.reconcile()
    assert result["users"]["7"]["upload_mbps"] == 20
    calls = [call[0] for call in runner.calls]
    down = str(action_index(7, "down"))
    up = str(action_index(7, "up"))
    # SAME action index is referenced by ingress inner-response and egress
    # outer SoftEther filters for BOTH L3 families: one aggregate token bucket,
    # not per-core, per-connection, or per-address-family state.
    assert sum(down in command for command in calls if "filter" in command) == 4
    assert sum(up in command for command in calls if "filter" in command) == 4
    ipv6_filters = [command for command in calls
                    if "filter" in command and "ipv6" in command]
    assert any("40001" in command and "ct" in command for command in ipv6_filters)
    assert result["users"]["7"]["prefs"]["ingress_down_v6"] == 21028
    police = [command for command in calls if command[:4] == ["tc", "actions", "replace", "action"]]
    assert any("100mbit" in command and down in command for command in police)
    assert any("20mbit" in command and up in command for command in police)

    nft = next(text for command, text, _check in runner.calls
               if command == ["nft", "-f", "-"])
    marks = marks_for_user(7)
    assert "ip saddr 10.66.66.7" in nft
    assert "ip6 saddr 2001:db8::7" in nft
    assert "meta skuid 1007" in nft
    assert "198.51.100.7 tcp sport 51234 tcp dport 443" in nft
    assert hex(marks["base"]) in nft and hex(marks["outer"]) in nft


def test_xray_config_keeps_legacy_email_but_uses_canonical_platform_mark(
    monkeypatch,
):
    import importlib

    config_module = importlib.import_module("app.xray.config")
    XRayConfig = config_module.XRayConfig

    row = SimpleNamespace(
        id=77, username="alice", type="shadowsocks",
        settings={"password": "pw", "method": "chacha20-ietf-poly1305"},
        excluded_inbound_tags=None,
    )

    class Query:
        def join(self, *_args, **_kwargs): return self
        def outerjoin(self, *_args, **_kwargs): return self
        def filter(self, *_args, **_kwargs): return self
        def group_by(self, *_args, **_kwargs): return self
        def all(self): return [row]

    class DB:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def query(self, *_args): return Query()

    monkeypatch.setattr(config_module, "GetDB", lambda: DB())
    config = XRayConfig({
        "inbounds": [{
            "tag": "ss-in", "port": 1080, "protocol": "shadowsocks",
            "settings": {"clients": []},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": []},
    })
    class Provider:
        # Modules are intentionally non-pickleable; a bound runtime method may
        # own one through SQLAlchemy/runtime state.
        module = importlib

        def resolve(self, names):
            return {"alice": 9}

    provider = Provider()
    config.bandwidth_user_id_provider = provider.resolve
    merged = config.include_db_users()
    assert merged.bandwidth_user_id_provider.__self__ is provider
    client = merged.get_inbound("ss-in")["settings"]["clients"][0]
    assert client["email"] == "77.alice"
    rule = next(item for item in merged["routing"]["rules"]
                if item.get("user") == ["77.alice"])
    assert rule["outboundTag"] == "zg-bw-u9"
    outbound = next(item for item in merged["outbounds"]
                    if item.get("tag") == "zg-bw-u9")
    assert outbound["streamSettings"]["sockopt"]["mark"] == mark_for_user(9)
    assert merged.bandwidth_identity_map == {77: 9}
    assert merged.bandwidth_user_ids == {9}


def test_xray_core_tracks_canonical_ids_from_exact_running_document():
    from app.xray.core import XRayCore

    parsed = XRayCore._bandwidth_ids({
        "outbounds": [
            {"tag": "direct"},
            {"tag": "zg-bw-u7"},
            {"tag": "zg-bw-u42"},
        ],
    })
    assert parsed == {7, 42}

    class Config(dict):
        bandwidth_user_ids = {91}

    assert XRayCore._bandwidth_ids(Config(outbounds=[
        {"tag": "zg-bw-u7"},
    ])) == {91}


def test_zero_zero_removes_owned_runtime_without_touching_root_qdisc(tmp_path, monkeypatch):
    runner = FakeRunner()
    limiter = BandwidthLimiter(DummyRuntime(), runner=runner)
    limiter._state = {"version": 1, "users": {}, "created_clsact": False}
    monkeypatch.setattr("app.platform.bandwidth.STATE_PATH", tmp_path / "state.json")
    limiter._desired = lambda: {7: UserLimit(7, "alice", 0, 0)}
    result = limiter.reconcile()
    assert result["users"] == {}
    assert any(command[:5] == ["nft", "delete", "table", "inet", "zagros_bw"]
               for command, _text, _check in runner.calls)
    assert not any(command[:4] == ["tc", "qdisc", "del", "dev"]
                   for command, _text, _check in runner.calls)


def test_softether_authenticated_log_event_maps_outer_transport():
    limiter = BandwidthLimiter(DummyRuntime(), runner=FakeRunner())
    limiter._owners = {"7.alice.sstp": 7}
    limiter.runtime.users = type("Users", (), {"accounts_of_core": lambda *a, **k: [
        {"account_id": "7.alice.sstp", "protocol": "sstp"}
    ]})()
    line = ('The connection "CID-1" (IP address: 198.51.100.7, Host name: x, '
            'Port number: 51234, Client name: "Microsoft SSTP VPN Client", '
            'Version: 4.44) is attempting to connect. The auth type provided '
            'is "External" and the user name is "7.alice.sstp".')
    assert limiter._consume_softether_line(line) is True
    endpoint = next(iter(limiter._endpoints.values()))
    assert (endpoint.transport, endpoint.client_port, endpoint.server_port) == (
        "tcp", 51234, 443)


def test_known_softether_identity_returns_before_shared_quarantine():
    limiter = BandwidthLimiter(DummyRuntime(), runner=FakeRunner())
    desired = {
        7: UserLimit(7, "alice", 20, 100,
                     inner_sources={"192.168.30.10"},
                     softether_accounts={"7.alice.softether"}),
    }
    limiter._owners = {"7.alice.softether": 7}
    limiter._soft_tap = "tap_zgsoft"
    limiter._endpoints[("198.51.100.7", 51000, 50154, "tcp")] = SoftEtherEndpoint(
        "7.alice.softether", "198.51.100.7", 51000, 50154, "tcp")
    script = limiter._nft_script(desired)
    # Without `return`, the following generic tap/port quarantine rule would
    # overwrite the user's mark and create a separate 1% bucket.
    assert "ip saddr 192.168.30.10 ct mark set 0x5a000700 meta mark set 0x5a000701 return" in script
    assert ("ip saddr 198.51.100.7 tcp sport 51000 tcp dport 50154 "
            "ct mark set 0x5a000740 return") in script


def test_softether_dhcp_identity_is_durable_and_reassigned():
    limiter = BandwidthLimiter(DummyRuntime(), runner=FakeRunner())
    limiter._owners = {"7.alice.softether": 7, "8.bob.softether": 8}
    limiter._limits = {
        7: UserLimit(7, "alice", 20, 100),
        8: UserLimit(8, "bob", 20, 100),
    }
    limiter._session_accounts = {"SID-ALICE": "7.alice.softether"}
    alice = ('The DHCP server of host "aa" (192.168.30.1) on this session '
             'allocated, for host "SID-ALICE" on another session "bb", '
             'the new IP address 192.168.30.10.')
    assert limiter._consume_softether_line(alice) is True
    assert limiter._soft_sources == {"192.168.30.10": 7}
    assert "192.168.30.10" in limiter._limits[7].inner_sources
    assert limiter._carry_fail_closed({})["softether_sources"] == {
        "192.168.30.10": 7}

    # DHCP reuse must move — never duplicate — a stable packet identity.
    limiter._session_accounts = {"SID-BOB": "8.bob.softether"}
    bob = alice.replace("SID-ALICE", "SID-BOB")
    assert limiter._consume_softether_line(bob) is True
    assert limiter._soft_sources == {"192.168.30.10": 8}
    assert "192.168.30.10" not in limiter._limits[7].inner_sources
    assert "192.168.30.10" in limiter._limits[8].inner_sources


def test_desired_reuses_live_softether_lease_during_api_reconcile():
    class Result:
        def scalars(self):
            return self

        def all(self):
            return [SimpleNamespace(
                id=7, username="alice",
                upload_limit_mbps=20, download_limit_mbps=100,
            )]

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, _query):
            return Result()

    runtime = SimpleNamespace(
        session_factory=lambda: Session(),
        users=SimpleNamespace(account_owners=lambda: {
            ("softether", "7.alice.softether"): 7,
        }),
        core_manager=SimpleNamespace(list_cores=lambda: []),
    )
    limiter = BandwidthLimiter(runtime, runner=FakeRunner())
    limiter._soft_sources = {"192.168.30.10": 7}
    desired = limiter._desired()
    assert desired[7].inner_sources == {"192.168.30.10"}
    assert desired[7].softether_accounts == {"7.alice.softether"}


def test_start_retries_transient_live_core_readiness(monkeypatch):
    limiter = BandwidthLimiter(DummyRuntime(), runner=FakeRunner())
    calls = []

    def reconcile():
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("vpncmd warming")
        return {}

    limiter.reconcile = reconcile
    started = []
    limiter._start_watcher = lambda: started.append(True)
    monkeypatch.setenv("ZAGROS_BANDWIDTH_START_ATTEMPTS", "3")
    monkeypatch.setenv("ZAGROS_BANDWIDTH_START_RETRY_SECONDS", "0")
    limiter.start()
    assert len(calls) == 3
    assert started == [True]


def test_recovery_replays_full_persisted_settings_and_clears_marker(
    tmp_path, monkeypatch,
):
    class Users:
        def accounts_of_core(self, core_id, *, decrypt=True):
            assert core_id == "softether" and decrypt is True
            return [{
                "user_id": 7, "core_id": core_id,
                "account_id": "7.alice.softether", "protocol": "softether",
                "enabled": True, "settings": {"password": "real-secret"},
            }]

        def get_user(self, user_id):
            assert user_id == 7
            return SimpleNamespace(id=7, username="alice", status="active")

    class Driver:
        def __init__(self):
            self.synced = []

        async def sync_accounts(self, accounts):
            self.synced.append(accounts)

    driver = Driver()
    runtime = SimpleNamespace(
        users=Users(),
        core_manager=SimpleNamespace(get=lambda core_id: driver),
    )
    limiter = BandwidthLimiter(runtime, runner=FakeRunner())
    monkeypatch.setattr("app.platform.bandwidth.STATE_PATH", tmp_path / "state.json")
    limiter._state = {
        "version": 1, "users": {},
        "fail_closed_accounts": [{
            "core_id": "softether", "account_id": "7.alice.softether",
        }],
    }
    limiter._recover_limited_accounts()
    assert len(driver.synced) == 1
    account = driver.synced[0][0]
    assert account.enabled is True
    assert account.settings == {"password": "real-secret"}
    assert "fail_closed_accounts" not in limiter._state
