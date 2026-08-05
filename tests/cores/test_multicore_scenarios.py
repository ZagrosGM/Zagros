"""Multi-Core integration scenarios — the phase-defining proof tests.

These run four real drivers (Xray, sing-box, OpenVPN, WireGuard) through one
CoreManager with protocol-level fake backends, and verify the platform's
cross-core guarantees:

  S1  one user provisioned on ALL cores at once; independent client access
  S2  unified quota: 1+2+3+4 GB across cores == exactly 10 GB deducted,
      with zero double counting on re-polls (incl. multi-node records)
  S3  suspend ⇒ simultaneous cut on every core
  S4  resume ⇒ simultaneous restore on every core
  S5  delete ⇒ accounts removed from every core
  +   global device limit across cores (same device on 2 cores = 1 device)
  +   unified session history (open/close with duration)
  +   fan-out fault isolation (one core down never blocks the others)
  +   concurrent provisioning + concurrent quota application (stress/soak)

Run: pytest tests/cores/test_multicore_scenarios.py -v
  OR python tests/cores/test_multicore_scenarios.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import time
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import (  # noqa: E402
    CoreManager,
    CoreState,
    DeviceManager,
    InMemoryDeviceStore,
    InMemoryQuotaStore,
    InMemorySessionStore,
    SessionManager,
    UnifiedQuotaService,
)
from app.cores.drivers.openvpn import OpenVPNDriver  # noqa: E402
from app.cores.drivers.openvpn.driver import _DISCONNECT_HOOK  # noqa: E402,F401
from app.cores.drivers.singbox import SingBoxDriver  # noqa: E402
from app.cores.drivers.wireguard import WireGuardDriver  # noqa: E402
from app.cores.drivers.xray import XrayDriver  # noqa: E402
from app.cores.types import UsageRecord, UserAccount  # noqa: E402
from tests.cores.fakes import (  # noqa: E402
    FakeOpenVPNBackend,
    FakeSingBoxBackend,
    FakeV2RayStats,
    FakeWireGuardBackend,
    FakeXrayBackend,
    FailingBackend,
    XrayUsageStat,
    wg_dump,
)

# avoid pytest collecting the package's __init__ side effects twice
_GB = 1024 ** 3


class InMemoryCoreStore:
    """CoreStateStore fake."""

    def __init__(self):
        self.saved: dict[str, dict] = {}

    async def load(self): return {}
    async def save_state(self, core_id, *, state, enabled, settings=None):
        self.saved[core_id] = {"state": state.value, "enabled": enabled}
    async def remove(self, core_id): self.saved.pop(core_id, None)


def _status3(rows: list[tuple[str, str, int, int]]) -> str:
    """Build a real-shaped `status 3` body: (cn, ip, rx, sent)."""
    lines = [
        "TITLE\tOpenVPN 2.6.10",
        "TIME\tMon Aug  3 12:00:00 2026\t1785758400",
        "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher",
    ]
    for i, (cn, ip, rx, tx) in enumerate(rows):
        lines.append(
            f"CLIENT_LIST\t{cn}\t{ip}:{40000 + i}\t10.8.0.{10 + i}\t\t{rx}\t{tx}\t"
            f"Mon Aug  3 11:5{i}:01 2026\t178575830{i}\t{cn}\t{i}\t{i}\tAES-256-GCM"
        )
    lines.append("END")
    return "\n".join(lines)


async def _cluster(tmp: str):
    """Four-core cluster: xray + sing-box + openvpn + wireguard via one manager."""
    xray = XrayDriver(backend=FakeXrayBackend())
    sing = SingBoxDriver(backend=FakeSingBoxBackend(), stats=FakeV2RayStats())
    ovpn = OpenVPNDriver(settings={"work_dir": f"{tmp}/ovpn"},
                         backend=FakeOpenVPNBackend())
    wg = WireGuardDriver(settings={"work_dir": f"{tmp}/wg"},
                         backend=FakeWireGuardBackend())

    mgr = CoreManager(InMemoryCoreStore())
    for driver in (xray, sing, ovpn, wg):
        mgr.attach(driver.metadata.id, driver, state=CoreState.RUNNING)
        await driver.start()
    return mgr, xray, sing, ovpn, wg


def _accounts(user: int, name: str) -> dict[str, UserAccount]:
    return {
        "xray": UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                            protocol="vless",
                            settings={"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}),
        "sing-box": UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                                protocol="vless",
                                settings={"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}),
        "openvpn": UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                               protocol="ovpn", settings={"password": "s3cret"}),
        "wireguard": UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                                 protocol="wireguard", settings={}),
    }


# ---------------------------------------------------------------------- #
# Scenario 1 — one user on every core at once                            #
# ---------------------------------------------------------------------- #

def test_scenario_1_provision_one_user_on_all_cores() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-sc1-") as tmp:
            mgr, xray, sing, ovpn, wg = await _cluster(tmp)
            accounts = _accounts(1, "alice")
            results = await mgr.provision_user(accounts)
            assert all(r.success for r in results), results

            # each core really holds the account
            assert xray._backend.added and xray._backend.added[0][2] == "1.alice"
            assert sing._accounts["1.alice"].settings["id"]
            assert ovpn._accounts["1.alice"].settings["password"] == "s3cret"
            assert wg._accounts["1.alice"].settings["public_key"]  # generated in place

            # independent client access per core (sealed payloads, per engine)
            cfg_x = await xray.build_client_config(accounts["xray"])
            cfg_s = await sing.build_client_config(accounts["sing-box"])
            cfg_o = await ovpn.build_client_config(accounts["openvpn"])
            cfg_w = await wg.build_client_config(wg._accounts["1.alice"])
            assert {c.engine for c in (cfg_x, cfg_s, cfg_o, cfg_w)} == {
                "sing-box", "openvpn", "wireguard"}
            assert cfg_o.payload["format"] == "ovpn"
            assert "PrivateKey" in cfg_w.payload["profile"]

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# Scenario 2 — unified quota: exactly 10 GB, zero double counting        #
# ---------------------------------------------------------------------- #

def test_scenario_2_unified_quota_exactly_10_gb_no_double_counting() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-sc2-") as tmp:
            mgr, xray, sing, ovpn, wg = await _cluster(tmp)
            wg_pub = wg._accounts  # populated on create
            accounts = _accounts(1, "alice")
            await mgr.provision_user(accounts)
            alice_wg = wg_pub["1.alice"].settings["public_key"]

            # ---- each core reports its own cumulative counters ------- #
            _H = _GB // 2  # 0.5 GB — exact integer, no float truncation artefacts
            xray._backend._stats = [XrayUsageStat("1.alice", _H, _H)]      # 1 GB exact
            sing._stats.counters = {"1.alice": (1 * _GB, 3 * _GB)}         # 4 GB
            ovpn._backend.status_text = _status3([("1.alice", "203.0.113.5", _H, 3 * _H)])  # 2 GB exact
            wg._backend.dump_text = wg_dump(wg._server_public, [(alice_wg, "198.51.100.7", 30, 1 * _GB, 2 * _GB)])

            owners = {
                ("xray", "1.alice"): 1, ("sing-box", "1.alice"): 1,
                ("openvpn", "1.alice"): 1, ("wireguard", "1.alice"): 1,
            }
            quota = UnifiedQuotaService(InMemoryQuotaStore(), limits={1: 20 * _GB})
            quota.set_limit(1, 20 * _GB)

            wanted = {cid: ["1.alice"] for cid in mgr.list_cores()}
            records = await mgr.aggregate_usage(wanted)
            applied, dropped = await quota.apply_usage(records, owners)
            assert not dropped, dropped

            view = await quota.get_view(1)
            assert view.total_bytes == 10 * _GB, (
                f"expected exactly 10 GB (1+2+3+4), got {view.total_bytes / _GB:.4f} GB")
            total_cores = set().union(*(a.cores for a in applied))
            assert total_cores == {"xray", "sing-box", "openvpn", "wireguard"}

            # ---- re-poll with identical counters → nothing new (no double count)
            records2 = await mgr.aggregate_usage(wanted)
            applied2, _ = await quota.apply_usage(records2, owners)
            view2 = await quota.get_view(1)
            assert view2.total_bytes == 10 * _GB, (
                f"re-poll must not double count: {view2.total_bytes / _GB:.4f} GB")
            assert all(a.applied_bytes == 0 for a in applied2) or not applied2

            # ---- growth: +1 GB on wireguard only
            wg._backend.dump_text = wg_dump(wg._server_public, [(alice_wg, "198.51.100.7", 5, 2 * _GB, 2 * _GB)])
            records3 = await mgr.aggregate_usage(wanted)
            await quota.apply_usage(records3, owners)
            view3 = await quota.get_view(1)
            assert view3.total_bytes == 11 * _GB

            # ---- unowned record is dropped with a reason, never absorbed
            applied4, dropped4 = await quota.apply_usage(
                [UsageRecord(core_id="xray", account_id="9.ghost", uplink_bytes=5 * _GB)],
                owners)
            assert applied4 == [] and len(dropped4) == 1
            assert (await quota.get_view(1)).total_bytes == 11 * _GB

    asyncio.run(run())


def test_scenario_2b_multinode_records_counted_once_each() -> None:
    async def run() -> None:
        quota = UnifiedQuotaService(InMemoryQuotaStore())
        owners = {("xray", "7.bob"): 7}
        records = [
            UsageRecord(core_id="xray", account_id="7.bob", node_id=None,
                        uplink_bytes=100, downlink_bytes=50),   # master core
            UsageRecord(core_id="xray", account_id="7.bob", node_id=3,
                        uplink_bytes=200, downlink_bytes=70),   # node 3
            UsageRecord(core_id="xray", account_id="7.bob", node_id=5,
                        uplink_bytes=40, downlink_bytes=10),    # node 5
        ]
        applied, dropped = await quota.apply_usage(records, owners)
        view = await quota.get_view(7)
        assert view.total_bytes == 100 + 50 + 200 + 70 + 40 + 10
        assert applied[0].applied_bytes == 470

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# Scenarios 3/4/5 — simultaneous suspend / resume / delete               #
# ---------------------------------------------------------------------- #

def test_scenario_3_4_5_suspend_resume_delete_simultaneously() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-sc345-") as tmp:
            mgr, xray, sing, ovpn, wg = await _cluster(tmp)
            accounts = _accounts(1, "alice")
            await mgr.provision_user(accounts)
            wg_conf_with_peer = wg._backend.synced[-1]
            assert "[Peer]" in wg_conf_with_peer

            # ---- S3: suspend ⇒ all cores cut access at once -----------
            results = await mgr.suspend_user(accounts)
            assert all(r.success for r in results), results
            assert ("VLESS_TCP", "1.alice") in xray._backend.removed  # xray: removal IS suspension
            assert not sing._accounts["1.alice"].enabled
            assert not ovpn._accounts["1.alice"].enabled
            assert "1.alice" in ovpn._backend.killed         # live session killed
            assert not wg._accounts["1.alice"].enabled
            assert "[Peer]" not in wg._backend.synced[-1]    # peer removed live

            # ---- S4: resume ⇒ all cores restore at once ----------------
            results = await mgr.resume_user(accounts)
            assert all(r.success for r in results), results
            adds_after = len([a for a in xray._backend.added if a[2] == "1.alice"])
            assert adds_after >= 2                             # re-added on resume
            assert sing._accounts["1.alice"].enabled
            assert ovpn._accounts["1.alice"].enabled
            assert wg._accounts["1.alice"].enabled
            assert "[Peer]" in wg._backend.synced[-1]

            # ---- S5: delete ⇒ accounts removed from every core ---------
            results = await mgr.deprovision_user(
                {cid: "1.alice" for cid in mgr.list_cores()})
            assert all(r.success for r in results), results
            assert ("VLESS_TCP", "1.alice") in xray._backend.removed
            assert "1.alice" not in sing._accounts
            assert "1.alice" not in ovpn._accounts
            assert "1.alice" not in wg._accounts

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# Global device limit across cores                                       #
# ---------------------------------------------------------------------- #

def test_global_device_limit_counts_one_device_per_ip_across_cores() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-dev-") as tmp:
            mgr, xray, sing, ovpn, wg = await _cluster(tmp)
            accounts = _accounts(1, "alice")
            await mgr.provision_user(accounts)
            alice_wg_key = wg._accounts["1.alice"].settings["public_key"]

            # same phone (IP A) on openvpn AND wireguard = ONE device;
            # laptop (IP B) on wireguard endpoint = device two
            ovpn._backend.status_text = _status3([("1.alice", "203.0.113.10", 100, 100)])
            wg._backend.dump_text = wg_dump(wg._server_public, [
                (alice_wg_key, "203.0.113.10:5555", 30, 100, 100),     # same IP A
            ])
            xray._backend._stats = []
            owners = {("openvpn", "1.alice"): 1, ("wireguard", "1.alice"): 1,
                      ("xray", "1.alice"): 1, ("sing-box", "1.alice"): 1}
            wanted = {cid: ["1.alice"] for cid in mgr.list_cores()}
            sessions = await mgr.online_devices(wanted)

            devices = DeviceManager(InMemoryDeviceStore())
            grouped: dict[tuple[str, str], tuple[int, list]] = {}
            for s in sessions:
                key = (s.core_id, s.account_id)
                grouped.setdefault(key, (1, []))[1].append(s)
            online = await devices.refresh(grouped)
            assert len(online) == 1, "same IP across two cores is ONE device"
            dev = online[0]
            assert dev.cores == {"openvpn", "wireguard"}
            assert dev.user_id == 1

            violations = await devices.enforce_limits({1: 1})
            assert violations == []
            # second device appears (laptop from IP B on xray-online)
            from app.cores.types import DeviceSession
            sessions.append(DeviceSession(core_id="xray", account_id="1.alice",
                                          ip="198.51.100.99"))
            grouped[("xray", "1.alice")] = (1, sessions[-1:])
            grouped[("openvpn", "1.alice")] = (1, grouped[("openvpn", "1.alice")][1])
            await devices.refresh(grouped)
            violations = await devices.enforce_limits({1: 1})
            assert len(violations) == 1 and violations[0].active_devices == 2

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# Unified session history (open → close with duration)                   #
# ---------------------------------------------------------------------- #

def test_session_manager_tracks_open_and_close_with_duration() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-sess-") as tmp:
            mgr, xray, sing, ovpn, wg = await _cluster(tmp)
            accounts = _accounts(1, "alice")
            await mgr.provision_user(accounts)
            ovpn._backend.status_text = _status3([("1.alice", "203.0.113.5", 1000, 500)])

            wanted = {cid: ["1.alice"] for cid in mgr.list_cores()}
            owners = {("openvpn", "1.alice"): 1}
            sessions = await mgr.online_devices(wanted)
            sm = SessionManager(InMemorySessionStore())

            report1 = await sm.refresh(sessions, owners)
            assert len(report1.opened) == 1
            active = sm.active(user_id=1)
            assert len(active) == 1 and active[0].core_id == "openvpn"

            report2 = await sm.refresh(sessions, owners)   # still connected
            assert not report2.opened and len(report2.ongoing) == 1

            ovpn._backend.status_text = ""                  # disconnected
            report3 = await sm.refresh([], owners)
            assert len(report3.closed) == 1
            rec = report3.closed[0]
            assert rec.account_id == "1.alice" and rec.user_id == 1
            assert rec.duration_seconds >= 0
            history = await sm.history(user_id=1)
            assert len(history) == 1 and history[0].ended_at >= history[0].started_at

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# Fault isolation + concurrency stress                                   #
# ---------------------------------------------------------------------- #

def test_fanout_fault_isolation_one_core_fails_others_succeed() -> None:
    async def run() -> None:
        mgr = CoreManager(InMemoryCoreStore())
        good = XrayDriver(backend=FakeXrayBackend())
        bad = XrayDriver(backend=FailingBackend())
        # two drivers of the same type under different ids: attach directly
        mgr._drivers["xray"] = good
        mgr._states["xray"] = CoreState.RUNNING
        mgr._enabled["xray"] = True
        mgr.attach("openvpn", bad, state=CoreState.RUNNING)  # id ≠ driver type on purpose

        accounts = {
            "xray": UserAccount(user_id=1, username="a", account_id="1.a",
                                protocol="vless", settings={"id": "x"}),
            "openvpn": UserAccount(user_id=1, username="a", account_id="1.a",
                                   protocol="vless", settings={"id": "y"}),
        }
        results = await mgr.provision_user(accounts)
        by_core = {r.core_id: r for r in results}
        assert by_core["xray"].success
        assert not by_core["openvpn"].success
        assert "outage" in (by_core["openvpn"].error or "")
        assert good._backend.added  # the healthy core still got the user

    asyncio.run(run())


def test_concurrent_provisioning_and_quota_stress() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-stress-") as tmp:
            mgr, xray, sing, ovpn, wg = await _cluster(tmp)
            started = time.perf_counter()

            # 50 users × 4 cores provisioned concurrently
            jobs = [
                mgr.provision_user(_accounts(u, f"u{u}"))
                for u in range(1, 51)
            ]
            batches = await asyncio.gather(*jobs)
            assert all(r.success for batch in batches for r in batch)

            # concurrent quota application of disjoint deltas
            quota = UnifiedQuotaService(InMemoryQuotaStore(), limits={})
            owners = {}
            records = []
            for u in range(1, 51):
                for core in ("xray", "sing-box", "openvpn", "wireguard"):
                    owners[(core, f"{u}.u{u}")] = u
                    records.append(UsageRecord(core_id=core, account_id=f"{u}.u{u}",
                                               uplink_bytes=u, downlink_bytes=1))
            # split into 8 overlapping-concurrent batches (no shared records)
            shards = [records[i::8] for i in range(8)]
            applied_groups = await asyncio.gather(*(
                quota.apply_usage(shard, owners) for shard in shards
            ))
            elapsed = time.perf_counter() - started

            expected = sum(u * 4 + 4 for u in range(1, 51))  # up: u per core ×4, down: 1 ×4
            total = 0
            for u in range(1, 51):
                total += (await quota.get_view(u)).total_bytes
            assert total == expected, f"{total} != {expected}"
            assert all(a.cores for group in applied_groups for a in group[0])
            assert elapsed < 10.0, f"stress run too slow: {elapsed:.2f}s"
            # concurrency determinism: re-applying zero deltas changes nothing
            zero = [UsageRecord(core_id="xray", account_id="1.u1")]
            applied, _ = await quota.apply_usage(zero, owners)
            assert applied == []

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
