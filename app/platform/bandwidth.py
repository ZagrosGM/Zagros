"""Kernel-backed global per-user aggregate bandwidth limiter.

Every user owns two global ``tc police`` action indices (upload/download).
Filters on both sides of the host's physical interface reference those SAME
actions, so token state is shared across cores, connections and CPUs.

Identity reaches the kernel through one stable mark per platform user:
* routed VPN peers: deterministic inner source IP -> conntrack mark;
* Xray/sing-box: per-user SO_MARK on the selected direct outbound;
* SSH: Unix account UID -> nft socket-owner mark;
* SoftEther: authenticated session log -> outer transport conntrack mark.

No Python or database access occurs in the packet path.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TABLE = "zagros_bw"
STATE_PATH = Path(os.environ.get(
    "ZAGROS_BANDWIDTH_STATE_PATH", "/var/lib/zagros/bandwidth/state.json"))
MARK_PREFIX = 0x5A000000
MARK_USER_MASK = 0xFFFF00
MARK_KIND_OUTER = 0x40
MARK_KIND_UP = 0x01
MARK_KIND_DOWN = 0x02
INGRESS_CHAIN = 901
CT_PREF = 40000
CT_PREF_V6 = 40001
IPV6_PREF_OFFSET = 20_000
IPV6_HANDLE_OFFSET = 0x10000
QUARANTINE_INNER = 0x5AFE0000
QUARANTINE_CT = 0x5AFE0040
QUARANTINE_UP = 0x5AFE0001
QUARANTINE_DOWN = 0x5AFE0002
QUARANTINE_UP_ACTION = 0x5BFE0000
QUARANTINE_DOWN_ACTION = 0x5BFE0001
MAX_MBIT = 100_000


class BandwidthError(RuntimeError):
    pass


def mark_for_user(user_id: int) -> int:
    value = int(user_id)
    if value <= 0 or value > 0xFFFF:
        raise BandwidthError(f"user id {value} is outside the 16-bit limiter identity range")
    return MARK_PREFIX | (value << 8)


def marks_for_user(user_id: int) -> dict[str, int]:
    base = mark_for_user(user_id)
    return {
        "base": base,
        "outer": base | MARK_KIND_OUTER,
        "up": base | MARK_KIND_UP,
        "down": base | MARK_KIND_DOWN,
    }


def action_index(user_id: int, direction: str) -> int:
    return 0x5B000000 + int(user_id) * 2 + (1 if direction == "down" else 0)


def _police_burst(rate_mbps: int) -> int:
    # 200 ms burst: large enough for normal TCP startup, bounded so sustained
    # throughput — not a multi-second burst — defines acceptance.
    return max(64 * 1024, min(16 * 1024 * 1024,
                              int(rate_mbps) * 1_000_000 // 8 // 5))


@dataclass(slots=True)
class UserLimit:
    user_id: int
    username: str
    upload_mbps: int
    download_mbps: int
    inner_sources: set[str] = field(default_factory=set)
    ssh_uids: set[int] = field(default_factory=set)
    softether_accounts: set[str] = field(default_factory=set)

    @property
    def limited(self) -> bool:
        return self.upload_mbps > 0 or self.download_mbps > 0


@dataclass(slots=True)
class SoftEtherEndpoint:
    account_id: str
    client_ip: str
    client_port: int
    server_port: int
    transport: str


class BandwidthLimiter:
    def __init__(self, runtime, *, interface: str | None = None,
                 runner=None) -> None:
        self.runtime = runtime
        self.interface = interface or os.environ.get("ZAGROS_BANDWIDTH_INTERFACE", "eth0")
        self._runner = runner or self._run
        self._lock = threading.RLock()
        self._limits: dict[int, UserLimit] = {}
        self._owners: dict[str, int] = {}
        self._endpoints: dict[tuple, SoftEtherEndpoint] = {}
        self._ipsec_ports: dict[str, int] = {}
        self._cid_accounts: dict[str, str] = {}
        self._session_accounts: dict[str, str] = {}
        self._soft_tap: str | None = None
        self._soft_subnet: str | None = None
        self._state = self._load_state()
        raw_soft_sources = self._state.get("softether_sources", {})
        self._soft_sources: dict[str, int] = {}
        if isinstance(raw_soft_sources, dict):
            for source, user_id in raw_soft_sources.items():
                try:
                    self._soft_sources[str(ipaddress.ip_address(source))] = int(user_id)
                except (TypeError, ValueError):
                    continue
        self._watcher: threading.Thread | None = None
        self._watch_stop = threading.Event()
        self._watch_failures = 0
        self._log_path: Path | None = None
        self._log_inode: int | None = None
        self._log_offset = 0
        self.last_error: str | None = None

    # ---------- process / persistence ----------
    @staticmethod
    def _run(argv: list[str], *, input_text: str | None = None,
             check: bool = True) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(
                argv, input=input_text, text=True, capture_output=True,
                timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BandwidthError(f"cannot execute {' '.join(argv)}: {exc}") from exc
        if check and result.returncode:
            detail = (result.stderr or result.stdout or "").strip()
            raise BandwidthError(
                f"command failed ({result.returncode}) {' '.join(argv)}: {detail[:600]}")
        return result

    def _load_state(self) -> dict[str, Any]:
        try:
            value = json.loads(STATE_PATH.read_text())
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_state(self, payload: dict[str, Any]) -> None:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        part = STATE_PATH.with_suffix(".part")
        part.write_text(json.dumps(payload, sort_keys=True) + "\n")
        os.chmod(part, 0o600)
        part.replace(STATE_PATH)
        self._state = payload

    def _fail_closed_keys(self) -> set[tuple[str, str]]:
        raw = self._state.get("fail_closed_accounts", [])
        if not isinstance(raw, list):
            return set()
        return {
            (str(item["core_id"]), str(item["account_id"]))
            for item in raw
            if isinstance(item, dict) and item.get("core_id") and item.get("account_id")
        }

    @staticmethod
    def _serialized_account_keys(
        keys: set[tuple[str, str]],
    ) -> list[dict[str, str]]:
        return [
            {"core_id": core_id, "account_id": account_id}
            for core_id, account_id in sorted(keys)
        ]

    def _carry_fail_closed(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Carry fail-closed and authenticated dynamic identity state.

        Recovery happens only *after* nft/tc has converged. Carrying the
        suspension marker closes the crash window where an account could stay
        suspended forever. SoftEther DHCP identities are also management-plane
        state: keeping them across API reconciles/container restarts prevents a
        live routed session from falling back to the conservative quarantine
        merely because its lease did not renew during that exact update.
        """
        keys = self._fail_closed_keys()
        if keys:
            payload["fail_closed_accounts"] = self._serialized_account_keys(keys)
            payload["fail_closed_at"] = int(
                self._state.get("fail_closed_at") or time.time())
        if self._soft_sources:
            payload["softether_sources"] = {
                source: int(user_id)
                for source, user_id in sorted(self._soft_sources.items())
            }
        return payload

    # ---------- desired identity ----------
    def _desired(self) -> dict[int, UserLimit]:
        from sqlalchemy import select
        from app.persistence.models import UserModel

        with self.runtime.session_factory() as session:
            rows = session.execute(select(UserModel)).scalars().all()
            desired = {
                int(row.id): UserLimit(
                    user_id=int(row.id), username=str(row.username),
                    upload_mbps=max(0, int(row.upload_limit_mbps or 0)),
                    download_mbps=max(0, int(row.download_limit_mbps or 0)),
                )
                for row in rows
            }
        owners = self.runtime.users.account_owners()
        self._owners = {
            account_id: user_id for (core_id, account_id), user_id in owners.items()
            if core_id == "softether"
        }
        for (core_id, account_id), user_id in owners.items():
            target = desired.get(int(user_id))
            if target is None:
                continue
            if core_id == "softether":
                target.softether_accounts.add(str(account_id))

        # Drivers own generated addresses/UIDs; query their hydrated desired
        # state, never the live packet path.
        for core_id in self.runtime.core_manager.list_cores():
            try:
                driver = self.runtime.core_manager.get(core_id)
                identities = driver.bandwidth_identities()
            except Exception:  # noqa: BLE001 — unavailable core contributes none
                continue
            for account_id, identity in (identities or {}).items():
                owner = owners.get((core_id, str(account_id)))
                target = desired.get(int(owner)) if owner is not None else None
                if target is None:
                    continue
                for source in identity.get("inner_sources", []):
                    try:
                        target.inner_sources.add(str(ipaddress.ip_interface(source).ip))
                    except ValueError:
                        logger.warning("invalid bandwidth source from %s/%s: %s",
                                       core_id, account_id, source)
                for uid in identity.get("uids", []):
                    target.ssh_uids.add(int(uid))

        # SoftEther's routed TAP learns the authenticated account -> DHCP IP
        # binding from server events. A normal API limit update rebuilds this
        # desired object while the existing client keeps its lease (and emits
        # no new DHCP line), so merge the durable live binding every time.
        self._soft_sources = {
            source: user_id for source, user_id in self._soft_sources.items()
            if int(user_id) in desired
        }
        for source, user_id in self._soft_sources.items():
            desired[int(user_id)].inner_sources.add(source)

        for limit in desired.values():
            if not 0 <= limit.upload_mbps <= MAX_MBIT:
                raise BandwidthError(f"invalid upload limit for {limit.username}")
            if not 0 <= limit.download_mbps <= MAX_MBIT:
                raise BandwidthError(f"invalid download limit for {limit.username}")
        return desired

    # ---------- tc ----------
    def _tc(self, *args: str, check: bool = True):
        return self._runner(["tc", *args], check=check)

    def _replace_or_add_filter(self, args: tuple[str, ...]) -> None:
        """Replace one exact tc filter, falling back to an idempotent add.

        iproute2 5.15 returns ``priority/protocol not found`` when ``replace``
        targets a new protocol at an existing block.  Delete only the exact
        family/pref/chain, then add — never delete the other address family.
        """
        result = self._tc(*args, check=False)
        if not result.returncode:
            return
        direction = args[args.index("dev") + 2]
        protocol = args[args.index("protocol") + 1]
        pref = args[args.index("pref") + 1]
        delete = ["filter", "del", "dev", self.interface, direction,
                  "protocol", protocol, "pref", pref]
        if "chain" in args:
            delete += ["chain", args[args.index("chain") + 1]]
        self._tc(*delete, check=False)
        add_args = list(args)
        add_args[1] = "add"
        self._tc(*add_args)

    def _ensure_clsact(self) -> None:
        show = self._tc("qdisc", "show", "dev", self.interface).stdout
        if "clsact" not in show:
            self._tc("qdisc", "add", "dev", self.interface, "clsact")
            self._state["created_clsact"] = True
        # One conntrack lookup per L3 family feeds the SAME private user chain.
        # Distinct preferences are required by iproute2 5.15; the chain and all
        # police action indices remain global/shared across IPv4 and IPv6.
        for protocol, pref, handle in (
            ("ip", CT_PREF, 0xB001),
            ("ipv6", CT_PREF_V6, 0x1B002),
        ):
            self._replace_or_add_filter((
                "filter", "replace", "dev", self.interface, "ingress",
                "protocol", protocol, "pref", str(pref), "chain", "0",
                "handle", hex(handle), "flower", "action", "ct", "pipe",
                "action", "goto", "chain", str(INGRESS_CHAIN),
            ))

    def _replace_police(self, user_id: int, direction: str, rate: int) -> int:
        index = action_index(user_id, direction)
        self._tc(
            "actions", "replace", "action", "police", "index", str(index),
            "rate", f"{rate}mbit", "burst", str(_police_burst(rate)),
            "mtu", "65535", "conform-exceed", "drop/ok",
        )
        return index

    def _replace_ingress_flower(
        self, pref: int, handle: int, flower_args: list[str],
        action_args: list[str], *, protocol: str = "ip",
    ) -> None:
        self._replace_or_add_filter((
            "filter", "replace", "dev", self.interface, "ingress",
            "protocol", protocol, "pref", str(pref),
            "chain", str(INGRESS_CHAIN), "handle", hex(handle),
            "flower", *flower_args, *action_args,
        ))

    def _replace_egress_fw(
        self, pref: int, mark: int, action_args: list[str],
        *, protocol: str = "ip",
    ) -> None:
        self._replace_or_add_filter((
            "filter", "replace", "dev", self.interface, "egress",
            "protocol", protocol, "pref", str(pref),
            "handle", hex(mark), "fw", *action_args,
        ))

    def _install_user_filters(self, limit: UserLimit) -> dict[str, int]:
        marks = marks_for_user(limit.user_id)
        base_pref = 1000 + limit.user_id * 4
        base_handle = 0xC000 + limit.user_id * 4
        prefs: dict[str, int] = {}
        families = (
            ("ip", 0, 0, ""),
            ("ipv6", IPV6_PREF_OFFSET, IPV6_HANDLE_OFFSET, "_v6"),
        )

        # Inner response at ingress => user download. The IPv4 and IPv6
        # classifiers bind the exact same action index/global token bucket.
        down_idx = (self._replace_police(limit.user_id, "down", limit.download_mbps)
                    if limit.download_mbps else None)
        for protocol, pref_offset, handle_offset, suffix in families:
            if down_idx is not None:
                self._replace_ingress_flower(
                    base_pref + pref_offset,
                    base_handle + handle_offset,
                    ["ct_state", "+trk", "ct_mark", hex(marks["base"])],
                    ["action", "police", "index", str(down_idx)],
                    protocol=protocol,
                )
                prefs[f"ingress_down{suffix}"] = base_pref + pref_offset
                self._replace_egress_fw(
                    base_pref + 1 + pref_offset, marks["down"],
                    ["action", "police", "index", str(down_idx)],
                    protocol=protocol,
                )
            else:
                # A mapped unlimited SoftEther user bypasses quarantine
                # explicitly in both address families.
                self._replace_egress_fw(
                    base_pref + 1 + pref_offset, marks["down"],
                    ["action", "pass"], protocol=protocol,
                )
            prefs[f"egress_down{suffix}"] = base_pref + 1 + pref_offset

        # Inner request at physical egress => user upload.
        up_idx = (self._replace_police(limit.user_id, "up", limit.upload_mbps)
                  if limit.upload_mbps else None)
        for protocol, pref_offset, handle_offset, suffix in families:
            if up_idx is not None:
                self._replace_egress_fw(
                    base_pref + 2 + pref_offset, marks["up"],
                    ["action", "police", "index", str(up_idx)],
                    protocol=protocol,
                )
                prefs[f"egress_up{suffix}"] = base_pref + 2 + pref_offset
                ingress_action = ["action", "police", "index", str(up_idx)]
            else:
                ingress_action = ["action", "pass"]
            # SoftEther outer client->server is physical ingress upload.
            self._replace_ingress_flower(
                base_pref + 3 + pref_offset,
                base_handle + 3 + handle_offset,
                ["ct_state", "+trk", "ct_mark", hex(marks["outer"])],
                ingress_action, protocol=protocol,
            )
            prefs[f"ingress_up{suffix}"] = base_pref + 3 + pref_offset
        return prefs

    def _install_softether_quarantine(
        self, desired: dict[int, UserLimit],
    ) -> dict[str, Any] | None:
        soft = [item for item in desired.values()
                if item.softether_accounts and item.limited]
        if not soft:
            return None
        prefs: dict[str, int] = {}
        actions: list[int] = []
        upload_rates = [item.upload_mbps for item in soft if item.upload_mbps]
        download_rates = [item.download_mbps for item in soft if item.download_mbps]
        families = (
            ("ip", 0, 0, ""),
            ("ipv6", IPV6_PREF_OFFSET, IPV6_HANDLE_OFFSET, "_v6"),
        )
        if upload_rates:
            rate = min(upload_rates)
            quarantine_kbit = max(64, rate * 10)  # 1% of the strictest Mbps
            self._tc(
                "actions", "replace", "action", "police", "index",
                str(QUARANTINE_UP_ACTION), "rate", f"{quarantine_kbit}kbit", "burst",
                str(64 * 1024), "mtu", "65535",
                "conform-exceed", "drop/ok",
            )
            for protocol, pref_offset, handle_offset, suffix in families:
                self._replace_ingress_flower(
                    30000 + pref_offset, 0xCFFE + handle_offset,
                    ["ct_state", "+trk", "ct_mark", hex(QUARANTINE_CT)],
                    ["action", "police", "index", str(QUARANTINE_UP_ACTION)],
                    protocol=protocol,
                )
                self._replace_egress_fw(
                    30002 + pref_offset, QUARANTINE_UP,
                    ["action", "police", "index", str(QUARANTINE_UP_ACTION)],
                    protocol=protocol,
                )
                prefs[f"ingress_quarantine{suffix}"] = 30000 + pref_offset
                prefs[f"egress_inner_quarantine{suffix}"] = 30002 + pref_offset
            actions.append(QUARANTINE_UP_ACTION)
        if download_rates:
            rate = min(download_rates)
            quarantine_kbit = max(64, rate * 10)
            self._tc(
                "actions", "replace", "action", "police", "index",
                str(QUARANTINE_DOWN_ACTION), "rate", f"{quarantine_kbit}kbit", "burst",
                str(64 * 1024), "mtu", "65535",
                "conform-exceed", "drop/ok",
            )
            for protocol, pref_offset, handle_offset, suffix in families:
                self._replace_egress_fw(
                    30001 + pref_offset, QUARANTINE_DOWN,
                    ["action", "police", "index", str(QUARANTINE_DOWN_ACTION)],
                    protocol=protocol,
                )
                self._replace_ingress_flower(
                    30003 + pref_offset, 0xCFFD + handle_offset,
                    ["ct_state", "+trk", "ct_mark", hex(QUARANTINE_INNER)],
                    ["action", "police", "index", str(QUARANTINE_DOWN_ACTION)],
                    protocol=protocol,
                )
                prefs[f"egress_quarantine{suffix}"] = 30001 + pref_offset
                prefs[f"ingress_inner_quarantine{suffix}"] = 30003 + pref_offset
            actions.append(QUARANTINE_DOWN_ACTION)
        return {"prefs": prefs, "actions": actions,
                "upload_mbps": min(upload_rates) if upload_rates else 0,
                "download_mbps": min(download_rates) if download_rates else 0}

    def _remove_old_tc(self, new_users: dict[str, Any]) -> None:
        previous = self._state.get("users", {}) if isinstance(self._state, dict) else {}
        keep_actions = {
            value for state in new_users.values()
            for value in state.get("actions", [])
        }
        obsolete_actions: set[int] = set()
        for user_state in previous.values():
            for hook, pref in user_state.get("prefs", {}).items():
                if any(pref in state.get("prefs", {}).values() for state in new_users.values()):
                    continue
                direction = "ingress" if hook.startswith("ingress") else "egress"
                protocol = "ipv6" if hook.endswith("_v6") else "ip"
                args = ["filter", "del", "dev", self.interface, direction,
                        "protocol", protocol, "pref", str(pref)]
                if direction == "ingress":
                    args += ["chain", str(INGRESS_CHAIN)]
                self._tc(*args, check=False)
            obsolete_actions.update(
                int(index) for index in user_state.get("actions", [])
                if index not in keep_actions)
        # Delete standalone actions only after *all* old bindings are gone.
        # Kernel RCU can release the first action's final bind slightly after
        # tc acknowledges filter deletion (observed as ref=1/bind=0 leakage).
        # Retry every obsolete index in delayed waves; API latency stays below
        # half a second and no unrelated User/action is touched.
        pending = set(obsolete_actions)
        for delay in (0.0, 0.05, 0.15, 0.30):
            if not pending:
                break
            if delay:
                time.sleep(delay)
            for index in sorted(tuple(pending)):
                result = self._tc(
                    "actions", "delete", "action", "police",
                    "index", str(index), check=False)
                if result.returncode == 0:
                    pending.discard(index)
        if pending:
            logger.warning("tc police actions pending kernel release: %s",
                           sorted(pending))

    # ---------- nft identity ----------
    def _nft_script(self, desired: dict[int, UserLimit]) -> str:
        lines = [
            f"table inet {TABLE} {{",
            " chain output { type route hook output priority mangle; policy accept;",
        ]
        active = {uid: limit for uid, limit in desired.items() if limit.limited}
        soft_guard = any(item.softether_accounts for item in active.values())
        endpoint_users = {
            self._owners.get(endpoint.account_id)
            for endpoint in self._endpoints.values()
        } if soft_guard else set()
        marked_users = set(active) | {int(uid) for uid in endpoint_users
                                      if uid is not None and int(uid) in desired}
        for uid in sorted(marked_users):
            limit = desired[uid]
            marks = marks_for_user(uid)
            lines.append(
                f"  ct mark {hex(marks['outer'])} meta mark set {hex(marks['down'])}")
            if limit.limited:
                lines.append(
                    f"  meta mark {hex(marks['base'])} ct mark set {hex(marks['base'])} "
                    f"meta mark set {hex(marks['up'])}")
                for unix_uid in sorted(limit.ssh_uids):
                    lines.append(
                        f"  meta skuid {unix_uid} ct mark set {hex(marks['base'])} "
                        f"meta mark set {hex(marks['up'])}")
        if soft_guard:
            lines.append(
                f"  ct mark {hex(QUARANTINE_CT)} meta mark set {hex(QUARANTINE_DOWN)}")
            lines.append(
                f"  ct mark {hex(QUARANTINE_INNER)} meta mark set {hex(QUARANTINE_DOWN)}")
        lines += [" }", " chain forward { type filter hook forward priority mangle; policy accept;"]
        for uid, limit in sorted(active.items()):
            marks = marks_for_user(uid)
            for source in sorted(limit.inner_sources):
                family = "ip6" if ipaddress.ip_address(source).version == 6 else "ip"
                lines.append(
                    f"  {family} saddr {source} ct mark set {hex(marks['base'])} "
                    f"meta mark set {hex(marks['up'])} return")
        if soft_guard and self._soft_tap:
            lines.append(
                f'  iifname "{self._soft_tap}" ct mark set {hex(QUARANTINE_INNER)} '
                f"meta mark set {hex(QUARANTINE_UP)}")
        lines += [" }", " chain prerouting { type filter hook prerouting priority mangle; policy accept;"]
        for endpoint in sorted(self._endpoints.values(),
                               key=lambda item: (item.client_ip, item.client_port,
                                                 item.server_port, item.account_id)):
            uid = self._owners.get(endpoint.account_id)
            if uid is None or int(uid) not in marked_users:
                continue
            mark = marks_for_user(int(uid))["outer"]
            ipword = "ip6" if ipaddress.ip_address(endpoint.client_ip).version == 6 else "ip"
            proto = endpoint.transport
            lines.append(
                f"  {ipword} saddr {endpoint.client_ip} {proto} sport {endpoint.client_port} "
                f"{proto} dport {endpoint.server_port} ct mark set {hex(mark)} return")
        if soft_guard:
            # Endpoint-specific rules above win. Unknown/auth-in-progress
            # transports enter a conservative shared quarantine instead of
            # bypassing every limited SoftEther user.
            for port in (443, 992, 1194, 5555, 50154):
                lines.append(
                    f"  tcp dport {port} ct mark set {hex(QUARANTINE_CT)}")
            for port in (500, 1701, 4500):
                lines.append(
                    f"  udp dport {port} ct mark set {hex(QUARANTINE_CT)}")
        lines += [" }", "}"]
        return "\n".join(lines) + "\n"

    def _apply_nft(self, desired: dict[int, UserLimit]) -> None:
        active = any(limit.limited for limit in desired.values())
        exists = self._runner(
            ["nft", "list", "table", "inet", TABLE], check=False
        ).returncode == 0
        if active:
            # Build/validate first, then replace in ONE nft transaction. A bad
            # dynamic identity can never delete the last enforced ruleset.
            script = self._nft_script(desired)
            if exists:
                script = f"delete table inet {TABLE}\n" + script
            self._runner(["nft", "-f", "-"], input_text=script)
        elif exists:
            self._runner(["nft", "delete", "table", "inet", TABLE])

    def _soft_nat_rule(self, *, enabled: bool) -> None:
        comment = "zagros:bandwidth:softether-nat"
        listing = self._runner(
            ["nft", "-a", "list", "chain", "ip", "nat", "POSTROUTING"],
            check=False,
        )
        handles = [int(value) for value in re.findall(
            rf'comment "{re.escape(comment)}" # handle (\d+)', listing.stdout)]
        if enabled and not handles and self._soft_subnet:
            result = self._runner([
                "nft", "add", "rule", "ip", "nat", "POSTROUTING",
                "ip", "saddr", self._soft_subnet, "oifname", self.interface,
                "counter", "masquerade", "comment", f'"{comment}"',
            ], check=False)
            if result.returncode:
                raise BandwidthError(
                    "cannot install SoftEther routed NAT: "
                    + (result.stderr or result.stdout).strip())
        elif not enabled:
            for handle in handles:
                self._runner([
                    "nft", "delete", "rule", "ip", "nat", "POSTROUTING",
                    "handle", str(handle)], check=False)

    def _ensure_softether_routed(self, desired: dict[int, UserLimit]) -> None:
        needed = any(item.limited and item.softether_accounts
                     for item in desired.values())
        try:
            driver = self.runtime.core_manager.get("softether")
        except Exception:
            if needed:
                raise BandwidthError("limited SoftEther account has no running driver")
            return
        existing = driver.policy_source()
        owned = bool(self._state.get("softether_routed_owned"))
        if needed:
            if existing is None:
                existing = driver.ensure_policy_source()
                owned = True
            self._soft_tap = str(existing["interface"])
            self._soft_subnet = str(existing["subnet"])
            self._soft_nat_rule(enabled=True)
            self._state["softether_routed_owned"] = owned
        else:
            self._soft_nat_rule(enabled=False)
            if owned:
                driver.disable_policy_source()
            self._soft_tap = None
            self._soft_subnet = None
            self._state["softether_routed_owned"] = False

    # ---------- public lifecycle ----------
    def reconcile(self) -> dict[str, Any]:
        with self._lock:
            desired = self._desired()
            active = {uid: item for uid, item in desired.items() if item.limited}
            self._ensure_softether_routed(desired)
            if not active:
                self._apply_nft(desired)
                self._remove_old_tc({})
                previous_actions = [
                    index for state in self._state.get("users", {}).values()
                    for index in state.get("actions", [])
                ]
                if self._state.get("created_clsact"):
                    self._tc("qdisc", "del", "dev", self.interface, "clsact", check=False)
                # qdisc deletion releases the last action bindings; retry the
                # standalone deletion so no ref=1 police objects leak.
                for index in previous_actions:
                    self._tc("actions", "delete", "action", "police",
                             "index", str(index), check=False)
                payload = self._carry_fail_closed({
                    "version": 1, "interface": self.interface, "users": {},
                    "created_clsact": False,
                    "softether_routed_owned": False,
                    "updated_at": int(time.time()),
                })
                self._save_state(payload)
                self._limits = desired
                self.last_error = None
                self._recover_limited_accounts()
                return dict(self._state)

            self._ensure_clsact()
            new_users: dict[str, Any] = {}
            soft_guard = any(item.softether_accounts for item in active.values())
            filter_users = dict(active)
            if soft_guard:
                filter_users.update({uid: item for uid, item in desired.items()
                                     if item.softether_accounts})
            for uid, limit in sorted(filter_users.items()):
                prefs = self._install_user_filters(limit)
                actions = []
                if limit.upload_mbps:
                    actions.append(action_index(uid, "up"))
                if limit.download_mbps:
                    actions.append(action_index(uid, "down"))
                new_users[str(uid)] = {
                    "username": limit.username,
                    "upload_mbps": limit.upload_mbps,
                    "download_mbps": limit.download_mbps,
                    "guard_only": not limit.limited,
                    "prefs": prefs, "actions": actions,
                }
            quarantine = self._install_softether_quarantine(desired)
            if quarantine:
                new_users["_quarantine"] = quarantine
            # Filters/actions exist before packets receive marks: no new-limit
            # bypass window. Obsolete filters are removed only after nft swap.
            self._apply_nft(desired)
            self._remove_old_tc(new_users)
            payload = self._carry_fail_closed({
                "version": 1, "interface": self.interface, "users": new_users,
                "created_clsact": bool(self._state.get("created_clsact")),
                "softether_routed_owned": bool(
                    self._state.get("softether_routed_owned")),
                "updated_at": int(time.time()),
            })
            self._save_state(payload)
            self._limits = desired
            self.last_error = None
            # Fail-closed is runtime state, not database state.  Resume only
            # after the complete replacement ruleset is live.
            self._recover_limited_accounts()
            return dict(self._state)

    def _start_watcher(self) -> None:
        if self._watcher is None or not self._watcher.is_alive():
            self._watch_stop.clear()
            self._watcher = threading.Thread(
                target=self._watch_loop, name="zagros-bandwidth-softether", daemon=True)
            self._watcher.start()

    def start(self) -> None:
        attempts = max(1, int(os.environ.get(
            "ZAGROS_BANDWIDTH_START_ATTEMPTS", "10")))
        delay = max(0.0, float(os.environ.get(
            "ZAGROS_BANDWIDTH_START_RETRY_SECONDS", "2")))
        failure: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                self.reconcile()
                if attempt > 1:
                    logger.info(
                        "bandwidth limiter startup recovered on attempt %d/%d",
                        attempt, attempts,
                    )
                self._start_watcher()
                return
            except Exception as exc:  # noqa: BLE001 — bounded readiness retry
                failure = exc
                self.last_error = str(exc)
                logger.warning(
                    "bandwidth limiter startup attempt %d/%d failed: %s",
                    attempt, attempts, exc,
                )
                if attempt < attempts and delay:
                    time.sleep(delay)
        assert failure is not None
        logger.critical("bandwidth limiter startup failed after %d attempts: %s",
                        attempts, failure)
        self._fail_closed_limited_accounts()
        # Keep a bounded-background recovery path alive.  Limited accounts stay
        # suspended until a complete future reconcile succeeds; unlimited
        # users are not changed.
        self._start_watcher()
        raise failure

    def stop(self) -> None:
        self._watch_stop.set()

    def _account_objects_for_core(self, core_id: str, *, suspended=None):
        """Rebuild one core's complete persisted desired account set.

        A full set lets SoftEther use its one-login batch reconciler instead of
        triggering the management DoS guard with four rapid per-user vpncmd
        calls.  Other users retain their exact persisted enabled state.
        """
        from app.cores.types import UserAccount

        suspended = set(suspended or ())
        rows = self.runtime.users.accounts_of_core(core_id, decrypt=True)
        owners: dict[int, Any] = {}
        accounts: list[UserAccount] = []
        for row in rows:
            user_id = int(row["user_id"])
            if user_id not in owners:
                owners[user_id] = self.runtime.users.get_user(user_id)
            owner = owners[user_id]
            if owner is None:
                continue
            key = (core_id, str(row["account_id"]))
            enabled = (bool(row["enabled"])
                       and str(owner.status) == "active"
                       and key not in suspended)
            accounts.append(UserAccount(
                user_id=user_id,
                username=str(owner.username),
                account_id=str(row["account_id"]),
                protocol=str(row["protocol"]),
                enabled=enabled,
                settings=dict(row.get("settings") or {}),
            ))
        return accounts

    def _write_fail_closed_keys(self, keys: set[tuple[str, str]]) -> None:
        with self._lock:
            payload = dict(self._state)
            if keys:
                payload["fail_closed_accounts"] = self._serialized_account_keys(keys)
                payload["fail_closed_at"] = int(
                    payload.get("fail_closed_at") or time.time())
            else:
                payload.pop("fail_closed_accounts", None)
                payload.pop("fail_closed_at", None)
            payload["updated_at"] = int(time.time())
            self._save_state(payload)

    def _fail_closed_limited_accounts(self) -> None:
        """Suspend only affected users and durably remember the intervention."""
        try:
            desired = self._desired()
            owners = self.runtime.users.account_owners()
        except Exception:  # noqa: BLE001
            logger.exception("cannot enumerate limited accounts for fail-closed")
            return
        targets = {
            (str(core_id), str(account_id))
            for (core_id, account_id), user_id in owners.items()
            if desired.get(int(user_id)) is not None
            and desired[int(user_id)].limited
        }
        if not targets:
            return
        # Record intent before touching drivers.  A process crash can therefore
        # never strand a runtime suspension without a recovery marker.
        targets |= self._fail_closed_keys()
        self._write_fail_closed_keys(targets)

        failures: list[str] = []

        def worker() -> None:
            import asyncio

            for core_id in sorted({core for core, _account in targets}):
                core_targets = {key for key in targets if key[0] == core_id}
                try:
                    driver = self.runtime.core_manager.get(core_id)
                    accounts = self._account_objects_for_core(
                        core_id, suspended=core_targets)
                    asyncio.run(driver.sync_accounts(accounts))
                except Exception as batch_exc:  # noqa: BLE001
                    # Isolate a broken account/core: best-effort individual
                    # suspension still protects every other limited identity.
                    logger.warning("fail-closed batch suspend failed for %s: %s",
                                   core_id, batch_exc)
                    for _core, account_id in sorted(core_targets):
                        try:
                            driver = self.runtime.core_manager.get(core_id)
                            asyncio.run(driver.suspend_account(account_id))
                        except Exception as exc:  # noqa: BLE001
                            failures.append(f"{core_id}/{account_id}: {exc}")
                            logger.exception(
                                "fail-closed suspend failed for %s/%s",
                                core_id, account_id,
                            )

        thread = threading.Thread(
            target=worker, name="zagros-bandwidth-fail-closed", daemon=True)
        thread.start()
        thread.join(timeout=60)
        if thread.is_alive():
            failures.append("fail-closed account worker timed out")
        if failures:
            self.last_error = "; ".join(failures)[:1200]

    def _recover_limited_accounts(self) -> None:
        """Undo only suspensions owned by this limiter after enforcement works."""
        keys = self._fail_closed_keys()
        if not keys:
            return
        remaining = set(keys)
        failures: list[str] = []

        def worker() -> None:
            import asyncio

            for core_id in sorted({core for core, _account in keys}):
                try:
                    driver = self.runtime.core_manager.get(core_id)
                    accounts = self._account_objects_for_core(core_id)
                    asyncio.run(driver.sync_accounts(accounts))
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{core_id}: {exc}")
                    logger.exception("fail-closed recovery failed for core %s", core_id)
                else:
                    remaining.difference_update(
                        {key for key in remaining if key[0] == core_id})

        thread = threading.Thread(
            target=worker, name="zagros-bandwidth-recovery", daemon=True)
        thread.start()
        thread.join(timeout=60)
        if thread.is_alive():
            failures.append("account recovery worker timed out")
        self._write_fail_closed_keys(remaining)
        if failures:
            self.last_error = ("limiter active; account recovery pending: "
                               + "; ".join(failures))[:1200]
        elif not remaining:
            self.last_error = None
            logger.info("bandwidth limiter recovered all fail-closed accounts")

    def status(self) -> dict[str, Any]:
        return {**self._state, "last_error": self.last_error,
                "softether_endpoints": len(self._endpoints)}

    # ---------- SoftEther event bridge ----------
    _SE_CONNECT = re.compile(
        r'The connection "([^"]+)" \(IP address: ([^,]+),.*?Port number: (\d+), '
        r'Client name: "([^"]+)".*?user name is "([^"]+)"\.', re.I)
    _SE_SESSION = re.compile(
        r'Connection "([^"]+)": The new session "([^"]+)" has been created', re.I)
    _SE_DHCP = re.compile(
        r'allocated, for host "([^"]+)".*?new IP address '
        r'([0-9]+(?:\.[0-9]+){3})', re.I)
    _SE_IPSEC = re.compile(
        r'IPsec Client \d+ \(([^:()]+):(\d+) -> [^)]+\)', re.I)

    def _classify_softether(self, account_id: str, client_name: str,
                            client_ip: str, client_port: int) -> tuple[str, int, int]:
        protocol = ""
        try:
            for row in self.runtime.users.accounts_of_core("softether", decrypt=False):
                if row["account_id"] == account_id:
                    protocol = str(row["protocol"])
                    break
        except Exception:  # noqa: BLE001
            pass
        if protocol == "sstp" or "sstp" in client_name.lower():
            return "tcp", client_port, 443
        if protocol == "l2tp":
            return "udp", int(self._ipsec_ports.get(client_ip, 4500)), 4500
        if protocol == "l2tp_raw" or "l2tp" in client_name.lower():
            return "udp", 1701, 1701
        return "tcp", client_port, 50154

    def _consume_softether_line(self, line: str) -> bool:
        ipsec = self._SE_IPSEC.search(line)
        if ipsec:
            self._ipsec_ports[ipsec.group(1)] = int(ipsec.group(2))
            return False
        session = self._SE_SESSION.search(line)
        if session:
            account_id = self._cid_accounts.get(session.group(1))
            if account_id:
                self._session_accounts[session.group(2)] = account_id
            return False
        dhcp = self._SE_DHCP.search(line)
        if dhcp:
            account_id = self._session_accounts.get(dhcp.group(1))
            uid = self._owners.get(account_id or "")
            if uid is not None and int(uid) in self._limits:
                source = str(ipaddress.ip_address(dhcp.group(2)))
                uid = int(uid)
                previous_uid = self._soft_sources.get(source)
                if previous_uid is not None and previous_uid in self._limits:
                    self._limits[previous_uid].inner_sources.discard(source)
                before = source in self._limits[uid].inner_sources
                self._soft_sources[source] = uid
                self._limits[uid].inner_sources.add(source)
                return previous_uid != uid or not before
            return False
        match = self._SE_CONNECT.search(line)
        if not match:
            return False
        cid, client_ip, raw_port, client_name, account_id = match.groups()
        if account_id not in self._owners:
            return False
        self._cid_accounts[cid] = account_id
        transport, client_port, server_port = self._classify_softether(
            account_id, client_name, client_ip, int(raw_port))
        endpoint = SoftEtherEndpoint(
            account_id=account_id, client_ip=client_ip,
            client_port=client_port, server_port=server_port,
            transport=transport,
        )
        key = (client_ip, client_port, server_port, transport)
        if self._endpoints.get(key) == endpoint:
            return False
        self._endpoints[key] = endpoint
        return True

    def _latest_softether_log(self) -> Path | None:
        paths = sorted(Path("/var/lib/zagros/cores/softether/runtime/server_log").glob("vpn_*.log"))
        return paths[-1] if paths else None

    def refresh_softether_endpoints(self) -> bool:
        with self._lock:
            path = self._latest_softether_log()
            if path is None:
                return False
            try:
                stat = path.stat()
                if path != self._log_path or stat.st_ino != self._log_inode:
                    self._log_path, self._log_inode = path, stat.st_ino
                    # Replay a bounded tail so sessions authenticated just
                    # before panel startup are recovered.
                    self._log_offset = max(0, stat.st_size - 512 * 1024)
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(self._log_offset)
                    changed = False
                    for line in handle:
                        if self._consume_softether_line(line):
                            changed = True
                    self._log_offset = handle.tell()
            except OSError:
                return False
            if changed:
                if any(limit.limited for limit in self._limits.values()):
                    self._apply_nft(self._limits)
                payload = self._carry_fail_closed(dict(self._state))
                payload["updated_at"] = int(time.time())
                self._save_state(payload)
            return changed

    def _watch_loop(self) -> None:
        next_recovery = 0.0
        while not self._watch_stop.wait(0.2):
            try:
                # start() can fail while a live-managed core is still warming.
                # Keep affected accounts suspended, then retry the *complete*
                # kernel reconciliation at a bounded cadence until it is safe
                # for reconcile() to resume them.
                if self._fail_closed_keys() and time.monotonic() >= next_recovery:
                    next_recovery = time.monotonic() + 2.0
                    self.reconcile()
                self.refresh_softether_endpoints()
                self._watch_failures = 0
                if not self._fail_closed_keys():
                    self.last_error = None
            except Exception as exc:  # noqa: BLE001
                self._watch_failures += 1
                self.last_error = str(exc)
                logger.error("SoftEther bandwidth identity watcher failed: %s", exc)
                if self._watch_failures == 3:
                    logger.critical(
                        "SoftEther identity watcher failed repeatedly; suspending "
                        "limited accounts fail-closed")
                    self._fail_closed_limited_accounts()

    # ---------- raw evidence ----------
    def tc_stats(self) -> str:
        result = self._tc("-s", "actions", "list", "action", "police", check=False)
        return result.stdout + result.stderr
