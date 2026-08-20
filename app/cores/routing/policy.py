"""Linux policy-routing runtime for cross-core egress.

The native rule engines in Xray and sing-box only see traffic accepted by
those processes. OpenVPN, WireGuard and SoftEther clients are forwarded by
the kernel, while SSH egress uses a managed OpenSSH dynamic-forward process.
This module is the shared routing plane that makes those traffic sources obey
the same named outbounds:

* every IP-network outbound owns a stable fwmark and routing table;
* OpenVPN and WireGuard profiles become real client interfaces;
* proxy profiles become a small sing-box TUN gateway;
* SSH profiles become real TCP-only OpenSSH SOCKS gateways;
* Xray/sing-box receive a marked direct outbound pointing at the table;
* service-core source subnets (and SSH account UIDs) are classified by an
  atomically replaced nftables table;
* all files are private, process arguments never contain credentials, and
  teardown is symmetric.

The manager deliberately supports only Linux.  On another OS it reports an
explicit capability gap instead of pretending rules were applied.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import os
import pwd
import re
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from app.cores.capabilities import (
    SupportState,
    outbound_capability,
    outbound_product_capability,
    routing_compatibility,
)
from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.model import RoutingRule, RuleAction, UnsupportedRule
from app.cores.routing.softether_client import parse_account_status, run_vpncmd_pty
from app.cores.routing.ppp_client import (
    render_ppp_client_plan,
    write_private_plan_files,
)

logger = logging.getLogger("zagros.cores.routing.policy")

_POLICY_TABLE = "zagros_policy"
# Decrypted outbound material is runtime state, never persistent desired state.
# Docker provides a container-ephemeral /run; the encrypted KV envelope remains
# the only restart-persistent credential source.
_RUNTIME_ROOT = "/run/zagros/routing"
_PERSISTENT_COUNTER_PATH = "/var/lib/zagros/routing/outbound-accounting.json"
_TABLE_MIN = 11000
_TABLE_SPAN = 18000
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")

# Profile directives that would execute code, expose a management socket, or
# mutate host routes outside Zagros' policy domain.  Imported profiles are
# data, not trusted root scripts.
_OVPN_FORBIDDEN = {
    "up", "down", "route-up", "route-pre-down", "ipchange",
    "client-connect", "client-disconnect", "learn-address", "auth-user-pass-verify",
    "plugin", "management", "management-client", "management-client-auth",
    "daemon", "log", "log-append", "writepid", "script-security",
}
_OVPN_OVERRIDDEN = {
    "dev", "dev-type", "route", "route-ipv6", "redirect-gateway",
    "redirect-private", "route-nopull", "ifconfig-noexec", "route-noexec",
    "pull-filter", "auth-user-pass",
}


@dataclass(slots=True)
class PolicyDomain:
    name: str
    kind: OutboundKind
    table_id: int
    fwmark: int
    bypass_mark: int
    return_mark: int
    interface: str                    # root-facing policy interface
    mode: str                         # openvpn | wireguard | proxy | ssh
    fingerprint: str
    tunnel_interface: str = ""        # real client/TUN interface
    vrf_interface: str | None = None   # overlapping client subnets stay L3-isolated
    proxy_port: int = 0                # loopback SOCKS gateway for native cores
    redirect_port: int = 0             # transparent TCP ingress for SSH owner rules
    process: subprocess.Popen[str] | None = field(default=None, repr=False)
    gateway_process: subprocess.Popen[str] | None = field(default=None, repr=False)
    auxiliary_processes: list[subprocess.Popen[str]] = field(
        default_factory=list, repr=False)
    runtime_dir: str = ""
    namespace: str | None = None
    control_interface: str | None = None
    control_peer: str | None = None
    data_peer: str | None = None
    route_gateway: str | None = None
    outer_interface: str | None = None
    client_adapter: str | None = None
    client_account: str | None = None
    client_address: str | None = None
    client_gateway: str | None = None
    client_uplink_bytes: int = 0
    client_downlink_bytes: int = 0
    counter_generation: str = ""
    establishment_ms: float | None = None
    ppp_ready_ms: float | None = None
    ready: bool = False
    detail: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "outbound": self.name,
            "kind": self.kind.value,
            "table_id": self.table_id,
            "fwmark": self.fwmark,
            "return_mark": self.return_mark,
            "interface": self.interface,
            "tunnel_interface": self.tunnel_interface or self.interface,
            "vrf_interface": self.vrf_interface,
            "proxy_port": self.proxy_port,
            "redirect_port": self.redirect_port,
            "mode": self.mode,
            "namespace": self.namespace,
            "control_interface": self.control_interface,
            "client_adapter": self.client_adapter,
            "client_account": self.client_account,
            "client_address": self.client_address,
            "client_gateway": self.client_gateway,
            "client_uplink_bytes": self.client_uplink_bytes,
            "client_downlink_bytes": self.client_downlink_bytes,
            "counter_generation": self.counter_generation,
            "establishment_ms": self.establishment_ms,
            "ppp_ready_ms": self.ppp_ready_ms,
            "ready": self.ready,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class TrafficSource:
    core_id: str
    inbound_tag: str
    source_subnet: str | None = None
    uid: int | None = None
    note: str | None = None


@dataclass(slots=True)
class PolicyRuleReport:
    applied: dict[str, list[str]] = field(default_factory=dict)
    unsupported: dict[str, list[UnsupportedRule]] = field(default_factory=dict)
    notes: dict[str, list[str]] = field(default_factory=dict)


class CommandRunner:
    """Small injectable subprocess boundary used by hermetic regression tests."""

    def run(
        self,
        argv: list[str],
        *,
        check: bool = True,
        input_text: str | None = None,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            argv,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            detail = (result.stderr or result.stdout or "command failed").strip().splitlines()
            tail = detail[-1] if detail else "command failed"
            raise CoreError(f"{os.path.basename(argv[0])} failed: {tail[:500]}")
        return result

    def tcp_ready(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            return False

    def popen(
        self, argv: list[str], *, stdout,
    ) -> subprocess.Popen[str]:
        return subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )


class PolicyRoutingManager:
    """Materialize named outbound domains and apply service traffic rules."""

    def __init__(
        self,
        core_manager,
        *,
        runtime_root: str = _RUNTIME_ROOT,
        counter_path: str | None = None,
        runner: CommandRunner | None = None,
        sleep: Callable[[float], None] = time.sleep,
        identity_provider: Callable[[list[str]], dict[str, tuple[int, int]]] | None = None,
        softether_commander: Callable[..., str] | None = None,
    ) -> None:
        self._cores = core_manager
        self._root = Path(runtime_root)
        self._runner = runner or CommandRunner()
        self._sleep = sleep
        self._identity_provider = identity_provider
        self._softether_commander = softether_commander or run_vpncmd_pty
        self._domains: dict[str, PolicyDomain] = {}
        self._outbounds: dict[str, Outbound] = {}
        self._rules: list[RoutingRule] = []
        # Source ids, not one process-wide boolean: every isolated Virtual Hub
        # owns a different TAP/subnet and can be converged independently.
        self._softether_routed: set[str] = set()
        # Transport diagnostics contain counters only and remain persistent;
        # decrypted provider configs stay below the ephemeral runtime root.
        self._counter_path = Path(
            counter_path
            or (_PERSISTENT_COUNTER_PATH if runtime_root == _RUNTIME_ROOT
                else str(self._root / "outbound-accounting.json"))
        )
        self._counter_ledger: dict[str, dict[str, Any]] | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # identities / introspection
    # ------------------------------------------------------------------ #
    @staticmethod
    def _hash(name: str) -> str:
        return hashlib.sha256(name.encode("utf-8")).hexdigest()

    def _load_counter_ledger(self) -> dict[str, dict[str, Any]]:
        if self._counter_ledger is not None:
            return self._counter_ledger
        data: dict[str, dict[str, Any]] = {}
        try:
            raw = json.loads(self._counter_path.read_text())
            if isinstance(raw, dict):
                for name, item in raw.items():
                    if isinstance(name, str) and isinstance(item, dict):
                        data[name] = {
                            "total_up": max(0, int(item.get("total_up") or 0)),
                            "total_down": max(0, int(item.get("total_down") or 0)),
                            "last_up": max(0, int(item.get("last_up") or 0)),
                            "last_down": max(0, int(item.get("last_down") or 0)),
                            "generation": str(item.get("generation") or ""),
                        }
        except (OSError, ValueError, TypeError):
            data = {}
        self._counter_ledger = data
        return data

    def _fold_outbound_counters(
        self, domain: PolicyDomain, *, uplink: int, downlink: int,
        generation: str,
    ) -> tuple[int, int]:
        """Persist exactly-once monotonic deltas across PPP/session resets.

        These are outbound transport diagnostics, never source-user quota.  A
        new interface/session generation starts from zero; an in-generation
        counter reset is treated as a reconnect and folds the new value once.
        """
        ledger = self._load_counter_ledger()
        row = ledger.setdefault(domain.name, {
            "total_up": 0, "total_down": 0,
            "last_up": 0, "last_down": 0, "generation": "",
        })
        uplink, downlink = max(0, int(uplink)), max(0, int(downlink))
        same = row["generation"] == generation
        delta_up = (uplink - row["last_up"]
                    if same and uplink >= row["last_up"] else uplink)
        delta_down = (downlink - row["last_down"]
                      if same and downlink >= row["last_down"] else downlink)
        row["total_up"] += delta_up
        row["total_down"] += delta_down
        row["last_up"] = uplink
        row["last_down"] = downlink
        row["generation"] = generation
        self._counter_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self._counter_path.parent, 0o700)
        self._atomic_text(
            self._counter_path,
            json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n",
        )
        domain.counter_generation = generation
        domain.client_uplink_bytes = int(row["total_up"])
        domain.client_downlink_bytes = int(row["total_down"])
        return domain.client_uplink_bytes, domain.client_downlink_bytes

    def _drop_outbound_counters(self, name: str) -> None:
        ledger = self._load_counter_ledger()
        if name not in ledger:
            return
        ledger.pop(name, None)
        self._counter_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self._counter_path.parent, 0o700)
        self._atomic_text(
            self._counter_path,
            json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n",
        )

    @classmethod
    def _table_for(cls, name: str, used: set[int]) -> int:
        candidate = _TABLE_MIN + int(cls._hash(name)[:8], 16) % _TABLE_SPAN
        while candidate in used or candidate in (253, 254, 255):
            candidate += 1
            if candidate >= _TABLE_MIN + _TABLE_SPAN:
                candidate = _TABLE_MIN
        return candidate

    @classmethod
    def _interface_for(cls, name: str, mode: str) -> str:
        prefix = {
            "openvpn": "zgo", "wireguard": "zgw", "proxy": "zgp",
            "xray_proxy": "zgx", "ssh": "zgs", "softether": "zge",
            "ppp": "zgl",
        }[mode]
        return prefix + cls._hash(name)[:10]

    @classmethod
    def _vrf_for(cls, name: str) -> str:
        return "zgr" + cls._hash(name)[:10]

    @classmethod
    def _softether_names(cls, name: str) -> dict[str, str]:
        digest = cls._hash(name)
        return {
            "namespace": "zgn" + digest[:11],
            "control": "zgc" + digest[:10],
            "nic": "zg" + digest[:8],
            "account": "zg" + digest[:12],
        }

    @staticmethod
    def _softether_links(table_id: int) -> dict[str, str]:
        """Two collision-free /30s from RFC 6598 space per stable table id."""
        index = int(table_id) - _TABLE_MIN
        if index < 0 or index >= _TABLE_SPAN:
            raise CoreError(f"invalid SoftEther policy table id {table_id}")
        base = int(ipaddress.IPv4Address("100.64.0.0")) + index * 8
        control = ipaddress.IPv4Network((base, 30))
        data = ipaddress.IPv4Network((base + 4, 30))
        return {
            "control_subnet": str(control),
            "control_root": str(control.network_address + 1),
            "control_peer": str(control.network_address + 2),
            "data_subnet": str(data),
            "data_root": str(data.network_address + 1),
            "data_peer": str(data.network_address + 2),
        }

    @classmethod
    def _port_for(cls, name: str, used: set[int]) -> int:
        port = 30000 + int(cls._hash(name)[8:16], 16) % 10000
        while port in used:
            port = 30000 if port >= 39999 else port + 1
        return port

    @staticmethod
    def _mode(kind: OutboundKind,
              settings: dict[str, Any] | None = None) -> str | None:
        """Select a host dataplane from the shared capability contract.

        ``policy_core=xray`` is an explicit execution choice for protocols
        Xray implements natively.  A small sing-box TUN adapter feeds a private
        Xray SOCKS inbound, so service packets genuinely traverse the Xray
        outbound process instead of relabelling a sing-box-only gateway.
        """
        if kind is OutboundKind.SSH:
            return "ssh"
        if kind is OutboundKind.SOFTETHER_NATIVE:
            return "softether"
        if kind in {
            OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW,
            OutboundKind.SSTP, OutboundKind.PPTP,
        }:
            return "ppp"
        capability = outbound_capability(kind)
        if not capability.tun:
            return None
        if kind is OutboundKind.OPENVPN:
            return "openvpn"
        if kind is OutboundKind.WIREGUARD:
            return "wireguard"
        requested = str((settings or {}).get("policy_core") or "").strip().lower()
        if requested == "xray":
            supported = {
                OutboundKind.SOCKS, OutboundKind.HTTP, OutboundKind.VLESS,
                OutboundKind.VMESS, OutboundKind.TROJAN,
                OutboundKind.SHADOWSOCKS,
            }
            if kind not in supported:
                raise CoreError(
                    f"policy_core=xray cannot execute '{kind.value}'; choose sing-box")
            return "xray_proxy"
        if requested not in ("", "sing-box"):
            raise CoreError("policy_core must be 'xray' or 'sing-box'")
        return "proxy"

    def validate_plan(
        self,
        rules: list[RoutingRule],
        outbounds: Iterable[Outbound],
        core_ids: Iterable[str] | None = None,
        source_core_map: dict[str, str] | None = None,
    ) -> None:
        """Pure source/dataplane/network compatibility preflight.

        ``source_core_map`` is supplied by the API's live inbound catalog.  A
        fallback keeps hostctl/tests and legacy callers conservative without
        turning an inbound tag prefix into the primary capability model.
        """
        by_name = {outbound.name: outbound for outbound in outbounds}
        service_cores = {"openvpn", "wireguard", "softether", "ssh", "pptp"}
        application_cores = {"xray", "sing-box"}
        targets = (set(core_ids) if core_ids is not None
                   else set(self._cores.list_cores()))
        policy_targets = service_cores.intersection(targets)
        sources = [source for source in self.traffic_sources()
                   if source.core_id in policy_targets]
        for rule in rules:
            if not rule.enabled or rule.action is not RuleAction.ROUTE_TO:
                continue
            outbound = by_name.get(str(rule.outbound))
            if outbound is None:
                raise CoreError(
                    f"rule '{rule.name}' references missing outbound '{rule.outbound}'")

            selected_cores: set[str] = set()
            if rule.matcher.inbounds and source_core_map is not None:
                selected_cores = {
                    source_core_map[tag] for tag in rule.matcher.inbounds
                    if tag in source_core_map
                }
                unknown = sorted(set(rule.matcher.inbounds) - set(source_core_map))
                if unknown:
                    raise CoreError(
                        f"rule '{rule.name}' references unknown/deleted inbound "
                        f"tag(s) {unknown}; select live catalog entries"
                    )
            elif rule.matcher.inbounds:
                selected_cores = {
                    source.core_id for source in sources
                    if source.inbound_tag in rule.matcher.inbounds
                }
                inferable = policy_targets if core_ids is not None else service_cores
                selected_cores.update(
                    prefix for tag in rule.matcher.inbounds
                    for prefix in [str(tag).split("-", 1)[0]]
                    if prefix in inferable
                )
                if not selected_cores:
                    selected_cores = application_cores.intersection(targets)
                    if not selected_cores:
                        selected_cores = set(application_cores)
            else:
                selected_cores = set(targets) or set(application_cores)

            capability = outbound_product_capability(outbound.kind)
            state, reason = routing_compatibility(
                capability,
                source_cores=selected_cores,
                networks=rule.matcher.networks,
            )
            if state is not SupportState.SUPPORTED:
                if (outbound.kind is OutboundKind.SSH
                        and set(rule.matcher.networks) != {"tcp"}):
                    raise CoreError(
                        f"rule '{rule.name}' targets TCP-only SSH outbound "
                        f"'{outbound.name}'; set the network matcher explicitly to tcp")
                raise CoreError(
                    f"rule '{rule.name}' cannot route {sorted(selected_cores)} "
                    f"through outbound '{outbound.name}': {reason or state.value}"
                )

    @staticmethod
    def _fingerprint(outbound: Outbound) -> str:
        raw = json.dumps(
            outbound.model_dump(mode="json"), sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
        ).encode()
        return hashlib.sha256(raw).hexdigest()

    def domain_views(self) -> list[dict[str, Any]]:
        for domain in self._domains.values():
            if domain.mode == "softether":
                status = self._softether_status(domain)
                domain.ready = bool(status.get("connected"))
            elif domain.mode == "ppp":
                status = self._ppp_status(domain)
                domain.ready = bool(status.get("connected"))
        return [self._domains[name].public() for name in sorted(self._domains)]

    def decorate(self, outbound: Outbound) -> Outbound:
        """Return a deployment-only copy carrying live domain metadata."""
        domain = self._domains.get(outbound.name)
        if domain is None or not domain.ready:
            return outbound
        settings = copy.deepcopy(outbound.settings)
        settings["_policy_socks_port"] = domain.proxy_port
        # Every ready domain, including SSH, now owns a scoped packet adapter.
        # Native cores still enter through SOCKS; service sources use this
        # exact mark/table/interface and remain limited to TCP by capability
        # validation and rule matchers.
        settings.update({
            "_policy_mark": domain.fwmark,
            "_policy_table": domain.table_id,
            "_policy_interface": domain.interface,
            "_policy_vrf": domain.vrf_interface,
        })
        return outbound.model_copy(update={"settings": settings})

    # ------------------------------------------------------------------ #
    # command helpers
    # ------------------------------------------------------------------ #
    def _run(self, *argv: str, check: bool = True, timeout: int = 30,
             input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        return self._runner.run(
            [str(item) for item in argv], check=check,
            timeout=timeout, input_text=input_text,
        )

    def _exists_interface(self, name: str) -> bool:
        return self._run("ip", "link", "show", "dev", name, check=False).returncode == 0

    def _domain_interfaces_exist(self, domain: PolicyDomain) -> bool:
        if domain.mode == "ssh":
            return bool(
                self._runner.tcp_ready("127.0.0.1", domain.proxy_port)
                and self._exists_interface(domain.interface)
                and domain.gateway_process is not None
                and domain.gateway_process.poll() is None
            )
        if not self._exists_interface(domain.interface):
            return False
        if domain.mode == "ppp" and not self._ppp_connected(domain):
            return False
        return (not domain.vrf_interface
                or self._exists_interface(domain.vrf_interface))

    def _wait_interface(self, domain: PolicyDomain, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._exists_interface(domain.interface):
                usable = True
                if domain.mode == "openvpn":
                    # OpenVPN creates its TUN before negotiation assigns the
                    # address and raises the link. Installing a default route
                    # at that first appearance races with initialization and
                    # fails `Device for nexthop is not up`.
                    state = self._run(
                        "ip", "-j", "address", "show", "dev", domain.interface,
                        check=False,
                    )
                    try:
                        rows = json.loads(state.stdout or "[]")
                        usable = bool(
                            rows and "UP" in (rows[0].get("flags") or [])
                            and any(item.get("family") == "inet"
                                    for item in rows[0].get("addr_info") or [])
                        )
                    except (ValueError, TypeError, IndexError):
                        usable = False
                if usable and (domain.process is None or domain.process.poll() is None):
                    return
                if domain.process is not None and domain.process.poll() is not None:
                    break
            if domain.process is not None and domain.process.poll() is not None:
                break
            self._sleep(0.25)
        log_path = Path(domain.runtime_dir) / "client.log"
        detail = "interface did not appear"
        if log_path.exists():
            lines = [line.strip() for line in log_path.read_text(errors="replace").splitlines()
                     if line.strip()]
            if lines:
                detail = lines[-1][:500]
        raise CoreError(
            f"outbound '{domain.name}' did not create {domain.tunnel_interface or domain.interface}: {detail}")

    @staticmethod
    def _atomic_text(path: Path, text: str, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        part = path.with_name(path.name + ".part")
        part.write_text(text)
        os.chmod(part, mode)
        os.replace(part, path)

    # ------------------------------------------------------------------ #
    # outbound materialization
    # ------------------------------------------------------------------ #
    def prepare(self, outbounds: Iterable[Outbound]) -> dict[str, PolicyDomain]:
        """Converge all enabled network outbounds before rules reference them."""
        with self._lock:
            if os.name != "posix" or not shutil.which("ip"):
                raise CoreError("cross-core policy routing requires Linux iproute2")
            self._root.mkdir(parents=True, exist_ok=True)
            os.chmod(self._root, 0o700)
            wanted_obs = [o for o in outbounds
                          if o.enabled and self._mode(o.kind, o.settings)]
            identities = (self._identity_provider([o.name for o in wanted_obs])
                          if self._identity_provider else {})
            used: set[int] = {int(pair[0]) for pair in identities.values()}
            used_ports: set[int] = set()
            wanted: dict[str, PolicyDomain] = {}
            for outbound in sorted(wanted_obs, key=lambda item: item.name):
                if outbound.name in identities:
                    table_id, fwmark = (int(value) for value in identities[outbound.name])
                else:
                    table_id = self._table_for(outbound.name, used)
                    fwmark = table_id
                used.add(table_id)
                mode = self._mode(outbound.kind, outbound.settings)
                assert mode is not None
                digest = self._hash(outbound.name)
                runtime_dir = str(self._root / digest[:20])
                isolated = mode in (
                    "openvpn", "wireguard", "softether", "ppp", "ssh",
                )
                interface = self._interface_for(outbound.name, mode)
                proxy_port = self._port_for(outbound.name, used_ports)
                used_ports.add(proxy_port)
                soft_names = (self._softether_names(outbound.name)
                              if mode in ("softether", "ppp") else {})
                soft_links = (self._softether_links(table_id)
                              if mode in ("softether", "ppp") else {})
                wanted[outbound.name] = PolicyDomain(
                    name=outbound.name,
                    kind=outbound.kind,
                    table_id=table_id,
                    fwmark=fwmark,
                    bypass_mark=0x40000000 | table_id,
                    return_mark=0x20000000 | table_id,
                    interface=interface,
                    tunnel_interface=interface,
                    vrf_interface=self._vrf_for(outbound.name) if isolated else None,
                    proxy_port=proxy_port,
                    redirect_port=proxy_port + 10000,
                    mode=mode,
                    fingerprint=self._fingerprint(outbound),
                    runtime_dir=runtime_dir,
                    namespace=soft_names.get("namespace"),
                    control_interface=soft_names.get("control"),
                    control_peer=soft_links.get("control_peer"),
                    data_peer=soft_links.get("data_peer"),
                    route_gateway=soft_links.get("data_peer"),
                    client_adapter=(
                        "vpn_" + soft_names["nic"] if mode == "softether"
                        else "ppp0" if mode == "ppp" else None
                    ),
                    client_account=(soft_names.get("account")
                                    if mode == "softether" else None),
                )

            # Start replacements before removing former healthy domains.
            started: dict[str, PolicyDomain] = {}
            try:
                for outbound in wanted_obs:
                    candidate = wanted[outbound.name]
                    previous = self._domains.get(outbound.name)
                    if (previous is not None
                            and previous.fingerprint == candidate.fingerprint
                            and previous.ready
                            and self._domain_interfaces_exist(previous)
                            and (previous.process is None or previous.process.poll() is None)
                            and (previous.gateway_process is None
                                 or previous.gateway_process.poll() is None)
                            and all(proc.poll() is None
                                    for proc in previous.auxiliary_processes)
                            and (previous.mode != "softether"
                                 or self._softether_connected(previous))
                            and (previous.mode != "ppp"
                                 or self._ppp_connected(previous))):
                        started[outbound.name] = previous
                        continue
                    if previous is not None:
                        self._stop_domain(previous)
                    self._start_domain(candidate, outbound)
                    self._install_table(candidate)
                    candidate.ready = True
                    if candidate.mode == "ssh":
                        candidate.detail = (
                            f"TCP-only fwmark {candidate.fwmark} → table "
                            f"{candidate.table_id} → {candidate.interface} → scoped "
                            f"sing-box adapter → OpenSSH SOCKS "
                            f"127.0.0.1:{candidate.proxy_port}")
                    elif candidate.mode == "softether":
                        candidate.detail = (
                            f"fwmark {candidate.fwmark} → table {candidate.table_id} → "
                            f"{candidate.interface} → {candidate.namespace}/"
                            f"{candidate.client_adapter} → native vpnclient")
                    elif candidate.mode == "ppp":
                        candidate.detail = (
                            f"fwmark {candidate.fwmark} → table {candidate.table_id} → "
                            f"{candidate.interface} → {candidate.namespace}/"
                            f"{candidate.client_adapter} → {candidate.kind.value}")
                    else:
                        candidate.detail = (
                            f"fwmark {candidate.fwmark} → table {candidate.table_id} "
                            f"→ {candidate.interface}")
                    started[outbound.name] = candidate
            except Exception:
                for name, domain in started.items():
                    if self._domains.get(name) is not domain:
                        self._stop_domain(domain)
                raise

            for name, old in list(self._domains.items()):
                if name not in wanted:
                    self._stop_domain(old)
                    self._drop_outbound_counters(name)
            self._domains = started
            self._outbounds = {o.name: o for o in outbounds}
            self._run("ip", "route", "flush", "cache", check=False)
            return dict(self._domains)

    def _attach_vrf(self, domain: PolicyDomain) -> None:
        """Move a VPN client interface into its own L3 routing domain.

        VRF keeps upstream addresses/routes out of ``main``. An outbound
        client may therefore receive 10.8/10.9 even when server inbounds use
        the same prefixes, without ambiguous return routes or packet loops.
        """
        if not domain.vrf_interface:
            return
        self._run("ip", "link", "del", "dev", domain.vrf_interface, check=False)
        self._run(
            "ip", "link", "add", "dev", domain.vrf_interface,
            "type", "vrf", "table", str(domain.table_id),
        )
        self._run("ip", "link", "set", "dev", domain.vrf_interface, "up")
        self._run(
            "ip", "link", "set", "dev", domain.interface,
            "master", domain.vrf_interface,
        )
        self._run(
            "sysctl", "-qw", f"net.ipv4.conf.{domain.interface}.rp_filter=0",
            check=False,
        )
        for key in ("tcp_l3mdev_accept", "udp_l3mdev_accept", "raw_l3mdev_accept"):
            self._run("sysctl", "-qw", f"net.ipv4.{key}=1", check=False)
        main = self._run("ip", "route", "show", "table", "main", check=False)
        if any(f" dev {domain.interface}" in line for line in main.stdout.splitlines()):
            raise CoreError(
                f"VRF isolation failed: {domain.interface} still owns a main-table route")

    def _start_domain(self, domain: PolicyDomain, outbound: Outbound) -> None:
        Path(domain.runtime_dir).mkdir(parents=True, exist_ok=True)
        os.chmod(domain.runtime_dir, 0o700)
        try:
            if domain.mode == "openvpn":
                self._start_openvpn(domain, outbound)
            elif domain.mode == "wireguard":
                self._start_wireguard(domain, outbound)
            elif domain.mode == "ssh":
                self._start_ssh(domain, outbound)
                self._start_ssh_packet_adapter(domain)
            elif domain.mode == "softether":
                self._start_softether(domain, outbound)
            elif domain.mode == "ppp":
                self._start_ppp(domain, outbound)
            elif domain.mode == "xray_proxy":
                self._start_xray_proxy(domain, outbound)
            else:
                self._start_proxy(domain, outbound)
            self._wait_interface(domain)
            self._attach_vrf(domain)
            if domain.mode in ("openvpn", "wireguard", "softether", "ppp"):
                # Native Xray/sing-box rules enter every packet-domain through
                # this loopback SOCKS gateway. PPP previously omitted it, so
                # service sources worked through fwmark/TUN while native-core
                # sources received connection resets despite a healthy tunnel.
                self._start_gateway(domain)
            elif domain.mode not in ("softether", "ppp", "ssh"):
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if self._runner.tcp_ready("127.0.0.1", domain.proxy_port):
                        break
                    if domain.process is not None and domain.process.poll() is not None:
                        raise CoreError(f"outbound '{domain.name}' proxy gateway exited")
                    self._sleep(0.2)
                else:
                    raise CoreError(
                        f"outbound '{domain.name}' SOCKS gateway did not listen on {domain.proxy_port}")
        except Exception:
            self._stop_process(domain.gateway_process)
            self._stop_process(domain.process)
            for process in domain.auxiliary_processes:
                self._stop_process(process)
            domain.auxiliary_processes.clear()
            if domain.mode == "softether":
                self._cleanup_softether(domain)
            elif domain.mode == "ppp":
                self._cleanup_ppp(domain)
            self._run("ip", "link", "del", "dev", domain.interface, check=False)
            if domain.vrf_interface:
                self._run("ip", "link", "del", "dev", domain.vrf_interface,
                          check=False)
            shutil.rmtree(domain.runtime_dir, ignore_errors=True)
            raise

    def _softether_binaries(self) -> tuple[str, str, str]:
        try:
            driver = self._cores.get("softether")
            backend = getattr(driver, "_backend", None)
            vpnclient = getattr(backend, "client_binary", lambda: None)()
            vpncmd = getattr(backend, "vpncmd_binary", lambda: None)()
        except Exception as exc:  # noqa: BLE001
            raise CoreError(
                "native SoftEther outbound requires an installed SoftEther core") from exc
        busybox = shutil.which("busybox")
        if not vpnclient or not vpncmd:
            raise CoreError(
                "SoftEther core has no vpnclient/vpncmd pair; Reinstall the core")
        if not busybox:
            raise CoreError("native SoftEther outbound requires busybox udhcpc")
        return str(vpnclient), str(vpncmd), str(busybox)

    @staticmethod
    def _resolve_ipv4(host: str) -> str:
        try:
            rows = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            raise CoreError(f"cannot resolve outbound server '{host}' to IPv4") from exc
        addresses = sorted({str(row[4][0]) for row in rows})
        if not addresses:
            raise CoreError(f"outbound server '{host}' has no IPv4 address")
        return addresses[0]

    def _softether_command(
        self, domain: PolicyDomain, vpncmd: str, commands: list[str],
        *, secrets: list[str] | None = None,
    ) -> str:
        if not domain.namespace:
            raise CoreError("SoftEther client namespace is missing")
        return self._softether_commander(
            ["ip", "netns", "exec", domain.namespace,
             vpncmd, "localhost", "/CLIENT"],
            commands=commands,
            administrator_password="",
            prompt="VPN Client",
            secrets=secrets or [],
            timeout=30,
        )

    def _softether_status(self, domain: PolicyDomain) -> dict[str, int | str | bool]:
        vpncmd = str(Path(domain.runtime_dir) / "client" / "vpncmd")
        if not os.path.isfile(vpncmd) or not domain.client_account:
            return {"connected": False, "state": "runtime missing",
                    "session": "", "uplink_bytes": 0, "downlink_bytes": 0}
        try:
            text = self._softether_command(
                domain, vpncmd, [f"AccountStatusGet {domain.client_account}"])
            status = parse_account_status(text)
            session_up = int(status["uplink_bytes"])
            session_down = int(status["downlink_bytes"])
            total_up, total_down = self._fold_outbound_counters(
                domain, uplink=session_up, downlink=session_down,
                generation=str(status.get("session") or domain.client_account or "native"),
            )
            status["session_uplink_bytes"] = session_up
            status["session_downlink_bytes"] = session_down
            status["uplink_bytes"] = total_up
            status["downlink_bytes"] = total_down
            return status
        except Exception:  # noqa: BLE001 - health probe stays a boolean boundary
            return {"connected": False, "state": "status unavailable",
                    "session": "", "uplink_bytes": 0, "downlink_bytes": 0}

    def _softether_connected(self, domain: PolicyDomain) -> bool:
        return bool(self._softether_status(domain).get("connected"))

    def _delete_iptables_rule(self, *argv: str) -> None:
        for _ in range(8):
            result = self._run("iptables", *argv, check=False)
            if result.returncode:
                break

    def _softether_root_firewall(
        self, domain: PolicyDomain, links: dict[str, str], *, enabled: bool,
        pptp_endpoint: str | None = None,
    ) -> None:
        if not domain.control_interface or not domain.outer_interface:
            return
        forward_out = (
            "-C", "FORWARD", "-i", domain.control_interface, "-j", "ACCEPT")
        forward_in = (
            "-C", "FORWARD", "-o", domain.control_interface,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        nat = (
            "-t", "nat", "-C", "POSTROUTING", "-s", links["control_subnet"],
            "-o", domain.outer_interface, "-j", "MASQUERADE")
        helper: tuple[str, ...] | None = None
        if domain.kind is OutboundKind.PPTP and pptp_endpoint:
            # GRE carries call IDs rather than TCP/UDP ports. Explicitly attach
            # the kernel PPTP helper to this one owned control flow so
            # nf_nat_pptp can translate reverse GRE through the control-veth
            # MASQUERADE. No unrelated flow or global helper policy is changed.
            helper = (
                "-t", "raw", "-C", "PREROUTING",
                "-s", links["control_subnet"], "-d", f"{pptp_endpoint}/32",
                "-p", "tcp", "--dport", "1723",
                "-j", "CT", "--helper", "pptp",
            )
        if enabled:
            operations = [
                (forward_out, ("-I", "FORWARD", "1", *forward_out[2:])),
                (forward_in, ("-I", "FORWARD", "1", *forward_in[2:])),
                (nat, ("-t", "nat", "-A", "POSTROUTING", *nat[4:])),
            ]
            if helper:
                operations.insert(
                    0, (helper, ("-t", "raw", "-I", "PREROUTING", "1", *helper[4:])))
            for check, add in operations:
                if self._run("iptables", *check, check=False).returncode:
                    self._run("iptables", *add)
        else:
            self._delete_iptables_rule(
                "-D", "FORWARD", "-i", domain.control_interface, "-j", "ACCEPT")
            self._delete_iptables_rule(
                "-D", "FORWARD", "-o", domain.control_interface,
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
            self._delete_iptables_rule(
                "-t", "nat", "-D", "POSTROUTING", "-s", links["control_subnet"],
                "-o", domain.outer_interface, "-j", "MASQUERADE")
            if helper:
                self._delete_iptables_rule(
                    "-t", "raw", "-D", "PREROUTING",
                    "-s", links["control_subnet"], "-d", f"{pptp_endpoint}/32",
                    "-p", "tcp", "--dport", "1723",
                    "-j", "CT", "--helper", "pptp")

    def _softether_namespace_sysctls(self, domain: PolicyDomain) -> None:
        """Disable strict reverse-path filtering only inside the owned netns.

        Docker mounts its container /proc/sys read-only. With SYS_ADMIN we can
        mount a short-lived proc view in a private *mount* namespace while the
        process is already in the SoftEther *network* namespace. The values are
        network-namespace state and survive that proc unmount; host/global
        rp_filter and routes are never changed.
        """
        if not domain.namespace:
            raise CoreError("SoftEther namespace is missing")
        proc_dir = Path(domain.runtime_dir) / ".proc-sys"
        proc_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        quoted = shlex.quote(str(proc_dir))
        script = (
            f"mount -t proc proc {quoted}; "
            f"printf 0 >{quoted}/sys/net/ipv4/conf/all/rp_filter; "
            f"printf 0 >{quoted}/sys/net/ipv4/conf/default/rp_filter; "
            f"printf 0 >{quoted}/sys/net/ipv4/conf/data0/rp_filter; "
            f"printf 0 >{quoted}/sys/net/ipv4/conf/ctl0/rp_filter; "
            f"umount {quoted}"
        )
        self._run(
            "ip", "netns", "exec", domain.namespace,
            "unshare", "-m", "sh", "-c", script,
        )

    def _cleanup_softether(self, domain: PolicyDomain) -> None:
        links = self._softether_links(domain.table_id)
        facts = Path(domain.runtime_dir) / "softether-resources.json"
        if facts.is_file():
            try:
                saved = json.loads(facts.read_text())
                domain.outer_interface = str(
                    saved.get("outer_interface") or domain.outer_interface or "") or None
            except (OSError, ValueError, TypeError):
                pass
        try:
            self._softether_root_firewall(domain, links, enabled=False)
        except Exception:  # noqa: BLE001 - continue namespace/interface teardown
            logger.exception("failed to remove SoftEther outer forwarding rules")
        client = Path(domain.runtime_dir) / "client" / "vpnclient"
        if domain.namespace and client.is_file():
            self._run(
                "ip", "netns", "exec", domain.namespace,
                str(client), "stop", check=False, timeout=30)
        if domain.namespace:
            self._run("ip", "netns", "del", domain.namespace, check=False)
        if domain.control_interface:
            self._run("ip", "link", "del", "dev", domain.control_interface,
                      check=False)
        self._run("ip", "link", "del", "dev", domain.interface, check=False)

    @staticmethod
    def _ppp_binary(name: str, *fallbacks: str) -> str:
        found = shutil.which(name)
        if found:
            return found
        for candidate in fallbacks:
            if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        raise CoreError(f"PPP outbound runtime is missing required binary '{name}'")

    def _ppp_status(self, domain: PolicyDomain) -> dict[str, Any]:
        disconnected = {
            "connected": False, "state": "PPP interface unavailable",
            "address": "", "uplink_bytes": 0, "downlink_bytes": 0,
        }
        if not domain.namespace or not domain.client_adapter:
            return disconnected
        link = self._run(
            "ip", "-n", domain.namespace, "-j", "-s", "link", "show",
            "dev", domain.client_adapter, check=False)
        addresses = self._run(
            "ip", "-n", domain.namespace, "-j", "-4", "address", "show",
            "dev", domain.client_adapter, check=False)
        route = self._run(
            "ip", "-n", domain.namespace, "route", "show", "default",
            check=False)
        if link.returncode or addresses.returncode or route.returncode:
            return disconnected
        try:
            link_rows = json.loads(link.stdout or "[]")
            address_rows = json.loads(addresses.stdout or "[]")
            stats = (link_rows[0].get("stats64") or link_rows[0].get("stats") or {})
            uplink = int((stats.get("tx") or {}).get("bytes") or 0)
            downlink = int((stats.get("rx") or {}).get("bytes") or 0)
            ifindex = int(link_rows[0].get("ifindex") or 0)
            address = next(
                str(item["local"])
                for row in address_rows
                for item in row.get("addr_info") or []
                if item.get("family") == "inet" and item.get("local")
            )
        except (ValueError, KeyError, IndexError, StopIteration, TypeError):
            return disconnected
        if f"dev {domain.client_adapter}" not in (route.stdout or ""):
            return disconnected
        if domain.kind is OutboundKind.L2TP_IPSEC:
            xfrm = self._run(
                "ip", "netns", "exec", domain.namespace,
                "ip", "xfrm", "state", check=False)
            if xfrm.returncode or not (xfrm.stdout or "").strip():
                return {**disconnected, "state": "PPP is up but IPsec CHILD_SA is absent"}
        domain.client_address = address
        total_up, total_down = self._fold_outbound_counters(
            domain, uplink=uplink, downlink=downlink,
            generation=f"{domain.namespace}:{ifindex}",
        )
        return {
            "connected": True, "state": "connected", "address": address,
            "uplink_bytes": total_up, "downlink_bytes": total_down,
            "session_uplink_bytes": uplink, "session_downlink_bytes": downlink,
        }

    def _ppp_connected(self, domain: PolicyDomain) -> bool:
        return bool(self._ppp_status(domain).get("connected"))

    @staticmethod
    def _ping_latency(
        text: str, *, expected: int, label: str, warmup_samples: int = 0,
    ) -> dict[str, Any]:
        """Reduce one completed ICMP window without mixing setup into RTT.

        ``warmup_samples`` are deliberately discarded from the selected
        latency window.  They are retained only as internal evidence so the
        first-packet/neighbor artifact can never become the user-facing RTT.
        """
        samples = [
            float(value) for value in re.findall(
                r"\btime[=<]([0-9]+(?:\.[0-9]+)?)\s*ms", text or "")
        ]
        observed = expected + warmup_samples
        if len(samples) != observed:
            raise CoreError(
                f"{label} returned {len(samples)}/{observed} RTT samples")
        warmup = samples[:warmup_samples]
        measured = samples[warmup_samples:]
        if not measured:
            raise CoreError(f"{label} returned no post-warm-up RTT samples")
        ordered = sorted(measured)
        # p95 remains internal diagnostics only. The public Test contract
        # exposes exactly one selected RTT (the measurement-window median).
        p95 = ordered[max(0, int((len(ordered) * 0.95) + 0.999999) - 1)]
        return {
            "samples": len(measured),
            "warmup_samples": len(warmup),
            "warmup_ms": [round(value, 3) for value in warmup],
            "measurement_samples_ms": [round(value, 3) for value in measured],
            "median_ms": round(float(statistics.median(measured)), 3),
            "p95_ms": round(float(p95), 3),
            "min_ms": round(min(measured), 3),
            "max_ms": round(max(measured), 3),
        }

    def measure_ppp(self, domain: PolicyDomain, outbound: Outbound) -> dict[str, Any]:
        """Measure real post-establishment PPP latency and validated HTTPS.

        Setup time is deliberately not called network latency. Direct and
        tunneled RTT use the same destination/sample count, while HTTPS runs
        once on the host and once inside the provider namespace with normal
        CA/hostname verification. The response body is hashed, never logged.
        """
        if domain.mode != "ppp" or not domain.namespace:
            raise CoreError("PPP diagnostics require a ready PPP namespace")
        settings = outbound.settings
        probe_url = str(
            settings.get("test_url") or "https://1.1.1.1/cdn-cgi/trace"
        ).strip()
        parsed = urlsplit(probe_url)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username or parsed.password or parsed.fragment):
            raise CoreError("PPP HTTPS probe URL is invalid")
        try:
            port = int(parsed.port or 443)
            rows = socket.getaddrinfo(
                parsed.hostname, port, socket.AF_INET, socket.SOCK_STREAM)
            probe_ip = str(rows[0][4][0])
            probe_address = ipaddress.ip_address(probe_ip)
        except (OSError, ValueError, IndexError) as exc:
            raise CoreError(f"PPP probe host resolution failed: {type(exc).__name__}") from exc
        # Test probes must leave the provider through a real public network
        # target.  This rejects localhost, Docker bridges, RFC1918/link-local,
        # multicast and other fabricated/local destinations before any RTT is
        # selected or reported.
        if (not isinstance(probe_address, ipaddress.IPv4Address)
                or probe_address.is_loopback or probe_address.is_private
                or probe_address.is_link_local or probe_address.is_unspecified
                or probe_address.is_multicast or probe_address.is_reserved):
            raise CoreError("PPP probe target must resolve to a public IPv4 address")
        samples = int(settings.get("test_samples") or 20)
        if not 20 <= samples <= 30:
            raise CoreError("PPP test_samples must be 20-30")
        warmup_samples = 3
        busybox = shutil.which("busybox")
        if not busybox:
            raise CoreError("PPP latency diagnostics require busybox ping")
        # The tunnel is already READY when measure_ppp is called.  One ICMP
        # window contains three event-driven warm-up replies followed by the
        # fixed 20-30 sample measurement window; startup/readiness/PPP/TLS
        # durations never enter the selected RTT.
        observed = samples + warmup_samples
        ping = [
            busybox, "ping", "-c", str(observed), "-W", "3", "-i", "0.1",
            probe_ip,
        ]
        before = self._ppp_status(domain)
        if not before.get("connected"):
            raise CoreError("PPP tunnel was not ready before RTT measurement")
        route_before = self._run(
            "ip", "-n", domain.namespace, "route", "get", probe_ip,
            check=False,
        )
        if (route_before.returncode
                or domain.client_adapter not in (route_before.stdout or "")):
            raise CoreError("PPP RTT probe route does not use the tunnel interface")
        direct = self._run(*ping, check=False, timeout=max(30, observed * 4))
        direct_stats = self._ping_latency(
            (direct.stdout or "") + "\n" + (direct.stderr or ""),
            expected=samples, label="direct baseline",
            warmup_samples=warmup_samples,
        )
        tunneled = self._run(
            "ip", "netns", "exec", domain.namespace, *ping,
            check=False, timeout=max(30, observed * 4),
        )
        tunnel_stats = self._ping_latency(
            (tunneled.stdout or "") + "\n" + (tunneled.stderr or ""),
            expected=samples, label="tunnel baseline",
            warmup_samples=warmup_samples,
        )

        runtime = Path(domain.runtime_dir)
        # Probe trust is independent from the SSTP peer CA. Reusing ca_pem
        # here would make a valid private SSTP CA replace system trust for an
        # unrelated HTTPS origin.
        ca_pem = str(settings.get("probe_ca_pem") or "").strip()
        ca_path = runtime / "https-probe-ca.pem"
        if ca_pem:
            if "-----BEGIN CERTIFICATE-----" not in ca_pem:
                raise CoreError("PPP HTTPS probe CA is not a PEM certificate")
            self._atomic_text(ca_path, ca_pem + ("\n" if not ca_pem.endswith("\n") else ""))
        script = runtime / "https-probe.py"
        self._atomic_text(script, '''import hashlib,json,ssl,sys,time,urllib.request
url,ca,nonce=sys.argv[1:4]
ctx=ssl.create_default_context(cafile=ca or None)
req=urllib.request.Request(url,headers={"X-Zagros-Probe-Nonce":nonce})
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
started=time.monotonic()
with opener.open(req,timeout=20) as response:
    body=response.read(1048576)
    status=int(response.status)
print(json.dumps({"status":status,"elapsed_ms":round((time.monotonic()-started)*1000,3),"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest()}))
''', mode=0o700)
        ca_arg = str(ca_path) if ca_pem else ""
        nonce_base = f"zg-{self._hash(outbound.name)[:10]}-{time.time_ns()}"

        def https(prefix: list[str], suffix: str) -> dict[str, Any]:
            result = self._run(
                *prefix, sys.executable, str(script), probe_url, ca_arg,
                f"{nonce_base}-{suffix}", timeout=30,
            )
            try:
                payload = json.loads(result.stdout)
            except (ValueError, TypeError) as exc:
                raise CoreError("PPP HTTPS probe returned invalid output") from exc
            if int(payload.get("status") or 0) < 200 \
                    or int(payload.get("status") or 0) >= 400:
                raise CoreError(
                    f"PPP HTTPS probe returned status {payload.get('status')}")
            payload["nonce"] = f"{nonce_base}-{suffix}"
            return payload

        direct_https = https([], "direct")
        tunnel_https = https(
            ["ip", "netns", "exec", domain.namespace], "tunnel")
        after = self._ppp_status(domain)
        route = self._run(
            "ip", "-n", domain.namespace, "route", "get", probe_ip,
            check=False,
        )
        if route.returncode or domain.client_adapter not in (route.stdout or ""):
            raise CoreError("PPP probe route does not use the tunnel interface")
        counter_delta = {
            "uplink_bytes": max(
                0, int(after.get("uplink_bytes") or 0)
                - int(before.get("uplink_bytes") or 0)),
            "downlink_bytes": max(
                0, int(after.get("downlink_bytes") or 0)
                - int(before.get("downlink_bytes") or 0)),
        }
        if (counter_delta["uplink_bytes"] <= 0
                or counter_delta["downlink_bytes"] <= 0):
            raise CoreError(
                "PPP tunnel counters did not increase in both directions during probes")
        selected_rtt = tunnel_stats["median_ms"]
        return {
            "probe_url": probe_url,
            "probe_ip": probe_ip,
            "probe_target": f"{parsed.hostname} ({probe_ip})",
            "measurement_timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": domain.client_adapter,
            "namespace": domain.namespace,
            "warmup_samples": warmup_samples,
            "measurement_window_samples": tunnel_stats["measurement_samples_ms"],
            "selected_rtt_ms": selected_rtt,
            "direct_rtt": direct_stats,
            "tunnel_rtt": tunnel_stats,
            "direct_https": direct_https,
            "tunnel_https": tunnel_https,
            "route_before": (route_before.stdout or "").strip(),
            "route": (route.stdout or "").strip(),
            "counter_delta": counter_delta,
        }

    def _cleanup_ppp(self, domain: PolicyDomain) -> None:
        links = self._softether_links(domain.table_id)
        facts = Path(domain.runtime_dir) / "ppp-resources.json"
        pptp_endpoint: str | None = None
        if facts.is_file():
            try:
                saved = json.loads(facts.read_text())
                domain.outer_interface = str(
                    saved.get("outer_interface") or domain.outer_interface or "") or None
                if domain.kind is OutboundKind.PPTP:
                    pptp_endpoint = str(saved.get("endpoint") or "") or None
            except (OSError, ValueError, TypeError):
                pass
        try:
            self._softether_root_firewall(
                domain, links, enabled=False, pptp_endpoint=pptp_endpoint)
        except Exception:  # noqa: BLE001 - exact namespace teardown must continue
            logger.exception("failed to remove PPP outer forwarding rules")
        if domain.kind is OutboundKind.SSTP:
            callback_id = f"zg{domain.table_id}"
            for path in (
                Path("/var/run/sstpc") / f"sstpc-{callback_id}",
                Path("/var/run/sstpc") / f"sstpc-{callback_id}-ca.pem",
            ):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    logger.exception("failed to remove owned SSTP runtime file %s", path)
        if domain.namespace:
            self._run("ip", "netns", "del", domain.namespace, check=False)
        if domain.control_interface:
            self._run("ip", "link", "del", "dev", domain.control_interface,
                      check=False)
        self._run("ip", "link", "del", "dev", domain.interface, check=False)

    @staticmethod
    def _ppp_log_tail(
        domain: PolicyDomain, outbound: Outbound, log, *, lines: int = 8,
    ) -> str:
        """Return a bounded, credential-redacted provider log tail."""
        try:
            log.flush()
        except Exception:  # noqa: BLE001 - diagnostic best effort
            pass
        values: list[str] = []
        try:
            values = [
                line.strip() for line in (
                    Path(domain.runtime_dir) / "client.log"
                ).read_text(errors="replace").splitlines() if line.strip()
            ][-lines:]
        except OSError:
            pass
        safe = " | ".join(values)
        for key in ("password", "ipsec_psk", "private_key", "preshared_key"):
            value = str(outbound.settings.get(key) or "")
            if value:
                safe = safe.replace(value, "<redacted>")
        # Startup libraries can emit many benign lines before the fatal one;
        # retain the end, not the beginning, of the bounded diagnostic.
        return safe[-500:]

    def _start_ppp(self, domain: PolicyDomain, outbound: Outbound) -> None:
        establishment_started = time.monotonic()
        if not all((domain.namespace, domain.control_interface,
                    domain.client_adapter)):
            raise CoreError("PPP policy resource identity is incomplete")
        endpoint = self._resolve_ipv4(str(outbound.settings.get("server") or ""))
        route = self._run("ip", "route", "get", endpoint, check=False)
        match = re.search(r"\bdev\s+(\S+)", route.stdout or "")
        if route.returncode or not match:
            raise CoreError(f"cannot resolve host route to PPP endpoint {endpoint}")
        domain.outer_interface = match.group(1)
        links = self._softether_links(domain.table_id)
        self._cleanup_ppp(domain)

        pppd = self._ppp_binary("pppd", "/usr/sbin/pppd")
        kwargs: dict[str, str] = {"pppd": pppd}
        if outbound.kind in (OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW):
            kwargs["xl2tpd"] = self._ppp_binary("xl2tpd", "/usr/sbin/xl2tpd")
        if outbound.kind is OutboundKind.SSTP:
            kwargs["sstpc"] = self._ppp_binary("sstpc", "/usr/sbin/sstpc")
            # sstp-client 1.0.20 fails to advance link negotiation when ipparam
            # exceeds ten characters. The allocated table id is transactionally
            # unique and yields a short, stable callback identity.
            kwargs["sstp_callback_id"] = f"zg{domain.table_id}"
        if outbound.kind is OutboundKind.PPTP:
            kwargs["pptp"] = self._ppp_binary("pptp", "/usr/sbin/pptp")
        if outbound.kind is OutboundKind.L2TP_IPSEC:
            kwargs["charon"] = self._ppp_binary(
                "charon", "/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon")
            kwargs["swanctl"] = self._ppp_binary("swanctl", "/usr/sbin/swanctl")
        plan = render_ppp_client_plan(
            outbound, runtime_dir=domain.runtime_dir,
            endpoint=endpoint, interface=domain.client_adapter, **kwargs)
        write_private_plan_files(plan)
        facts = Path(domain.runtime_dir) / "ppp-resources.json"
        self._atomic_text(facts, json.dumps({
            "provider": outbound.kind.value,
            "namespace": domain.namespace,
            "control_interface": domain.control_interface,
            "data_interface": domain.interface,
            "tunnel_interface": domain.client_adapter,
            "outer_interface": domain.outer_interface,
            "endpoint": endpoint,
            "control_subnet": links["control_subnet"],
            "data_subnet": links["data_subnet"],
        }, sort_keys=True) + "\n")

        self._run("ip", "netns", "add", domain.namespace)
        self._run(
            "ip", "link", "add", "dev", domain.control_interface,
            "type", "veth", "peer", "name", "ctl0", "netns", domain.namespace)
        self._run(
            "ip", "link", "add", "dev", domain.interface,
            "type", "veth", "peer", "name", "data0", "netns", domain.namespace)
        self._run("ip", "address", "add", f"{links['control_root']}/30",
                  "dev", domain.control_interface)
        self._run("ip", "address", "add", f"{links['data_root']}/30",
                  "dev", domain.interface)
        self._run("ip", "link", "set", "dev", domain.control_interface, "up")
        self._run("ip", "link", "set", "dev", domain.interface, "up")
        for peer, address in (("ctl0", links["control_peer"]),
                              ("data0", links["data_peer"])):
            self._run("ip", "-n", domain.namespace, "address", "add",
                      f"{address}/30", "dev", peer)
            self._run("ip", "-n", domain.namespace, "link", "set", "dev", peer, "up")
        self._run("ip", "-n", domain.namespace, "link", "set", "dev", "lo", "up")
        self._run("ip", "-n", domain.namespace, "route", "replace",
                  f"{endpoint}/32", "via", links["control_root"], "dev", "ctl0")
        self._run("ip", "-n", domain.namespace, "route", "replace", "default",
                  "via", links["control_root"], "dev", "ctl0")
        self._softether_namespace_sysctls(domain)
        self._softether_root_firewall(
            domain, links, enabled=True,
            pptp_endpoint=endpoint if outbound.kind is OutboundKind.PPTP else None,
        )

        log = open(Path(domain.runtime_dir) / "client.log", "a", encoding="utf-8")  # noqa: SIM115
        # L2TP/IPsec owns one profile-specific charon daemon.  Its two swanctl
        # operations are one-shot, secret-free argv and complete before L2TP is
        # allowed to send UDP/1701.
        if outbound.kind is OutboundKind.L2TP_IPSEC:
            charon_argv, load_argv, initiate_argv = plan.auxiliary_argv
            charon_process = self._runner.popen(
                ["ip", "netns", "exec", domain.namespace, *charon_argv], stdout=log)
            domain.auxiliary_processes.append(charon_process)
            vici = Path(domain.runtime_dir) / "charon.vici"
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                charon_exit = charon_process.poll()
                if charon_exit is not None:
                    tail = self._ppp_log_tail(domain, outbound, log)
                    raise CoreError(
                        "strongSwan charon exited before VICI became ready; "
                        f"exit_code={charon_exit}; stderr_tail={tail}")
                if vici.exists():
                    break
                self._sleep(0.2)
            else:
                raise CoreError("strongSwan VICI socket did not become ready")
            self._run("ip", "netns", "exec", domain.namespace, *load_argv, timeout=30)
            self._run("ip", "netns", "exec", domain.namespace,
                      *initiate_argv, timeout=45)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                state = self._run(
                    "ip", "netns", "exec", domain.namespace,
                    "ip", "xfrm", "state", check=False)
                policy = self._run(
                    "ip", "netns", "exec", domain.namespace,
                    "ip", "xfrm", "policy", check=False)
                if (state.stdout or "").strip() and (policy.stdout or "").strip():
                    break
                self._sleep(0.25)
            else:
                raise CoreError("L2TP/IPsec established no XFRM state/policy")

        ppp_started = time.monotonic()
        domain.process = self._runner.popen(
            ["ip", "netns", "exec", domain.namespace, *plan.primary_argv],
            stdout=log)
        timeout = int(outbound.settings.get("connect_timeout") or 60)
        deadline = time.monotonic() + max(15, min(timeout, 180))
        status: dict[str, Any] = {}
        while time.monotonic() < deadline:
            exit_code = domain.process.poll()
            if exit_code is not None:
                safe_tail = self._ppp_log_tail(domain, outbound, log)
                callback = "not_applicable"
                if outbound.kind is OutboundKind.SSTP:
                    callback_id = f"zg{domain.table_id}"
                    callback_path = Path("/var/run/sstpc") / f"sstpc-{callback_id}"
                    if callback_path.exists():
                        try:
                            callback = (
                                f"present:mode={callback_path.stat().st_mode & 0o777:o}")
                        except OSError:
                            callback = "present:stat_failed"
                    else:
                        callback = "absent"
                adapter = self._run(
                    "ip", "-n", domain.namespace, "-br", "link", "show",
                    "dev", domain.client_adapter, check=False)
                adapter_state = (adapter.stdout or adapter.stderr or "absent").strip()
                raise CoreError(
                    f"{outbound.kind.value} client exited before PPP connected; "
                    f"exit_code={exit_code}; callback_socket={callback}; "
                    f"interface={adapter_state[:160]}; stderr_tail={safe_tail}")
            dead_aux = [
                process.poll() for process in domain.auxiliary_processes
                if process.poll() is not None
            ]
            if dead_aux:
                tail = self._ppp_log_tail(domain, outbound, log)
                raise CoreError(
                    "L2TP/IPsec auxiliary process exited; "
                    f"exit_codes={dead_aux}; stderr_tail={tail}")
            status = self._ppp_status(domain)
            if status.get("connected"):
                break
            self._sleep(0.25)
        else:
            raise CoreError(
                f"{outbound.kind.value} did not establish PPP: "
                f"{status.get('state', 'unknown')}")

        domain.ppp_ready_ms = round((time.monotonic() - ppp_started) * 1000, 3)

        # pppd may replace the namespace default; the outer control path must
        # always stay pinned to ctl0 to prevent recursive tunnel establishment.
        self._run("ip", "-n", domain.namespace, "route", "replace",
                  f"{endpoint}/32", "via", links["control_root"], "dev", "ctl0")
        forwarding = self._run(
            "ip", "netns", "exec", domain.namespace,
            "cat", "/proc/sys/net/ipv4/ip_forward", check=False)
        if forwarding.returncode or forwarding.stdout.strip() != "1":
            raise CoreError(
                "PPP namespace inherited ip_forward=0; enable host net.ipv4.ip_forward")
        self._run("ip", "netns", "exec", domain.namespace,
                  "iptables", "-A", "FORWARD", "-i", "data0", "-o",
                  domain.client_adapter, "-j", "ACCEPT")
        self._run("ip", "netns", "exec", domain.namespace,
                  "iptables", "-A", "FORWARD", "-o", "data0", "-i",
                  domain.client_adapter, "-m", "conntrack", "--ctstate",
                  "ESTABLISHED,RELATED", "-j", "ACCEPT")
        self._run("ip", "netns", "exec", domain.namespace,
                  "iptables", "-t", "nat", "-A", "POSTROUTING",
                  "-o", domain.client_adapter, "-j", "MASQUERADE")
        domain.tunnel_interface = domain.client_adapter
        domain.client_address = str(status.get("address") or "")
        domain.establishment_ms = round(
            (time.monotonic() - establishment_started) * 1000, 3)
        domain.detail = plan.health_protocol

    def _copy_softether_client_runtime(
        self, domain: PolicyDomain, vpnclient: str, vpncmd: str,
    ) -> tuple[str, str]:
        target = Path(domain.runtime_dir) / "client"
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True, mode=0o700)
        sources = {"vpnclient": Path(vpnclient), "vpncmd": Path(vpncmd)}
        hamcore = Path(vpnclient).with_name("hamcore.se2")
        if not hamcore.is_file():
            hamcore = Path(vpncmd).with_name("hamcore.se2")
        if not hamcore.is_file():
            raise CoreError("SoftEther vpnclient runtime has no hamcore.se2")
        for name, source in (*sources.items(), ("hamcore.se2", hamcore)):
            destination = target / name
            shutil.copy2(source, destination)
            os.chmod(destination, 0o700 if name != "hamcore.se2" else 0o600)
        # Source-build runtimes use adjacent shared libraries.
        for source in Path(vpnclient).parent.glob("lib*.so*"):
            if source.is_file():
                shutil.copy2(source, target / source.name)
        return str(target / "vpnclient"), str(target / "vpncmd")

    def _start_softether(self, domain: PolicyDomain, outbound: Outbound) -> None:
        if not all((domain.namespace, domain.control_interface,
                    domain.client_adapter, domain.client_account)):
            raise CoreError("SoftEther policy resource identity is incomplete")
        settings = outbound.settings
        server = str(settings.get("server") or "").strip()
        port = int(settings.get("server_port") or 5555)
        hub = str(settings.get("hub") or "")
        username = str(settings.get("username") or "")
        password = str(settings.get("password") or "")
        endpoint = self._resolve_ipv4(server)
        route = self._run("ip", "route", "get", endpoint, check=False)
        match = re.search(r"\bdev\s+(\S+)", route.stdout or "")
        if route.returncode or not match:
            raise CoreError(f"cannot resolve host route to SoftEther endpoint {endpoint}")
        domain.outer_interface = match.group(1)
        links = self._softether_links(domain.table_id)
        names = self._softether_names(domain.name)

        # Remove a prior container generation's deterministic namespace/rules
        # before publishing replacements. The host main/default route is never
        # changed; only two owned veth pairs and exact firewall entries exist.
        self._cleanup_softether(domain)
        vpnclient_source, vpncmd_source, busybox = self._softether_binaries()
        vpnclient, vpncmd = self._copy_softether_client_runtime(
            domain, vpnclient_source, vpncmd_source)
        facts = Path(domain.runtime_dir) / "softether-resources.json"
        self._atomic_text(facts, json.dumps({
            "namespace": domain.namespace,
            "control_interface": domain.control_interface,
            "data_interface": domain.interface,
            "outer_interface": domain.outer_interface,
            "control_subnet": links["control_subnet"],
            "data_subnet": links["data_subnet"],
        }, sort_keys=True) + "\n")

        self._run("ip", "netns", "add", domain.namespace)
        self._run(
            "ip", "link", "add", "dev", domain.control_interface,
            "type", "veth", "peer", "name", "ctl0", "netns", domain.namespace)
        self._run(
            "ip", "link", "add", "dev", domain.interface,
            "type", "veth", "peer", "name", "data0", "netns", domain.namespace)
        self._run("ip", "address", "add", f"{links['control_root']}/30",
                  "dev", domain.control_interface)
        self._run("ip", "address", "add", f"{links['data_root']}/30",
                  "dev", domain.interface)
        self._run("ip", "link", "set", "dev", domain.control_interface, "up")
        self._run("ip", "link", "set", "dev", domain.interface, "up")
        for peer, address in (("ctl0", links["control_peer"]),
                              ("data0", links["data_peer"])):
            self._run("ip", "-n", domain.namespace, "address", "add",
                      f"{address}/30", "dev", peer)
            self._run("ip", "-n", domain.namespace, "link", "set", "dev", peer, "up")
        self._run("ip", "-n", domain.namespace, "link", "set", "dev", "lo", "up")
        self._run("ip", "-n", domain.namespace, "route", "replace", "default",
                  "via", links["control_root"], "dev", "ctl0")
        self._softether_namespace_sysctls(domain)
        self._softether_root_firewall(domain, links, enabled=True)

        self._run(
            "ip", "netns", "exec", domain.namespace,
            vpnclient, "start", timeout=60)
        # The real stable client management listener is namespace-local 9930.
        for _ in range(60):
            probe = self._run(
                "ip", "netns", "exec", domain.namespace,
                "ss", "-lnt", check=False)
            if ":9930 " in (probe.stdout or ""):
                break
            self._sleep(0.25)
        else:
            raise CoreError("SoftEther vpnclient management listener did not start")

        nic = names["nic"]
        account = domain.client_account
        commands = [
            f"NicCreate {nic}",
            (f"AccountCreate {account} /SERVER:{endpoint}:{port} /HUB:{hub} "
             f"/USERNAME:{username} /NICNAME:{nic}"),
            f"AccountPasswordSet {account} /PASSWORD:{password} /TYPE:standard",
        ]
        certificate = str(settings.get("server_cert") or "").strip()
        verify_certificate = bool(settings.get("verify_server_certificate"))
        if verify_certificate and not certificate:
            raise CoreError(
                "SoftEther server certificate verification requires server_cert PEM")
        if certificate:
            cert_path = Path(domain.runtime_dir) / "server-cert.cer"
            self._atomic_text(cert_path, certificate + "\n")
            commands.extend((
                f"AccountServerCertSet {account} /LOADCERT:{cert_path}",
                f"AccountServerCertEnable {account}",
            ))
        commands.extend((f"AccountStartupSet {account}", f"AccountConnect {account}"))
        self._softether_command(
            domain, vpncmd, commands, secrets=[password])

        timeout = int(settings.get("dhcp_timeout") or 45)
        deadline = time.monotonic() + timeout
        status: dict[str, int | str | bool] = {}
        while time.monotonic() < deadline:
            status = self._softether_status(domain)
            adapter = self._run(
                "ip", "-n", domain.namespace, "link", "show", "dev",
                domain.client_adapter, check=False)
            if status.get("connected") and adapter.returncode == 0:
                break
            self._sleep(0.5)
        else:
            raise CoreError(
                f"SoftEther account did not connect: {status.get('state', 'unknown')}")

        mtu = int(settings.get("mtu") or 1500)
        self._run("ip", "-n", domain.namespace, "link", "set", "dev",
                  domain.client_adapter, "mtu", str(mtu), "up")
        # Pin the native control session before DHCP is allowed to install the
        # data-plane default.  The same lease hook can then safely restore that
        # default after every vpnclient reconnect or service restart.
        self._run("ip", "-n", domain.namespace, "route", "replace",
                  f"{endpoint}/32", "via", links["control_root"], "dev", "ctl0")
        lease = Path(domain.runtime_dir) / "lease"
        lease.mkdir(mode=0o700, exist_ok=True)
        address_file, gateway_file = lease / "address", lease / "gateway"
        address_file.unlink(missing_ok=True)
        gateway_file.unlink(missing_ok=True)
        ip_binary = shutil.which("ip") or "/usr/sbin/ip"
        script = lease / "udhcpc.sh"
        self._atomic_text(script, f'''#!/bin/sh
set -eu
case "$1" in
  bound|renew)
    prefix=$(python3 -c 'import ipaddress,os; print(ipaddress.IPv4Network("0.0.0.0/"+os.environ["subnet"]).prefixlen)')
    gateway="${{router%% *}}"
    {shlex.quote(ip_binary)} addr flush dev "$interface"
    {shlex.quote(ip_binary)} addr add "$ip/$prefix" dev "$interface"
    {shlex.quote(ip_binary)} link set "$interface" up
    {shlex.quote(ip_binary)} route replace default via "$gateway" dev "$interface"
    printf '%s\\n' "$ip" > {shlex.quote(str(address_file))}
    printf '%s\\n' "$gateway" > {shlex.quote(str(gateway_file))}
  ;;
esac
''', mode=0o700)
        # vpnclient keeps its Virtual NIC object across a service/account
        # reconnect, but Stable may flush the NIC's IPv4 lease while doing so.
        # A one-shot DHCP child would then stay alive with stale lease state and
        # the domain would report an authenticated session that cannot carry a
        # packet.  Own a tiny namespace-local supervisor with the domain: after
        # an address has existed, its disappearance replaces udhcpc with a fresh
        # discover cycle; an exited child is likewise restarted.  The wrapper
        # and child share a process group, so exact domain cleanup terminates
        # both without a host-global service or watchdog.
        watchdog = lease / "dhcp-watch.sh"
        self._atomic_text(watchdog, f'''#!/bin/sh
set -u
child=""
had_address=0
start_client() {{
  {shlex.quote(busybox)} udhcpc -f -n -i {shlex.quote(domain.client_adapter)} -T 2 -t 20 -s {shlex.quote(str(script))} &
  child=$!
}}
stop_client() {{
  if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
}}
cleanup() {{
  stop_client
  exit 0
}}
trap cleanup TERM INT HUP
start_client
while :; do
  if ! kill -0 "$child" 2>/dev/null; then
    wait "$child" 2>/dev/null || true
    start_client
    had_address=0
  fi
  if {shlex.quote(ip_binary)} -4 -o addr show dev {shlex.quote(domain.client_adapter)} 2>/dev/null | grep -q ' inet '; then
    had_address=1
  elif [ "$had_address" -eq 1 ]; then
    stop_client
    start_client
    had_address=0
  fi
  sleep 1
done
''', mode=0o700)
        log = open(Path(domain.runtime_dir) / "dhcp.log", "a", encoding="utf-8")  # noqa: SIM115
        domain.process = self._runner.popen([
            "ip", "netns", "exec", domain.namespace, str(watchdog),
        ], stdout=log)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if address_file.is_file() and gateway_file.is_file():
                break
            if domain.process.poll() is not None:
                raise CoreError("SoftEther Virtual NIC DHCP client exited before a lease")
            self._sleep(0.25)
        else:
            raise CoreError("SoftEther Virtual NIC obtained no DHCP lease")
        address = address_file.read_text().strip()
        gateway = gateway_file.read_text().strip()
        ipaddress.ip_address(address)
        ipaddress.ip_address(gateway)
        domain.client_address = address
        domain.client_gateway = gateway
        domain.tunnel_interface = domain.client_adapter

        # Preserve the outer native session when the namespace default becomes
        # the tunnel, then turn data0 into a private routed/NAT gateway.
        self._run("ip", "-n", domain.namespace, "route", "replace",
                  f"{endpoint}/32", "via", links["control_root"], "dev", "ctl0")
        self._run("ip", "-n", domain.namespace, "route", "replace", "default",
                  "via", gateway, "dev", domain.client_adapter)
        forwarding = self._run(
            "ip", "netns", "exec", domain.namespace,
            "cat", "/proc/sys/net/ipv4/ip_forward", check=False)
        if forwarding.returncode or forwarding.stdout.strip() != "1":
            raise CoreError(
                "SoftEther namespace inherited ip_forward=0; enable host "
                "net.ipv4.ip_forward before deploying client outbounds")
        self._run("ip", "netns", "exec", domain.namespace,
                  "iptables", "-A", "FORWARD", "-i", "data0", "-o",
                  domain.client_adapter, "-j", "ACCEPT")
        self._run("ip", "netns", "exec", domain.namespace,
                  "iptables", "-A", "FORWARD", "-o", "data0", "-i",
                  domain.client_adapter, "-m", "conntrack", "--ctstate",
                  "ESTABLISHED,RELATED", "-j", "ACCEPT")
        self._run("ip", "netns", "exec", domain.namespace,
                  "iptables", "-t", "nat", "-A", "POSTROUTING",
                  "-o", domain.client_adapter, "-j", "MASQUERADE")

    def _render_openvpn_profile(self, outbound: Outbound, runtime: Path) -> str:
        settings = outbound.settings
        content = str(settings.get("ovpn_content") or "").lstrip("\ufeff").strip()
        if not content:
            server = str(settings.get("server") or "").strip()
            port = int(settings.get("server_port") or 1194)
            proto = str(settings.get("proto") or "udp")
            if not server:
                raise CoreError(f"OpenVPN outbound '{outbound.name}' has no remote server")
            lines = ["client", "nobind", f"proto {proto}", f"remote {server} {port}",
                     "remote-cert-tls server", "verb 3"]
            for key, tag in (("ca_pem", "ca"), ("cert_pem", "cert"), ("key_pem", "key")):
                value = str(settings.get(key) or "").strip()
                if value:
                    lines.extend((f"<{tag}>", value, f"</{tag}>"))
            content = "\n".join(lines)

        output: list[str] = []
        inline: str | None = None
        saw_remote = False
        for raw in content.splitlines():
            stripped = raw.strip()
            if inline is not None:
                output.append(raw)
                if stripped.lower() == f"</{inline}>":
                    inline = None
                continue
            match = re.fullmatch(r"<([A-Za-z0-9_-]+)>", stripped)
            if match:
                inline = match.group(1).lower()
                output.append(raw)
                continue
            if not stripped or stripped.startswith(("#", ";")):
                output.append(raw)
                continue
            try:
                parts = shlex.split(stripped)
            except ValueError as exc:
                raise CoreError(f"OpenVPN outbound '{outbound.name}' has invalid syntax") from exc
            key = parts[0].lower()
            if key in _OVPN_FORBIDDEN:
                raise CoreError(
                    f"OpenVPN outbound '{outbound.name}' contains forbidden directive '{key}'")
            if key in _OVPN_OVERRIDDEN:
                continue
            if key in {"ca", "cert", "key", "tls-auth", "tls-crypt", "pkcs12"}:
                raise CoreError(
                    f"OpenVPN outbound '{outbound.name}' must inline <{key}> material; external paths are refused")
            if key == "remote":
                saw_remote = True
            output.append(raw)
        if inline is not None:
            raise CoreError(f"OpenVPN outbound '{outbound.name}' has an unclosed <{inline}> block")
        if not saw_remote:
            raise CoreError(f"OpenVPN outbound '{outbound.name}' has no remote directive")

        username = str(settings.get("username") or "")
        password = str(settings.get("password") or "")
        if username or password:
            if not username or not password or "\n" in username or "\n" in password:
                raise CoreError(f"OpenVPN outbound '{outbound.name}' has invalid auth-user-pass credentials")
            auth = runtime / "auth.txt"
            self._atomic_text(auth, f"{username}\n{password}\n")
            output.append(f"auth-user-pass {auth}")
        elif any(line.strip().lower() == "auth-user-pass" for line in content.splitlines()):
            raise CoreError(
                f"OpenVPN outbound '{outbound.name}' needs username/password for auth-user-pass")
        output.extend((
            "route-noexec",
            'pull-filter ignore "redirect-gateway"',
            'pull-filter ignore "route"',
            "script-security 1",
            "persist-key",
            "persist-tun",
        ))
        return "\n".join(output) + "\n"

    def _start_openvpn(self, domain: PolicyDomain, outbound: Outbound) -> None:
        executable = shutil.which("openvpn")
        if not executable:
            raise CoreError("OpenVPN outbound runtime needs the openvpn client binary")
        runtime = Path(domain.runtime_dir)
        config = runtime / "client.ovpn"
        self._atomic_text(config, self._render_openvpn_profile(outbound, runtime))
        log = open(runtime / "client.log", "a", encoding="utf-8")  # noqa: SIM115
        argv = [executable, "--config", str(config),
                "--dev", domain.interface, "--dev-type", "tun"]
        domain.process = self._runner.popen(argv, stdout=log)

    def _start_wireguard(self, domain: PolicyDomain, outbound: Outbound) -> None:
        if not shutil.which("wg"):
            raise CoreError("WireGuard outbound runtime needs wireguard-tools")
        s = outbound.settings
        required = ("private_key", "peer_public_key", "server", "server_port", "local_address")
        missing = [key for key in required if not s.get(key)]
        if missing:
            raise CoreError(
                f"WireGuard outbound '{outbound.name}' missing {', '.join(missing)}")
        endpoint_host = str(s["server"])
        endpoint = (f"[{endpoint_host}]:{int(s['server_port'])}"
                    if ":" in endpoint_host and not endpoint_host.startswith("[")
                    else f"{endpoint_host}:{int(s['server_port'])}")
        lines = [
            "[Interface]", f"PrivateKey = {s['private_key']}",
            f"FwMark = {domain.bypass_mark}", "", "[Peer]",
            f"PublicKey = {s['peer_public_key']}",
        ]
        if s.get("preshared_key"):
            lines.append(f"PresharedKey = {s['preshared_key']}")
        allowed = s.get("allowed_ips") or ["0.0.0.0/0", "::/0"]
        if isinstance(allowed, str):
            allowed = [item.strip() for item in allowed.split(",") if item.strip()]
        lines.extend((
            f"AllowedIPs = {', '.join(allowed)}",
            f"Endpoint = {endpoint}",
            f"PersistentKeepalive = {int(s.get('keepalive') or 25)}",
        ))
        runtime = Path(domain.runtime_dir)
        config = runtime / "wg.conf"
        self._atomic_text(config, "\n".join(lines) + "\n")
        self._run("ip", "link", "del", "dev", domain.interface, check=False)
        self._run("ip", "link", "add", "dev", domain.interface,
                  "type", "wireguard")
        self._run("wg", "setconf", domain.interface, str(config))
        addresses = s["local_address"]
        if isinstance(addresses, str):
            addresses = [item.strip() for item in addresses.split(",") if item.strip()]
        for address in addresses:
            ipaddress.ip_interface(str(address))
            self._run("ip", "address", "add", str(address),
                      "dev", domain.interface)
        mtu = int(s.get("mtu") or 1420)
        self._run("ip", "link", "set", "mtu", str(mtu), "up",
                  "dev", domain.interface)

    def _singbox_binary(self) -> str:
        try:
            driver = self._cores.get("sing-box")
            backend = getattr(driver, "_backend", None)
            candidate = str(getattr(backend, "executable", "") or
                            driver.settings.get("executable_path") or "")
            if candidate and os.path.isfile(candidate):
                return candidate
        except Exception:  # noqa: BLE001
            pass
        candidate = shutil.which("sing-box")
        if not candidate:
            raise CoreError("proxy policy domains need an installed sing-box binary")
        return candidate

    def _start_ssh(self, domain: PolicyDomain, outbound: Outbound) -> None:
        """Start a real OpenSSH dynamic-forward TCP application proxy.

        Credentials live only in the private runtime directory. Passwords are
        supplied through SSH_ASKPASS (never argv or process environment), keys
        are mode 0600, and a provided public host key is pinned. Otherwise a
        private accept-new TOFU store rejects later key changes.
        """
        binary = shutil.which("ssh")
        env_binary = shutil.which("env")
        if not binary or not env_binary:
            raise CoreError("SSH outbound requires the OpenSSH client")
        settings = outbound.settings
        server = str(settings.get("server") or "").strip()
        username = str(settings.get("username") or "").strip()
        try:
            port = int(settings.get("server_port") or 22)
        except (TypeError, ValueError) as exc:
            raise CoreError(f"SSH outbound '{outbound.name}' has an invalid server port") from exc
        if not server or not username or not (1 <= port <= 65535):
            raise CoreError(
                f"SSH outbound '{outbound.name}' requires server, server_port and username")
        password = str(settings.get("password") or "")
        private_key = str(settings.get("private_key") or "").strip()
        if not password and not private_key:
            raise CoreError(
                f"SSH outbound '{outbound.name}' requires a password or private key")
        if "\n" in password:
            raise CoreError(f"SSH outbound '{outbound.name}' has an invalid password")

        runtime = Path(domain.runtime_dir)
        known_hosts = runtime / "known_hosts"
        known_hosts.touch(mode=0o600, exist_ok=True)
        os.chmod(known_hosts, 0o600)
        host_key = str(settings.get("host_key") or "").strip()
        strict = "accept-new"
        if host_key:
            key_type = host_key.split(None, 1)[0]
            if not (key_type.startswith("ssh-") or key_type.startswith("ecdsa-")
                    or key_type.startswith("sk-")):
                raise CoreError(
                    f"SSH outbound '{outbound.name}' host_key must be a public host key, not a fingerprint")
            host_label = server if port == 22 else f"[{server}]:{port}"
            self._atomic_text(known_hosts, f"{host_label} {host_key}\n")
            strict = "yes"

        askpass = runtime / "askpass.sh"
        password_file = runtime / "password"
        if password:
            self._atomic_text(password_file, password + "\n")
            self._atomic_text(
                askpass,
                "#!/bin/sh\nexec cat " + shlex.quote(str(password_file)) + "\n",
                mode=0o700,
            )
        else:
            self._atomic_text(askpass, "#!/bin/sh\nexit 1\n", mode=0o700)

        argv = [
            env_binary,
            "DISPLAY=zagros:0",
            "SSH_ASKPASS_REQUIRE=force",
            f"SSH_ASKPASS={askpass}",
            binary,
            "-F", "/dev/null",
            "-N", "-T", "-D", f"127.0.0.1:{domain.proxy_port}",
            "-p", str(port), "-l", username,
            "-o", "ExitOnForwardFailure=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "IdentityAgent=none",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "ServerAliveInterval=20",
            "-o", "ServerAliveCountMax=3",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", f"StrictHostKeyChecking={strict}",
        ]
        if private_key:
            key_path = runtime / "identity"
            self._atomic_text(key_path, private_key.rstrip() + "\n")
            argv.extend(("-o", "IdentitiesOnly=yes", "-i", str(key_path)))
        if not password:
            argv.extend(("-o", "BatchMode=yes"))
        argv.extend(("--", server))
        log = open(runtime / "client.log", "a", encoding="utf-8")  # noqa: SIM115
        domain.process = self._runner.popen(argv, stdout=log)

    def _start_ssh_packet_adapter(self, domain: PolicyDomain) -> None:
        """Expose one SSH dynamic forward as a scoped TCP policy TUN.

        The OpenSSH process remains the authenticated target transport. A
        per-domain sing-box adapter owns only this TUN and redirect listener;
        nft/source classifiers decide which TCP flows enter it. There is no
        global transparent proxy and UDP is intentionally not advertised.
        """
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._runner.tcp_ready("127.0.0.1", domain.proxy_port):
                break
            if domain.process is not None and domain.process.poll() is not None:
                raise CoreError(f"outbound '{domain.name}' SSH process exited")
            self._sleep(0.2)
        else:
            raise CoreError(
                f"outbound '{domain.name}' SSH SOCKS listener did not start")

        binary = self._singbox_binary()
        digest = int(self._hash(domain.name)[:6], 16)
        third = 16 + ((digest >> 8) % 200)
        fourth = (digest & 0x3F) & ~0x03
        address = f"172.31.{third}.{fourth + 1}/30"
        config = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "tun", "tag": "ssh-policy-in",
                    "interface_name": domain.interface,
                    "address": [address], "mtu": 1400,
                    "auto_route": False, "strict_route": False,
                    "stack": "gvisor",
                },
                {
                    "type": "redirect", "tag": "ssh-policy-redirect",
                    "listen": "127.0.0.1",
                    "listen_port": domain.redirect_port,
                },
            ],
            "outbounds": [{
                "type": "socks", "tag": "ssh-policy-egress",
                "server": "127.0.0.1", "server_port": domain.proxy_port,
                "version": "5",
            }],
            "route": {"final": "ssh-policy-egress"},
        }
        runtime = Path(domain.runtime_dir)
        path = runtime / "ssh-tun-adapter.json"
        self._atomic_text(path, json.dumps(config, indent=2) + "\n")
        self._run(binary, "check", "-c", str(path), timeout=30)
        adapter_log = open(
            runtime / "ssh-tun-adapter.log", "a", encoding="utf-8")  # noqa: SIM115
        domain.gateway_process = self._runner.popen(
            [binary, "run", "-c", str(path)], stdout=adapter_log)
        domain.tunnel_interface = domain.interface

    def _start_gateway(self, domain: PolicyDomain) -> None:
        binary = self._singbox_binary()
        direct: dict[str, Any] = {"type": "direct", "tag": "policy-egress"}
        if domain.vrf_interface:
            direct["bind_interface"] = domain.vrf_interface
        config = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "mixed", "tag": "policy-socks",
                    "listen": "127.0.0.1", "listen_port": domain.proxy_port,
                },
                {
                    "type": "redirect", "tag": "policy-redirect",
                    "listen": "127.0.0.1", "listen_port": domain.redirect_port,
                },
            ],
            "outbounds": [direct],
            "route": {"final": "policy-egress"},
        }
        runtime = Path(domain.runtime_dir)
        path = runtime / "gateway.json"
        self._atomic_text(path, json.dumps(config, indent=2) + "\n")
        self._run(binary, "check", "-c", str(path), timeout=30)
        log = open(runtime / "gateway.log", "a", encoding="utf-8")  # noqa: SIM115
        domain.gateway_process = self._runner.popen(
            [binary, "run", "-c", str(path)], stdout=log)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._runner.tcp_ready("127.0.0.1", domain.proxy_port):
                return
            if domain.gateway_process.poll() is not None:
                break
            self._sleep(0.2)
        raise CoreError(
            f"outbound '{domain.name}' SOCKS gateway did not listen on {domain.proxy_port}")

    def _singbox_outbound(self, outbound: Outbound) -> dict[str, Any]:
        try:
            driver = self._cores.get("sing-box")
            native, gap = driver._outbound_to_native(outbound)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            raise CoreError(f"cannot translate outbound '{outbound.name}' for policy TUN: {exc}") from exc
        if gap is not None or native is None:
            reason = gap.reason if gap is not None else "not representable"
            raise CoreError(f"outbound '{outbound.name}' cannot back a policy TUN: {reason}")
        return native

    def _xray_binary(self) -> str:
        try:
            driver = self._cores.get("xray")
            backend = getattr(driver, "_backend", None)
            getter = getattr(backend, "executable_path", None)
            candidate = str(getter() if callable(getter) else "")
            if candidate and os.path.isfile(candidate):
                return candidate
        except Exception:  # noqa: BLE001
            pass
        candidate = shutil.which("xray")
        if not candidate:
            raise CoreError("Xray policy domains need an installed xray binary")
        return candidate

    def _xray_outbound(self, outbound: Outbound) -> dict[str, Any]:
        try:
            driver = self._cores.get("xray")
            native, gap = driver._outbound_to_native(outbound)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            raise CoreError(
                f"cannot translate outbound '{outbound.name}' for Xray policy runtime: {exc}") from exc
        if gap is not None or native is None:
            reason = gap.reason if gap is not None else "not representable"
            raise CoreError(
                f"outbound '{outbound.name}' cannot run through Xray: {reason}")
        return native

    def _start_xray_proxy(self, domain: PolicyDomain, outbound: Outbound) -> None:
        """Run the selected upstream in Xray behind a private TUN adapter."""
        xray = self._xray_binary()
        singbox = self._singbox_binary()
        native = self._xray_outbound(outbound)
        runtime = Path(domain.runtime_dir)
        xray_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "policy-socks", "listen": "127.0.0.1",
                "port": domain.proxy_port, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }],
            "outbounds": [native, {"protocol": "freedom", "tag": "policy-direct"}],
        }
        xray_path = runtime / "xray.json"
        self._atomic_text(xray_path, json.dumps(xray_config, indent=2) + "\n")
        self._run(xray, "run", "-test", "-c", str(xray_path), timeout=30)
        xray_log = open(runtime / "xray.log", "a", encoding="utf-8")  # noqa: SIM115
        domain.process = self._runner.popen(
            [xray, "run", "-c", str(xray_path)], stdout=xray_log)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._runner.tcp_ready("127.0.0.1", domain.proxy_port):
                break
            if domain.process.poll() is not None:
                raise CoreError(f"outbound '{domain.name}' Xray process exited")
            self._sleep(0.2)
        else:
            raise CoreError(
                f"outbound '{domain.name}' Xray SOCKS ingress did not listen")

        digest = int(self._hash(outbound.name)[:6], 16)
        third = 16 + ((digest >> 8) % 200)
        fourth = (digest & 0x3F) & ~0x03
        address = f"172.31.{third}.{fourth + 1}/30"
        adapter_config = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "tun", "tag": "policy-in",
                    "interface_name": domain.interface,
                    "address": [address], "mtu": 1400,
                    "auto_route": False, "strict_route": False, "stack": "gvisor",
                },
                {
                    "type": "redirect", "tag": "policy-redirect",
                    "listen": "127.0.0.1", "listen_port": domain.redirect_port,
                },
            ],
            "outbounds": [{
                "type": "socks", "tag": "xray-egress",
                "server": "127.0.0.1", "server_port": domain.proxy_port,
                "version": "5",
            }],
            "route": {"final": "xray-egress", "auto_detect_interface": True},
        }
        adapter_path = runtime / "xray-tun-adapter.json"
        self._atomic_text(adapter_path, json.dumps(adapter_config, indent=2) + "\n")
        self._run(singbox, "check", "-c", str(adapter_path), timeout=30)
        adapter_log = open(
            runtime / "xray-tun-adapter.log", "a", encoding="utf-8")  # noqa: SIM115
        domain.gateway_process = self._runner.popen(
            [singbox, "run", "-c", str(adapter_path)], stdout=adapter_log)

    def _start_proxy(self, domain: PolicyDomain, outbound: Outbound) -> None:
        binary = self._singbox_binary()
        native = self._singbox_outbound(outbound)
        # Stable RFC1918 /30; only the local TUN address is installed and no
        # main-table default is touched.
        digest = int(self._hash(outbound.name)[:6], 16)
        third = 16 + ((digest >> 8) % 200)
        fourth = (digest & 0x3F) & ~0x03
        address = f"172.31.{third}.{fourth + 1}/30"
        config = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "tun", "tag": "policy-in",
                    "interface_name": domain.interface,
                    "address": [address], "mtu": 1400,
                    "auto_route": False, "strict_route": False,
                    "stack": "gvisor",
                },
                {
                    "type": "mixed", "tag": "policy-socks",
                    "listen": "127.0.0.1", "listen_port": domain.proxy_port,
                },
                {
                    "type": "redirect", "tag": "policy-redirect",
                    "listen": "127.0.0.1", "listen_port": domain.redirect_port,
                },
            ],
            "outbounds": [native, {"type": "direct", "tag": "policy-direct"}],
            "route": {"final": outbound.name, "auto_detect_interface": True},
        }
        runtime = Path(domain.runtime_dir)
        path = runtime / "sing-box.json"
        self._atomic_text(path, json.dumps(config, indent=2) + "\n")
        self._run(binary, "check", "-c", str(path), timeout=30)
        log = open(runtime / "client.log", "a", encoding="utf-8")  # noqa: SIM115
        domain.process = self._runner.popen([binary, "run", "-c", str(path)], stdout=log)

    def _install_table(self, domain: PolicyDomain) -> None:
        priority = domain.table_id
        # Delete by priority until absent. iproute2 returns 2 when no rule
        # remains; this is expected and keeps the operation idempotent.
        for _ in range(4):
            result = self._run("ip", "rule", "del", "priority", str(priority), check=False)
            if result.returncode:
                break
        self._run(
            "ip", "rule", "add", "priority", str(priority),
            "fwmark", f"{domain.fwmark}/0xffffffff",
            "lookup", str(domain.table_id),
        )
        # Reverse packets carry a separate conntrack mark and must leave an
        # overlapping VRF through main (e.g. outbound and inbound both 10.9/24).
        for _ in range(4):
            result = self._run(
                "ip", "rule", "del", "priority", "800",
                "fwmark", f"{domain.return_mark}/0xffffffff",
                "lookup", "main", check=False)
            if result.returncode:
                break
        self._run(
            "ip", "rule", "add", "priority", "800",
            "fwmark", f"{domain.return_mark}/0xffffffff", "lookup", "main")
        # VRF installs an l3mdev rule at priority 1000. WireGuard outer UDP
        # carries bypass_mark and must hit main *before* l3mdev can recurse it
        # into the tunnel. Match-specific deletion never steals another WG.
        bypass_priority = 900
        if domain.mode == "wireguard":
            for _ in range(4):
                result = self._run(
                    "ip", "rule", "del", "priority", str(bypass_priority),
                    "fwmark", f"{domain.bypass_mark}/0xffffffff",
                    "lookup", "main", check=False)
                if result.returncode:
                    break
            self._run(
                "ip", "rule", "add", "priority", str(bypass_priority),
                "fwmark", f"{domain.bypass_mark}/0xffffffff", "lookup", "main")
        route_args = ["default"]
        if domain.route_gateway:
            route_args.extend(("via", domain.route_gateway))
        route_args.extend(("dev", domain.interface))
        self._run(
            "ip", "route", "replace", "table", str(domain.table_id),
            *route_args,
        )
        probe = self._run(
            "ip", "route", "get", "1.1.1.1", "mark", str(domain.fwmark),
            check=False,
        )
        if probe.returncode or f"dev {domain.interface}" not in probe.stdout:
            raise CoreError(
                f"policy table {domain.table_id} does not route mark {domain.fwmark} through {domain.interface}")

    def _stop_process(self, process: subprocess.Popen[str] | None) -> None:
        if process is None:
            return
        # The tracked leader may already have exited while a pty connection
        # manager (notably sstpc) remains in its process group.  Returning on
        # leader.poll() leaked that child and its callback socket, so the next
        # transactional attempt could connect its plugin to a stale process.
        # Every process is created with start_new_session=True; terminate that
        # exact owned group even when the leader has already been reaped.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=8)
        except Exception:  # noqa: BLE001
            pass
        # If the leader was already dead, wait() returns immediately while a
        # child can still be alive.  A final group probe/kill makes cleanup
        # synchronous and prevents callback-socket reuse races.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _stop_domain(self, domain: PolicyDomain) -> None:
        self._stop_process(domain.gateway_process)
        self._stop_process(domain.process)
        for process in domain.auxiliary_processes:
            self._stop_process(process)
        domain.auxiliary_processes.clear()
        if domain.mode == "softether":
            self._cleanup_softether(domain)
        elif domain.mode == "ppp":
            self._cleanup_ppp(domain)
        self._run("ip", "rule", "del", "priority", str(domain.table_id), check=False)
        self._run(
            "ip", "rule", "del", "priority", "800",
            "fwmark", f"{domain.return_mark}/0xffffffff",
            "lookup", "main", check=False)
        if domain.mode == "wireguard":
            self._run(
                "ip", "rule", "del", "priority", "900",
                "fwmark", f"{domain.bypass_mark}/0xffffffff",
                "lookup", "main", check=False)
        self._run("ip", "route", "flush", "table", str(domain.table_id), check=False)
        self._run("ip", "link", "del", "dev", domain.interface, check=False)
        if domain.vrf_interface:
            self._run("ip", "link", "del", "dev", domain.vrf_interface,
                      check=False)
        shutil.rmtree(domain.runtime_dir, ignore_errors=True)
        domain.ready = False

    # ------------------------------------------------------------------ #
    # source discovery / rule translation
    # ------------------------------------------------------------------ #
    def traffic_sources(self) -> list[TrafficSource]:
        sources: list[TrafficSource] = []
        for core_id in self._cores.list_cores():
            try:
                driver = self._cores.get(core_id)
            except Exception:  # noqa: BLE001
                continue
            if core_id == "openvpn":
                for row in driver._listeners():  # noqa: SLF001
                    try:
                        network = ipaddress.ip_network(
                            f"{row['subnet']}/{row.get('netmask') or '255.255.255.0'}",
                            strict=False,
                        )
                    except (KeyError, ValueError):
                        continue
                    sources.append(TrafficSource(
                        core_id=core_id, inbound_tag=str(row["tag"]),
                        source_subnet=str(network),
                    ))
            elif core_id == "wireguard":
                for row in driver._listeners():  # noqa: SLF001
                    try:
                        network = ipaddress.ip_network(str(row["subnet"]), strict=False)
                    except (KeyError, ValueError):
                        continue
                    if network.version == 4:
                        sources.append(TrafficSource(
                            core_id=core_id, inbound_tag=str(row["tag"]),
                            source_subnet=str(network),
                        ))
            elif core_id == "softether":
                spec_provider = getattr(driver, "routing_source_specs", None)
                active_provider = getattr(driver, "policy_sources", None)
                if callable(spec_provider):
                    specs = spec_provider()
                    active = {
                        str(item["id"]): item
                        for item in (active_provider() if callable(active_provider) else [])
                    }
                else:  # compatibility with a pre-isolated-hub test double
                    settings = getattr(driver, "settings", {})
                    tags = list((settings.get("feature_tags") or {}).values())
                    source = getattr(driver, "policy_source", lambda: None)()
                    specs = [{
                        "id": "primary", "hub": settings.get("hub", "DEFAULT"),
                        "tags": tags, "subnet": (source or {}).get("subnet"),
                        "legacy": True,
                    }]
                    active = {"primary": source} if source else {}
                for spec in specs:
                    policy_source = active.get(str(spec["id"]))
                    shared = len(spec.get("tags") or []) > 1
                    for tag in spec.get("tags") or []:
                        if policy_source:
                            sources.append(TrafficSource(
                                core_id=core_id, inbound_tag=str(tag),
                                source_subnet=str(policy_source["subnet"]),
                                note=(
                                    "SoftEther transports in this Virtual Hub share one routed subnet"
                                    if shared else
                                    "SoftEther inbound has a dedicated managed Virtual Hub/TAP identity"
                                ),
                            ))
                        else:
                            sources.append(TrafficSource(
                                core_id=core_id, inbound_tag=str(tag),
                                note=(
                                    "SoftEther SecureNAT hides client source addresses; routed TAP mode is required"
                                    if spec.get("legacy") else
                                    "SoftEther source is not routed yet; deploy a matching rule "
                                    "to materialize its managed TAP"
                                ),
                            ))
            elif core_id == "pptp":
                # Independent ACCEL-PPP inbound identity.  PPTP has one fixed
                # listener and one configured IPv4 pool, so the assigned client
                # subnet is an honest kernel classifier without conflating it
                # with SoftEther or an outbound PPTP session.
                for row in driver.settings.get("inbounds") or []:
                    if row.get("protocol") != "pptp":
                        continue
                    try:
                        network = ipaddress.ip_network(
                            str(row.get("subnet") or ""), strict=True)
                    except ValueError:
                        continue
                    if network.version == 4:
                        sources.append(TrafficSource(
                            core_id=core_id,
                            inbound_tag=str(row.get("tag") or "pptp"),
                            source_subnet=str(network),
                            note="independent ACCEL-PPP assigned-address pool",
                        ))
            elif core_id == "ssh":
                try:
                    uids = sorted({entry.pw_uid for entry in pwd.getpwall()
                                   if entry.pw_name.startswith("zg-")})
                except Exception:  # noqa: BLE001
                    uids = []
                listeners = driver.settings.get("listeners") or [
                    {"tag": "ssh"}
                ]
                for row in listeners:
                    tag = str(row.get("tag") or "ssh")
                    for uid in uids:
                        sources.append(TrafficSource(
                            core_id=core_id, inbound_tag=tag, uid=uid,
                        ))
        return sources

    @staticmethod
    def _service_unsupported(rule: RoutingRule) -> UnsupportedRule | None:
        m = rule.matcher
        unsupported = []
        for field in (
            "domains", "domain_suffixes", "domain_keywords", "domain_regexes",
            "geosites", "geoips", "process_names", "protocols",
        ):
            if getattr(m, field):
                unsupported.append(field)
        if unsupported:
            return UnsupportedRule(
                rule=rule.name, fields=unsupported,
                reason="kernel service routing cannot inspect domain/geo/process/sniffed protocol fields",
            )
        if rule.action not in (RuleAction.ROUTE_TO, RuleAction.ALLOW, RuleAction.BLOCK):
            return UnsupportedRule(
                rule=rule.name, fields=["action"],
                reason=f"kernel service routing does not implement action '{rule.action.value}'",
            )
        return None

    def validate_rule_set(self, rules: list[RoutingRule]) -> None:
        """Reject a transport-only selector on a shared Virtual Hub.

        Destination/protocol/priority overlap is representable in nftables and
        remains deterministic.  What is not representable is selecting only
        one of several transport labels that all terminate in the same hub/TAP.
        A managed isolated hub has one tag and therefore an honest source
        identity independent of the production hub.
        """
        try:
            driver = self._cores.get("softether")
        except Exception:  # noqa: BLE001
            return
        provider = getattr(driver, "routing_source_specs", None)
        if callable(provider):
            specs = provider()
        else:
            tags = sorted(set(str(value) for value in
                              (driver.settings.get("feature_tags") or {}).values()))
            specs = [{"hub": driver.settings.get("hub", "DEFAULT"), "tags": tags}]
        for spec in specs:
            tags = set(str(value) for value in spec.get("tags") or [])
            if len(tags) <= 1:
                continue
            for rule in rules:
                if not rule.enabled or not rule.matcher.inbounds:
                    continue
                selected = tags.intersection(rule.matcher.inbounds)
                if selected and selected != tags:
                    raise CoreError(
                        f"SoftEther hub '{spec.get('hub')}' shares one TAP/subnet for "
                        f"tags {sorted(tags)}; rule '{rule.name}' selects only "
                        f"{sorted(selected)}. Select every tag in that hub or create "
                        "a managed isolated Virtual Hub."
                    )

    def _converge_softether_source(self, rules: list[RoutingRule]) -> None:
        try:
            driver = self._cores.get("softether")
        except Exception:  # noqa: BLE001
            return
        provider = getattr(driver, "routing_source_specs", None)
        if callable(provider):
            specs = provider()
        else:
            tags = sorted(set(str(value) for value in
                              (driver.settings.get("feature_tags") or {}).values()))
            specs = [{"id": "primary", "tags": tags}]
        needed: set[str] = set()
        for spec in specs:
            tags = set(str(value) for value in spec.get("tags") or [])
            if any(
                rule.enabled
                and (not rule.matcher.inbounds
                     or bool(tags.intersection(rule.matcher.inbounds)))
                for rule in rules
            ):
                needed.add(str(spec["id"]))
        for source_id in sorted(needed - self._softether_routed):
            driver.ensure_policy_source(source_id)
            self._softether_routed.add(source_id)
        for source_id in sorted(self._softether_routed - needed):
            driver.disable_policy_source(source_id)
            self._softether_routed.discard(source_id)

    def preview_rules(self, rules: list[RoutingRule]) -> PolicyRuleReport:
        report = PolicyRuleReport()
        sources = self.traffic_sources()
        by_core: dict[str, list[TrafficSource]] = {}
        for source in sources:
            by_core.setdefault(source.core_id, []).append(source)
        for core_id, core_sources in by_core.items():
            tags = {source.inbound_tag for source in core_sources}
            for rule in rules:
                if rule.matcher.inbounds and not tags.intersection(rule.matcher.inbounds):
                    continue
                gap = self._service_unsupported(rule)
                selected = [s for s in core_sources
                            if not rule.matcher.inbounds or s.inbound_tag in rule.matcher.inbounds]
                unavailable = [s for s in selected if s.source_subnet is None and s.uid is None]
                if gap is None and unavailable:
                    gap = UnsupportedRule(
                        rule=rule.name, fields=["inbounds"],
                        reason=unavailable[0].note or "traffic source is not classifiable",
                    )
                if gap is None and rule.action is RuleAction.ROUTE_TO:
                    domain = self._domains.get(str(rule.outbound))
                    if domain is None or not domain.ready:
                        gap = UnsupportedRule(
                            rule=rule.name, fields=["outbound"],
                            reason=f"outbound '{rule.outbound}' has no running policy domain",
                        )
                if gap:
                    report.unsupported.setdefault(core_id, []).append(gap)
                else:
                    report.applied.setdefault(core_id, []).append(rule.name)
            if core_id == "softether":
                source_notes = list(dict.fromkeys(
                    source.note for source in core_sources if source.note))
                if source_notes:
                    report.notes.setdefault(core_id, []).extend(source_notes)
        return report

    @staticmethod
    def _nft_set(values: Iterable[str | int]) -> str:
        return "{ " + ", ".join(str(value) for value in values) + " }"

    def _nft_conditions(self, rule: RoutingRule, source: TrafficSource) -> list[str]:
        cond: list[str] = []
        if source.source_subnet:
            cond.append(f"ip saddr {source.source_subnet}")
        if source.uid is not None:
            cond.append(f"meta skuid {source.uid}")
        m = rule.matcher
        if m.source_ip_cidrs:
            networks = [str(ipaddress.ip_network(value, strict=False))
                        for value in m.source_ip_cidrs]
            cond.append(f"ip saddr {self._nft_set(networks)}")
        if m.ip_cidrs:
            networks = [str(ipaddress.ip_network(value, strict=False))
                        for value in m.ip_cidrs]
            cond.append(f"ip daddr {self._nft_set(networks)}")
        if m.networks:
            protocols = sorted({item for value in m.networks
                                for item in str(value).split(",")
                                if item in ("tcp", "udp")})
            if protocols:
                cond.append(f"meta l4proto {self._nft_set(protocols)}")
        return cond

    def _nft_action(self, rule: RoutingRule) -> str:
        if rule.action is RuleAction.ALLOW:
            return "return"
        if rule.action is RuleAction.BLOCK:
            return "drop"
        domain = self._domains[str(rule.outbound)]
        return (
            f"ct mark set {domain.return_mark} "
            f"meta mark set {domain.fwmark} return"
        )

    def _nft_script(self, rules: list[RoutingRule], report: PolicyRuleReport) -> str:
        sources = self.traffic_sources()
        supported_names = {name for values in report.applied.values() for name in values}
        prerouting: list[str] = []
        output: list[str] = []
        output_nat: list[str] = []
        for rule in rules:
            if rule.name not in supported_names:
                continue
            for source in sources:
                if rule.matcher.inbounds and source.inbound_tag not in rule.matcher.inbounds:
                    continue
                if source.source_subnet is None and source.uid is None:
                    continue
                conditions = self._nft_conditions(rule, source)
                if source.uid is not None and rule.action is RuleAction.ROUTE_TO:
                    domain = self._domains[str(rule.outbound)]
                    line = "    " + " ".join([
                        *conditions, "meta l4proto tcp", "counter",
                        f"redirect to :{domain.redirect_port}",
                    ])
                    target = output_nat
                else:
                    line = "    " + " ".join([
                        *conditions, "counter", self._nft_action(rule)])
                    target = output if source.uid is not None else prerouting
                if line not in target:
                    target.append(line)
        nat_lines: list[str] = []
        restore_lines: list[str] = []
        output_track: list[str] = []
        for domain in sorted(self._domains.values(), key=lambda item: item.table_id):
            restore_lines.append(
                f"    ct mark {domain.return_mark} counter meta mark set {domain.return_mark}")
            output_track.append(
                f"    meta mark {domain.fwmark} counter ct mark set {domain.return_mark}")
            if domain.mode in ("openvpn", "wireguard", "softether", "ppp"):
                nat_lines.append(
                    f'    meta mark {domain.fwmark} oifname "{domain.interface}" counter masquerade')
        body = [
            f"table inet {_POLICY_TABLE} {{",
            "  chain prerouting {",
            "    type filter hook prerouting priority mangle; policy accept;",
            *restore_lines,
            *prerouting,
            "  }",
            "  chain output {",
            "    type route hook output priority mangle; policy accept;",
            *output_track,
            *output,
            "  }",
            "  chain output_nat {",
            "    type nat hook output priority dstnat; policy accept;",
            *output_nat,
            "  }",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
            *nat_lines,
            "  }",
            "}",
        ]
        return "\n".join(body) + "\n"

    def apply_rules(self, rules: list[RoutingRule]) -> PolicyRuleReport:
        """Atomically replace classifiers and roll back hub source lifecycle.

        nft applies a script transactionally, but TAP/SecureNAT convergence is
        an external vpncmd transaction.  If rule rendering or nft replacement
        fails, restore exactly the previously active hub source ids instead of
        leaving a disposable hub bridged with no matching classifier.
        """
        with self._lock:
            self.validate_rule_set(rules)
            previous_sources = set(self._softether_routed)
            try:
                self._converge_softether_source(rules)
                report = self.preview_rules(rules)
                script = self._nft_script(rules, report)
                exists = self._run(
                    "nft", "list", "table", "inet", _POLICY_TABLE,
                    check=False,
                ).returncode == 0
                if exists:
                    script = f"delete table inet {_POLICY_TABLE}\n" + script
                self._run("nft", "-f", "-", input_text=script)
            except Exception:
                try:
                    driver = self._cores.get("softether")
                    for source_id in sorted(self._softether_routed - previous_sources):
                        driver.disable_policy_source(source_id)
                    for source_id in sorted(previous_sources - self._softether_routed):
                        driver.ensure_policy_source(source_id)
                    self._softether_routed = previous_sources
                except Exception:  # noqa: BLE001 - preserve deployment failure
                    logger.exception("SoftEther source rollback failed after routing error")
                raise
            self._rules = list(rules)
            return report

    def stop(self) -> None:
        with self._lock:
            self._run("nft", "delete", "table", "inet", _POLICY_TABLE, check=False)
            for source_id in sorted(self._softether_routed):
                try:
                    self._cores.get("softether").disable_policy_source(source_id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "SoftEther routed TAP cleanup failed for %s: %s",
                        source_id, exc)
            self._softether_routed.clear()
            for domain in list(self._domains.values()):
                self._stop_domain(domain)
            self._domains.clear()
            self._outbounds.clear()
            self._rules.clear()
