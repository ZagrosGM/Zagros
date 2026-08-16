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
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from app.cores.capabilities import outbound_capability
from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.model import RoutingRule, RuleAction, UnsupportedRule

logger = logging.getLogger("zagros.cores.routing.policy")

_POLICY_TABLE = "zagros_policy"
_RUNTIME_ROOT = "/var/lib/zagros/routing"
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
    runtime_dir: str = ""
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
        runner: CommandRunner | None = None,
        sleep: Callable[[float], None] = time.sleep,
        identity_provider: Callable[[list[str]], dict[str, tuple[int, int]]] | None = None,
    ) -> None:
        self._cores = core_manager
        self._root = Path(runtime_root)
        self._runner = runner or CommandRunner()
        self._sleep = sleep
        self._identity_provider = identity_provider
        self._domains: dict[str, PolicyDomain] = {}
        self._outbounds: dict[str, Outbound] = {}
        self._rules: list[RoutingRule] = []
        # Source ids, not one process-wide boolean: every isolated Virtual Hub
        # owns a different TAP/subnet and can be converged independently.
        self._softether_routed: set[str] = set()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # identities / introspection
    # ------------------------------------------------------------------ #
    @staticmethod
    def _hash(name: str) -> str:
        return hashlib.sha256(name.encode("utf-8")).hexdigest()

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
            "xray_proxy": "zgx", "ssh": "zgs",
        }[mode]
        return prefix + cls._hash(name)[:10]

    @classmethod
    def _vrf_for(cls, name: str) -> str:
        return "zgr" + cls._hash(name)[:10]

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

    def validate_plan(self, rules: list[RoutingRule],
                      outbounds: Iterable[Outbound],
                      core_ids: Iterable[str] | None = None) -> None:
        """Fail before mutation when a selected *service source* needs no TUN.

        Xray-only deployment of its native SSH outbound is valid. OpenVPN,
        WireGuard, SSH-inbound and SoftEther source traffic, however, reaches
        egress through the shared host policy plane and therefore requires a
        real TUN/kernel domain. This distinction preserves the application
        proxy while refusing the impossible IP-routing interpretation.
        """
        by_name = {outbound.name: outbound for outbound in outbounds}
        service_cores = {"openvpn", "wireguard", "softether", "ssh"}
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
            if rule.matcher.inbounds:
                needs_policy = any(
                    source.inbound_tag in rule.matcher.inbounds
                    for source in sources)
                # Keep pure preflight conservative even before an adapter is
                # installed when a matcher explicitly names a service family.
                if not needs_policy:
                    inferable = policy_targets if core_ids is not None else service_cores
                    needs_policy = any(
                        str(tag).split("-", 1)[0] in inferable
                        for tag in rule.matcher.inbounds)
            else:
                needs_policy = bool(policy_targets)
            capability = outbound_capability(outbound.kind)
            if needs_policy and not capability.tun:
                raise CoreError(
                    f"rule '{rule.name}' cannot use outbound '{outbound.name}' "
                    f"({outbound.kind.value}) as a policy TUN: "
                    f"{capability.reason or 'this outbound has no TUN dataplane'}. "
                    "Limit the rule to native-core TCP application routing or choose a real TUN egress."
                )
            if outbound.kind is OutboundKind.SSH and not needs_policy:
                networks = {str(item).lower() for item in rule.matcher.networks}
                if networks != {"tcp"}:
                    raise CoreError(
                        f"rule '{rule.name}' targets TCP-only SSH outbound '{outbound.name}'; "
                        "set the network matcher explicitly to tcp")

    @staticmethod
    def _fingerprint(outbound: Outbound) -> str:
        raw = json.dumps(
            outbound.model_dump(mode="json"), sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
        ).encode()
        return hashlib.sha256(raw).hexdigest()

    def domain_views(self) -> list[dict[str, Any]]:
        return [self._domains[name].public() for name in sorted(self._domains)]

    def decorate(self, outbound: Outbound) -> Outbound:
        """Return a deployment-only copy carrying live domain metadata."""
        domain = self._domains.get(outbound.name)
        if domain is None or not domain.ready:
            return outbound
        settings = copy.deepcopy(outbound.settings)
        settings["_policy_socks_port"] = domain.proxy_port
        # An SSH domain is a TCP application SOCKS proxy only.  Advertising a
        # mark/table/interface for it would falsely imply an IP dataplane.
        if domain.mode != "ssh":
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
            return self._runner.tcp_ready("127.0.0.1", domain.proxy_port)
        if not self._exists_interface(domain.interface):
            return False
        return (not domain.vrf_interface
                or self._exists_interface(domain.vrf_interface))

    def _wait_interface(self, domain: PolicyDomain, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._exists_interface(domain.interface):
                if domain.process is None or domain.process.poll() is None:
                    return
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
                isolated = mode in ("openvpn", "wireguard")
                interface = self._interface_for(outbound.name, mode)
                proxy_port = self._port_for(outbound.name, used_ports)
                used_ports.add(proxy_port)
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
                                 or previous.gateway_process.poll() is None)):
                        started[outbound.name] = previous
                        continue
                    if previous is not None:
                        self._stop_domain(previous)
                    self._start_domain(candidate, outbound)
                    if candidate.mode != "ssh":
                        self._install_table(candidate)
                    candidate.ready = True
                    candidate.detail = (
                        f"TCP application SOCKS → 127.0.0.1:{candidate.proxy_port}"
                        if candidate.mode == "ssh"
                        else f"fwmark {candidate.fwmark} → table {candidate.table_id} → {candidate.interface}"
                    )
                    started[outbound.name] = candidate
            except Exception:
                for name, domain in started.items():
                    if self._domains.get(name) is not domain:
                        self._stop_domain(domain)
                raise

            for name, old in list(self._domains.items()):
                if name not in wanted:
                    self._stop_domain(old)
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
            elif domain.mode == "xray_proxy":
                self._start_xray_proxy(domain, outbound)
            else:
                self._start_proxy(domain, outbound)
            if domain.mode != "ssh":
                self._wait_interface(domain)
                self._attach_vrf(domain)
            if domain.mode in ("openvpn", "wireguard"):
                self._start_gateway(domain)
            else:
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
            self._run("ip", "link", "del", "dev", domain.interface, check=False)
            if domain.vrf_interface:
                self._run("ip", "link", "del", "dev", domain.vrf_interface,
                          check=False)
            shutil.rmtree(domain.runtime_dir, ignore_errors=True)
            raise

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
        self._run(
            "ip", "route", "replace", "table", str(domain.table_id),
            "default", "dev", domain.interface,
        )
        probe = self._run(
            "ip", "route", "get", "1.1.1.1", "mark", str(domain.fwmark),
            check=False,
        )
        if probe.returncode or f"dev {domain.interface}" not in probe.stdout:
            raise CoreError(
                f"policy table {domain.table_id} does not route mark {domain.fwmark} through {domain.interface}")

    def _stop_process(self, process: subprocess.Popen[str] | None) -> None:
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=8)
        except Exception:  # noqa: BLE001
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _stop_domain(self, domain: PolicyDomain) -> None:
        self._stop_process(domain.gateway_process)
        self._stop_process(domain.process)
        if domain.mode == "ssh":
            shutil.rmtree(domain.runtime_dir, ignore_errors=True)
            domain.ready = False
            return
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
                    tags = list((driver.settings.get("feature_tags") or {}).values())
                    source = getattr(driver, "policy_source", lambda: None)()
                    specs = [{
                        "id": "primary", "hub": driver.settings.get("hub", "DEFAULT"),
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
            if domain.mode == "ssh":
                continue
            restore_lines.append(
                f"    ct mark {domain.return_mark} counter meta mark set {domain.return_mark}")
            output_track.append(
                f"    meta mark {domain.fwmark} counter ct mark set {domain.return_mark}")
            if domain.mode in ("openvpn", "wireguard"):
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
