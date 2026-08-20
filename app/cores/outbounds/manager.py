"""OutboundManager — central registry of outbounds + chain routing resolution.

Responsibilities:
  * registry + validation of named outbounds (later persisted via repository)
  * **chain resolution**: ``Outbound(kind=CORE)`` becomes a concrete upstream
    (socks/http/...) by asking the target core for a chain endpoint
    (``get_chain_endpoints`` / ``ensure_chain_listener``)
  * **cycle detection** on the core→core chain graph — a chain that would loop
    (xray → sing-box → xray) is rejected *before* touching any core
  * deployment fan-out with explicit per-core gap reports
"""
from __future__ import annotations

import logging
import socket
from typing import TYPE_CHECKING, Any

from app.cores.exceptions import CoreError, CoreNotFoundError
from app.cores.outbounds.model import (
    Outbound,
    OutboundDeploymentReport,
    OutboundKind,
    TranslatedOutbound,
    UnsupportedOutbound,
)
from app.cores.types import Capability

if TYPE_CHECKING:
    from app.cores.manager import CoreManager

logger = logging.getLogger("zagros.cores.outbounds")

#: chain endpoint protocol -> outbound kind the *source* core must understand.
#: Credential-bearing endpoints (wireguard/hysteria2/tuic/ssh) carry their
#: secrets in ``endpoint.metadata``, which is merged into the materialized
#: outbound settings so translators can build real native upstreams.
_ENDPOINT_KIND = {
    "socks": OutboundKind.SOCKS,
    "http": OutboundKind.HTTP,
    "vless": OutboundKind.VLESS,
    "vmess": OutboundKind.VMESS,
    "trojan": OutboundKind.TROJAN,
    "shadowsocks": OutboundKind.SHADOWSOCKS,
    "wireguard": OutboundKind.WIREGUARD,
    "hysteria2": OutboundKind.HYSTERIA2,
    "tuic": OutboundKind.TUIC,
    "ssh": OutboundKind.SSH,
}

#: endpoint metadata keys copied into materialized settings per protocol.
#: These names are the *contract* between chain-endpoint providers (drivers)
#: and source-core outbound translators (see docs §12.7 cross-core matrix).
_METADATA_KEYS = {
    "wireguard": (
        "private_key", "peer_public_key", "local_address", "allowed_ips",
        "reserved", "mtu",
    ),
    "hysteria2": ("password", "sni", "insecure", "alpn", "obfs"),
    "tuic": ("uuid", "password", "sni", "insecure", "alpn", "congestion_control"),
    "ssh": ("username", "password"),
}


class OutboundManager:
    def __init__(self, core_manager: "CoreManager", *, policy_router=None) -> None:
        self._cores = core_manager
        self._policy = policy_router
        self._outbounds: dict[str, Outbound] = {}
        self._last_report: "OutboundDeploymentReport | None" = None

    # ------------------------------------------------------------------ #
    # registry
    # ------------------------------------------------------------------ #
    def register(self, outbound: Outbound) -> Outbound:
        if outbound.name in self._outbounds:
            raise CoreError(f"Outbound '{outbound.name}' already exists.")
        self._validate_external(outbound)
        self._outbounds[outbound.name] = outbound
        return outbound

    def unregister(self, name: str) -> None:
        if name not in self._outbounds:
            raise CoreError(f"Outbound '{name}' does not exist.")
        del self._outbounds[name]

    def get(self, name: str) -> Outbound:
        try:
            return self._outbounds[name]
        except KeyError:
            raise CoreError(f"Outbound '{name}' does not exist.") from None

    def list(self) -> list[Outbound]:
        return [o for o in self._outbounds.values() if o.enabled]

    def _validate_external(self, outbound: Outbound) -> None:
        if outbound.kind is OutboundKind.CORE:
            core_id = outbound.settings["core_id"]
            try:
                self._cores.get(core_id)
            except CoreNotFoundError as exc:
                raise CoreError(
                    f"Outbound '{outbound.name}': chain target core '{core_id}' is not installed."
                ) from exc

    # ------------------------------------------------------------------ #
    # chain resolution (+ cycle guard)
    # ------------------------------------------------------------------ #
    async def materialize(
        self,
        outbound: Outbound,
        *,
        requester_core_id: str,
        chain_edges: dict[str, set[str]] | None = None,
    ) -> Outbound:
        """Resolve a CORE-kind outbound into a concrete upstream definition.

        ``chain_edges`` is the *shared* chain graph of the whole deployment
        plan; a newly resolved edge is recorded into it after the cycle check.
        """
        if outbound.kind is not OutboundKind.CORE:
            return outbound

        target_core = outbound.settings["core_id"]
        if target_core == requester_core_id:
            raise CoreError(
                f"Outbound '{outbound.name}': a core cannot chain into itself."
            )
        edges = chain_edges if chain_edges is not None else {}
        if self._reaches(edges, start=target_core, goal=requester_core_id):
            raise CoreError(
                f"Chain cycle detected: '{requester_core_id}' → '{target_core}' "
                f"would close a loop ({self._describe_path(edges, target_core, requester_core_id)})."
            )

        driver = self._cores.get(target_core)
        preferred = outbound.settings.get("protocol", "socks")
        endpoints = await driver.get_chain_endpoints()
        endpoint = next((e for e in endpoints if e.protocol == preferred), None)
        if endpoint is None:
            if not driver.supports(Capability.CHAIN_ROUTING):
                raise CoreError(
                    f"Core '{target_core}' cannot host chain endpoints "
                    f"(no CHAIN_ROUTING capability) — needed by outbound '{outbound.name}'."
                )
            endpoint = await driver.ensure_chain_listener(
                preferred, self._free_port()
            )
        kind = _ENDPOINT_KIND.get(endpoint.protocol)
        if kind is None:
            raise CoreError(
                f"Chain endpoint protocol '{endpoint.protocol}' on core "
                f"'{target_core}' cannot be expressed as an outbound."
            )
        edges.setdefault(requester_core_id, set()).add(target_core)
        settings: dict[str, Any] = {"server": endpoint.host, "server_port": endpoint.port}
        for key in _METADATA_KEYS.get(endpoint.protocol, ()):
            if key in endpoint.metadata:
                settings[key] = endpoint.metadata[key]
        return Outbound(name=outbound.name, kind=kind, settings=settings)

    async def materialize_for(
        self,
        core_id: str,
        outbounds: list[Outbound] | None = None,
        chain_edges: dict[str, set[str]] | None = None,
    ) -> dict[str, Outbound]:
        """Resolve every outbound as seen from one core (CORE refs expanded)."""
        edges = chain_edges if chain_edges is not None else {}
        resolved: dict[str, Outbound] = {}
        for outbound in outbounds if outbounds is not None else self.list():
            if (
                outbound.kind is OutboundKind.CORE
                and outbound.settings.get("core_id") == core_id
            ):
                continue  # a core never materializes a chain into *itself*
            resolved[outbound.name] = await self.materialize(
                outbound, requester_core_id=core_id, chain_edges=edges
            )
        return resolved

    @staticmethod
    def _reaches(edges: dict[str, set[str]], *, start: str, goal: str) -> bool:
        """DFS: does `start` already reach `goal` in the chain graph?"""
        stack, seen = [start], set()
        while stack:
            node = stack.pop()
            if node == goal:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(edges.get(node, ()))
        return False

    @staticmethod
    def _describe_path(edges: dict[str, set[str]], start: str, goal: str) -> str:
        return " → ".join([start, "...", goal])

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    # ------------------------------------------------------------------ #
    # deployment
    # ------------------------------------------------------------------ #
    async def deploy(
        self, *, core_ids: list[str] | None = None
    ) -> OutboundDeploymentReport:
        """Converge kernel domains, then push marked outbounds to native cores.

        A route must never reference a name that was merely saved in SQL.  The
        policy layer first proves every VPN/proxy domain has a live interface,
        fwmark and table. Xray/sing-box receive deployment-only marked-direct
        copies; service cores use the same domains through source classifiers.
        """
        import asyncio

        active = self.list()
        targets = core_ids if core_ids is not None else self._cores.list_cores()
        domains = {}
        policy_cores = {"xray", "sing-box", "openvpn", "wireguard", "softether", "ssh", "pptp"}
        if self._policy is not None and policy_cores.intersection(targets):
            domains = await asyncio.to_thread(self._policy.prepare, active)
        results: dict[str, TranslatedOutbound] = {}
        plan_edges: dict[str, set[str]] = {}
        for core_id in targets:
            try:
                driver = self._cores.get(core_id)
            except CoreNotFoundError:
                continue
            if not driver.supports(Capability.OUTBOUND_MANAGEMENT):
                applied: list[str] = []
                unsupported: list[UnsupportedOutbound] = []
                for outbound in active:
                    if outbound.kind in (
                        OutboundKind.DIRECT, OutboundKind.BLOCK,
                        OutboundKind.BLACKHOLE,
                    ) or outbound.name in domains:
                        applied.append(outbound.name)
                    else:
                        unsupported.append(UnsupportedOutbound(
                            name=outbound.name,
                            reason=(
                                f"Core '{core_id}' has no native outbound management "
                                "and no kernel policy domain could represent this profile."
                            ),
                        ))
                results[core_id] = TranslatedOutbound(
                    core_id=core_id, applied=applied, unsupported=unsupported,
                    notes=["service traffic uses the shared Linux policy-routing plane"],
                )
                continue
            resolved: list[Outbound] = []
            notes: list[str] = []
            for ob in active:
                if ob.kind is OutboundKind.CORE and ob.settings["core_id"] == core_id:
                    notes.append(
                        f"outbound '{ob.name}' chains INTO this core; not materialized locally."
                    )
                    continue
                materialized = await self.materialize(
                    ob, requester_core_id=core_id, chain_edges=plan_edges)
                if self._policy is not None:
                    materialized = self._policy.decorate(materialized)
                resolved.append(materialized)
            report = await driver.deploy_outbounds(resolved)
            report.notes.extend(notes)
            results[core_id] = report
        deployment = OutboundDeploymentReport(results=results)
        self._last_report = deployment
        return deployment

    @property
    def last_report(self) -> "OutboundDeploymentReport | None":
        """Most recent deployment report (dashboard/status surfaces)."""
        return self._last_report
