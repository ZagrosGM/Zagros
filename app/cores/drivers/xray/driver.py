"""XrayDriver — the original Zagros core, adapted to the multi-core contract.

Ownership split (Dependency Inversion):
  * this class holds the *policy*: inbound selection, XTLS-flow sanitization,
    suspend/update semantics, usage-delta computation, sealed payload shaping.
  * :class:`XrayBackend` holds the *mechanics*: process control, gRPC calls,
    node fan-out. Production wires ``LegacyXrayBackend``; tests wire fakes.

Until Phase 3 rewires configuration, process/config details still come from
the legacy singletons (env-based), exactly as Zagros works today.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from datetime import datetime, timezone
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind, TranslatedOutbound, UnsupportedOutbound
from app.cores.routing.model import (
    RouteContext,
    RoutingRule,
    RuleAction,
    TranslatedRoute,
    UnsupportedRule,
)
from app.cores.types import (
    Capability,
    ChainEndpoint,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    UsageRecord,
    UserAccount,
)

FLOW_NONE = ""  # XTLSFlows.NONE.value — XTLS only supports TCP/mKCP + tls/reality

_PROTOCOL_SETTINGS_KEYS: dict[str, set[str]] = {
    "vmess": {"id"},
    "vless": {"id", "flow"},
    "trojan": {"password", "flow"},
    "shadowsocks": {"password", "method"},
}
_PROTOCOLS = set(_PROTOCOL_SETTINGS_KEYS)


class XrayDriver(BaseCoreDriver):
    """Driver for Xray-core (VLESS / VMess / Trojan / Shadowsocks)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="xray",
        name="Xray-core",
        description=(
            "Original Zagros engine. Managed over the gRPC Handler/Stats API, "
            "with fan-out to panel-connected nodes (zagros-node)."
        ),
        protocols=sorted(_PROTOCOLS),
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.SERVICE_CONTROL,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
            Capability.MULTI_NODE,
            Capability.ROUTING,
            Capability.GEO_ROUTING,
            Capability.OUTBOUND_MANAGEMENT,
            Capability.CHAIN_ROUTING,
            Capability.UDP_SUPPORT,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string", "default": "/usr/bin/xray"},
                "assets_path": {"type": "string", "default": "/usr/share/xray"},
                "config_path": {"type": "string", "default": "xray_config.json"},
            },
        },
        default_settings={
            "executable_path": "/usr/bin/xray",
            "assets_path": "/usr/share/xray",
            "config_path": "xray_config.json",
        },
        homepage="https://github.com/XTLS/Xray-core",
        studio_inbounds_path="/inbounds",
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: "Any | None" = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.xray.backend import LegacyXrayBackend

            backend = LegacyXrayBackend(self.settings)
        self._backend = backend
        from app.cores.stats import DeltaTracker

        self._deltas = DeltaTracker()

    # ------------------------------------------------------------------ #
    # helpers / policy
    # ------------------------------------------------------------------ #
    @staticmethod
    def _ensure_supported(protocol: str) -> str:
        if protocol not in _PROTOCOLS:
            raise CoreError(
                f"Protocol '{protocol}' is not supported by the xray core "
                f"({', '.join(sorted(_PROTOCOLS))})."
            )
        return protocol

    def _clean_settings(self, account: UserAccount) -> dict[str, Any]:
        """Keep only the keys the xray account model understands."""
        keys = _PROTOCOL_SETTINGS_KEYS[account.protocol]
        cleaned = {k: v for k, v in account.settings.items() if k in keys}
        if account.protocol in ("vless", "trojan"):
            cleaned.setdefault("flow", FLOW_NONE)
        return cleaned

    @staticmethod
    def _apply_flow_policy(settings: dict[str, Any], inbound: Mapping[str, Any]) -> dict[str, Any]:
        """XTLS flow is only valid on TCP/mKCP with tls/reality (mirrors the
        rules previously hard-coded in app/xray/operations.py)."""
        adjusted = dict(settings)
        flow = adjusted.get("flow")
        if flow:
            network = inbound.get("network", "tcp")
            tls_level = inbound.get("tls", "none")
            if (
                network not in ("tcp", "kcp")
                or (network in ("tcp", "kcp") and tls_level not in ("tls", "reality"))
                or inbound.get("header_type", "") == "http"
            ):
                adjusted["flow"] = FLOW_NONE
        return adjusted

    async def _inbounds(self) -> Mapping[str, dict[str, Any]]:
        return await asyncio.to_thread(self._backend.inbounds)

    async def _target_inbounds(self, account: UserAccount) -> dict[str, dict[str, Any]]:
        excluded = set(account.settings.get("excluded_inbounds", []))
        inbounds = await self._inbounds()
        return {
            tag: info
            for tag, info in inbounds.items()
            if info.get("protocol") == account.protocol and tag not in excluded
        }

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    # lifecycle: install / update / uninstall (real SELF_INSTALL)
    # ------------------------------------------------------------------ #

    async def install(self) -> None:
        await asyncio.to_thread(_install_xray, self.settings)

    async def update(self, version: str | None = None) -> str:
        return await asyncio.to_thread(_install_xray, self.settings)

    async def uninstall(self, purge: bool = False) -> None:
        await asyncio.to_thread(_uninstall_xray, self.settings, purge)

    async def start(self) -> None:
        await asyncio.to_thread(self._backend.start)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def restart(self) -> None:
        await asyncio.to_thread(self._backend.restart)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        version: str | None = None
        metrics = None
        if running:
            try:
                version = await asyncio.to_thread(self._backend.version)
                metrics = await asyncio.to_thread(self._backend.metrics)
            except CoreError:
                version = None
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=HealthStatus.HEALTHY if running else HealthStatus.UNKNOWN,
            core_version=version,
            metrics=metrics,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        lines = await asyncio.to_thread(self._backend.logs, tail)
        for line in lines:
            yield line

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    async def create_account(self, account: UserAccount) -> None:
        protocol = self._ensure_supported(account.protocol)
        if not account.enabled:
            return  # suspended users must not exist on the core

        settings = self._clean_settings(account)
        targets = await self._target_inbounds(account)
        if not targets:
            raise CoreError(
                f"No active xray inbound matches protocol '{protocol}' "
                f"for account '{account.account_id}'."
            )
        for tag, info in targets.items():
            per_inbound = self._apply_flow_policy(settings, info)
            await asyncio.to_thread(
                self._backend.add_user, tag, protocol, account.account_id, per_inbound
            )

    async def update_account(self, account: UserAccount) -> None:
        # Legacy "alter" semantics: wipe from *every* inbound, then re-add to
        # the currently-desired ones (also handles protocol/inbound changes).
        await self.delete_account(account.account_id)
        await self.create_account(account)

    async def delete_account(self, account_id: str) -> None:
        inbounds = await self._inbounds()
        for tag in inbounds:
            await asyncio.to_thread(self._backend.remove_user, tag, account_id)

    async def suspend_account(self, account_id: str) -> None:
        # xray has no "disabled user" concept — removal *is* suspension.
        await self.delete_account(account_id)

    async def resume_account(self, account: UserAccount) -> None:
        await self.create_account(account)

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        """Converge the core to the desired set after downtime."""
        for account in accounts:
            await self.delete_account(account.account_id)
        for account in accounts:
            await self.create_account(account)

    # ------------------------------------------------------------------ #
    # statistics
    # ------------------------------------------------------------------ #
    async def get_usage(
        self,
        account_ids: list[str] | None = None,
        since: Any | None = None,
    ) -> list[UsageRecord]:
        """Delta report since the previous call (xray counters are cumulative
        since core start; the recorder job in Phase 4 will own baselining)."""
        stats = await asyncio.to_thread(self._backend.usage, False)
        records: list[UsageRecord] = []
        for stat in stats:
            if account_ids is not None and stat.email not in account_ids:
                continue
            delta_up, delta_down = self._deltas.observe(
                (stat.node_id, stat.email), stat.uplink, stat.downlink
            )
            records.append(
                UsageRecord(
                    core_id=self.metadata.id,
                    account_id=stat.email,
                    node_id=stat.node_id,
                    uplink_bytes=delta_up,
                    downlink_bytes=delta_down,
                )
            )
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        online = await asyncio.to_thread(self._backend.online_accounts)
        now = datetime.now(timezone.utc)
        return [
            DeviceSession(
                core_id=self.metadata.id,
                account_id=email,
                ip=None,  # xray stats API has no per-user IP table
                last_activity=now,
            )
            for email in online
            if account_ids is None or email in account_ids
        ]

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    def _compose_outbound(
        self,
        protocol: str,
        settings: dict[str, Any],
        tag: str,
        inbound: dict[str, Any],
        host: dict[str, Any],
    ) -> dict[str, Any]:
        """Build the sing-box-shaped outbound fragment for one (inbound, host).

        Pure/deterministic — shared by :meth:`build_client_config` (first
        target) and :meth:`describe_delivery` (every target × host).
        """
        settings = self._apply_flow_policy(settings, inbound)
        addresses = host.get("address") or []
        snis = host.get("sni") or inbound.get("sni") or []
        tls_level = host.get("tls") or inbound.get("tls", "none")

        outbound: dict[str, Any] = {
            "type": protocol,
            "tag": tag,
            "server": addresses[0] if addresses else None,
            "server_port": host.get("port") or inbound.get("port"),
        }
        if protocol in ("vless", "vmess"):
            outbound["uuid"] = str(settings["id"])
            if settings.get("flow"):
                outbound["flow"] = settings["flow"]
        elif protocol == "trojan":
            outbound["password"] = settings["password"]
            if settings.get("flow"):
                outbound["flow"] = settings["flow"]
        else:  # shadowsocks
            outbound["method"] = settings.get("method")
            outbound["password"] = settings["password"]

        if tls_level in ("tls", "reality"):
            outbound["tls"] = {
                "enabled": True,
                "server_name": snis[0] if snis else None,
                "alpn": [a for a in (host.get("alpn") or "").split(",") if a] or None,
                "utls": {
                    "enabled": bool(host.get("fingerprint")),
                    "fingerprint": host.get("fingerprint") or None,
                },
            }
            if tls_level == "reality":
                outbound["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": inbound.get("pbk"),
                    "short_id": (inbound.get("sids") or [None])[0],
                }
        else:
            outbound["tls"] = {"enabled": False}

        network = inbound.get("network", "tcp")
        transport: dict[str, Any] = {"type": network}
        if network == "ws":
            hostnames = host.get("host") or []
            transport.update(
                {"path": host.get("path") or "/", "headers": {"Host": hostnames[0]} if hostnames else {}}
            )
        outbound["transport"] = transport
        return outbound

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        protocol = self._ensure_supported(account.protocol)
        settings = self._clean_settings(account)
        targets = await self._target_inbounds(account)
        if not targets:
            raise CoreError(
                f"No xray inbound available for protocol '{protocol}'."
            )
        tag, inbound = next(iter(targets.items()))
        hosts = await asyncio.to_thread(self._backend.host_options, tag)
        host = hosts[0] if hosts else {}
        outbound = self._compose_outbound(protocol, settings, tag, inbound, host)

        return ClientConfig(
            core_id=self.metadata.id,
            protocol=protocol,
            engine="sing-box",
            payload={"outbounds": [outbound]},
            display_name=host.get("remark") or f"{protocol} · {tag}",
        )

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """One share link per (inbound × host) — the rich view of what
        :meth:`build_client_config` picks a single representative of."""
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryProfile,
            DeliverySection,
            ShareLinkError,
            share_url_for_outbound,
        )

        protocol = self._ensure_supported(account.protocol)
        settings = self._clean_settings(account)
        targets = await self._target_inbounds(account)
        section = DeliverySection(
            protocol=protocol,
            title=f"{self.metadata.name} · {protocol.upper()}",
            engine="sing-box",
        )
        if not targets:
            section.artifacts.append(DeliveryArtifact(
                kind=ArtifactKind.NOTE, label="Unavailable",
                note=f"No inbound is available for protocol '{protocol}' "
                     "on this core right now.",
            ))
            return DeliveryProfile(core_id=self.metadata.id, sections=[section])

        for tag, inbound in targets.items():
            hosts = await asyncio.to_thread(self._backend.host_options, tag) or [{}]
            for host in hosts:
                remark = host.get("remark") or f"{protocol} · {tag}"
                outbound = self._compose_outbound(
                    protocol, dict(settings), tag, inbound, host
                )
                try:
                    link = share_url_for_outbound(outbound, remark)
                except ShareLinkError as exc:
                    section.artifacts.append(DeliveryArtifact(
                        kind=ArtifactKind.NOTE, label=remark,
                        note=f"Share link unavailable: {exc}",
                    ))
                    continue
                section.artifacts.append(DeliveryArtifact(
                    kind=ArtifactKind.LINK, label=remark, content=link, qr=True,
                ))
        return DeliveryProfile(core_id=self.metadata.id, sections=[section])

    # ------------------------------------------------------------------ #
    # routing translation (ROUTING + GEO_ROUTING)
    # ------------------------------------------------------------------ #
    #: base outbounds the driver keeps alive for rule actions
    _BASE_OUTBOUNDS = {"direct": "mz-direct", "block": "mz-block", "dns": "mz-dns"}

    def _rule_to_native(
        self, rule: RoutingRule, ctx: RouteContext
    ) -> tuple[dict | None, UnsupportedRule | None]:
        m = rule.matcher
        native: dict[str, Any] = {"type": "field"}
        domains: list[str] = []
        domains += [f"full:{d}" for d in m.domains]
        domains += [f"domain:{d}" for d in m.domain_suffixes]
        domains += [f"keyword:{d}" for d in m.domain_keywords]
        domains += [f"regexp:{d}" for d in m.domain_regexes]
        domains += [f"geosite:{d}" for d in m.geosites]
        if domains:
            native["domain"] = domains
        ips = [f"geoip:{g}" for g in m.geoips] + m.ip_cidrs
        if ips:
            native["ip"] = ips
        if m.source_ip_cidrs:
            native["sourceIp"] = m.source_ip_cidrs
        port_spec = [str(p) for p in m.ports] + m.port_ranges
        if port_spec:
            native["port"] = ",".join(port_spec)
        if m.protocols:
            native["protocol"] = m.protocols
        if m.networks:
            native["network"] = ",".join(m.networks)
        if m.process_names:
            return None, UnsupportedRule(rule=rule.name, fields=["process_names"],
                                         reason="xray cannot match by process name.")

        action = rule.action
        if action is RuleAction.ALLOW:
            native["outboundTag"] = self._BASE_OUTBOUNDS["direct"]
        elif action is RuleAction.BLOCK:
            native["outboundTag"] = self._BASE_OUTBOUNDS["block"]
        elif action is RuleAction.DNS:
            native["outboundTag"] = self._BASE_OUTBOUNDS["dns"]
        elif action is RuleAction.ROUTE_TO:
            if rule.outbound not in ctx.available_outbounds:
                return None, UnsupportedRule(
                    rule=rule.name, fields=["outbound"],
                    reason=f"Outbound '{rule.outbound}' is not registered in the outbound manager.",
                )
            native["outboundTag"] = rule.outbound
        elif action is RuleAction.REDIRECT:
            return None, UnsupportedRule(rule=rule.name, fields=["action"],
                                         reason="xray rewrites destinations via dokodemo inbounds, not route rules.")
        elif action is RuleAction.FAKE_DNS:
            return None, UnsupportedRule(rule=rule.name, fields=["action"],
                                         reason="xray FakeDNS is an inbound-level feature, not a route action.")
        elif action is RuleAction.DNS_OVERRIDE:
            return None, UnsupportedRule(rule=rule.name, fields=["action"],
                                         reason="xray DNS overrides live in the dns module, not route rules.")
        return native, None

    async def deploy_routing_rules(
        self, rules: list[RoutingRule], ctx: RouteContext
    ) -> TranslatedRoute:
        native_rules: list[dict] = []
        applied: list[str] = []
        unsupported: list[UnsupportedRule] = []
        notes: list[str] = []
        for rule in rules:
            native, gap = self._rule_to_native(rule, ctx)
            if gap is not None:
                unsupported.append(gap)
            else:
                native_rules.append(native)
                applied.append(rule.name)

        if not self.settings.get("geo_files_configured", True):
            for rule in rules:
                if (rule.matcher.geosites or rule.matcher.geoips) and rule.name in applied:
                    notes.append(
                        f"Geo databases must exist under assets path for rule '{rule.name}' (geosite.dat/geoip.dat)."
                    )
                    break

        await asyncio.to_thread(self._backend.set_routing_rules, native_rules)
        await self._ensure_base_outbounds()
        payload = {"routing": {"rules": native_rules, "domainStrategy": "IPIfNonMatch"}}
        return TranslatedRoute(core_id=self.metadata.id, applied=applied,
                               unsupported=unsupported, notes=notes, payload=payload)

    # ------------------------------------------------------------------ #
    # outbound translation (OUTBOUND_MANAGEMENT)
    # ------------------------------------------------------------------ #
    def _outbound_to_native(self, ob: Outbound) -> tuple[dict | None, UnsupportedOutbound | None]:
        s = ob.settings
        kind, name = ob.kind, ob.name
        if kind is OutboundKind.DIRECT:
            return {"protocol": "freedom", "tag": name}, None
        if kind in (OutboundKind.BLOCK, OutboundKind.BLACKHOLE):
            settings = {"response": {"type": "http"}} if kind is OutboundKind.BLOCK else {}
            return {"protocol": "blackhole", "tag": name, "settings": settings}, None
        if kind is OutboundKind.DNS:
            return {"protocol": "dns", "tag": name}, None
        if kind is OutboundKind.SOCKS:
            server: dict[str, Any] = {"address": s["server"], "port": int(s["server_port"])}
            if s.get("username"):
                server["users"] = [{"user": s["username"], "pass": s.get("password", "")}]
            return {"protocol": "socks", "tag": name, "settings": {"servers": [server]}}, None
        if kind is OutboundKind.HTTP:
            server = {"address": s["server"], "port": int(s["server_port"])}
            if s.get("username"):
                server["users"] = [{"user": s["username"], "pass": s.get("password", "")}]
            return {"protocol": "http", "tag": name, "settings": {"servers": [server]}}, None
        if kind is OutboundKind.VLESS:
            user = {"id": str(s["uuid"]), "encryption": "none"}
            if s.get("flow"):
                user["flow"] = s["flow"]
            return {"protocol": "vless", "tag": name,
                    "settings": {"vnext": [{"address": s["server"], "port": int(s["server_port"]), "users": [user]}]}}, None
        if kind is OutboundKind.VMESS:
            return {"protocol": "vmess", "tag": name,
                    "settings": {"vnext": [{"address": s["server"], "port": int(s["server_port"]),
                                            "users": [{"id": str(s["uuid"]), "alterId": 0, "security": s.get("security", "auto")}]}]}}, None
        if kind is OutboundKind.TROJAN:
            return {"protocol": "trojan", "tag": name,
                    "settings": {"servers": [{"address": s["server"], "port": int(s["server_port"]), "password": s["password"]}]}}, None
        if kind is OutboundKind.SHADOWSOCKS:
            return {"protocol": "shadowsocks", "tag": name,
                    "settings": {"servers": [{"address": s["server"], "port": int(s["server_port"]),
                                              "method": s.get("method", "chacha20-ietf-poly1305"), "password": s["password"]}]}}, None
        if kind is OutboundKind.WIREGUARD:
            peer: dict[str, Any] = {
                "publicKey": s["peer_public_key"],
                "endpoint": f"{s['server']}:{int(s['server_port'])}",
                "allowedIPs": s.get("allowed_ips", ["0.0.0.0/0", "::/0"]),
            }
            if s.get("reserved"):
                peer["reserved"] = s["reserved"]
            return {"protocol": "wireguard", "tag": name,
                    "settings": {"secretKey": s["private_key"], "peers": [peer],
                                 "address": s.get("local_address", [])}}, None
        if kind is OutboundKind.SSH:
            if gap := need("server", "server_port", "username"):
                return None, gap
            native: dict[str, Any] = {"protocol": "ssh", "tag": name, "settings": {
                "address": s["server"], "port": int(s["server_port"]),
                "user": s["username"], "password": s.get("password", ""),
            }}
            return native, None
        return None, UnsupportedOutbound(
            name=name,
            reason=f"xray has no native '{kind.value}' outbound (use a CORE chain to sing-box instead).",
        )

    async def _ensure_base_outbounds(self) -> None:
        native = [
            {"protocol": "freedom", "tag": self._BASE_OUTBOUNDS["direct"]},
            {"protocol": "blackhole", "tag": self._BASE_OUTBOUNDS["block"]},
            {"protocol": "dns", "tag": self._BASE_OUTBOUNDS["dns"]},
        ]
        await asyncio.to_thread(self._backend.set_outbounds, native)

    async def deploy_outbounds(self, outbounds: list[Outbound]) -> TranslatedOutbound:
        native: list[dict] = []
        applied: list[str] = []
        unsupported: list[UnsupportedOutbound] = []
        for ob in outbounds:
            translated, gap = self._outbound_to_native(ob)
            if gap is not None:
                unsupported.append(gap)
            else:
                native.append(translated)
                applied.append(ob.name)
        await asyncio.to_thread(self._backend.set_outbounds, native)
        return TranslatedOutbound(core_id=self.metadata.id, applied=applied,
                                  unsupported=unsupported, payload=native)

    # ------------------------------------------------------------------ #
    # chain ingress (CHAIN_ROUTING)
    # ------------------------------------------------------------------ #
    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        inbounds = await self._inbounds()
        endpoints: list[ChainEndpoint] = []
        for tag, info in inbounds.items():
            if tag.startswith("mz-chain-"):
                endpoints.append(ChainEndpoint(
                    core_id=self.metadata.id,
                    protocol=str(info.get("protocol", "socks")),
                    host="127.0.0.1",
                    port=int(info.get("port") or 0),
                ))
        return endpoints

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        if protocol not in ("socks", "http"):
            raise CoreError(
                f"xray chain ingress supports socks/http listeners, not '{protocol}'."
            )
        endpoint = ChainEndpoint(core_id=self.metadata.id, protocol=protocol, port=port)
        await asyncio.to_thread(self._backend.ensure_listener, protocol, port)
        return endpoint


# ---------------------------------------------------------------------- #
# self-install (module level, shared by install/update)
# ---------------------------------------------------------------------- #

_XRAY_ASSETS = {
    ("linux", "amd64"): "Xray-linux-64.zip",
    ("linux", "arm64"): "Xray-linux-arm64-v8a.zip",
    ("darwin", "amd64"): "Xray-macos-64.zip",
    ("darwin", "arm64"): "Xray-macos-arm64-v8a.zip",
    ("windows", "amd64"): "Xray-windows-64.zip",
}
#: marker proving Zagros installed this copy — uninstall refuses otherwise
_MARKER = ".zagros-installed"


def _install_xray(settings: dict[str, Any]) -> str:
    import os

    from app.cores.github_install import host_arch, host_os, install_from_github

    system, arch = host_os(), host_arch()
    asset = _XRAY_ASSETS.get((system, arch))
    if asset is None:
        raise CoreError(f"no prebuilt Xray binary for {system}/{arch}.")
    executable = settings["executable_path"]
    extras: dict[str, str] = {}
    assets_dir = settings.get("assets_path")
    if assets_dir:
        # the official zip bundles both data files (documented upstream)
        extras = {
            "geoip.dat": os.path.join(assets_dir, "geoip.dat"),
            "geosite.dat": os.path.join(assets_dir, "geosite.dat"),
        }
    tag = install_from_github(
        repo="XTLS/Xray-core",
        target_executable=executable,
        asset_match=lambda name: name == asset,
        member_match=lambda m: m.rsplit("/", 1)[-1] in ("xray", "xray.exe"),
        direct_asset=asset,
        extra_members=extras,
    )
    with open(executable + _MARKER, "w", encoding="utf-8") as fh:
        fh.write(tag + "\n")
    return tag


def _uninstall_xray(settings: dict[str, Any], purge: bool) -> None:
    import os

    executable = settings["executable_path"]
    marker = executable + _MARKER
    if not os.path.exists(marker):
        raise CoreError(
            "refusing to uninstall: this xray binary was not installed by "
            "Zagros (no marker file). Uninstall your system package instead."
        )
    os.remove(executable)
    os.remove(marker)
    if purge and settings.get("assets_path"):
        for name in ("geoip.dat", "geosite.dat"):
            path = os.path.join(settings["assets_path"], name)
            if os.path.exists(path):
                os.remove(path)
