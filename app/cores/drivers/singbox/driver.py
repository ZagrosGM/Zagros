"""SingBoxDriver — sing-box as a first-class panel core.

Reality of sing-box (and how this driver deals with it):
  * no user-management API → users are rendered into the JSON config and the
    process restarts (sub-second, stateless); the driver owns desired state.
  * per-user traffic stats ARE available through the experimental v2ray API
    (StatsService, enabled by the driver) → honest USAGE_ACCOUNTING with
    cumulative-counter deltas; online detection uses the documented
    counter-delta heuristic (the same technique 3x-ui/x-ui panels use for
    hysteria). If the binary was built without v2ray_api, the core degrades
    gracefully (DEGRADED health, explicit error) — nothing is faked.
  * excellent native routing/process/geosite + the richest outbound set of any
    core (wireguard/hysteria2/tuic/shadowsocks native) → the panel's prime
    *chain target* and outbound Swiss-army-knife.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.stats import DeltaTracker
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

_INBOUND_KEYS: dict[str, set[str]] = {
    "vless": {"id", "flow"},
    "vmess": {"id"},
    "trojan": {"password"},
    "shadowsocks": {"password"},
}
_PROTOCOLS = set(_INBOUND_KEYS)


class SingBoxDriver(BaseCoreDriver):
    """Driver for SagerNet sing-box (config-render + restart strategy)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="sing-box",
        name="sing-box",
        description=(
            "Universal proxy platform by SagerNet. Config-render driver; the "
            "richest native outbound set (wireguard, hysteria2, tuic, "
            "shadowsocks, socks, http) — the panel's prime chain target."
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
            Capability.ROUTING,
            Capability.GEO_ROUTING,
            Capability.PROCESS_ROUTING,
            Capability.OUTBOUND_MANAGEMENT,
            Capability.CHAIN_ROUTING,
            Capability.UDP_SUPPORT,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string"},
                "work_dir": {"type": "string"},
                "listen": {"type": "string", "default": "::"},
                "ports": {"type": "object"},
                "advertise_host": {"type": "string",
                                   "description": "public address the client app connects to"},
                "ss_method": {"type": "string", "default": "aes-128-gcm"},
                "final_outbound": {"type": "string", "default": "direct"},
                "stats_enabled": {"type": "boolean", "default": True},
                "stats_api": {"type": "string", "default": "127.0.0.1:19091"},
                "geoip_db": {"type": "string"},
                "geosite_db": {"type": "string"},
            },
        },
        default_settings={
            "executable_path": "sing-box",
            "work_dir": "/var/lib/zagros/cores/sing-box",
            "listen": "::",
            "ports": {"vless": 10001, "vmess": 10002, "trojan": 10003, "shadowsocks": 10004},
            "advertise_host": "127.0.0.1",
            "ss_method": "aes-128-gcm",
            "final_outbound": "direct",
            "geoip_db": "",
            "geosite_db": "",
            "stats_enabled": True,
            "stats_api": "127.0.0.1:19091",
        },
        homepage="https://github.com/SagerNet/sing-box",
        studio_inbounds_path="/inbounds",
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None,
                 stats: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.singbox.backend import LocalSingBoxBackend

            backend = LocalSingBoxBackend(self.settings)
        self._backend = backend
        if stats is None:
            from app.cores.drivers.singbox.backend import V2RayStatsSource

            stats = V2RayStatsSource(self.settings["stats_api"])
        self._stats = stats
        self._accounts: dict[str, UserAccount] = {}
        self._native_rules: list[dict[str, Any]] = []
        self._native_outbounds: list[dict[str, Any]] = []
        self._chain_listeners: dict[tuple[str, int], ChainEndpoint] = {}
        self._usage = DeltaTracker()
        self._online_seen: dict[str, tuple[int, int]] = {}
        self._stats_error: str | None = None

    # ------------------------------------------------------------------ #
    # config rendering + publishing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _user_entry(account: UserAccount) -> dict[str, Any]:
        protocol = account.protocol
        entry: dict[str, Any] = {"name": account.account_id}
        if protocol in ("vless", "vmess"):
            entry["uuid"] = str(account.settings["id"])
            if protocol == "vless" and account.settings.get("flow"):
                entry["flow"] = account.settings["flow"]
        else:
            entry["password"] = account.settings["password"]
        return entry

    def _render_inbounds(self) -> list[dict[str, Any]]:
        ports: dict[str, int] = self.settings["ports"]
        inbounds: list[dict[str, Any]] = []
        for protocol in sorted(_PROTOCOLS):
            users = [
                self._user_entry(a)
                for a in self._accounts.values()
                if a.protocol == protocol and a.enabled
            ]
            if not users:
                # sing-box >=1.11 rejects inbounds whose users list is empty
                # ("initialize inbound[0]: missing password"). Render an
                # inbound only once it has at least one enabled user — a port
                # with nobody on it is dead weight anyway, and a fresh core
                # with no accounts starts cleanly with zero inbounds.
                continue
            inbounds.append({
                "type": protocol,
                "tag": f"{protocol}-in",
                "listen": self.settings["listen"],
                "listen_port": int(ports[protocol]),
                "users": users,
                **({"method": self.settings["ss_method"]} if protocol == "shadowsocks" else {}),
            })
        for (protocol, port), _ep in sorted(self._chain_listeners.items()):
            inbounds.append({
                "type": protocol,
                "tag": f"zg-chain-{protocol}-{port}",
                "listen": "127.0.0.1",
                "listen_port": port,
            })
        return inbounds

    def render_config(self) -> dict[str, Any]:
        """Desired-state → full sing-box JSON (deterministic, testable)."""
        outbounds = [
            {"type": "direct", "tag": "direct"},
            *self._native_outbounds,
        ]
        final = self.settings.get("final_outbound") or "direct"
        inbounds = self._render_inbounds()
        config: dict[str, Any] = {
            "log": {"level": "warning", "timestamp": True},
            "dns": {"servers": [{"type": "local", "tag": "dns-local"}]},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {
                # DNS interception without the deprecated legacy `dns` special
                # outbound (removed upstream in 1.13): rule action hijack-dns
                "rules": [{"protocol": "dns", "action": "hijack-dns"},
                          *self._native_rules],
                "final": final,
                "auto_detect_interface": True,
            },
        }
        if self.settings.get("stats_enabled"):
            config["experimental"] = {
                "v2ray_api": {
                    "listen": self.settings["stats_api"],
                    "stats": {
                        "enabled": True,
                        "inbounds": [
                            f"{ib['tag']}"
                            for ib in inbounds
                            if not ib["tag"].startswith("zg-chain-")
                        ],
                        "outbounds": ["direct"],
                        "users": sorted(self._accounts),
                    },
                },
            }
        return config

    async def _republish(self) -> None:
        await asyncio.to_thread(self._backend.apply_config, self.render_config())
        if await asyncio.to_thread(self._backend.is_running):
            await asyncio.to_thread(self._backend.restart)

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        await asyncio.to_thread(self._backend.apply_config, self.render_config())
        await asyncio.to_thread(self._backend.start)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def restart(self) -> None:
        await asyncio.to_thread(self._backend.restart)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        metrics = await asyncio.to_thread(self._backend.metrics) if running else None
        version = await asyncio.to_thread(self._backend.version)
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=(
                HealthStatus.DEGRADED if (running and self._stats_error)
                else HealthStatus.HEALTHY if running
                else HealthStatus.UNKNOWN
            ),
            core_version=version,
            metrics=metrics,
            message=self._stats_error,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def install(self) -> None:
        """Fetch the latest sing-box release binary matching this OS/arch."""
        await asyncio.to_thread(self._backend.install_binary)

    async def update(self, version: str | None = None) -> str:
        await asyncio.to_thread(self._backend.install_binary)
        new_version = await asyncio.to_thread(self._backend.version) or "unknown"
        return new_version

    # (binary fetch lives in app.cores.github_install — shared by all drivers)

    async def uninstall(self, purge: bool = False) -> None:
        await asyncio.to_thread(self._backend.stop)

    # ------------------------------------------------------------------ #
    # user management (config-render strategy)
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol not in _PROTOCOLS:
            raise CoreError(
                f"Protocol '{protocol}' is not supported by the sing-box core ({sorted(_PROTOCOLS)})."
            )

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        key = account.settings.get("id") or account.settings.get("password")
        if account.enabled and not key:
            raise CoreError(
                f"Account '{account.account_id}' for '{account.protocol}' is missing credentials "
                f"({sorted(_INBOUND_KEYS[account.protocol])})."
            )
        self._accounts[account.account_id] = account
        await self._republish()

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account
        await self._republish()

    async def delete_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
        self._usage.forget(account_id)
        self._online_seen.pop(account_id, None)
        await self._republish()

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await self._republish()

    async def resume_account(self, account: UserAccount) -> None:
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})
        await self._republish()

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        """Config-render cores converge best by rebuilding user state wholesale."""
        self._accounts = {
            a.account_id: a for a in accounts if a.protocol in _PROTOCOLS
        }
        await self._republish()

    # ------------------------------------------------------------------ #
    # statistics — v2ray StatsService (experimental API)
    # ------------------------------------------------------------------ #
    async def _query_counters(self) -> dict[str, tuple[int, int]]:
        try:
            counters = await asyncio.to_thread(self._stats.query_user_counters)
        except Exception as exc:
            self._stats_error = str(exc)
            raise
        self._stats_error = None
        return counters

    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        counters = await self._query_counters()
        records: list[UsageRecord] = []
        for account_id, (up_total, down_total) in counters.items():
            if account_id not in self._accounts:
                continue  # counters for removed users are never billed
            if account_ids is not None and account_id not in account_ids:
                continue
            up, down = self._usage.observe(account_id, up_total, down_total)
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=account_id,
                uplink_bytes=up, downlink_bytes=down,
            ))
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        """Counter-delta heuristic (documented, same technique 3x-ui uses):

        the stats API exposes traffic counters but no session list — a user
        whose counters grew since the last poll is *active* right now. The
        user's IP is not exposed by the API and is honestly reported as None.
        """
        from datetime import datetime, timezone

        counters = await self._query_counters()
        now = datetime.now(timezone.utc)
        sessions: list[DeviceSession] = []
        for account_id, (up, down) in counters.items():
            if account_id not in self._accounts:
                continue
            if account_ids is not None and account_id not in account_ids:
                continue
            previous = self._online_seen.get(account_id)
            if previous is not None and (up, down) != previous:
                sessions.append(DeviceSession(
                    core_id=self.metadata.id,
                    account_id=account_id,
                    ip=None,  # the API exposes no client IPs (documented)
                    last_activity=now,
                    metadata={"detection": "counter-delta heuristic"},
                ))
            self._online_seen[account_id] = (up, down)
        return sessions

    # ------------------------------------------------------------------ #
    # routing translation (ROUTING + GEO_ROUTING + PROCESS_ROUTING)
    # ------------------------------------------------------------------ #
    def _geo_ready(self) -> bool:
        return bool(self.settings.get("geoip_db") and self.settings.get("geosite_db"))

    def _rule_to_native(
        self, rule: RoutingRule, ctx: RouteContext
    ) -> tuple[dict[str, Any] | None, UnsupportedRule | None]:
        m = rule.matcher
        native: dict[str, Any] = {}
        if m.inbounds:
            native["inbound"] = m.inbounds
        for src, dst in (
            ("domains", "domain"), ("domain_suffixes", "domain_suffix"),
            ("domain_keywords", "domain_keyword"), ("domain_regexes", "domain_regex"),
            ("ip_cidrs", "ip_cidr"), ("source_ip_cidrs", "source_ip_cidr"),
            ("process_names", "process_name"), ("protocols", "protocol"),
            ("networks", "network"),
        ):
            values = getattr(m, src)
            if values:
                native[dst] = values
        if m.ports:
            native["port"] = m.ports
        if m.port_ranges:
            native["port_range"] = m.port_ranges
        if m.geosites or m.geoips:
            if not self._geo_ready():
                missing = [f for f in ("geosites", "geoips") if getattr(m, f)]
                return None, UnsupportedRule(
                    rule=rule.name, fields=missing,
                    reason="sing-box geo rules need geoip_db/geosite_db paths in core settings.",
                )
            if m.geosites:
                native["geosite"] = m.geosites
            if m.geoips:
                native["geoip"] = m.geoips

        action = rule.action
        if action is RuleAction.ALLOW:
            native.update({"action": "route", "outbound": "direct"})
        elif action is RuleAction.BLOCK:
            native["action"] = "reject"
        elif action is RuleAction.ROUTE_TO:
            if rule.outbound not in ctx.available_outbounds:
                return None, UnsupportedRule(
                    rule=rule.name, fields=["outbound"],
                    reason=f"Outbound '{rule.outbound}' is not registered in the outbound manager.",
                )
            native.update({"action": "route", "outbound": rule.outbound})
        elif action is RuleAction.DNS:
            native["action"] = "hijack-dns"
        elif action is RuleAction.REDIRECT:
            return None, UnsupportedRule(
                rule=rule.name, fields=["action"],
                reason="sing-box redirection exists only as an inbound type, not a route action.",
            )
        elif action is RuleAction.FAKE_DNS:
            return None, UnsupportedRule(
                rule=rule.name, fields=["action"],
                reason="sing-box serves fakeip via its DNS server config, not route actions.",
            )
        elif action is RuleAction.DNS_OVERRIDE:
            return None, UnsupportedRule(
                rule=rule.name, fields=["action"],
                reason="sing-box DNS overrides live in dns.rules, not route rules.",
            )
        return native, None

    async def translate_routing_rules(
        self, rules: list[RoutingRule], ctx: RouteContext
    ) -> TranslatedRoute:
        """Dry preview (no republish) used by the rule builder."""
        native: list[dict[str, Any]] = []
        applied: list[str] = []
        unsupported: list[UnsupportedRule] = []
        for rule in rules:
            translated, gap = self._rule_to_native(rule, ctx)
            if gap is not None:
                unsupported.append(gap)
            else:
                native.append(translated)
                applied.append(rule.name)
        return TranslatedRoute(core_id=self.metadata.id, applied=applied,
                               unsupported=unsupported,
                               payload={"route": {"rules": native}})

    async def deploy_routing_rules(
        self, rules: list[RoutingRule], ctx: RouteContext
    ) -> TranslatedRoute:
        native: list[dict[str, Any]] = []
        applied: list[str] = []
        unsupported: list[UnsupportedRule] = []
        for rule in rules:
            translated, gap = self._rule_to_native(rule, ctx)
            if gap is not None:
                unsupported.append(gap)
            else:
                native.append(translated)
                applied.append(rule.name)
        self._native_rules = native
        await self._republish()
        return TranslatedRoute(
            core_id=self.metadata.id, applied=applied, unsupported=unsupported,
            payload={"route": {"rules": native}},
        )

    # ------------------------------------------------------------------ #
    # outbound translation (OUTBOUND_MANAGEMENT) — sing-box's home turf
    # ------------------------------------------------------------------ #
    def _outbound_to_native(
        self, ob: Outbound
    ) -> tuple[dict[str, Any] | None, UnsupportedOutbound | None]:
        s, kind, name = ob.settings, ob.kind, ob.name

        def need(*keys: str) -> UnsupportedOutbound | None:
            missing = [k for k in keys if s.get(k) in (None, "")]
            if missing:
                return UnsupportedOutbound(name=name, reason=f"missing settings: {', '.join(missing)}")
            return None

        if kind is OutboundKind.DIRECT:
            return {"type": "direct", "tag": name}, None
        if kind is OutboundKind.DNS:
            # the legacy `dns` special outbound is deprecated in sing-box 1.11
            # and removed in 1.13; DNS interception is built-in via the
            # hijack-dns route action, so a *named* dns target is not
            # representable — reported honestly instead of emitting a dying
            # config construct.
            return None, UnsupportedOutbound(
                name=name,
                reason="sing-box removed the legacy 'dns' special outbound; "
                       "DNS interception ships via route action 'hijack-dns' "
                       "(a named dns outbound is not representable).",
            )
        if kind in (OutboundKind.BLOCK, OutboundKind.BLACKHOLE):
            return None, UnsupportedOutbound(
                name=name, reason="sing-box has no block outbound; use routing rules with action=block/reject.",
            )
        if kind is OutboundKind.SOCKS:
            if gap := need("server", "server_port"):
                return None, gap
            native: dict[str, Any] = {"type": "socks", "tag": name, "server": s["server"],
                                      "server_port": int(s["server_port"]), "version": "5"}
            if s.get("username"):
                native.update({"username": s["username"], "password": s.get("password", "")})
            return native, None
        if kind is OutboundKind.HTTP:
            if gap := need("server", "server_port"):
                return None, gap
            native = {"type": "http", "tag": name, "server": s["server"],
                      "server_port": int(s["server_port"])}
            if s.get("username"):
                native.update({"username": s["username"], "password": s.get("password", "")})
            return native, None
        if kind is OutboundKind.VLESS:
            if gap := need("server", "server_port", "uuid"):
                return None, gap
            native = {"type": "vless", "tag": name, "server": s["server"],
                      "server_port": int(s["server_port"]), "uuid": str(s["uuid"])}
            if s.get("flow"):
                native["flow"] = s["flow"]
            return native, None
        if kind is OutboundKind.VMESS:
            if gap := need("server", "server_port", "uuid"):
                return None, gap
            return {"type": "vmess", "tag": name, "server": s["server"],
                    "server_port": int(s["server_port"]), "uuid": str(s["uuid"]),
                    "security": s.get("security", "auto"), "alter_id": 0}, None
        if kind is OutboundKind.TROJAN:
            if gap := need("server", "server_port", "password"):
                return None, gap
            return {"type": "trojan", "tag": name, "server": s["server"],
                    "server_port": int(s["server_port"]), "password": s["password"]}, None
        if kind is OutboundKind.SHADOWSOCKS:
            if gap := need("server", "server_port", "password", "method"):
                return None, gap
            return {"type": "shadowsocks", "tag": name, "server": s["server"],
                    "server_port": int(s["server_port"]), "method": s["method"],
                    "password": s["password"]}, None
        if kind is OutboundKind.WIREGUARD:
            if gap := need("server", "server_port", "private_key", "peer_public_key", "local_address"):
                return None, gap
            native = {"type": "wireguard", "tag": name, "server": s["server"],
                      "server_port": int(s["server_port"]), "local_address": s["local_address"],
                      "private_key": s["private_key"], "peer_public_key": s["peer_public_key"]}
            if s.get("reserved"):
                native["reserved"] = s["reserved"]
            return native, None
        if kind is OutboundKind.HYSTERIA2:
            if gap := need("server", "server_port", "password"):
                return None, gap
            return {"type": "hysteria2", "tag": name, "server": s["server"],
                    "server_port": int(s["server_port"]), "password": s["password"],
                    "tls": {"enabled": True, "server_name": s.get("sni") or s["server"],
                            "insecure": bool(s.get("insecure", False))}}, None
        if kind is OutboundKind.TUIC:
            if gap := need("server", "server_port", "uuid", "password"):
                return None, gap
            return {"type": "tuic", "tag": name, "server": s["server"],
                    "server_port": int(s["server_port"]), "uuid": str(s["uuid"]),
                    "password": s["password"],
                    "congestion_control": s.get("congestion_control", "bbr"),
                    "tls": {"enabled": True, "server_name": s.get("sni") or s["server"]}}, None
        return None, UnsupportedOutbound(
            name=name, reason=f"sing-box cannot host a '{kind.value}' client outbound.",
        )

    async def deploy_outbounds(self, outbounds: list[Outbound]) -> TranslatedOutbound:
        native: list[dict[str, Any]] = []
        applied: list[str] = []
        unsupported: list[UnsupportedOutbound] = []
        for ob in outbounds:
            translated, gap = self._outbound_to_native(ob)
            if gap is not None:
                unsupported.append(gap)
            else:
                native.append(translated)
                applied.append(ob.name)
        self._native_outbounds = native
        await self._republish()
        return TranslatedOutbound(core_id=self.metadata.id, applied=applied,
                                  unsupported=unsupported, payload=native)

    # ------------------------------------------------------------------ #
    # chain ingress (CHAIN_ROUTING)
    # ------------------------------------------------------------------ #
    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        return list(self._chain_listeners.values())

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        if protocol not in ("socks", "http", "mixed"):
            raise CoreError(
                f"sing-box chain ingress supports socks/http/mixed listeners, not '{protocol}'."
            )
        key = (protocol, port)
        if key not in self._chain_listeners:
            self._chain_listeners[key] = ChainEndpoint(
                core_id=self.metadata.id, protocol=protocol, port=port
            )
            await self._republish()
        return self._chain_listeners[key]

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        host = self.settings["advertise_host"]
        port = int(self.settings["ports"][account.protocol])
        outbound: dict[str, Any] = {
            "type": account.protocol,
            "tag": f"{account.protocol}-svc",
            "server": host,
            "server_port": port,
        }
        if account.protocol in ("vless", "vmess"):
            outbound["uuid"] = str(account.settings["id"])
            if account.protocol == "vless" and account.settings.get("flow"):
                outbound["flow"] = account.settings["flow"]
        else:
            outbound["password"] = account.settings["password"]
            if account.protocol == "shadowsocks":
                outbound["method"] = self.settings["ss_method"]
        outbound["tls"] = {"enabled": False}
        return ClientConfig(
            core_id=self.metadata.id,
            protocol=account.protocol,
            engine="sing-box",
            payload={"outbounds": [outbound]},
            display_name=f"{account.protocol} · sing-box",
        )



