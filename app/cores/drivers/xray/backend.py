"""Adapter boundary between :class:`XrayDriver` and the legacy ``app.xray`` stack.

The driver programs against the :class:`XrayBackend` protocol (Dependency
Inversion). In production the protocol is fulfilled by :class:`LegacyXrayBackend`,
which lazily imports the existing singletons (process wrapper ``XRayCore``,
gRPC client, connected nodes, hosts storage) — so importing/scanning drivers
never requires the xray binary or a live grpc stack. Tests inject a fake.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from app.cores.exceptions import CoreError
from app.cores.types import CoreMetrics


@dataclass(frozen=True, slots=True)
class XrayUsageStat:
    """Per-user counters read from one xray instance (main core or a node)."""

    email: str
    uplink: int
    downlink: int
    node_id: int | None = None          # None => master core


@runtime_checkable
class XrayBackend(Protocol):
    """Everything the driver needs from the underlying xray machinery."""

    # ---- process ---- #
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def restart(self) -> None: ...
    def is_running(self) -> bool: ...
    def version(self) -> str | None: ...
    def metrics(self) -> CoreMetrics: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...

    # ---- configuration snapshot ---- #
    def inbounds(self) -> Mapping[str, dict[str, Any]]:
        """tag -> inbound info (protocol, network, tls, header_type, port, ...)."""
        ...

    def host_options(self, tag: str) -> Sequence[dict[str, Any]]:
        """Resolved host entries (address/sni/port/alpn/fingerprint/...) per tag."""
        ...

    # ---- user management (fan-out to connected nodes included) ---- #
    def add_user(self, tag: str, protocol: str, email: str, settings: dict[str, Any]) -> None: ...
    def remove_user(self, tag: str, email: str) -> None: ...

    # ---- statistics ---- #
    def usage(self, reset: bool = False) -> list[XrayUsageStat]: ...
    def online_accounts(self) -> list[str]:
        """Emails with traffic growth since the previous sample (delta probe)."""
        ...

    # ---- config injection (routing/outbounds/chain listeners) ---- #
    def set_routing_rules(self, rules: list[dict[str, Any]]) -> None:
        """Replace panel-managed routing rules; restart the core if running."""
        ...

    def set_outbounds(self, outbounds: list[dict[str, Any]]) -> None:
        """Merge panel-managed outbounds (tags prefixed ``mz-``) into config."""
        ...

    def ensure_listener(self, protocol: str, port: int) -> None:
        """Guarantee a loopback ``protocol`` inbound on ``port`` exists."""
        ...


class LegacyXrayBackend:
    """Production backend: wraps ``app.xray`` (lazy, fault-isolated import).

    The legacy module creates its singletons at import time (process wrapper,
    parsed config, grpc channel). Importing it may fail on hosts without the
    xray binary — that failure must surface as :class:`CoreError` on first
    *use*, never at driver-registration time.
    """

    def __init__(self, settings: dict[str, Any] | None = None):
        self._settings = settings or {}
        self._mod = None                          # the `app.xray` module
        self._counters: dict[str, tuple[int, int]] = {}   # online-delta baseline

    # ------------------------------------------------------------------ #
    # bridge
    # ------------------------------------------------------------------ #
    def _x(self):
        if self._mod is None:
            try:
                from app import xray as mod
            except Exception as exc:  # noqa: BLE001 - report ANY bootstrap failure
                raise CoreError(f"Legacy xray stack unavailable: {exc}") from exc
            self._mod = mod
        return self._mod

    def _connected_nodes(self) -> list[tuple[int, Any]]:
        mod = self._x()
        return [
            (node_id, node)
            for node_id, node in list(mod.nodes.items())
            if getattr(node, "connected", False) and getattr(node, "started", False)
        ]

    # ------------------------------------------------------------------ #
    # process
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        mod = self._x()
        mod.core.start(mod.config.include_db_users())

    def stop(self) -> None:
        self._x().core.stop()

    def restart(self) -> None:
        mod = self._x()
        mod.core.restart(mod.config.include_db_users())
        for node_id, _node in self._connected_nodes():
            mod.operations.restart_node(node_id)  # legacy is already threaded

    def is_running(self) -> bool:
        return bool(self._x().core.started)

    def version(self) -> str | None:
        return self._x().core.version

    def metrics(self) -> CoreMetrics:
        metrics = CoreMetrics()
        try:
            import psutil

            proc = self._x().core.process
            if proc is not None and proc.poll() is None:
                ps = psutil.Process(proc.pid)
                metrics.cpu_percent = ps.cpu_percent(interval=None)
                metrics.memory_bytes = ps.memory_info().rss
        except Exception:  # noqa: BLE001 - metrics are best-effort
            pass
        try:
            sys_stats = self._x().api.get_sys_stats(timeout=10)
            metrics.memory_bytes = metrics.memory_bytes or sys_stats.alloc
        except Exception:  # noqa: BLE001
            pass
        return metrics

    def logs(self, tail: int = 200) -> Sequence[str]:
        with self._x().core.get_logs() as buffer:
            lines = list(buffer)
        return lines[-tail:]

    # ------------------------------------------------------------------ #
    # configuration
    # ------------------------------------------------------------------ #
    def inbounds(self) -> Mapping[str, dict[str, Any]]:
        return dict(self._x().config.inbounds_by_tag)

    def host_options(self, tag: str) -> Sequence[dict[str, Any]]:
        return list(self._x().hosts.get(tag, []))

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    _ACCOUNT_MODELS = {
        "vmess": "VMessAccount",
        "vless": "VLESSAccount",
        "trojan": "TrojanAccount",
        "shadowsocks": "ShadowsocksAccount",
    }

    def _account_model(self, protocol: str):
        try:
            from xray_api.types import account as account_types
        except Exception as exc:  # noqa: BLE001
            raise CoreError(f"xray_api account types unavailable: {exc}") from exc
        try:
            return getattr(account_types, self._ACCOUNT_MODELS[protocol])
        except KeyError:
            raise CoreError(f"Protocol '{protocol}' has no xray account model.") from None

    def add_user(self, tag: str, protocol: str, email: str, settings: dict[str, Any]) -> None:
        mod = self._x()
        account = self._account_model(protocol)(email=email, **settings)
        try:
            mod.api.add_inbound_user(tag=tag, user=account, timeout=30)
        except (mod.exc.EmailExistsError, mod.exc.ConnectionError):
            pass
        for _node_id, node in self._connected_nodes():
            try:
                node.api.add_inbound_user(tag=tag, user=account, timeout=30)
            except (mod.exc.EmailExistsError, mod.exc.ConnectionError):
                pass

    def remove_user(self, tag: str, email: str) -> None:
        mod = self._x()
        try:
            mod.api.remove_inbound_user(tag=tag, email=email, timeout=30)
        except (mod.exc.EmailNotFoundError, mod.exc.ConnectionError):
            pass
        for _node_id, node in self._connected_nodes():
            try:
                node.api.remove_inbound_user(tag=tag, email=email, timeout=30)
            except (mod.exc.EmailNotFoundError, mod.exc.ConnectionError):
                pass

    # ------------------------------------------------------------------ #
    # statistics
    # ------------------------------------------------------------------ #
    def usage(self, reset: bool = False) -> list[XrayUsageStat]:
        mod = self._x()
        sources: list[tuple[int | None, Any]] = [(None, mod.api)]
        sources += [(nid, node.api) for nid, node in self._connected_nodes()]

        records: list[XrayUsageStat] = []
        for node_id, api in sources:
            aggregates: dict[str, list[int]] = defaultdict(lambda: [0, 0])
            try:
                stats = api.get_users_stats(reset=reset, timeout=30)
            except Exception:  # noqa: BLE001 - node outage must not kill the sweep
                continue
            for stat in filter(lambda s: s.value, stats):
                slot = 0 if stat.link == "uplink" else 1
                aggregates[stat.name][slot] += stat.value
            records.extend(
                XrayUsageStat(email=email, uplink=up, downlink=down, node_id=node_id)
                for email, (up, down) in aggregates.items()
            )
        return records

    def online_accounts(self) -> list[str]:
        """Xray's stats API has no per-user IP table; online == counters grew
        since the previous sample."""
        current: dict[str, tuple[int, int]] = {}
        try:
            for stat in self._x().api.get_users_stats(reset=False, timeout=30):
                up, down = current.get(stat.name, (0, 0))
                if stat.link == "uplink":
                    current[stat.name] = (up + stat.value, down)
                else:
                    current[stat.name] = (up, down + stat.value)
        except Exception:  # noqa: BLE001
            return []
        online = [
            email
            for email, totals in current.items()
            if email in self._counters and sum(totals) > sum(self._counters[email])
        ]
        self._counters = current
        return online

    # ------------------------------------------------------------------ #
    # config injection
    # ------------------------------------------------------------------ #
    def _persist_and_maybe_restart(self) -> None:
        """Apply in-memory config mutations to the live core (restart path)."""
        mod = self._x()
        if mod.core.started:
            mod.core.restart(mod.config.include_db_users())

    def set_routing_rules(self, rules: list[dict[str, Any]]) -> None:
        mod = self._x()
        routing = dict(mod.config.get("routing") or {})
        routing["rules"] = rules
        routing.setdefault("domainStrategy", "IPIfNonMatch")
        mod.config["routing"] = routing
        self._persist_and_maybe_restart()

    def set_outbounds(self, outbounds: list[dict[str, Any]]) -> None:
        mod = self._x()
        existing = [
            ob for ob in (mod.config.get("outbounds") or [])
            if not str(ob.get("tag", "")).startswith("mz-")
        ]
        mod.config["outbounds"] = existing + outbounds
        self._persist_and_maybe_restart()

    def ensure_listener(self, protocol: str, port: int) -> None:
        mod = self._x()
        tag = f"mz-chain-{protocol}-{port}"
        inbounds = list(mod.config.get("inbounds") or [])
        if any(ib.get("tag") == tag for ib in inbounds):
            return
        settings = {"auth": "noauth", "udp": False} if protocol == "socks" else {}
        inbounds.append({
            "listen": "127.0.0.1",
            "port": port,
            "protocol": protocol,
            "tag": tag,
            "settings": settings,
        })
        mod.config["inbounds"] = inbounds
        self._persist_and_maybe_restart()
