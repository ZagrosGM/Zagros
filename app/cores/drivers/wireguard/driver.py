"""WireGuardDriver — kernel WireGuard as a first-class, multi-inbound core.

Each Studio inbound is a real and independent kernel WireGuard interface with
its own UDP port, tunnel subnet and server key.  User operations remain hot:
``wg syncconf`` updates peers on every granted interface without restarting
unrelated peers.  Studio topology changes reconcile the interface set through
``wg-quick`` because Address/MTU/routes/NAT cannot be changed by syncconf.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from typing import Any, Callable, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.drivers.wireguard.wgtool import (
    DesiredPeer,
    allocate_address,
    is_valid_key,
    render_client,
    render_interface,
    server_address,
)
from app.cores.exceptions import CoreError
from app.cores.qr import EccLevel, encode_matrix, to_svg
from app.cores.stats import DeltaTracker
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

logger = logging.getLogger("zagros.cores.drivers.wireguard")

_DEFAULT_SUBNET = "10.66.66.0/24"
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")


class WireGuardDriver(BaseCoreDriver):
    """Driver for one or more kernel WireGuard interfaces."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="wireguard",
        name="WireGuard",
        description=(
            "Kernel WireGuard via wg/wg-quick. Multiple independent inbounds, "
            "live peer sync, key rotation, per-peer usage, handshake-based "
            "online detection, real wg-to-wg chain ingress and QR delivery."
        ),
        protocols=["wireguard"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.HOT_RELOAD,
            Capability.SERVICE_CONTROL,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
            Capability.CHAIN_ROUTING,
            Capability.KEY_ROTATION,
        },
        config_schema={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "default": "mzwg0"},
                "work_dir": {"type": "string"},
                "listen": {"type": "string", "default": "0.0.0.0"},
                "port": {"type": "integer", "default": 51820},
                "subnet": {"type": "string", "default": _DEFAULT_SUBNET},
                "dns_servers": {"type": "array", "items": {"type": "string"}},
                "advertise_host": {
                    "type": "string",
                    "description": "public endpoint; blank uses the subscription request host",
                },
                "allow_loopback_advertise": {"type": "boolean", "default": False},
                "mtu": {"type": "integer"},
                "use_preshared_keys": {"type": "boolean", "default": True},
                "online_threshold_seconds": {"type": "integer", "default": 180},
                "peer_allowed_ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["0.0.0.0/0", "::/0"],
                },
                "peer_keepalive": {"type": "integer", "default": 25},
                "enable_nat": {
                    "type": "boolean",
                    "default": True,
                    "description": "wg-quick forwarding/MASQUERADE hooks",
                },
                "listeners": {
                    "type": "array",
                    "description": (
                        "Independent WireGuard listeners. Empty/missing migrates the "
                        "legacy flat settings to one 'wireguard' listener."
                    ),
                },
            },
        },
        default_settings={
            "interface": "mzwg0",
            "work_dir": "/var/lib/zagros/cores/wireguard",
            "listen": "0.0.0.0",
            "port": 51820,
            "subnet": _DEFAULT_SUBNET,
            "dns_servers": ["1.1.1.1"],
            "advertise_host": "",
            "allow_loopback_advertise": False,
            "mtu": None,
            "use_preshared_keys": True,
            "online_threshold_seconds": 180,
            "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
            "peer_keepalive": 25,
            "enable_nat": True,
            "listeners": [],
        },
        homepage="https://www.wireguard.com/",
        provides=set(),
        requires=set(),
        # A WireGuard inbound maps to one kernel interface.  The core may own
        # as many interfaces as the host can serve; the wizard must APPEND.
        studio_inbounds_path="/inbounds",
    )

    _LISTENER_KEYS = (
        "interface",
        "listen",
        "port",
        "subnet",
        "dns_servers",
        "advertise_host",
        "mtu",
        "use_preshared_keys",
        "peer_allowed_ips",
        "peer_keepalive",
        "enable_nat",
    )

    def __init__(
        self,
        settings: dict[str, Any] | None = None,
        *,
        backend: Any | None = None,
        backend_factory: Callable[[dict[str, Any]], Any] | None = None,
    ):
        super().__init__(settings)
        raw = self.settings.get("listeners") or []
        if raw:
            listeners = [
                self._normalize_listener(row, self.settings, index)
                for index, row in enumerate(raw)
            ]
        else:
            listeners = [self._listener_from_flat(self.settings)]
        self._validate_listener_set(listeners)
        self.settings["listeners"] = [dict(listener) for listener in listeners]

        self._provided_backend = backend
        self._backend_factory = backend_factory
        self._local_backend_class: type | None = None
        if backend is None:
            from app.cores.drivers.wireguard.backend import LocalWireGuardBackend

            self._local_backend_class = LocalWireGuardBackend

        self._backends: dict[str, Any] = {}
        self._backend_specs: dict[str, tuple[str, str]] = {}
        self._configure_backend_set(listeners, reuse={})
        # Compatibility alias: older integrations/tests use _backend for the
        # sole interface.  It now means the first (primary) listener backend.
        self._backend = self._backends[listeners[0]["tag"]]

        self._accounts: dict[str, UserAccount] = {}
        import asyncio
        self._account_lock = asyncio.Lock()
        self._chain_peers: dict[str, DesiredPeer] = {}
        self._chain_private = ""
        self._usage = DeltaTracker()
        self._restore_chain_state()
        self._server_keys: dict[str, tuple[str, str]] = {}
        self._server_private: str | None = None  # primary compatibility alias
        self._server_public: str | None = None   # primary compatibility alias
        self._last_sync_error: str | None = None

    # ------------------------------------------------------------------ #
    # listener model + backend set                                       #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _interface_for_tag(tag: str) -> str:
        # Linux IFNAMSIZ is 16 including NUL.  A digest avoids truncation
        # collisions and keeps names stable over panel/container restarts.
        return "mzwg" + hashlib.sha256(tag.encode("utf-8")).hexdigest()[:10]

    @classmethod
    def _listener_from_flat(cls, settings: dict[str, Any]) -> dict[str, Any]:
        return {
            "tag": "wireguard",
            "interface": str(settings.get("interface") or "mzwg0"),
            "listen": str(settings.get("listen") or "0.0.0.0"),
            "port": int(settings.get("port") or 51820),
            "subnet": str(settings.get("subnet") or _DEFAULT_SUBNET),
            "dns_servers": list(settings.get("dns_servers") or ["1.1.1.1"]),
            "advertise_host": str(settings.get("advertise_host") or ""),
            "mtu": settings.get("mtu") or None,
            "use_preshared_keys": bool(settings.get("use_preshared_keys", True)),
            "peer_allowed_ips": list(
                settings.get("peer_allowed_ips") or ["0.0.0.0/0", "::/0"]
            ),
            "peer_keepalive": int(settings.get("peer_keepalive") or 25),
            "enable_nat": bool(settings.get("enable_nat", True)),
            "_work_dir": str(
                settings.get("work_dir") or "/var/lib/zagros/cores/wireguard"
            ),
        }

    @classmethod
    def _normalize_listener(
        cls, row: Any, settings: dict[str, Any], index: int
    ) -> dict[str, Any]:
        template = cls._listener_from_flat(settings)
        if not isinstance(row, dict):
            row = {}
        out = dict(template)
        tag = str(row.get("tag") or "").strip()
        port = int(row.get("port") or out["port"])
        out["tag"] = tag or f"wireguard-{port}"
        for key in cls._LISTENER_KEYS:
            if row.get(key) is not None:
                out[key] = row[key]
        if not row.get("interface"):
            out["interface"] = (
                str(settings.get("interface") or "mzwg0")
                if index == 0
                else cls._interface_for_tag(out["tag"])
            )
        out["interface"] = str(out["interface"])
        out["listen"] = str(out.get("listen") or "0.0.0.0")
        out["port"] = int(out["port"])
        out["subnet"] = str(out.get("subnet") or _DEFAULT_SUBNET)
        out["dns_servers"] = list(out.get("dns_servers") or [])
        out["advertise_host"] = str(out.get("advertise_host") or "")
        out["mtu"] = int(out["mtu"]) if out.get("mtu") not in (None, "") else None
        out["use_preshared_keys"] = bool(out.get("use_preshared_keys", True))
        out["peer_allowed_ips"] = list(
            out.get("peer_allowed_ips") or ["0.0.0.0/0", "::/0"]
        )
        out["peer_keepalive"] = int(out.get("peer_keepalive") or 25)
        out["enable_nat"] = bool(out.get("enable_nat", True))
        if row.get("_work_dir"):
            out["_work_dir"] = str(row["_work_dir"])
        else:
            base = str(settings.get("work_dir") or "/var/lib/zagros/cores/wireguard")
            legacy_interface = str(settings.get("interface") or "mzwg0")
            out["_work_dir"] = (
                base if index == 0 and out["interface"] == legacy_interface
                else os.path.join(base, "listeners", out["interface"])
            )
        return out

    def _listeners(self) -> list[dict[str, Any]]:
        listeners = [dict(listener) for listener in (self.settings.get("listeners") or [])]
        # Legacy/operator integrations historically changed flat settings in
        # place.  Preserve that contract for the migrated one-inbound shape;
        # in multi-inbound mode the listener rows are authoritative.
        if len(listeners) == 1:
            for key in self._LISTENER_KEYS:
                if key in self.settings:
                    listeners[0][key] = copy.deepcopy(self.settings[key])
        return listeners

    def _primary_listener(self) -> dict[str, Any]:
        listeners = self._listeners()
        if not listeners:  # guarded on every apply; defensive for corrupt settings
            raise CoreError("wireguard has no configured inbound.")
        return listeners[0]

    def _listener_work_dir(self, listener: dict[str, Any], index: int) -> str:
        stored = listener.get("_work_dir")
        if stored:
            return str(stored)
        base = str(self.settings.get("work_dir") or "/var/lib/zagros/cores/wireguard")
        legacy_interface = str(self.settings.get("interface") or "mzwg0")
        if index == 0 and listener["interface"] == legacy_interface:
            return base
        return os.path.join(base, "listeners", listener["interface"])

    def _backend_settings(self, listener: dict[str, Any], index: int) -> dict[str, Any]:
        settings = dict(self.settings)
        settings.update(listener)
        settings["work_dir"] = self._listener_work_dir(listener, index)
        settings["interface"] = listener["interface"]
        return settings

    def _new_backend(self, listener: dict[str, Any], index: int) -> Any:
        settings = self._backend_settings(listener, index)
        if self._local_backend_class is not None:
            return self._local_backend_class(settings)
        if index == 0 and self._provided_backend is not None:
            return self._provided_backend
        factory = self._backend_factory
        if factory is None and self._provided_backend is not None:
            factory = getattr(self._provided_backend, "for_listener", None)
        if callable(factory):
            return factory(settings)
        raise CoreError(
            "the injected WireGuard backend serves only one interface; provide "
            "backend_factory/for_listener to test or embed multiple inbounds."
        )

    def _configure_backend_set(
        self,
        listeners: list[dict[str, Any]],
        *,
        reuse: dict[str, Any],
        reuse_specs: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        reuse_specs = reuse_specs or {}
        by_spec = {spec: backend for tag, backend in reuse.items()
                   if (spec := reuse_specs.get(tag)) is not None}
        configured: dict[str, Any] = {}
        specs: dict[str, tuple[str, str]] = {}
        used_backend_ids: set[int] = set()
        for index, listener in enumerate(listeners):
            tag = listener["tag"]
            settings = self._backend_settings(listener, index)
            spec = (str(listener["interface"]), str(settings["work_dir"]))
            backend = None
            if tag in reuse and reuse_specs.get(tag) == spec:
                backend = reuse[tag]
            elif spec in by_spec:
                backend = by_spec[spec]
            if backend is None or id(backend) in used_backend_ids:
                backend = self._new_backend(listener, index)
            configured[tag] = backend
            specs[tag] = spec
            used_backend_ids.add(id(backend))
        self._backends = configured
        self._backend_specs = specs

    def _mirror_primary_flat_settings(self) -> None:
        # Read the just-installed listener row directly.  _listeners() also
        # overlays legacy flat edits in the one-inbound case, and using that
        # view here would overwrite a freshly-applied Studio candidate with
        # the OLD flat values before they can be mirrored.
        rows = self.settings.get("listeners") or []
        if not rows:
            raise CoreError("wireguard has no configured inbound.")
        primary = dict(rows[0])
        for key in self._LISTENER_KEYS:
            self.settings[key] = copy.deepcopy(primary[key])
        self._backend = self._backends[primary["tag"]]

    @staticmethod
    def _validate_listener_set(listeners: list[dict[str, Any]]) -> None:
        if not listeners:
            raise CoreError("wireguard needs at least ONE inbound (kernel interface).")
        seen_tags: set[str] = set()
        seen_interfaces: dict[str, str] = {}
        seen_ports: dict[int, str] = {}
        networks: list[tuple[ipaddress._BaseNetwork, str]] = []
        for listener in listeners:
            tag = str(listener.get("tag") or "").strip()
            interface = str(listener.get("interface") or "")
            port = int(listener.get("port") or 0)
            if not tag:
                raise CoreError("wireguard inbound tag cannot be empty.")
            if tag in seen_tags:
                raise CoreError(f"duplicate wireguard inbound name '{tag}'.")
            if not _INTERFACE_RE.fullmatch(interface):
                raise CoreError(
                    f"wireguard inbound '{tag}': interface '{interface}' must be "
                    "1-15 Linux interface-name characters."
                )
            if interface in seen_interfaces:
                raise CoreError(
                    f"wireguard inbounds '{seen_interfaces[interface]}' and '{tag}' "
                    f"share kernel interface '{interface}'."
                )
            if not 1 <= port <= 65535:
                raise CoreError(f"wireguard inbound '{tag}': port out of range ({port}).")
            if port in seen_ports:
                raise CoreError(
                    f"wireguard inbounds '{seen_ports[port]}' and '{tag}' share UDP "
                    f"port {port}; each kernel interface needs its own ListenPort."
                )
            try:
                network = ipaddress.ip_network(str(listener.get("subnet") or ""), strict=False)
                server_address(str(network))
            except ValueError as exc:
                raise CoreError(
                    f"wireguard inbound '{tag}': invalid tunnel subnet "
                    f"'{listener.get('subnet')}': {exc}"
                ) from exc
            for other, other_tag in networks:
                if network.overlaps(other):
                    raise CoreError(
                        f"wireguard inbounds '{other_tag}' and '{tag}' have "
                        f"overlapping tunnel subnets {other} and {network}."
                    )
            listener["subnet"] = str(network)
            seen_tags.add(tag)
            seen_interfaces[interface] = tag
            seen_ports[port] = tag
            networks.append((network, tag))

    def _parse_studio_document(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        inbounds = (document or {}).get("inbounds") or []
        if not inbounds:
            raise CoreError(
                "a wireguard core needs at least ONE inbound; the Studio document is empty."
            )
        existing = {listener["tag"]: listener for listener in self._listeners()}
        template = self._listener_from_flat(self.settings)
        listeners: list[dict[str, Any]] = []
        used_interfaces: set[str] = set()
        for index, inbound in enumerate(inbounds):
            if not isinstance(inbound, dict):
                raise CoreError(f"wireguard inbound #{index + 1} must be an object.")
            protocol = str(inbound.get("protocol") or "wireguard")
            if protocol != "wireguard":
                raise CoreError(
                    f"a wireguard core cannot host a '{inbound.get('protocol')}' listener."
                )
            tag = str(inbound.get("tag") or "").strip()
            port_value = inbound.get("port", template["port"])
            try:
                port = int(port_value)
            except (TypeError, ValueError):
                raise CoreError(
                    f"wireguard inbound '{tag or '?'}': invalid port {port_value!r}."
                ) from None
            prior = existing.get(tag)
            entry = dict(template)
            entry.pop("_work_dir", None)
            entry["tag"] = tag or f"wireguard-{port}"
            if prior:
                entry.update(prior)
                entry["tag"] = tag
            entry["port"] = port
            if inbound.get("listen"):
                entry["listen"] = str(inbound["listen"])
            if inbound.get("mtu") not in (None, ""):
                entry["mtu"] = int(inbound["mtu"])
            elif "mtu" in inbound:
                entry["mtu"] = None
            if inbound.get("dns") is not None:
                entry["dns_servers"] = [
                    item.strip() for item in str(inbound["dns"]).split(",") if item.strip()
                ]
            if inbound.get("address"):
                entry["subnet"] = str(inbound["address"])
            if inbound.get("endpoint") is not None:
                entry["advertise_host"] = str(inbound["endpoint"])
            if inbound.get("allowed_ips") is not None:
                entry["peer_allowed_ips"] = [
                    item.strip()
                    for item in str(inbound["allowed_ips"]).split(",")
                    if item.strip()
                ]
            if inbound.get("persistent_keepalive") is not None:
                entry["peer_keepalive"] = int(inbound["persistent_keepalive"])
            if inbound.get("preshared_keys") is not None:
                entry["use_preshared_keys"] = bool(inbound["preshared_keys"])
            if inbound.get("enable_nat") is not None:
                entry["enable_nat"] = bool(inbound["enable_nat"])
            if inbound.get("interface"):
                entry["interface"] = str(inbound["interface"])
            elif prior:
                entry["interface"] = prior["interface"]
            elif index == 0:
                candidate = str(self.settings.get("interface") or "mzwg0")
                entry["interface"] = (
                    candidate if candidate not in used_interfaces
                    else self._interface_for_tag(entry["tag"])
                )
            else:
                entry["interface"] = self._interface_for_tag(entry["tag"])
            entry = self._normalize_listener(entry, self.settings, index)
            used_interfaces.add(entry["interface"])
            listeners.append(entry)
        self._validate_listener_set(listeners)
        return listeners

    # ------------------------------------------------------------------ #
    # desired state                                                      #
    # ------------------------------------------------------------------ #
    def _granted_listeners(self, account: UserAccount) -> list[dict[str, Any]]:
        wanted = {str(tag) for tag in account.settings.get("inbound_tags") or []}
        excluded = {str(tag) for tag in account.settings.get("excluded_inbounds") or []}
        listeners = self._listeners()
        if wanted:
            listeners = [listener for listener in listeners if listener["tag"] in wanted]
        return [listener for listener in listeners if listener["tag"] not in excluded]

    def _address_for(self, account: UserAccount, listener: dict[str, Any]) -> str | None:
        addresses = account.settings.get("inbound_addresses") or {}
        value = addresses.get(listener["tag"]) if isinstance(addresses, dict) else None
        if value:
            return str(value)
        if listener["tag"] == self._primary_listener()["tag"]:
            legacy = account.settings.get("address")
            return str(legacy) if legacy else None
        return None

    def _taken_addresses(
        self, listener: dict[str, Any], *, exclude_account_id: str | None = None
    ) -> set[str]:
        taken: set[str] = set()
        for account in self._accounts.values():
            if account.account_id == exclude_account_id:
                continue
            address = self._address_for(account, listener)
            if address:
                taken.add(address)
        if listener["tag"] == self._primary_listener()["tag"]:
            for peer in self._chain_peers.values():
                taken.update(peer.allowed_ips)
        return taken

    def _desired_peers(
        self, listener: dict[str, Any] | None = None
    ) -> list[DesiredPeer]:
        listener = listener or self._primary_listener()
        peers: list[DesiredPeer] = []
        tag = listener["tag"]
        for account in self._accounts.values():
            if not account.enabled:
                continue
            if tag not in {item["tag"] for item in self._granted_listeners(account)}:
                continue
            public_key = account.settings.get("public_key")
            address = self._address_for(account, listener)
            if not public_key or not address:
                continue
            peers.append(DesiredPeer(
                comment=account.account_id,
                public_key=str(public_key),
                allowed_ips=(address,),
                preshared_key=(
                    account.settings.get("preshared_key") or None
                    if listener.get("use_preshared_keys", True)
                    else None
                ),
            ))
        if tag == self._primary_listener()["tag"]:
            peers.extend(self._chain_peers.values())
        return peers

    def _refresh_primary_key_aliases(self) -> None:
        pair = self._server_keys.get(self._primary_listener()["tag"])
        self._server_private = pair[0] if pair else None
        self._server_public = pair[1] if pair else None

    def _ensure_server_keys(self, listener: dict[str, Any]) -> tuple[str, str]:
        tag = listener["tag"]
        pair = self._server_keys.get(tag)
        if pair is None:
            pair = self._backends[tag].ensure_server_keys()
            self._server_keys[tag] = pair
            self._refresh_primary_key_aliases()
        return pair

    def render_server_config(self, listener: dict[str, Any] | None = None) -> str:
        listener = listener or self._primary_listener()
        pair = self._server_keys.get(listener["tag"])
        if pair is None:
            raise CoreError(
                f"WireGuard server keys for inbound '{listener['tag']}' are not initialized."
            )
        return render_interface(
            private_key=pair[0],
            address=server_address(listener["subnet"]),
            listen_port=int(listener["port"]),
            peers=self._desired_peers(listener),
            forward_nat=bool(listener.get("enable_nat", True)),
        )

    async def _wait_ready(self, listener: dict[str, Any] | None = None) -> None:
        import asyncio

        listener = listener or self._primary_listener()
        verify = getattr(self._backends[listener["tag"]], "wait_ready", None)
        if callable(verify):
            await asyncio.to_thread(verify, int(listener["port"]))

    async def _publish(self) -> None:
        """Hot-sync peers and ListenPort on every currently-running inbound."""
        import asyncio

        if not self._server_keys:
            return
        try:
            for listener in self._listeners():
                backend = self._backends[listener["tag"]]
                if not await asyncio.to_thread(backend.is_running):
                    continue
                await asyncio.to_thread(backend.sync, self.render_server_config(listener))
                await self._wait_ready(listener)
            self._last_sync_error = None
        except CoreError as exc:
            self._last_sync_error = str(exc)
            raise

    # ------------------------------------------------------------------ #
    # Config Studio bridge                                               #
    # ------------------------------------------------------------------ #
    def export_config_document(self) -> dict[str, Any]:
        entries: list[dict[str, Any]] = []
        for listener in self._listeners():
            public = self._server_keys.get(listener["tag"], ("", ""))[1]
            entries.append({
                "tag": listener["tag"],
                "protocol": "wireguard",
                "listen": listener["listen"],
                "port": int(listener["port"]),
                "mtu": listener.get("mtu") or None,
                "dns": ", ".join(str(item) for item in listener["dns_servers"]),
                "address": listener["subnet"],
                "endpoint": listener["advertise_host"],
                "allowed_ips": ", ".join(
                    str(item) for item in listener["peer_allowed_ips"]
                ),
                "persistent_keepalive": int(listener["peer_keepalive"]),
                "preshared_keys": bool(listener["use_preshared_keys"]),
                "enable_nat": bool(listener.get("enable_nat", True)),
                "public_key": public,
            })
        return {"inbounds": entries}

    async def _provision_keys(self, account: UserAccount) -> None:
        """Create one client identity plus one tunnel address per grant.

        The private/public/PSK tuple remains backward-compatible and shared
        across the account's profiles.  ``inbound_addresses`` is new and is
        persisted encrypted by the service layer after create/update/replay.
        """
        import asyncio

        settings = account.settings
        generator = self._backend
        if not (settings.get("private_key") and settings.get("public_key")):
            private, public = await asyncio.to_thread(generator.generate_keypair)
            settings["private_key"], settings["public_key"] = private, public
        if not is_valid_key(str(settings["public_key"])):
            raise CoreError(f"invalid wireguard public key for '{account.account_id}'.")
        granted = self._granted_listeners(account)
        if (any(listener.get("use_preshared_keys", True) for listener in granted)
                and not settings.get("preshared_key")):
            settings["preshared_key"] = await asyncio.to_thread(generator.generate_preshared)

        addresses = settings.get("inbound_addresses")
        if not isinstance(addresses, dict):
            addresses = {}
        addresses = {str(key): str(value) for key, value in addresses.items() if value}
        primary_tag = self._primary_listener()["tag"]
        for listener in granted:
            tag = listener["tag"]
            current = addresses.get(tag)
            if not current and tag == primary_tag and settings.get("address"):
                current = str(settings["address"])
            valid = False
            if current:
                try:
                    valid = ipaddress.ip_interface(current).ip in ipaddress.ip_network(
                        listener["subnet"], strict=False
                    )
                except ValueError:
                    valid = False
            if not valid:
                current = allocate_address(
                    listener["subnet"],
                    self._taken_addresses(listener, exclude_account_id=account.account_id),
                )
            addresses[tag] = current
            if tag == primary_tag:
                settings["address"] = current
        settings["inbound_addresses"] = addresses

    def _repair_chain_address(self) -> None:
        peer = self._chain_peers.get("_zg-chain")
        if peer is None:
            return
        primary = self._primary_listener()
        try:
            valid = ipaddress.ip_interface(peer.allowed_ips[0]).ip in ipaddress.ip_network(
                primary["subnet"], strict=False
            )
        except (IndexError, ValueError):
            valid = False
        if valid:
            return
        address = allocate_address(primary["subnet"], self._taken_addresses(primary))
        self._chain_peers["_zg-chain"] = DesiredPeer(
            comment=peer.comment,
            public_key=peer.public_key,
            allowed_ips=(address,),
            preshared_key=peer.preshared_key,
        )
        self._persist_chain_state()

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Atomically replace the desired interface set with all Studio entries.

        This is deliberately a set reconciliation, not single-listener
        replacement.  A failed live bring-up rolls the old interfaces and
        in-memory account addresses back before surfacing the error.
        """
        import asyncio

        inbounds = (document or {}).get("inbounds") or []
        listeners = self._parse_studio_document(document)
        old_settings = copy.deepcopy(self.settings)
        old_backends = dict(self._backends)
        old_specs = dict(self._backend_specs)
        old_keys = dict(self._server_keys)
        old_account_settings = {
            account_id: copy.deepcopy(account.settings)
            for account_id, account in self._accounts.items()
        }
        old_running = {
            tag for tag, backend in old_backends.items()
            if await asyncio.to_thread(backend.is_running)
        }
        was_running = bool(old_running)

        try:
            # Stop the complete old topology.  syncconf cannot change Address,
            # interface identity, routes or PostUp/PostDown NAT ownership.
            for tag, backend in reversed(list(old_backends.items())):
                if tag in old_running:
                    await asyncio.to_thread(backend.down)

            self.settings["listeners"] = [dict(listener) for listener in listeners]
            self._configure_backend_set(
                listeners, reuse=old_backends, reuse_specs=old_specs
            )
            self._mirror_primary_flat_settings()
            self._server_keys = {}

            for inbound, listener in zip(inbounds, listeners):
                backend = self._backends[listener["tag"]]
                private = str(inbound.get("private_key") or "").strip()
                prior_pair = old_keys.get(listener["tag"])
                if private and prior_pair and private == prior_pair[0]:
                    # Write-only wizard field replay: do not touch the key file
                    # or rotate/restart identity when the value is unchanged.
                    pair = prior_pair
                elif private:
                    public = await asyncio.to_thread(backend.public_from_private, private)
                    await asyncio.to_thread(backend.write_server_private_key, private)
                    pair = (private, public)
                else:
                    pair = await asyncio.to_thread(backend.ensure_server_keys)
                self._server_keys[listener["tag"]] = pair
            self._refresh_primary_key_aliases()

            for account in self._accounts.values():
                await self._provision_keys(account)
            self._repair_chain_address()

            if was_running:
                started: list[Any] = []
                try:
                    for listener in listeners:
                        backend = self._backends[listener["tag"]]
                        await asyncio.to_thread(
                            backend.up, self.render_server_config(listener)
                        )
                        started.append(backend)
                        await self._wait_ready(listener)
                except Exception:
                    for backend in reversed(started):
                        try:
                            await asyncio.to_thread(backend.down)
                        except Exception:  # noqa: BLE001 — rollback continues
                            pass
                    raise
            self._last_sync_error = None
        except Exception as exc:
            self._last_sync_error = str(exc)
            # Restore all in-memory desired state before attempting old live
            # topology recovery.  The Studio service will not persist the
            # rejected candidate.
            self.settings.clear()
            self.settings.update(old_settings)
            self._backends = old_backends
            self._backend_specs = old_specs
            self._server_keys = old_keys
            self._backend = old_backends[self._primary_listener()["tag"]]
            self._refresh_primary_key_aliases()
            for account_id, settings_snapshot in old_account_settings.items():
                self._accounts[account_id].settings.clear()
                self._accounts[account_id].settings.update(settings_snapshot)
            if was_running:
                for listener in self._listeners():
                    backend = self._backends[listener["tag"]]
                    try:
                        if not await asyncio.to_thread(backend.is_running):
                            await asyncio.to_thread(
                                backend.up, self.render_server_config(listener)
                            )
                            await self._wait_ready(listener)
                    except Exception as rollback_exc:  # noqa: BLE001
                        logger.error(
                            "wireguard rollback could not restore inbound %s: %s",
                            listener["tag"], rollback_exc,
                        )
            raise

    # ------------------------------------------------------------------ #
    # lifecycle                                                          #
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        import asyncio

        started: list[Any] = []
        try:
            for listener in self._listeners():
                pair = await asyncio.to_thread(
                    self._backends[listener["tag"]].ensure_server_keys
                )
                self._server_keys[listener["tag"]] = pair
            self._refresh_primary_key_aliases()
            for account in self._accounts.values():
                await self._provision_keys(account)
            self._repair_chain_address()
            for listener in self._listeners():
                backend = self._backends[listener["tag"]]
                await asyncio.to_thread(backend.up, self.render_server_config(listener))
                started.append(backend)
                await self._wait_ready(listener)
            self._last_sync_error = None
        except Exception:
            for backend in reversed(started):
                try:
                    await asyncio.to_thread(backend.down)
                except Exception:  # noqa: BLE001
                    pass
            raise

    async def stop(self) -> None:
        import asyncio

        first_error: Exception | None = None
        for listener in reversed(self._listeners()):
            backend = self._backends[listener["tag"]]
            try:
                await asyncio.to_thread(backend.down)
            except Exception as exc:  # noqa: BLE001 — clean every interface
                first_error = first_error or exc
        if first_error is not None:
            raise first_error

    async def status(self) -> CoreStatus:
        import asyncio

        listeners = self._listeners()
        running_by_tag = {
            listener["tag"]: await asyncio.to_thread(
                self._backends[listener["tag"]].is_running
            )
            for listener in listeners
        }
        running_count = sum(running_by_tag.values())
        all_running = running_count == len(listeners)
        any_running = running_count > 0
        health = HealthStatus.UNKNOWN
        message = self._last_sync_error
        version = await self.version()
        metrics = None
        if any_running:
            metrics = await asyncio.to_thread(self._backend.metrics)
            sessions = await self.get_online_devices()
            metrics.active_sessions = len(sessions)
            dump = await asyncio.to_thread(self._backend.dump)
            wrong = []
            for listener in listeners:
                observed = int(dump.listen_ports.get(listener["interface"], 0))
                if not running_by_tag[listener["tag"]] or observed != int(listener["port"]):
                    wrong.append(
                        f"{listener['tag']}({listener['interface']}): "
                        f"expected {listener['port']}, observed {observed}"
                    )
            if wrong:
                health = HealthStatus.UNHEALTHY
                message = "WireGuard listener mismatch: " + "; ".join(wrong)
            else:
                health = (
                    HealthStatus.DEGRADED if self._last_sync_error
                    else HealthStatus.HEALTHY
                )
        state = (
            CoreState.RUNNING if all_running
            else CoreState.ERROR if any_running
            else CoreState.STOPPED
        )
        return CoreStatus(
            core_id=self.metadata.id,
            state=state,
            health=health,
            core_version=version.version,
            version_reason=version.reason,
            metrics=metrics,
            message=message,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        import asyncio

        listeners = self._listeners()
        for listener in listeners:
            lines = await asyncio.to_thread(self._backends[listener["tag"]].logs, tail)
            for line in lines:
                yield line if len(listeners) == 1 else f"[{listener['tag']}] {line}"

    async def install(self) -> None:
        import asyncio

        if not await asyncio.to_thread(self._backend.is_installed):
            await asyncio.to_thread(self._backend.install_packages)

    async def uninstall(self, purge: bool = False) -> None:
        await self.stop()

    # ------------------------------------------------------------------ #
    # user management                                                    #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _ensure_supported(protocol: str) -> None:
        if protocol != "wireguard":
            raise CoreError(
                f"WireGuard core only serves protocol 'wireguard', got '{protocol}'."
            )

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        async with self._account_lock:
            await self._provision_keys(account)
            self._accounts[account.account_id] = account
            await self._publish()

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        async with self._account_lock:
            await self._provision_keys(account)
            previous = self._accounts.get(account.account_id)
            if (previous is not None
                    and previous.settings.get("public_key") != account.settings.get("public_key")):
                self._usage.forget(previous.settings.get("public_key"))
            self._accounts[account.account_id] = account
            await self._publish()

    async def delete_account(self, account_id: str) -> None:
        existing = self._accounts.pop(account_id, None)
        if existing is not None:
            self._usage.forget(existing.settings.get("public_key"))
        await self._publish()

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await self._publish()

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        resumed = account.model_copy(update={"enabled": True})
        await self._provision_keys(resumed)
        self._accounts[account.account_id] = resumed
        await self._publish()

    async def rotate_credentials(self, account: UserAccount) -> UserAccount:
        import asyncio

        existing = self._accounts.get(account.account_id)
        if existing is None:
            raise CoreError(f"cannot rotate unknown wireguard peer '{account.account_id}'.")
        private, public = await asyncio.to_thread(self._backend.generate_keypair)
        updates: dict[str, Any] = {"private_key": private, "public_key": public}
        if any(
            listener.get("use_preshared_keys", True)
            for listener in self._granted_listeners(existing)
        ):
            updates["preshared_key"] = await asyncio.to_thread(
                self._backend.generate_preshared
            )
        rotated = existing.model_copy(
            update={"settings": {**existing.settings, **updates}}
        )
        self._usage.forget(existing.settings.get("public_key"))
        self._accounts[account.account_id] = rotated
        await self._publish()
        return rotated

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        for account in accounts:
            self._ensure_supported(account.protocol)
            await self._provision_keys(account)
        self._accounts = {account.account_id: account for account in accounts}
        await self._publish()

    # ------------------------------------------------------------------ #
    # durable usage baselines                                            #
    # ------------------------------------------------------------------ #
    def usage_tracker_snapshot(
        self, account_ids: list[str] | None = None,
    ) -> dict[str, tuple[int, int]]:
        """Translate provider public-key cursors to stable account ids.

        ``get_usage`` correctly keys raw WireGuard counters by public key, but
        the recorder persists account ids.  Passing account ids directly to
        DeltaTracker.baseline_snapshot used to return an empty mapping, so a
        panel restart re-billed every peer's lifetime transfer counter.
        """
        wanted = set(account_ids) if account_ids is not None else None
        raw = self._usage.baseline_snapshot()
        out: dict[str, tuple[int, int]] = {}
        for account_id, account in self._accounts.items():
            if wanted is not None and account_id not in wanted:
                continue
            public_key = account.settings.get("public_key")
            if public_key in raw:
                out[account_id] = raw[public_key]
        return out

    def restore_usage_baselines(self, baselines: dict) -> None:
        translated: dict[str, tuple[int, int]] = {}
        for account_id, totals in (baselines or {}).items():
            account = self._accounts.get(str(account_id))
            if account is None:
                continue
            public_key = account.settings.get("public_key")
            if public_key:
                translated[str(public_key)] = (int(totals[0]), int(totals[1]))
        self._usage.restore(translated)

    # ------------------------------------------------------------------ #
    # statistics                                                         #
    # ------------------------------------------------------------------ #
    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        import asyncio

        dump = await asyncio.to_thread(self._backend.dump)
        by_public = {
            str(account.settings.get("public_key")): account
            for account in self._accounts.values()
            if account.settings.get("public_key")
        }
        allowed_interfaces = {
            account.account_id: {
                listener["interface"] for listener in self._granted_listeners(account)
            }
            for account in self._accounts.values()
        }
        totals: dict[str, list[int]] = {}
        seen_public: dict[str, str] = {}
        for peer in dump.peers:
            account = by_public.get(peer.public_key)
            if account is None or peer.interface not in allowed_interfaces[account.account_id]:
                continue
            if account_ids is not None and account.account_id not in account_ids:
                continue
            total = totals.setdefault(account.account_id, [0, 0])
            total[0] += peer.transfer_rx
            total[1] += peer.transfer_tx
            seen_public[account.account_id] = peer.public_key
        records: list[UsageRecord] = []
        for account_id, (rx, tx) in totals.items():
            public_key = seen_public[account_id]
            up, down = self._usage.observe(public_key, rx, tx)
            records.append(UsageRecord(
                core_id=self.metadata.id,
                account_id=account_id,
                uplink_bytes=up,
                downlink_bytes=down,
            ))
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        import asyncio
        from datetime import datetime, timezone

        dump = await asyncio.to_thread(self._backend.dump)
        threshold = int(self.settings["online_threshold_seconds"])
        now = int(time.time())
        by_public = {
            str(account.settings.get("public_key")): account
            for account in self._accounts.values()
            if account.settings.get("public_key")
        }
        interface_tags = {
            listener["interface"]: listener["tag"] for listener in self._listeners()
        }
        sessions: list[DeviceSession] = []
        for peer in dump.peers:
            account = by_public.get(peer.public_key)
            tag = interface_tags.get(peer.interface)
            if account is None or tag is None:
                continue
            if tag not in {listener["tag"] for listener in self._granted_listeners(account)}:
                continue
            if account_ids is not None and account.account_id not in account_ids:
                continue
            if peer.latest_handshake <= 0 or now - peer.latest_handshake > threshold:
                continue
            endpoint_host = (peer.endpoint or "").rsplit(":", 1)[0] or None
            sessions.append(DeviceSession(
                core_id=self.metadata.id,
                account_id=account.account_id,
                ip=endpoint_host,
                connected_at=datetime.fromtimestamp(peer.latest_handshake, tz=timezone.utc),
                metadata={
                    "inbound_tag": tag,
                    "interface": peer.interface,
                    "endpoint": peer.endpoint,
                    "allowed_ips": list(peer.allowed_ips),
                    "latest_handshake_age_seconds": now - peer.latest_handshake,
                    "session_rx_bytes": peer.transfer_rx,
                    "session_tx_bytes": peer.transfer_tx,
                },
            ))
        return sessions

    # ------------------------------------------------------------------ #
    # client config + delivery                                           #
    # ------------------------------------------------------------------ #
    def _select_listener(
        self, account: UserAccount, inbound_tag: str | None = None
    ) -> dict[str, Any]:
        granted = self._granted_listeners(account)
        if inbound_tag is not None:
            listener = next(
                (item for item in granted if item["tag"] == inbound_tag), None
            )
            if listener is None:
                raise CoreError(
                    f"wireguard account '{account.account_id}' is not granted "
                    f"inbound '{inbound_tag}'."
                )
            return listener
        if not granted:
            raise CoreError(
                f"wireguard account '{account.account_id}' has no granted inbound."
            )
        return granted[0]

    def render_client_profile(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
        listener: dict[str, Any] | None = None,
    ) -> str:
        self._ensure_supported(account.protocol)
        listener = listener or self._select_listener(account)
        pair = self._server_keys.get(listener["tag"])
        if pair is None:
            raise CoreError(
                f"WireGuard server keys for inbound '{listener['tag']}' are not initialized."
            )
        address = self._address_for(account, listener)
        for key, value in (("private_key", account.settings.get("private_key")),
                           ("address", address)):
            if not value:
                raise CoreError(
                    f"wireguard account '{account.account_id}' is missing '{key}' "
                    f"for inbound '{listener['tag']}'."
                )
        from app.cores.delivery import resolve_delivery_host

        endpoint_host = resolve_delivery_host(
            listener.get("advertise_host"),
            context,
            allow_loopback=bool(self.settings.get("allow_loopback_advertise", False)),
        )
        if not endpoint_host:
            raise CoreError(
                f"no public endpoint is configured for WireGuard inbound "
                f"'{listener['tag']}' — set endpoint or fetch through a public host"
            )
        return render_client(
            private_key=str(account.settings["private_key"]),
            address=str(address),
            server_public_key=pair[1],
            endpoint_host=endpoint_host,
            endpoint_port=int(listener["port"]),
            preshared_key=(
                account.settings.get("preshared_key") or None
                if listener.get("use_preshared_keys", True)
                else None
            ),
            dns=list(listener["dns_servers"]),
            mtu=listener.get("mtu"),
            allowed_ips=tuple(
                listener.get("peer_allowed_ips") or ("0.0.0.0/0", "::/0")
            ),
            persistent_keepalive=int(listener.get("peer_keepalive") or 25),
        )

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryField,
            DeliveryProfile,
            DeliverySection,
            resolve_delivery_host,
        )

        self._ensure_supported(account.protocol)
        await self._provision_keys(account)
        sections: list[DeliverySection] = []
        for listener in self._granted_listeners(account):
            pair = self._server_keys.get(listener["tag"])
            if pair is None:
                raise CoreError(
                    f"WireGuard server keys for inbound '{listener['tag']}' are not initialized."
                )
            profile_text = self.render_client_profile(account, context, listener)
            endpoint_host = resolve_delivery_host(
                listener.get("advertise_host"),
                context,
                allow_loopback=bool(self.settings.get("allow_loopback_advertise", False)),
            )
            fields = [
                DeliveryField(
                    key="address", label="Address",
                    value=str(self._address_for(account, listener) or ""),
                ),
                DeliveryField(
                    key="public_key", label="Server Public Key", value=pair[1]
                ),
                DeliveryField(
                    key="endpoint", label="Endpoint",
                    value=f"{endpoint_host}:{int(listener['port'])}",
                ),
                DeliveryField(
                    key="dns", label="DNS",
                    value=", ".join(str(item) for item in listener["dns_servers"]),
                ),
                DeliveryField(
                    key="allowed_ips", label="Allowed IPs",
                    value=", ".join(str(item) for item in listener["peer_allowed_ips"]),
                ),
                DeliveryField(
                    key="keepalive", label="Persistent Keepalive",
                    value=f"{int(listener['peer_keepalive'])} s",
                ),
            ]
            if listener.get("mtu"):
                fields.append(DeliveryField(
                    key="mtu", label="MTU", value=str(int(listener["mtu"]))
                ))
            if account.settings.get("public_key"):
                fields.append(DeliveryField(
                    key="client_public_key",
                    label="Client Public Key (peer identity)",
                    value=str(account.settings["public_key"]),
                ))
            if (listener.get("use_preshared_keys", True)
                    and account.settings.get("preshared_key")):
                fields.append(DeliveryField(
                    key="preshared_key", label="Preshared Key",
                    value=str(account.settings["preshared_key"]), secret=True,
                ))
            sections.append(DeliverySection(
                protocol="wireguard",
                title=f"{listener['tag']} · WireGuard",
                engine="wireguard",
                inbound_tag=listener["tag"],
                artifacts=[
                    DeliveryArtifact(
                        kind=ArtifactKind.FILE,
                        label="WireGuard configuration",
                        content=profile_text,
                        filename=f"{account.username}-{listener['tag']}.conf",
                        mime="text/plain",
                        qr=True,
                    ),
                    DeliveryArtifact(
                        kind=ArtifactKind.FIELDS,
                        label="Connection details",
                        fields=fields,
                    ),
                    DeliveryArtifact(
                        kind=ArtifactKind.NOTE,
                        label="How to connect",
                        note=(
                            "Scan the QR code or import this inbound's .conf file "
                            "with the WireGuard app."
                        ),
                    ),
                ],
            ))
        return DeliveryProfile(core_id=self.metadata.id, sections=sections)

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        listener = self._select_listener(account)
        profile = self.render_client_profile(account, node, listener=listener)
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="wireguard",
            engine="wireguard",
            payload={"format": "ini", "profile": profile},
            display_name=f"WireGuard · {listener['tag']}",
        )

    def client_config_qr(
        self,
        account: UserAccount,
        *,
        as_ascii: bool = False,
        inbound_tag: str | None = None,
    ) -> str:
        listener = self._select_listener(account, inbound_tag)
        matrix = encode_matrix(
            self.render_client_profile(account, listener=listener),
            level=EccLevel.MEDIUM,
        )
        if as_ascii:
            from app.cores.qr import to_ascii

            return to_ascii(matrix)
        return to_svg(matrix)

    # ------------------------------------------------------------------ #
    # chain ingress — bound to the primary WireGuard inbound             #
    # ------------------------------------------------------------------ #
    _CHAIN_STATE_FILE = "chain-peers.json"

    def _chain_state_path(self) -> str:
        return os.path.join(self.settings["work_dir"], self._CHAIN_STATE_FILE)

    def _restore_chain_state(self) -> None:
        import json

        path = self._chain_state_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as handle:
                state = json.load(handle)
            self._chain_peers["_zg-chain"] = DesiredPeer(
                comment="_zg-chain",
                public_key=state["public_key"],
                allowed_ips=tuple(state["allowed_ips"]),
            )
            self._chain_private = state["private_key"]
        except (OSError, KeyError, ValueError) as exc:
            logger.warning(
                "wireguard: could not restore chain peer state (%s); a fresh "
                "peer is provisioned on the next chain deployment", exc,
            )

    def _persist_chain_state(self) -> None:
        import json

        peer = self._chain_peers.get("_zg-chain")
        if peer is None:
            return
        path = self._chain_state_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump({
                    "public_key": peer.public_key,
                    "private_key": self._chain_private,
                    "allowed_ips": list(peer.allowed_ips),
                }, handle)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError as exc:
            logger.warning(
                "wireguard: chain peer state could not be persisted (%s); "
                "chains survive runtime but not panel restarts", exc,
            )

    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        if self._server_public is None or "_zg-chain" not in self._chain_peers:
            return []
        return [self._chain_endpoint_for(self._chain_peers["_zg-chain"])]

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        if protocol != "wireguard":
            raise CoreError(
                f"WireGuard cannot host a '{protocol}' chain endpoint; it only "
                "accepts real wireguard peers."
            )
        existing = self._chain_peers.get("_zg-chain")
        if existing is None:
            import asyncio

            private, public = await asyncio.to_thread(self._backend.generate_keypair)
            primary = self._primary_listener()
            address = allocate_address(
                primary["subnet"], self._taken_addresses(primary)
            )
            existing = DesiredPeer(
                comment="_zg-chain",
                public_key=public,
                allowed_ips=(address,),
                preshared_key=None,
            )
            self._chain_peers["_zg-chain"] = existing
            self._chain_private = private
            self._persist_chain_state()
            await self._publish()
        return self._chain_endpoint_for(existing)

    def _chain_endpoint_for(self, peer: DesiredPeer) -> ChainEndpoint:
        if self._server_public is None:
            raise CoreError("WireGuard server is not running; no chain endpoint yet.")
        primary = self._primary_listener()
        return ChainEndpoint(
            core_id=self.metadata.id,
            protocol="wireguard",
            host=primary["advertise_host"],
            port=int(primary["port"]),
            network="udp",
            requires_credentials=True,
            metadata={
                "private_key": self._chain_private,
                "peer_public_key": self._server_public,
                "local_address": [peer.allowed_ips[0]],
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            },
        )
