"""WireGuardDriver — WireGuard as a first-class panel core.

Real capabilities used (no pretend features):
  * **Live peer management** via ``wg syncconf`` (kernel-native,
    non-disruptive) → suspend/delete/rotate take effect *without* dropping
    other peers' sessions (honest HOT_RELOAD).
  * **Key rotation**: fresh Curve25519 keypair (+ optional preshared key),
    applied live; old key dies the moment syncconf lands.
  * **Usage**: per-peer cumulative ``transfer-rx/tx`` from
    ``wg show all dump`` → :class:`DeltaTracker` deltas. Counters reset on
    interface restart — deltas then clamp to 0 for that interval (same
    semantics as xray in-memory stats; documented, never double counted).
  * **Online/handshake detection**: ``latest-handshake`` within the
    threshold → online + endpoint IP.
  * **Chain ingress**: other cores tunnel INTO this server through a real
    WireGuard peering (a dedicated system peer is provisioned; sing-box/xray
    dial it with their native wireguard outbound).
  * **QR**: share the sealed INI profile as an ISO-conformant QR code via
    the built-in dependency-free encoder (app/cores/qr.py).

Honestly NOT claimed (documented limitations):
  * DEVICE_DETECTION — WireGuard carries zero client identity beyond the
    public key; there is no platform/agent field to report.
  * ROUTING / per-peer routing rules — not a server-side concept in wg
    (policy routing is panel/OS scope, see doc §12.7).
  * USAGE persistence across interface restarts — kernel counters only.
  * CHAIN_ROUTING as *source* (wg cannot pick per-connection egress peers);
    it is a chain *target* only (real wg-to-wg peering).
"""
from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from typing import Any, ClassVar

logger = logging.getLogger("zagros.cores.drivers.wireguard")

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

_DEFAULT_SUBNET = "10.66.66.0/24"


class WireGuardDriver(BaseCoreDriver):
    """Driver for the kernel WireGuard module via wireguard-tools."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="wireguard",
        name="WireGuard",
        description=(
            "Kernel WireGuard via wg/wg-quick. Live peer sync (syncconf), key "
            "rotation, per-peer usage, handshake-based online detection, real "
            "wg-to-wg chain ingress, QR config delivery."
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
                "advertise_host": {"type": "string"},
                "mtu": {"type": "integer"},
                "use_preshared_keys": {"type": "boolean", "default": True},
                "online_threshold_seconds": {"type": "integer", "default": 180},
                "peer_allowed_ips": {"type": "array", "items": {"type": "string"},
                                     "default": ["0.0.0.0/0", "::/0"]},
                "peer_keepalive": {"type": "integer", "default": 25},
                "enable_nat": {"type": "boolean", "default": True,
                               "description": "PostUp/PostDown forwarding+"
                                              "MASQUERADE hooks (needed for "
                                              "full-tunnel clients); False = "
                                              "bare point-to-point link"},
            },
        },
        default_settings={
            "interface": "mzwg0",
            "work_dir": "/var/lib/zagros/cores/wireguard",
            "listen": "0.0.0.0",
            "port": 51820,
            "subnet": _DEFAULT_SUBNET,
            "dns_servers": ["1.1.1.1"],
            "advertise_host": "127.0.0.1",
            "mtu": None,
            "use_preshared_keys": True,
            "online_threshold_seconds": 180,
            "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
            "peer_keepalive": 25,
        },
        homepage="https://www.wireguard.com/",
        provides=set(),
        requires=set(),
        # ONE kernel interface per core — the studio manages it as a
        # single-entry listener list (the wizard rewrites that entry).
        studio_inbounds_path="/inbounds",
        studio_max_inbounds=1,
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.wireguard.backend import LocalWireGuardBackend

            backend = LocalWireGuardBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._chain_peers: dict[str, DesiredPeer] = {}   # system peers (chain ingress)
        self._chain_private = ""
        self._usage = DeltaTracker()
        self._restore_chain_state()
        self._server_private: str | None = None
        self._server_public: str | None = None
        self._last_sync_error: str | None = None

    # ------------------------------------------------------------------ #
    # desired-state rendering + live apply                               #
    # ------------------------------------------------------------------ #
    def _desired_peers(self) -> list[DesiredPeer]:
        peers: list[DesiredPeer] = []
        for account in self._accounts.values():
            if not account.enabled:
                continue
            public_key = account.settings.get("public_key")
            address = account.settings.get("address")
            if not public_key or not address:
                continue  # credentials not provisioned yet — will retry on next sync
            peers.append(DesiredPeer(
                comment=account.account_id,
                public_key=public_key,
                allowed_ips=(address,),
                preshared_key=account.settings.get("preshared_key") or None,
            ))
        peers.extend(self._chain_peers.values())
        return peers

    def render_server_config(self) -> str:
        if self._server_private is None:
            raise CoreError("WireGuard server keys not initialized — start the core first.")
        s = self.settings
        return render_interface(
            private_key=self._server_private,
            address=server_address(s["subnet"]),
            listen_port=int(s["port"]),
            peers=self._desired_peers(),
            # item 12: forwarding + NAT hooks ship by default (full-tunnel
            # client configs are the product default); operators running a
            # bare point-to-point link disable them via enable_nat=false
            forward_nat=bool(s.get("enable_nat", True)),
        )

    async def _publish(self) -> None:
        """Render desired state and push it to the kernel (syncconf live apply).

        Offline-first (alpha.7.2): configuring the core — the studio wizard,
        account provisioning — must NEVER require a running daemon. When the
        interface is down the desired state simply persists; start() renders
        it into the interface config at bring-up."""
        import asyncio

        if self._server_private is None:
            return  # keys never materialized; config lands on start()
        if not await asyncio.to_thread(self._backend.is_running):
            self._last_sync_error = None
            return  # stopped core: state persists, sync happens at start()
        config = self.render_server_config()
        try:
            await asyncio.to_thread(self._backend.sync, config)
            self._last_sync_error = None
        except CoreError as exc:
            self._last_sync_error = str(exc)
            raise

    # ------------------------------------------------------------------ #
    # Config Studio bridge (single-interface engine)
    # ------------------------------------------------------------------ #
    def export_config_document(self) -> dict[str, Any]:
        """Studio seed: the kernel interface modelled as a one-entry inbound
        list (pure settings read; private key never leaves the host — the
        wizard field is write-only, blank = keep the persisted keypair)."""
        s = self.settings
        return {
            "inbounds": [{
                "tag": "wireguard",
                "protocol": "wireguard",
                "listen": s.get("listen") or "0.0.0.0",
                "port": int(s.get("port") or 51820),
                "mtu": s.get("mtu") or None,
                "dns": ", ".join(str(d) for d in (s.get("dns_servers") or [])),
                "address": s.get("subnet") or "10.66.66.0/24",
                "endpoint": s.get("advertise_host") or "",
                "allowed_ips": ", ".join(str(a) for a in (s.get("peer_allowed_ips")
                                                          or ["0.0.0.0/0", "::/0"])),
                "persistent_keepalive": int(s.get("peer_keepalive") or 25),
                "preshared_keys": bool(s.get("use_preshared_keys", True)),
                "public_key": self._server_public or "",
            }],
        }

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Adopt the studio document's single entry as THE interface config."""
        import asyncio

        inbounds = (document or {}).get("inbounds") or []
        if len(inbounds) != 1:
            raise CoreError(
                f"wireguard serves exactly ONE interface; the studio document "
                f"carries {len(inbounds)} inbounds — keep exactly one."
            )
        ib = inbounds[0]
        if str(ib.get("protocol") or "wireguard") != "wireguard":
            raise CoreError(f"a wireguard core cannot host a '{ib.get('protocol')}' listener.")
        s = self.settings
        if ib.get("port") is not None:
            s["port"] = int(ib["port"])
        if ib.get("listen"):
            s["listen"] = str(ib["listen"])
        if ib.get("mtu") not in (None, ""):
            s["mtu"] = int(ib["mtu"])
        if ib.get("dns") is not None:
            s["dns_servers"] = [d.strip() for d in str(ib["dns"]).split(",") if d.strip()]
        if ib.get("address"):
            s["subnet"] = str(ib["address"])
        if ib.get("endpoint") is not None:
            s["advertise_host"] = str(ib["endpoint"])
        if ib.get("allowed_ips") is not None:
            s["peer_allowed_ips"] = [a.strip() for a in str(ib["allowed_ips"]).split(",")
                                     if a.strip()]
        if ib.get("persistent_keepalive") is not None:
            s["peer_keepalive"] = int(ib["persistent_keepalive"])
        if ib.get("preshared_keys") is not None:
            s["use_preshared_keys"] = bool(ib["preshared_keys"])
        # operator-supplied server key (wizard field, blank = keep persisted)
        private = str(ib.get("private_key") or "").strip()
        if private:
            if self._server_private and private == self._server_private:
                pass  # idempotent — no key churn, no restart ripple
            else:
                public = await asyncio.to_thread(self._backend.public_from_private, private)
                self._backend.write_server_private_key(private)
                self._server_private, self._server_public = private, public
                logger.info("wireguard: server private key replaced via studio.")
        if self._server_private is None:
            # Materialize the server identity at CONFIGURE time, not at start
            # time: the export (and the user's config delivery) shows the
            # public key immediately, and building the inbound never needs a
            # running core. Key math is pure python — no wireguard-tools
            # required on the host for this step.
            self._server_private, self._server_public = await asyncio.to_thread(
                self._backend.ensure_server_keys
            )
            logger.info("wireguard: server keypair materialized via studio (pre-start).")
        await self._publish()

    async def start(self) -> None:
        import asyncio

        self._server_private, self._server_public = await asyncio.to_thread(
            self._backend.ensure_server_keys
        )
        await asyncio.to_thread(self._backend.up, self.render_server_config())

    async def stop(self) -> None:
        import asyncio

        await asyncio.to_thread(self._backend.down)

    async def status(self) -> CoreStatus:
        import asyncio

        running = await asyncio.to_thread(self._backend.is_running)
        health = HealthStatus.UNKNOWN
        version: str | None = None
        metrics = None
        if running:
            version = await asyncio.to_thread(self._backend.version)
            metrics = await asyncio.to_thread(self._backend.metrics)
            sessions = await self.get_online_devices()
            metrics.active_sessions = len(sessions)
            health = HealthStatus.DEGRADED if self._last_sync_error else HealthStatus.HEALTHY
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=health,
            core_version=version,
            metrics=metrics,
            message=self._last_sync_error,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        import asyncio

        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def install(self) -> None:
        import asyncio

        if not await asyncio.to_thread(self._backend.is_installed):
            await asyncio.to_thread(self._backend.install_packages)

    async def uninstall(self, purge: bool = False) -> None:
        await self.stop()

    # ------------------------------------------------------------------ #
    # credential provisioning helpers                                    #
    # ------------------------------------------------------------------ #
    def _taken_addresses(self) -> set[str]:
        taken = {
            a.settings["address"]
            for a in self._accounts.values()
            if a.settings.get("address")
        }
        for peer in self._chain_peers.values():
            taken.update(peer.allowed_ips)
        return taken

    async def _provision_keys(self, account: UserAccount) -> None:
        """Generate whatever secret material is missing (writes in place).

        Called before peer registration; the service layer persists the
        mutated account afterwards (documented contract in BaseCoreDriver).
        """
        import asyncio

        s = account.settings
        if not (s.get("private_key") and s.get("public_key")):
            private, public = await asyncio.to_thread(self._backend.generate_keypair)
            s["private_key"], s["public_key"] = private, public
        if not is_valid_key(s["public_key"]):
            raise CoreError(f"invalid wireguard public key for '{account.account_id}'.")
        if self.settings["use_preshared_keys"] and not s.get("preshared_key"):
            s["preshared_key"] = await asyncio.to_thread(self._backend.generate_preshared)
        if not s.get("address"):
            s["address"] = allocate_address(self.settings["subnet"], self._taken_addresses())

    # ------------------------------------------------------------------ #
    # user management                                                    #
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol != "wireguard":
            raise CoreError(
                f"WireGuard core only serves protocol 'wireguard', got '{protocol}'."
            )

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        await self._provision_keys(account)
        self._accounts[account.account_id] = account
        await self._publish()

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        await self._provision_keys(account)
        previous = self._accounts.get(account.account_id)
        if previous is not None and previous.settings.get("public_key") !=                 account.settings.get("public_key"):
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
            await self._publish()  # peer leaves the config live via syncconf

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})
        await self._publish()

    async def rotate_credentials(self, account: UserAccount) -> UserAccount:
        import asyncio

        existing = self._accounts.get(account.account_id)
        if existing is None:
            raise CoreError(f"cannot rotate unknown wireguard peer '{account.account_id}'.")
        private, public = await asyncio.to_thread(self._backend.generate_keypair)
        updates: dict[str, Any] = {"private_key": private, "public_key": public}
        if self.settings["use_preshared_keys"]:
            updates["preshared_key"] = await asyncio.to_thread(self._backend.generate_preshared)
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
        self._accounts = {a.account_id: a for a in accounts}
        await self._publish()

    # ------------------------------------------------------------------ #
    # statistics                                                         #
    # ------------------------------------------------------------------ #
    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        import asyncio

        dump = await asyncio.to_thread(self._backend.dump)
        by_key = {
            a.settings.get("public_key"): a.account_id
            for a in self._accounts.values()
        }
        records: list[UsageRecord] = []
        for peer in dump.peers:
            account_id = by_key.get(peer.public_key)
            if account_id is None:
                continue  # system chain peers / foreign peers — never billed to users
            if account_ids is not None and account_id not in account_ids:
                continue
            up, down = self._usage.observe(peer.public_key, peer.transfer_rx, peer.transfer_tx)
            records.append(UsageRecord(
                core_id=self.metadata.id,
                account_id=account_id,
                uplink_bytes=up,       # transfer-rx = client → server
                downlink_bytes=down,   # transfer-tx = server → client
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
        by_key = {
            a.settings.get("public_key"): a.account_id
            for a in self._accounts.values()
        }
        sessions: list[DeviceSession] = []
        for peer in dump.peers:
            account_id = by_key.get(peer.public_key)
            if account_id is None:
                continue
            if account_ids is not None and account_id not in account_ids:
                continue
            if peer.latest_handshake <= 0 or now - peer.latest_handshake > threshold:
                continue  # configured but not currently alive
            endpoint_host = (peer.endpoint or "").rsplit(":", 1)[0] or None
            sessions.append(DeviceSession(
                core_id=self.metadata.id,
                account_id=account_id,
                ip=endpoint_host,
                connected_at=datetime.fromtimestamp(peer.latest_handshake, tz=timezone.utc),
                metadata={
                    "endpoint": peer.endpoint,
                    "allowed_ips": list(peer.allowed_ips),
                    "latest_handshake_age_seconds": now - peer.latest_handshake,
                    "session_rx_bytes": peer.transfer_rx,
                    "session_tx_bytes": peer.transfer_tx,
                },
            ))
        return sessions

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only) + QR                          #
    # ------------------------------------------------------------------ #
    def render_client_profile(self, account: UserAccount) -> str:
        self._ensure_supported(account.protocol)
        s = account.settings
        if self._server_public is None:
            raise CoreError("WireGuard server keys not initialized — start the core first.")
        for key in ("private_key", "address"):
            if not s.get(key):
                raise CoreError(f"wireguard account '{account.account_id}' is missing '{key}'.")
        cfg = self.settings
        return render_client(
            private_key=s["private_key"],
            address=s["address"],
            server_public_key=self._server_public,
            endpoint_host=cfg["advertise_host"],
            endpoint_port=int(cfg["port"]),
            preshared_key=s.get("preshared_key") or None,
            dns=list(cfg["dns_servers"]),
            mtu=cfg.get("mtu"),
            allowed_ips=tuple(cfg.get("peer_allowed_ips") or ("0.0.0.0/0", "::/0")),
            persistent_keepalive=int(cfg.get("peer_keepalive") or 25),
        )

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """WireGuard delivery: QR-able .conf file + inspectable fields.

        The interface private key intentionally stays inside the file only
        (it is not listed as a field); the server's public key is shown.
        """
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryField,
            DeliveryProfile,
            DeliverySection,
        )

        profile_text = self.render_client_profile(account)
        cfg = self.settings
        fields = [
            DeliveryField(key="address", label="Address", value=str(account.settings["address"])),
            DeliveryField(
                key="public_key", label="Server Public Key",
                value=self._server_public or "",
            ),
            DeliveryField(
                key="endpoint", label="Endpoint",
                value=f"{cfg['advertise_host']}:{int(cfg['port'])}",
            ),
            DeliveryField(
                key="dns", label="DNS",
                value=", ".join(str(d) for d in cfg["dns_servers"]),
            ),
            DeliveryField(
                key="allowed_ips", label="Allowed IPs",
                value=", ".join(str(ip) for ip in (
                    cfg.get("peer_allowed_ips") or ("0.0.0.0/0", "::/0"))),
            ),
            DeliveryField(
                key="keepalive", label="Persistent Keepalive",
                value=f"{int(cfg.get('peer_keepalive') or 25)} s",
            ),
        ]
        if cfg.get("mtu"):
            fields.append(DeliveryField(key="mtu", label="MTU", value=str(int(cfg["mtu"]))))
        # peer / key material (alpha.7.2 item 15): the account's OWN public
        # key identifies the peer server-side; a preshared key only exists
        # when the operator enabled them (use_preshared_keys) — secret
        # either way, and honestly absent when never provisioned.
        if account.settings.get("public_key"):
            fields.append(DeliveryField(
                key="client_public_key", label="Client Public Key (peer identity)",
                value=str(account.settings["public_key"]),
            ))
        if account.settings.get("preshared_key"):
            fields.append(DeliveryField(
                key="preshared_key", label="Preshared Key",
                value=str(account.settings["preshared_key"]), secret=True,
            ))
        section = DeliverySection(
            protocol="wireguard",
            title=f"{self.metadata.name} · WireGuard",
            engine="wireguard",
            inbound_tag="wireguard",
            artifacts=[
                DeliveryArtifact(
                    kind=ArtifactKind.FILE,
                    label="WireGuard configuration",
                    content=profile_text,
                    filename=f"{account.username}-wireguard.conf",
                    mime="text/plain",
                    qr=True,
                ),
                DeliveryArtifact(
                    kind=ArtifactKind.FIELDS, label="Connection details", fields=fields,
                ),
                DeliveryArtifact(
                    kind=ArtifactKind.NOTE,
                    label="How to connect",
                    note="Scan the QR code (or import the .conf file) with the "
                         "WireGuard app. The interface private key only ever "
                         "lives inside the file — it is not shown as a field.",
                ),
            ],
        )
        return DeliveryProfile(core_id=self.metadata.id, sections=[section])

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        profile = self.render_client_profile(account)
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="wireguard",
            engine="wireguard",
            payload={"format": "ini", "profile": profile},
            display_name=f"WireGuard ({self.settings['interface']})",
        )

    def client_config_qr(self, account: UserAccount, *, as_ascii: bool = False) -> str:
        """QR code of the sealed client profile (SVG by default).

        The profile contains private keys — it must only ever travel through
        the sealed delivery channel, exactly like ClientConfig.payload.
        """
        matrix = encode_matrix(self.render_client_profile(account), level=EccLevel.MEDIUM)
        if as_ascii:
            from app.cores.qr import to_ascii

            return to_ascii(matrix)
        return to_svg(matrix)

    # ------------------------------------------------------------------ #
    # chain ingress — real wireguard-to-wireguard peering                #
    # ------------------------------------------------------------------ #
    _CHAIN_STATE_FILE = "chain-peers.json"

    def _chain_state_path(self) -> str:
        import os

        return os.path.join(self.settings["work_dir"], self._CHAIN_STATE_FILE)

    def _restore_chain_state(self) -> None:
        """Reload the chain peer provisioned before a panel restart."""
        import json
        import logging
        import os

        path = self._chain_state_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as fh:
                state = json.load(fh)
            self._chain_peers["_zg-chain"] = DesiredPeer(
                comment="_zg-chain",
                public_key=state["public_key"],
                allowed_ips=tuple(state["allowed_ips"]),
            )
            self._chain_private = state["private_key"]
        except (OSError, KeyError, ValueError) as exc:
            logging.getLogger("zagros.cores.drivers.wireguard").warning(
                "wireguard: could not restore chain peer state (%s) — a fresh "
                "peer is provisioned on the next chain deployment.", exc,
            )

    def _persist_chain_state(self) -> None:
        import json
        import logging
        import os

        peer = self._chain_peers.get("_zg-chain")
        if peer is None:
            return
        path = self._chain_state_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({
                    "public_key": peer.public_key,
                    "private_key": self._chain_private,
                    "allowed_ips": list(peer.allowed_ips),
                }, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError as exc:
            logging.getLogger("zagros.cores.drivers.wireguard").warning(
                "wireguard: chain peer state could not be persisted (%s) — "
                "chains survive runtime but not panel restarts.", exc,
            )

    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        if self._server_public is None or "_zg-chain" not in self._chain_peers:
            return []
        peer = self._chain_peers["_zg-chain"]
        return [self._chain_endpoint_for(peer)]

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        if protocol != "wireguard":
            raise CoreError(
                f"WireGuard cannot host a '{protocol}' chain endpoint — it only "
                f"accepts real wireguard peers (protocol='wireguard')."
            )
        existing = self._chain_peers.get("_zg-chain")
        if existing is None:
            import asyncio

            private, public = await asyncio.to_thread(self._backend.generate_keypair)
            address = allocate_address(self.settings["subnet"], self._taken_addresses())
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
            raise CoreError("WireGuard server is not running — no chain endpoint yet.")
        address = peer.allowed_ips[0]
        return ChainEndpoint(
            core_id=self.metadata.id,
            protocol="wireguard",
            host=self.settings["advertise_host"],
            port=int(self.settings["port"]),
            network="udp",
            requires_credentials=True,
            metadata={
                # consumed by the source core's native wireguard outbound
                # translator (contract keys — see OutboundManager._METADATA_KEYS)
                "private_key": self._chain_private,
                "peer_public_key": self._server_public,
                "local_address": [address],
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            },
        )
