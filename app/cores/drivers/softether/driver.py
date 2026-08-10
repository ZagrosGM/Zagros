"""SoftEtherDriver — SoftEther VPN Server as a first-class panel core.

Real capabilities used (via the official vpncmd management interface):
  * **User management**: UserCreate/UserDelete/UserPasswordSet — applied
    instantly to the live server (SoftEther has true runtime management;
    HOT_RELOAD is honest here).
  * **Suspend**: native per-user expiration switched to a fixed past date
    (``UserExpiresSet 2000/01/01``) + live sessions disconnected;
    resume restores the account's real (or none) expiration.
  * **Usage accounting**: per-user cumulative counters from ``UserGet``
    (Incoming/Outgoing total sizes; direction convention documented in
    setool.py) → DeltaTracker deltas.
  * **Online + device detection**: ``SessionList`` per user — source host
    names/IPs are real device identity signals (SE client reports hostname).
  * **Kick**: SessionDisconnect on suspend/delete — the cut is immediate.
  * **Client config**: L2TP/IPsec and SSTP/OpenVPN-clone transports are the
    protocol's client surface; the sealed payload carries the L2TP/IPsec
    parameters (+ note when an admin password-less PSK is configured).

Honestly NOT claimed (documented):
  * SELF_INSTALL — SoftEther has no distribution package in standard repos;
    install docs are referenced instead of fragile scripted downloads.
  * ROUTING / OUTBOUND_MANAGEMENT / CHAIN ingress — the hub forwards at L2;
    it cannot select per-connection egress or dial upstream proxies.
  * CLIENT-config for WireGuard — SE does not speak WireGuard. (The app's
    engine matrix covers the SE exports: openvpn-clone / l2tp / sstp.)
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import AsyncIterator
from typing import Any, ClassVar

logger = logging.getLogger("zagros.cores.drivers.softether")

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.stats import DeltaTracker
from app.cores.types import (
    Capability,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    UsageRecord,
    UserAccount,
)


class SoftEtherDriver(BaseCoreDriver):
    """Driver for SoftEther VPN Server (vpncmd-managed hub)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="softether",
        name="SoftEther VPN",
        description=(
            "SoftEther stable server: native SoftEther, L2TP/IPsec, raw L2TP, "
            "EtherIP, SSTP and OpenVPN compatibility with live vpncmd user, "
            "session and traffic management. PPTP is not implemented upstream."
        ),
        protocols=["softether", "l2tp", "l2tp_raw", "etherip", "sstp", "ovpn"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.DEVICE_DETECTION,
            Capability.HOT_RELOAD,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
            Capability.SELF_INSTALL,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string", "default": "vpncmd"},
                "server": {"type": "string", "default": "localhost"},
                "hub": {"type": "string", "default": "DEFAULT"},
                "admin_password": {"type": "string"},
                "ipsec_psk": {"type": "string", "minLength": 1, "maxLength": 128},
                "native_port": {"type": "integer", "default": 5555},
                "ovpn_ports": {"type": "string", "default": "1194"},
                "advertise_host": {"type": "string"},
            },
        },
        default_settings={
            "executable_path": "vpncmd",
            "server": "localhost",
            "hub": "DEFAULT",
            "admin_password": "",
            "ipsec_psk": "",
            "native_port": 5555,
            "ovpn_ports": "1194",
            "feature_softether": False,
            "feature_l2tp": False,
            "feature_l2tp_raw": False,
            "feature_etherip": False,
            "feature_sstp": False,
            "feature_ovpn": False,
            "advertise_host": "127.0.0.1",
        },
        homepage="https://www.softether.org/",
        provides=set(),
        requires=set(),
    # hub features are listener-shaped but MANY-valued: each studio
    # inbound entry = one hub capability (l2tp/sstp/pptp) driven by a
    # real vpncmd verb on apply. The OpenVPN clone is delivered as
    # client-config facts only — vpncmd 5.02 has no toggle verb for it.
        studio_inbounds_path="/inbounds",
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.softether.backend import LocalSoftEtherBackend

            backend = LocalSoftEtherBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._usage = DeltaTracker()
        self._suspended_expire_restore: dict[str, str | None] = {}

    # ------------------------------------------------------------------ #
    # Config Studio bridge — every offered entry maps to a REAL stable-line
    # vpncmd capability. PPTP is not a SoftEther protocol. EtherIP remains
    # Advanced-only because a usable setup additionally needs per-router
    # EtherIpClientAdd mappings (a bare enable switch would be misleading).
    # ------------------------------------------------------------------ #
    _STUDIO_FEATURES = {"softether", "l2tp", "l2tp_raw", "etherip", "sstp", "ovpn"}

    def export_config_document(self) -> dict[str, Any]:
        """Current enabled feature set. An unconfigured hub exports an EMPTY
        list — never an invented blank L2TP inbound. That phantom entry was
        why creating SSTP/native incorrectly failed L2TP PSK validation."""
        s = self.settings
        inbounds: list[dict[str, Any]] = []
        if s.get("feature_softether"):
            inbounds.append({"tag": "softether", "protocol": "softether",
                             "port": int(s.get("native_port") or 5555), "transport": "tcp"})
        if s.get("feature_l2tp"):
            inbounds.append({
                "tag": "l2tp", "protocol": "l2tp", "port": 1701,
                "ipsec_psk": "", "has_ipsec_psk": bool(s.get("ipsec_psk")),
            })
        if s.get("feature_l2tp_raw"):
            inbounds.append({"tag": "l2tp-raw", "protocol": "l2tp_raw", "port": 1701})
        if s.get("feature_etherip"):
            inbounds.append({"tag": "etherip", "protocol": "etherip", "port": 0})
        if s.get("feature_sstp"):
            inbounds.append({"tag": "sstp", "protocol": "sstp", "port": 443})
        if s.get("feature_ovpn"):
            inbounds.append({"tag": "softether-openvpn", "protocol": "ovpn",
                             "port": int(str(s.get("ovpn_ports") or "1194").split(",")[0]),
                             "transport": "udp"})
        return {"inbounds": inbounds}

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Converge hub features to the document via real vpncmd verbs:
        IPsecEnable (full 5-arg form) / ListenerCreate / ListenerDelete.

        Every entry maps to a server-side effect; entries with unknown
        protocols or missing required fields (the L2TP pre-shared key)
        fail loudly BEFORE anything is commanded."""
        inbounds = (document or {}).get("inbounds") or []
        if not inbounds:
            raise CoreError(
                "an empty SoftEther feature set disconnects every client — "
                "keep at least one feature inbound."
            )
        s = self.settings
        hub = s["hub"]
        wanted: dict[str, dict[str, Any]] = {}
        for ib in inbounds:
            proto = str(ib.get("protocol") or "")
            if proto == "pptp":
                raise CoreError(
                    "SoftEther does not implement PPTP. Use L2TP/IPsec, SSTP, "
                    "OpenVPN compatibility, or the native SoftEther protocol."
                )
            if proto not in self._STUDIO_FEATURES:
                raise CoreError(
                    f"SoftEther has no hub feature '{proto}' "
                    f"({sorted(self._STUDIO_FEATURES)})."
                )
            wanted[proto] = ib

        if not await asyncio.to_thread(self._backend.reachable):
            raise CoreError(
                "SoftEther hub is not reachable right now — Start the core "
                "first; feature changes need a live vpncmd."
            )

        # IPsec family is one atomic vpncmd setting. Only L2TP/IPsec consumes
        # a user-facing PSK in the simple wizard. Raw L2TP has no IPsec layer;
        # EtherIP is Advanced-only and reuses the server's existing IPsec key.
        try:
            current = await asyncio.to_thread(self._backend.ipsec_get)
        except (CoreError, AttributeError):
            current = None
        l2tp = "l2tp" in wanted
        l2tp_raw = "l2tp_raw" in wanted
        etherip = "etherip" in wanted
        supplied_psk = str(wanted.get("l2tp", {}).get("ipsec_psk") or "").strip()
        stored_psk = str(s.get("ipsec_psk") or "").strip()
        current_psk = current.psk if current else ""
        # Enabling L2TP honours the wizard/stored admin choice. Disabling the
        # IPsec family carries the server's CURRENT PSK to avoid clobbering a
        # value changed out-of-band.
        psk = (supplied_psk or stored_psk or current_psk) if l2tp \
            else (current_psk or stored_psk)
        if l2tp and not psk:
            raise CoreError("L2TP/IPsec needs a non-empty pre-shared key (ipsec_psk).")
        # IPsecEnable's CLI parser requires /PSK even when only raw L2TP is
        # enabled or all services are disabled. This value is inert unless an
        # IPsec-backed feature is on; it is never presented as a PPTP/SSTP PSK.
        command_psk = psk or "zagrosoff"  # 9 chars: stable vpncmd's PSK maximum
        target_changed = current is None or (
            current.l2tp != l2tp or current.l2tp_raw != l2tp_raw
            or current.etherip != etherip
        )
        if target_changed:
            await asyncio.to_thread(
                self._backend.ipsec_services_set,
                l2tp=l2tp, l2tp_raw=l2tp_raw, etherip=etherip,
                psk=command_psk,
                default_hub=(current.default_hub if current else "") or hub,
            )
        if l2tp and psk:
            s["ipsec_psk"] = psk
        s["feature_l2tp"] = l2tp
        s["feature_l2tp_raw"] = l2tp_raw
        s["feature_etherip"] = etherip

        async def command(command: str, *, ignore_exists: bool = False) -> None:
            try:
                await asyncio.to_thread(self._backend._cmd, command, hub=False)  # noqa: SLF001
            except CoreError as exc:
                text = str(exc).lower()
                if ignore_exists and any(marker in text for marker in
                                         ("exist", "already", "not found", "not exist")):
                    return
                raise

        # Native SoftEther is a TCP listener, independently managed.
        if "softether" in wanted:
            native_port = int(wanted["softether"].get("port") or 5555)
            await command(f"ListenerCreate {native_port}", ignore_exists=True)
            old_native = int(s.get("native_port") or native_port)
            if s.get("feature_softether") and old_native != native_port:
                await command(f"ListenerDelete {old_native}", ignore_exists=True)
            s["native_port"] = native_port
            s["feature_softether"] = True
        else:
            if s.get("feature_softether"):
                await command(f"ListenerDelete {int(s.get('native_port') or 5555)}",
                              ignore_exists=True)
            s["feature_softether"] = False

        # SSTP/OpenVPN are real stable-line protocol switches. ListenerCreate
        # alone does NOT turn a port into PPTP/SSTP (the prior implementation
        # did exactly that); PPTP is absent because SoftEther does not support it.
        sstp = "sstp" in wanted
        if sstp != bool(s.get("feature_sstp")):
            await command(f"SstpEnable {'yes' if sstp else 'no'}")
        if sstp:
            await command("ListenerCreate 443", ignore_exists=True)
        s["feature_sstp"] = sstp

        ovpn = "ovpn" in wanted
        ovpn_port = int(wanted.get("ovpn", {}).get("port") or 1194)
        if ovpn != bool(s.get("feature_ovpn")) or (
                ovpn and str(s.get("ovpn_ports") or "1194") != str(ovpn_port)):
            await command(f"OpenVpnEnable {'yes' if ovpn else 'no'} /PORTS:{ovpn_port}")
        s["feature_ovpn"] = ovpn
        s["ovpn_ports"] = str(ovpn_port)

    # ------------------------------------------------------------------ #
    # lifecycle — the server is external/systemd-owned; we verify reachability
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        if await asyncio.to_thread(self._backend.reachable):
            return
        # not reachable: if the binaries exist (systemd-less container), bring
        # the daemon up ourselves once, honestly re-check, then decide
        server_start = getattr(self._backend, "server_start", None)
        if callable(server_start) and getattr(self._backend, "server_binary", lambda: None)() is not None:
            await asyncio.to_thread(server_start)
            for _ in range(10):
                await asyncio.sleep(0.5)
                if await asyncio.to_thread(self._backend.reachable):
                    return
        raise CoreError(
            f"SoftEther hub '{self.settings['hub']}' unreachable via vpncmd "
            f"at {self.settings['server']} — press Install first or check "
            f"server/credentials."
        )

    async def stop(self) -> None:
        # the VPN server stays up (system-owned); accounts remain provisioned
        pass

    async def status(self) -> CoreStatus:
        reachable = await asyncio.to_thread(self._backend.reachable)
        sessions = []
        if reachable:
            try:
                sessions = await self.get_online_devices()
            except CoreError:
                reachable = True  # reachability degrades separately
        from app.cores.types import CoreMetrics

        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if reachable else CoreState.STOPPED,
            health=HealthStatus.HEALTHY if reachable else HealthStatus.UNHEALTHY,
            metrics=CoreMetrics(
                active_accounts=len(self._accounts), active_sessions=len(sessions)
            ) if reachable else None,
            message=None if reachable else "vpncmd cannot reach the hub.",
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        # hub logs are the server's own logs; nothing panel-side to stream
        return
        yield  # pragma: no cover - keeps this an async generator

    async def install(self) -> None:
        """Real install: apt when shipped by the distro, else the official
        GitHub release (vpnserver + vpncmd + hamcore.se2), then a first
        daemon start so the hub answers right away."""
        detail = await asyncio.to_thread(self._backend.install_packages)
        logger.info("softether %s", detail)
        if not await asyncio.to_thread(self._backend.reachable):
            try:
                await asyncio.to_thread(self._backend.server_start)
            except Exception as exc:  # noqa: BLE001 — install still valid
                logger.warning("softether installed but first start failed: %s", exc)
        for _ in range(10):
            await asyncio.sleep(0.5)
            if await asyncio.to_thread(self._backend.reachable):
                break

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol not in self.metadata.protocols:
            raise CoreError(
                f"SoftEther core serves {self.metadata.protocols}, got '{protocol}'."
            )

    def _ensure_credentials(self, account: UserAccount) -> None:
        if not account.settings.get("password"):
            raise CoreError(f"SoftEther account '{account.account_id}' needs settings.password.")

    def _provision_credentials(self, account: UserAccount) -> None:
        """alpha.7.2 (item 10): a password-less SoftEther account must NEVER
        fail provisioning — mint a secure random password in place (the
        apply_grants registry persists it like SSH/OpenVPN)."""
        if not account.settings.get("password"):
            account.settings = dict(account.settings)
            account.settings["password"] = secrets.token_urlsafe(18)

    async def _kick_user_sessions(self, account_id: str) -> None:
        try:
            for session in await asyncio.to_thread(self._backend.session_list):
                if session.username == account_id:
                    await asyncio.to_thread(self._backend.session_disconnect,
                                            session.session_name)
        except CoreError:
            pass  # server momentarily unreachable; expiry/auth still blocks access

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        existing = await asyncio.to_thread(self._backend.user_list)
        if account.account_id not in existing:
            await asyncio.to_thread(self._backend.user_create, account.account_id,
                                    account.username)
        await asyncio.to_thread(self._backend.user_password_set, account.account_id,
                                str(account.settings["password"]))
        self._accounts[account.account_id] = account
        if account.enabled:
            await asyncio.to_thread(self._backend.user_expires_set, account.account_id, None)
        else:
            await asyncio.to_thread(self._backend.suspend_user, account.account_id)
            await self._kick_user_sessions(account.account_id)

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        previous = self._accounts.get(account.account_id)
        if previous is None or account.account_id not in (
                await asyncio.to_thread(self._backend.user_list)):
            await self.create_account(account)
            return
        if previous.settings.get("password") != account.settings.get("password"):
            await asyncio.to_thread(self._backend.user_password_set, account.account_id,
                                    str(account.settings["password"]))
            await self._kick_user_sessions(account.account_id)
        self._accounts[account.account_id] = account
        if account.enabled:
            await asyncio.to_thread(self._backend.user_expires_set, account.account_id, None)
        else:
            await asyncio.to_thread(self._backend.suspend_user, account.account_id)
            await self._kick_user_sessions(account.account_id)

    async def delete_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
        self._usage.forget(account_id)
        try:
            await asyncio.to_thread(self._backend.user_list)
        except CoreError:
            return  # server down; local desired state already updated
        await self._kick_user_sessions(account_id)
        await asyncio.to_thread(self._backend.user_delete, account_id)

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await asyncio.to_thread(self._backend.suspend_user, account_id)
            await self._kick_user_sessions(account_id)

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})
        await asyncio.to_thread(self._backend.user_expires_set, account.account_id, None)

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        desired = {a.account_id: a for a in accounts}
        current = set(await asyncio.to_thread(self._backend.user_list))
        stale = (current & set(self._accounts)) - set(desired)
        for account_id in stale:
            await asyncio.to_thread(self._backend.user_delete, account_id)
        for account in accounts:
            await self.create_account(account)

    # ------------------------------------------------------------------ #
    # statistics — native per-user counters + live sessions
    # ------------------------------------------------------------------ #
    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        wanted = account_ids if account_ids is not None else list(self._accounts)
        records: list[UsageRecord] = []
        for account_id in wanted:
            if account_id not in self._accounts:
                continue
            try:
                stats = await asyncio.to_thread(self._backend.user_get, account_id)
            except CoreError:
                continue  # user vanished server-side; nothing to report
            up, down = self._usage.observe(
                account_id, stats.incoming_bytes, stats.outgoing_bytes
            )
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=account_id,
                uplink_bytes=up, downlink_bytes=down,
            ))
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        sessions = await asyncio.to_thread(self._backend.session_list)
        out: list[DeviceSession] = []
        for session in sessions:
            account_id = session.username
            if account_id not in self._accounts:
                continue
            if account_ids is not None and account_id not in account_ids:
                continue
            host = session.source_host or None
            out.append(DeviceSession(
                core_id=self.metadata.id,
                account_id=account_id,
                ip=host,
                metadata={
                    "session_name": session.session_name,
                    "hostname": host,
                    "stable_id": f"se-{account_id}-{host}" if host else None,
                    "transport": session.raw.get("Session Mode") or None,
                },
            ))
        return out

    # ------------------------------------------------------------------ #
    # delivery (item 15): every granted compat transport, honestly
    # ------------------------------------------------------------------ #

    #: per-transport presentation facts — ports mirror EXACTLY what
    #: apply_studio_document converges on the hub (no invented settings).
    _TRANSPORTS = {
        "softether": {"catalog_tag": "softether", "title": "Native SoftEther VPN",
                       "port": None, "feature": "feature_softether", "needs_psk": False},
        "l2tp": {"catalog_tag": "l2tp", "title": "VPN (L2TP/IPsec)",
                 "port": "UDP 500 · 4500 · 1701", "feature": "feature_l2tp",
                 "needs_psk": True},
        "l2tp_raw": {"catalog_tag": "l2tp-raw", "title": "VPN (raw L2TP; unencrypted)",
                      "port": "1701/udp", "feature": "feature_l2tp_raw", "needs_psk": False},
        "etherip": {"catalog_tag": "etherip", "title": "EtherIP / L2TPv3 over IPsec",
                    "port": "UDP 500 · 4500", "feature": "feature_etherip", "needs_psk": False},
        "sstp": {"catalog_tag": "sstp", "title": "VPN (SSTP)",
                 "port": "443/tcp", "feature": "feature_sstp", "needs_psk": False},
        "ovpn": {"catalog_tag": "softether-openvpn", "title": "VPN (OpenVPN compatibility)",
                 "port": None, "feature": "feature_ovpn", "needs_psk": False},
    }

    def _granted_transports(self, account: UserAccount) -> list[str]:
        """Grant-aware transport view (same convention as sing-box/ssh):
        inbound_tags whitelists, excluded_inbounds blacklists; catalog
        tags are l2tp/sstp/pptp/softether; default = every transport."""
        wanted = set(account.settings.get("inbound_tags") or [])
        excluded = set(account.settings.get("excluded_inbounds") or [])
        out = []
        for proto, facts in self._TRANSPORTS.items():
            tag = facts["catalog_tag"]
            if wanted and tag not in wanted:
                continue
            if tag in excluded:
                continue
            out.append(proto)
        return out

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """SoftEther delivery (item 15): one section per GRANTED compat
        transport — L2TP/IPsec (+PSK), SSTP, PPTP and the OpenVPN clone —
        with full connection fields. Missing server facts (advertise_host,
        an unset IPsec PSK, a disabled hub feature) become honest NOTE
        artifacts instead of failing the whole delivery."""
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryField,
            DeliveryProfile,
            DeliverySection,
        )

        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        s = self.settings
        server = s.get("advertise_host")
        password = str(account.settings["password"])
        profile = DeliveryProfile(core_id=self.metadata.id)

        for proto in self._granted_transports(account):
            facts = self._TRANSPORTS[proto]
            if facts["port"]:
                port = facts["port"]
            elif proto == "ovpn":
                port = f"{str(s.get('ovpn_ports') or '1194').split(',')[0].strip()}/udp"
            else:
                port = f"{int(s.get('native_port') or 5555)}/tcp"
            fields = [
                DeliveryField(key="host", label="Server",
                              value=str(server) if server else "—"),
                DeliveryField(key="port", label="Port", value=port),
                DeliveryField(key="username", label="Username",
                              value=account.account_id),
                DeliveryField(key="password", label="Password",
                              value=password, secret=True),
                DeliveryField(key="hub", label="Virtual Hub",
                              value=str(s["hub"])),
            ]
            notes: list[str] = []
            if facts["needs_psk"]:
                psk = str(s.get("ipsec_psk") or "")
                if psk:
                    fields.append(DeliveryField(key="ipsec_psk",
                                                label="IPsec Pre-Shared Key",
                                                value=psk, secret=True))
                else:
                    notes.append("L2TP/IPsec needs a pre-shared key — the admin "
                                 "must set ipsec_psk (studio → SoftEther → L2TP) "
                                 "before clients can connect.")
            if not server:
                notes.append("The server address is not configured yet "
                             "(settings.advertise_host) — clients cannot dial "
                             "until the admin sets it.")
            if proto == "etherip":
                notes.append("EtherIP also needs an EtherIpClientAdd router identity "
                             "mapping; enabling the server bit alone is not a usable tunnel.")
            if not s.get(facts["feature"]):
                notes.append(f"The '{proto}' feature is currently OFF on the hub "
                             "— enable it in the SoftEther studio document.")
            artifacts: list[DeliveryArtifact] = [
                DeliveryArtifact(kind=ArtifactKind.FIELDS, label=facts["title"],
                                 fields=tuple(fields)),
            ]
            for text in notes:
                artifacts.append(DeliveryArtifact(
                    kind=ArtifactKind.NOTE, label="Attention", note=text))
            profile.sections.append(DeliverySection(
                protocol=proto, title=f"{self.metadata.name} · {facts['title']}",
                engine="softether", inbound_tag=facts["catalog_tag"],
                artifacts=artifacts,
            ))
        if not profile.sections:
            profile.sections.append(DeliverySection(
                protocol=account.protocol,
                title=self.metadata.name, engine="softether",
                artifacts=[DeliveryArtifact(
                    kind=ArtifactKind.NOTE, label="No transports granted",
                    note="No SoftEther transport is assigned to this account — "
                         "select one in the user's core access.")],
            ))
        return profile

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        s = self.settings
        server = s.get("advertise_host")
        password = str(account.settings["password"])
        if account.protocol == "sstp":
            if not server:
                raise CoreError(
                    "SSTP client config requires settings.advertise_host — clients "
                    "dial the SSTP TLS endpoint by hostname."
                )
            return ClientConfig(
                core_id=self.metadata.id,
                protocol="sstp",
                engine="sstp",
                payload={
                    "format": "sstp",
                    "server": server,
                    "port": 443,
                    "username": account.account_id,
                    "password": password,
                    "hub": s["hub"],
                    "note": "SSTP listener must be enabled on the SoftEther server "
                            "(SecureNAT/Listener 443 or your SSTP port).",
                },
                display_name="VPN (SSTP)",
            )
        if account.protocol == "pptp":
            if not server:
                raise CoreError(
                    "PPTP client config requires settings.advertise_host — clients "
                    "dial the PPTP endpoint by address."
                )
            return ClientConfig(
                core_id=self.metadata.id,
                protocol="pptp",
                engine="pptp",
                payload={
                    "format": "pptp",
                    "server": server,
                    "port": 1723,
                    "username": account.account_id,
                    "password": password,
                    "hub": s["hub"],
                    "note": "PPTP is served by SoftEther's L2TP/PPTP compatible mode; "
                            "enable it in the server's IPsec/L2TP settings.",
                },
                display_name="VPN (PPTP)",
            )
        if account.protocol == "ovpn":
            if not server:
                raise CoreError(
                    "OpenVPN-clone client config requires settings.advertise_host."
                )
            return ClientConfig(
                core_id=self.metadata.id,
                protocol="ovpn",
                engine="openvpn-clone",
                payload={
                    "format": "openvpn-clone",
                    "server": server,
                    "port": int(str(s.get("ovpn_ports")
                                    or "1194").split(",")[0].strip() or 1194),
                    "username": account.account_id,
                    "password": password,
                    "hub": s["hub"],
                    "note": "SoftEther's OpenVPN-clone listener — the clone is "
                            "toggled ONLY by SoftEther Server Manager (vpncmd "
                            "5.02 has no verb); make sure the operator enabled "
                            "it there, then import with any OpenVPN client.",
                },
                display_name="VPN (OpenVPN clone)",
            )
        # l2tp (default) — IPsec/L2TP needs the hub's pre-shared key
        if not s.get("ipsec_psk"):
            raise CoreError(
                "L2TP/IPsec client config requires settings.ipsec_psk — set the "
                "hub's IPsec pre-shared key first (IPsecEnable)."
            )
        if not server:
            raise CoreError(
                "L2TP/IPsec client config requires settings.advertise_host."
            )
        psk = s["ipsec_psk"]
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="l2tp",
            engine="l2tp-ipsec",
            payload={
                "format": "l2tp-ipsec",
                "server": server,
                "ipsec_psk": psk,
                "username": account.account_id,
                "password": password,
                "hub": s["hub"],
            },
            display_name="VPN (L2TP/IPsec)",
        )
