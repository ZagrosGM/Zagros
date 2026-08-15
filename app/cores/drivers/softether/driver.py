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
from app.cores.types import (
    Capability,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    ListenerClaim,
    UsageRecord,
    UserAccount,
)


class _SoftEtherUsageTracker:
    """Exactly-once merger for delayed UserGet and live SessionGet counters.

    SoftEther can copy active session counters into UserGet on a delayed
    internal tick *before* disconnect. Therefore simply adding both ledgers
    can double bill a 50 MB transfer. This tracker emits the union of their
    deltas: a UserGet increase first absorbs live bytes already emitted from
    SessionGet; only any excess is new completed-session traffic.
    """

    def __init__(self) -> None:
        self._billed: dict[str, tuple[int, int]] = {}
        self._last_user: dict[str, tuple[int, int]] = {}
        self._last_sessions: dict[tuple[str, str], tuple[int, int]] = {}
        self._outstanding: dict[str, tuple[int, int]] = {}
        self._cold_after_restore: set[str] = set()

    def register(self, account_id: str) -> None:
        self._billed.setdefault(account_id, (0, 0))
        self._last_user.setdefault(account_id, (0, 0))
        self._outstanding.setdefault(account_id, (0, 0))

    @staticmethod
    def _delta(current: tuple[int, int], previous: tuple[int, int]) -> tuple[int, int]:
        return (max(0, current[0] - previous[0]),
                max(0, current[1] - previous[1]))

    def observe(
        self,
        account_id: str,
        completed: tuple[int, int],
        live_sessions: dict[str, tuple[int, int]],
    ) -> tuple[int, int]:
        self.register(account_id)
        if account_id in self._cold_after_restore:
            # The persisted baseline is the authoritative already-billed
            # total. Seed volatile session/user cursors from live state; only
            # a completed counter beyond that baseline is immediately new.
            billed = self._billed[account_id]
            emitted = self._delta(completed, billed)
            self._billed[account_id] = (
                billed[0] + emitted[0], billed[1] + emitted[1])
            self._last_user[account_id] = completed
            for session_name, counters in live_sessions.items():
                self._last_sessions[(account_id, session_name)] = counters
            self._outstanding[account_id] = (0, 0)
            self._cold_after_restore.discard(account_id)
            return emitted

        user_delta = self._delta(completed, self._last_user[account_id])
        self._last_user[account_id] = completed

        live_delta = [0, 0]
        current_keys: set[tuple[str, str]] = set()
        for session_name, counters in live_sessions.items():
            key = (account_id, session_name)
            current_keys.add(key)
            previous = self._last_sessions.get(key, (0, 0))
            delta = self._delta(counters, previous)
            live_delta[0] += delta[0]
            live_delta[1] += delta[1]
            self._last_sessions[key] = counters
        for key in [key for key in self._last_sessions
                    if key[0] == account_id and key not in current_keys]:
            self._last_sessions.pop(key, None)

        outstanding = self._outstanding[account_id]
        # UserGet's delayed increase may represent live bytes emitted on a
        # previous poll OR bytes SessionGet exposed for the first time in this
        # same poll. Subtract that overlap once, direction by direction.
        available = (outstanding[0] + live_delta[0],
                     outstanding[1] + live_delta[1])
        overlap = (min(user_delta[0], available[0]),
                   min(user_delta[1], available[1]))
        emitted = (user_delta[0] + live_delta[0] - overlap[0],
                   user_delta[1] + live_delta[1] - overlap[1])
        self._outstanding[account_id] = (
            available[0] - overlap[0], available[1] - overlap[1])
        billed = self._billed[account_id]
        self._billed[account_id] = (
            billed[0] + emitted[0], billed[1] + emitted[1])
        return emitted

    def forget(self, account_id: str) -> None:
        self._billed.pop(account_id, None)
        self._last_user.pop(account_id, None)
        self._outstanding.pop(account_id, None)
        self._cold_after_restore.discard(account_id)
        for key in [key for key in self._last_sessions if key[0] == account_id]:
            self._last_sessions.pop(key, None)

    def baseline_snapshot(
        self, keys: list[object] | None = None,
    ) -> dict[object, tuple[int, int]]:
        if keys is None:
            return dict(self._billed)
        return {key: self._billed[key] for key in keys if key in self._billed}

    def restore(self, baseline: dict[object, tuple[int, int]]) -> None:
        for raw_key, totals in baseline.items():
            key = str(raw_key)
            self._billed[key] = (int(totals[0]), int(totals[1]))
            self._last_user.pop(key, None)
            self._outstanding[key] = (0, 0)
            for session_key in [item for item in self._last_sessions
                                if item[0] == key]:
                self._last_sessions.pop(session_key, None)
            self._cold_after_restore.add(key)


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
                "install_root": {"type": "string",
                                 "default": "/var/lib/zagros/cores/softether/runtime",
                                 "description": "persistent vpnserver root; must survive panel container upgrades"},
                "server": {"type": "string", "default": "localhost"},
                "hub": {"type": "string", "default": "DEFAULT"},
                "admin_password": {"type": "string"},
                "ipsec_psk": {"type": "string", "minLength": 1, "maxLength": 128},
                "native_port": {"type": "integer", "default": 5555},
                "sstp_port": {"type": "integer", "default": 443},
                "ovpn_ports": {"type": "string", "default": "1194"},
                "secure_nat": {"type": "boolean", "default": True,
                               "description": "enable the hub's Virtual NAT + DHCP so remote-access clients receive an IP; policy routing automatically switches NAT to routed TAP while keeping DHCP"},
                "policy_tap_device": {"type": "string", "default": "zgsoft"},
                "policy_subnet": {"type": "string", "default": "192.168.30.0/24"},
                "policy_gateway": {"type": "string", "default": "192.168.30.254"},
                "policy_routing_scope": {
                    "type": "string", "enum": ["shared_hub"],
                    "default": "shared_hub",
                    "description": "all SoftEther transports in this instance share one hub/TAP routing decision"},
                "advertise_host": {"type": "string"},
            },
        },
        default_settings={
            "executable_path": "vpncmd",
            "install_root": "/var/lib/zagros/cores/softether/runtime",
            "server": "localhost",
            "hub": "DEFAULT",
            "admin_password": "",
            "ipsec_psk": "",
            "native_port": 5555,
            "sstp_port": 443,
            "ovpn_ports": "1194",
            "secure_nat": True,
            "policy_tap_device": "zgsoft",
            "policy_subnet": "192.168.30.0/24",
            "policy_gateway": "192.168.30.254",
            "policy_routing_scope": "shared_hub",
            "feature_tags": {},
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
    # inbound entry = one hub capability (l2tp/raw/sstp/ovpn/native) driven by a
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
        self._usage = _SoftEtherUsageTracker()
        self._suspended_expire_restore: dict[str, str | None] = {}
        self._policy_source: dict[str, str] | None = None

    async def listener_claims(self) -> list[ListenerClaim]:
        """Describe configured TCP listeners for host-level collision checks."""
        claims: list[ListenerClaim] = []
        if self.settings.get("feature_sstp"):
            claims.append(ListenerClaim(
                core_id="softether", protocol="sstp", transport="tcp",
                port=int(self.settings.get("sstp_port") or 443),
                label="SoftEther SSTP",
            ))
        if self.settings.get("feature_softether"):
            claims.append(ListenerClaim(
                core_id="softether", protocol="softether", transport="tcp",
                port=int(self.settings.get("native_port") or 5555),
                label="SoftEther native VPN",
            ))
        if self.settings.get("feature_ovpn"):
            for raw in str(self.settings.get("ovpn_ports") or "1194").split(","):
                try:
                    port = int(raw.strip())
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    claims.append(ListenerClaim(
                        core_id="softether", protocol="openvpn-clone",
                        transport="tcp", port=port,
                        label="SoftEther OpenVPN compatibility",
                    ))
        return claims

    def ensure_policy_source(self) -> dict[str, str]:
        """Switch SecureNAT to DHCP+routed TAP and configure its Linux gateway.

        SoftEther's default Virtual NAT creates root-owned host sockets, so
        netfilter never sees a client's source subnet. A TAP local bridge is
        required for real per-service policy routing; this method is invoked
        only when an enabled rule targets a SoftEther inbound.
        """
        import ipaddress
        import shutil
        import subprocess
        import time

        ensure = getattr(self._backend, "routed_tap_ensure", None)
        if not callable(ensure):
            raise CoreError("SoftEther backend has no routed TAP capability")
        device = str(self.settings.get("policy_tap_device") or "zgsoft")
        subnet = str(self.settings.get("policy_subnet") or "192.168.30.0/24")
        gateway = str(self.settings.get("policy_gateway") or "192.168.30.254")
        network = ipaddress.ip_network(subnet, strict=False)
        prefix = network.prefixlen
        interface = ensure(device=device, subnet=str(network), gateway=gateway)
        ip = shutil.which("ip")
        if not ip:
            raise CoreError("SoftEther routed TAP needs iproute2")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if subprocess.run([ip, "link", "show", "dev", interface],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise CoreError(
                f"SoftEther BridgeCreate succeeded but Linux interface '{interface}' did not appear")
        for argv in (
            [ip, "address", "replace", f"{gateway}/{prefix}", "dev", interface],
            [ip, "link", "set", "dev", interface, "up"],
        ):
            result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            if result.returncode:
                raise CoreError(result.stderr.strip() or f"cannot configure {interface}")
        self._policy_source = {
            "interface": interface, "subnet": str(network), "gateway": gateway,
        }
        return dict(self._policy_source)

    def disable_policy_source(self) -> None:
        import shutil
        import subprocess

        device = str(self.settings.get("policy_tap_device") or "zgsoft")
        disable = getattr(self._backend, "routed_tap_disable", None)
        if callable(disable):
            disable(device=device)
        source = self._policy_source or {}
        interface = source.get("interface") or f"tap_{device}"
        ip = shutil.which("ip")
        if ip:
            # BridgeDelete normally closes SoftEther's TAP fd and removes the
            # interface. If vpnserver was recreated, however, a stale kernel
            # TAP can survive without a BridgeList row; the next BridgeCreate
            # reports a duplicate and an unbridged, DHCP-dead device is reused.
            # This exact interface name is Panel-owned, so remove the stale
            # link rather than merely setting it DOWN.
            subprocess.run([ip, "link", "delete", "dev", interface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._policy_source = None

    def policy_source(self) -> dict[str, str] | None:
        return dict(self._policy_source) if self._policy_source else None

    # ------------------------------------------------------------------ #
    # Config Studio bridge — every offered entry maps to a REAL stable-line
    # vpncmd capability. PPTP is not a SoftEther protocol. EtherIP remains
    # Advanced-only because a usable setup additionally needs per-router
    # EtherIpClientAdd mappings (a bare enable switch would be misleading).
    # ------------------------------------------------------------------ #
    _STUDIO_FEATURES = {"softether", "l2tp", "l2tp_raw", "etherip", "sstp", "ovpn"}

    def _feature_tag(self, protocol: str) -> str:
        defaults = {
            "softether": "softether", "l2tp": "l2tp",
            "l2tp_raw": "l2tp-raw", "etherip": "etherip",
            "sstp": "sstp", "ovpn": "softether-openvpn",
        }
        tags = self.settings.get("feature_tags") or {}
        return str(tags.get(protocol) or defaults[protocol])

    _FIXED_PROTOCOL_PORTS = {"l2tp": 1701, "l2tp_raw": 1701}

    def normalize_studio_document(self, document: dict[str, Any]) -> dict[str, Any]:
        """Repair legacy fake-custom ports for wire-standard protocols.

        SoftEther/IPsec cannot move IKE 500/4500 or L2TP 1701. Older wizards
        accepted a random number and persisted it even though the daemon kept
        the standards. Normalize in place so API transactions persist the
        truthful port and boot hydration can migrate old documents.
        """
        for inbound in (document or {}).get("inbounds") or []:
            protocol = str(inbound.get("protocol") or "")
            if protocol in self._FIXED_PROTOCOL_PORTS:
                inbound["port"] = self._FIXED_PROTOCOL_PORTS[protocol]
        return document

    def export_config_document(self) -> dict[str, Any]:
        """Current enabled feature set. An unconfigured hub exports an EMPTY
        list — never an invented blank L2TP inbound. That phantom entry was
        why creating SSTP/native incorrectly failed L2TP PSK validation."""
        s = self.settings
        inbounds: list[dict[str, Any]] = []
        if s.get("feature_softether"):
            inbounds.append({"tag": self._feature_tag("softether"), "protocol": "softether",
                             "port": int(s.get("native_port") or 5555), "transport": "tcp"})
        if s.get("feature_l2tp"):
            inbounds.append({
                "tag": self._feature_tag("l2tp"), "protocol": "l2tp", "port": 1701,
                "ipsec_psk": "", "has_ipsec_psk": bool(s.get("ipsec_psk")),
            })
        if s.get("feature_l2tp_raw"):
            inbounds.append({"tag": self._feature_tag("l2tp_raw"), "protocol": "l2tp_raw", "port": 1701})
        if s.get("feature_etherip"):
            inbounds.append({"tag": self._feature_tag("etherip"), "protocol": "etherip", "port": 0})
        if s.get("feature_sstp"):
            inbounds.append({
                "tag": self._feature_tag("sstp"), "protocol": "sstp",
                "port": int(s.get("sstp_port") or 443),
            })
        if s.get("feature_ovpn"):
            inbounds.append({"tag": self._feature_tag("ovpn"), "protocol": "ovpn",
                             "port": int(str(s.get("ovpn_ports") or "1194").split(",")[0]),
                             "transport": "udp"})
        return {"inbounds": inbounds}

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Converge hub features to the document via real vpncmd verbs:
        IPsecEnable (full 5-arg form) / ListenerCreate / ListenerDelete.

        Every entry maps to a server-side effect; entries with unknown
        protocols or missing required fields (the L2TP pre-shared key)
        fail loudly BEFORE anything is commanded."""
        self.normalize_studio_document(document)
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
            if proto in wanted:
                raise CoreError(
                    f"SoftEther '{proto}' is a server-wide hub feature, not "
                    "a multi-listener protocol; keep exactly one inbound for it."
                )
            tag = str(ib.get("tag") or "").strip() or self._feature_tag(proto)
            wanted[proto] = {**ib, "tag": tag}

        if not await asyncio.to_thread(self._backend.reachable):
            raise CoreError(
                "SoftEther hub is not reachable right now — Start the core "
                "first; feature changes need a live vpncmd."
            )

        # A remote-access hub without DHCP produces PPP's "Could not
        # determine local IP address" after successful CHAP. SecureNAT is the
        # self-contained VPS mode (Virtual NAT + Virtual DHCP). Operators with
        # an explicit local bridge/external DHCP can opt out in core settings.
        remote_access = bool(set(wanted) & {
            "softether", "l2tp", "l2tp_raw", "sstp", "ovpn"
        })
        if remote_access and bool(s.get("secure_nat", True)):
            ensure_nat = getattr(self._backend, "secure_nat_ensure", None)
            if not callable(ensure_nat):
                raise CoreError(
                    "SoftEther backend cannot ensure hub DHCP/SecureNAT; "
                    "upgrade the driver or configure external DHCP explicitly."
                )
            await asyncio.to_thread(ensure_nat)

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
        # Explicit wizard input wins. Otherwise the live server is
        # authoritative: using a stale persisted default (commonly "vpn")
        # made every subscription show a PSK different from IPsecGet.
        psk = (supplied_psk or current_psk or stored_psk) if l2tp \
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
        old_sstp_port = int(s.get("sstp_port") or 443)
        sstp_port = int(wanted.get("sstp", {}).get("port") or 443)
        if not 1 <= sstp_port <= 65535:
            raise CoreError(f"SoftEther SSTP port out of range: {sstp_port}.")
        if sstp != bool(s.get("feature_sstp")):
            await command(f"SstpEnable {'yes' if sstp else 'no'}")
        if sstp:
            # SSTP is enabled server-wide and is accepted on SoftEther TCP
            # listeners. Materialize the exact wizard port instead of always
            # creating 443 while displaying a different saved value.
            await command(f"ListenerCreate {sstp_port}", ignore_exists=True)
        if (old_sstp_port != 443 and old_sstp_port != sstp_port
                and old_sstp_port != int(s.get("native_port") or 5555)):
            await command(f"ListenerDelete {old_sstp_port}", ignore_exists=True)
        s["feature_sstp"] = sstp
        s["sstp_port"] = sstp_port

        ovpn = "ovpn" in wanted
        ovpn_port = int(wanted.get("ovpn", {}).get("port") or 1194)
        if ovpn != bool(s.get("feature_ovpn")) or (
                ovpn and str(s.get("ovpn_ports") or "1194") != str(ovpn_port)):
            await command(f"OpenVpnEnable {'yes' if ovpn else 'no'} /PORTS:{ovpn_port}")
        s["feature_ovpn"] = ovpn
        s["ovpn_ports"] = str(ovpn_port)

        # Stable grant identity: catalog/user entitlements carry the actual
        # wizard tag, not a hardcoded alias such as "l2tp-raw".
        s["feature_tags"] = {
            proto: str(entry["tag"]) for proto, entry in wanted.items()
        }

    # ------------------------------------------------------------------ #
    # lifecycle — the server is external/systemd-owned; we verify reachability
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        async def restore_policy_source() -> None:
            """Re-attach Linux state after vpnserver/service recreation.

            SoftEther persists BridgeCreate in ``vpn_server.config`` and
            recreates the TAP device, but an OS interface's address/UP state is
            not persisted by SoftEther.  Without this reconciliation a daemon
            restart leaves the bridge present but unnumbered, so DHCP clients
            connect successfully while every routed packet black-holes until
            the whole Panel is restarted.
            """
            if self._policy_source is not None:
                # A persisted BridgeCreate row can recreate a TAP that looks
                # UP but no longer forwards frames after the daemon replaced
                # its bridge object. Rebuild the bridge transactionally; merely
                # re-adding the Linux address leaves client ARP/DHCP black-holed.
                await asyncio.to_thread(self.disable_policy_source)
                await asyncio.to_thread(self.ensure_policy_source)

        if await asyncio.to_thread(self._backend.reachable):
            await restore_policy_source()
            return
        server_binary = getattr(self._backend, "server_binary", lambda: None)
        # Package/container filesystems are replaced during panel upgrades.
        # Recover the daemon automatically into the persistent install root;
        # the stable-bundle installer reuses its mounted cache and preserves
        # vpn_server.config when present. A saved core must never require a
        # manual Reinstall merely because the image changed.
        if server_binary() is None:
            repair = getattr(self._backend, "install_packages", None)
            if not callable(repair):
                raise CoreError(
                    "SoftEther runtime disappeared after upgrade and this "
                    "backend cannot repair it automatically."
                )
            detail = await asyncio.to_thread(repair)
            logger.info("softether automatic runtime recovery: %s", detail)
        server_start = getattr(self._backend, "server_start", None)
        if callable(server_start) and server_binary() is not None:
            await asyncio.to_thread(server_start)
            # Real persistent servers can spend well over ten seconds loading
            # vpn_server.config, SecureNAT and packet/security logs after a
            # container/host restart. Probe slowly: rapid localhost vpncmd TLS
            # connections trigger SoftEther's own DoS guard and prevent the
            # daemon from ever becoming ready. Bound the quiet wait at 60s.
            await asyncio.sleep(3.0)
            for _ in range(30):
                if await asyncio.to_thread(self._backend.reachable):
                    await restore_policy_source()
                    return
                await asyncio.sleep(2.0)
            recover_password = getattr(
                self._backend, "recover_fresh_server_password", None)
            if callable(recover_password) and await asyncio.to_thread(recover_password):
                logger.warning(
                    "softether recovered persisted admin authority on a fresh "
                    "post-upgrade server; Studio/accounts will now reconcile"
                )
                await restore_policy_source()
                return
        raise CoreError(
            f"SoftEther hub '{self.settings['hub']}' unreachable via vpncmd "
            f"at {self.settings['server']} after automatic runtime recovery — "
            f"check the persisted admin password/hub and core logs."
        )

    async def stop(self) -> None:
        # the VPN server stays up (system-owned); accounts remain provisioned
        pass

    async def status(self) -> CoreStatus:
        reachable = await asyncio.to_thread(self._backend.reachable)
        version = await self.version()
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
            core_version=version.version,
            version_reason=version.reason,
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
        self._usage.register(account.account_id)
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
        # SessionGet is the immediate ledger; UserGet catches up on a delayed
        # internal tick and/or disconnect. _SoftEtherUsageTracker reconciles
        # their overlap so long-lived sessions advance quota without counting
        # the later UserGet catch-up a second time.
        try:
            sessions = await asyncio.to_thread(self._backend.session_list)
        except CoreError:
            sessions = []
        session_get = getattr(self._backend, "session_get", None)
        by_account: dict[str, list[Any]] = {}
        for session in sessions:
            by_account.setdefault(session.username, []).append(session)

        for account_id in wanted:
            if account_id not in self._accounts:
                continue
            try:
                completed = await asyncio.to_thread(self._backend.user_get, account_id)
            except CoreError:
                continue  # user vanished server-side; nothing to report
            live_sessions: dict[str, tuple[int, int]] = {}
            if callable(session_get):
                for session in by_account.get(account_id, []):
                    try:
                        live = await asyncio.to_thread(
                            session_get, session.session_name)
                    except CoreError:
                        # Disconnect raced this poll. The committed bytes show
                        # up in UserGet on this or the next 30-second tick.
                        continue
                    # SoftEther names directions from the VPN Server/hub:
                    # Outgoing leaves the hub toward the Internet (client
                    # upload); Incoming enters the hub toward the client
                    # (client download). Expose client semantics everywhere.
                    live_sessions[session.session_name] = (
                        int(live.outgoing_bytes), int(live.incoming_bytes))
            up, down = self._usage.observe(
                account_id,
                (completed.outgoing_bytes, completed.incoming_bytes),
                live_sessions,
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
                 "port": None, "feature": "feature_sstp", "needs_psk": False},
        "ovpn": {"catalog_tag": "softether-openvpn", "title": "VPN (OpenVPN compatibility)",
                 "port": None, "feature": "feature_ovpn", "needs_psk": False},
    }

    def _granted_transports(self, account: UserAccount) -> list[tuple[str, str]]:
        """Return ``(protocol, actual inbound tag)`` grants.

        Studio tags are admin-defined identities. Comparing grants only with
        hardcoded aliases (notably ``l2tp-raw``) made a valid custom
        ``l2tp_raw`` inbound resolve to “No transports granted”. Canonical
        aliases remain accepted for pre-migration accounts.
        """
        wanted = {str(tag) for tag in account.settings.get("inbound_tags") or []}
        excluded = {str(tag) for tag in account.settings.get("excluded_inbounds") or []}
        out: list[tuple[str, str]] = []
        for proto, facts in self._TRANSPORTS.items():
            actual = self._feature_tag(proto)
            aliases = {actual, str(facts["catalog_tag"])}
            if aliases & excluded:
                continue
            if wanted:
                selected = aliases & wanted
                if not selected:
                    continue
                # Preserve the exact grant identity in the portal/Host engine.
                tag = actual if actual in selected else sorted(selected)[0]
            else:
                tag = actual
            out.append((proto, tag))
        return out

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """SoftEther delivery: one section per GRANTED compatibility
        transport — native, L2TP/IPsec, raw L2TP, SSTP and OpenVPN —
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

        for proto, inbound_tag in self._granted_transports(account):
            facts = self._TRANSPORTS[proto]
            if facts["port"]:
                port = facts["port"]
            elif proto == "ovpn":
                port = f"{str(s.get('ovpn_ports') or '1194').split(',')[0].strip()}/udp"
            elif proto == "sstp":
                port = f"{int(s.get('sstp_port') or 443)}/tcp"
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
                engine="softether", inbound_tag=inbound_tag,
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
                    "port": int(s.get("sstp_port") or 443),
                    "username": account.account_id,
                    "password": password,
                    "hub": s["hub"],
                    "note": "SSTP listener must be enabled on the SoftEther server "
                            "(SecureNAT/Listener 443 or your SSTP port).",
                },
                display_name="VPN (SSTP)",
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
                    "note": "SoftEther's OpenVPN compatibility listener; "
                            "Zagros enables it with the stable-line "
                            "OpenVpnEnable command.",
                },
                display_name="VPN (OpenVPN clone)",
            )
        if account.protocol == "l2tp_raw":
            if not server:
                raise CoreError(
                    "Raw L2TP client config requires settings.advertise_host."
                )
            return ClientConfig(
                core_id=self.metadata.id,
                protocol="l2tp_raw",
                engine="l2tp",
                payload={
                    "format": "l2tp-raw",
                    "server": server,
                    "port": 1701,
                    "username": account.account_id,
                    "password": password,
                    "hub": s["hub"],
                    "warning": "Raw L2TP has no IPsec encryption.",
                },
                display_name="VPN (Raw L2TP)",
            )
        if account.protocol != "l2tp":
            raise CoreError(
                f"no SoftEther client config renderer for '{account.protocol}'"
            )
        # L2TP/IPsec uses one server-wide PSK (the live IPsecGet value).
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
