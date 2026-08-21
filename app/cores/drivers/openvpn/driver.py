"""OpenVPNDriver — OpenVPN as a first-class panel core.

Real capabilities used (no pretend features):
  * **Live user management** via ``--management-client-auth``: the panel answers
    every handshake on the management channel → add/edit/delete/suspend take
    effect *without a restart*. ``--username-as-common-name`` makes the
    username the CN, so ``kill <cn>`` ties sessions to accounts.
  * **Accounting**: authoritative per-session finals from the
    ``client-disconnect`` hook (env ``bytes_received/bytes_sent``), merged with
    interim deltas from ``status 3`` through the shared
    :class:`SessionUsageTracker` — interim and final never double-counted.
  * **Online + device detection**: ``status 3`` rows + handshake env
    (``IV_PLAT``/``IV_VER``).
  * Honestly NOT claimed: ROUTING (per-user rules don't exist server-side),
    HOT_RELOAD (SIGUSR1 reloads, not rule-level), PROCESS/GEO routing.
"""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
from datetime import datetime, timezone
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.stats import SessionUsageTracker
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

logger = logging.getLogger("zagros.cores.drivers.openvpn")

_DISCONNECT_HOOK = """#!/bin/sh
# zagros openvpn accounting hook -- authoritative per-session final counters.
printf '%s\\n' "{{\\"cn\\":\\"$common_name\\",\\"bytes_received\\":$bytes_received,\\"bytes_sent\\":$bytes_sent,\\"duration\\":$time_duration,\\"ts\\":$(date +%s)}}" >> "{log_path}"
"""

_NETWORK_HOOK = """#!/bin/sh
# Zagros-owned OpenVPN forwarding/NAT rules. Every rule is scoped to this
# listener's tunnel subnet, so stopping one inbound cannot steal another
# VPN core's firewall state.
IF=$(ip route show default 2>/dev/null | awk '/^default/ {{print $5; exit}}')
[ -n "$IF" ] || exit 1
case "${{script_type:-}}" in
  up)
    iptables -C FORWARD -i "$dev" -s {subnet} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$dev" -s {subnet} -j ACCEPT
    iptables -C FORWARD -o "$dev" -d {subnet} -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$dev" -d {subnet} -j ACCEPT
    iptables -t nat -C POSTROUTING -s {subnet} -o "$IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} -o "$IF" -j MASQUERADE
    ;;
  down)
    iptables -D FORWARD -i "$dev" -s {subnet} -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$dev" -d {subnet} -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s {subnet} -o "$IF" -j MASQUERADE 2>/dev/null || true
    ;;
esac
"""


class OpenVPNDriver(BaseCoreDriver):
    """Driver for OpenVPN community server (management-interface managed)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="openvpn",
        name="OpenVPN",
        description=(
            "OpenVPN community server. Live user auth via management-client-auth, "
            "authoritative usage via client-disconnect hook + status, online "
            "sessions and device detection (IV_PLAT/IV_VER)."
        ),
        protocols=["ovpn"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.DEVICE_DETECTION,
            Capability.SERVICE_CONTROL,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
            Capability.SELF_INSTALL,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string"},
                "openvpn_version": {
                    "type": "string",
                    "description": "installed OpenVPN version override (e.g. "
                                   "'2.3.18') — gates version-dependent "
                                   "directives; blank = probe the binary"},
                "work_dir": {"type": "string"},
                "listen": {"type": "string", "default": "0.0.0.0"},
                "port": {"type": "integer", "default": 1194},
                "proto": {"type": "string", "enum": ["udp", "tcp"]},
                "subnet": {"type": "string", "default": "10.8.0.0"},
                "netmask": {"type": "string", "default": "255.255.255.0"},
                "management_port": {"type": "integer", "default": 17505},
                "redirect_gateway": {"type": "boolean", "default": True},
                "dns_servers": {"type": "array", "items": {"type": "string"}},
                "advertise_host": {"type": "string"},
                "topology": {"type": "string", "enum": ["subnet", "net30", "p2p"],
                             "default": "subnet"},
                "cipher": {"type": "string", "default": "AES-256-GCM"},
                "cipher_fallback": {"type": "string", "default": "AES-128-GCM"},
                "auth_digest": {"type": "string",
                                "description": "HMAC digest directive (blank = omit — "
                                               "AEAD ciphers ignore --auth)"},
                "compression": {"type": "string",
                                "enum": ["", "lz4-v2", "lzo"], "default": ""},
                "auth_mode": {"type": "string",
                              "enum": ["management", "static"], "default": "management",
                              "description": "management = per-user panel credentials "
                                             "via management-client-auth; static = one "
                                             "shared username/password "
                                             "(auth-user-pass-verify)"},
                "static_user": {"type": "string"},
                "static_pass": {"type": "string"},
                "extra_directives": {"type": "string",
                                     "description": "raw server.conf lines appended "
                                                    "(operator escape hatch, e.g. "
                                                    "'max-clients 512')"},
                "listeners": {"type": "array",
                              "description": "listener set (xray-style multi-inbound, "
                                             "alpha.7.2): [{'tag', 'port', 'proto', "
                                             "'subnet'?, 'cipher'?, ...}] — empty = "
                                             "derive ONE listener from the legacy flat "
                                             "port/proto/subnet keys"},
            },
        },
        default_settings={
            "executable_path": "openvpn",
            "work_dir": "/var/lib/zagros/cores/openvpn",
            "listen": "0.0.0.0",
            "port": 1194,
            "proto": "udp",
            "subnet": "10.8.0.0",
            "netmask": "255.255.255.0",
            "management_port": 17505,
            "redirect_gateway": True,
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
            "advertise_host": "127.0.0.1",
            "topology": "subnet",
            "cipher": "AES-256-GCM",
            "cipher_fallback": "AES-128-GCM",
            "auth_digest": "",
            "compression": "",
            "auth_mode": "management",
            "static_user": "",
            "static_pass": "",
            "extra_directives": "",
            "listeners": [],
        },
        homepage="https://openvpn.net/community/",
        provides=set(),
        requires=set(),
        # openvpn is one listener PER PROCESS — multi-inbound = one process
        # per port (openvpn@server style), panel-managed as N inbounds with
        # distinct tags (alpha.7.2), applied like xray (no replace).
        studio_inbounds_path="/inbounds",
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        # multi-inbound bridge (alpha.7.2): persisted pre-7.2 settings carry
        # no "listeners" — derive ONE listener from the legacy flat
        # port/proto/subnet/… keys so the served config is bit-identical.
        if not self.settings.get("listeners"):
            self.settings["listeners"] = [self._listener_from_flat(self.settings)]
        else:
            # normalize + fill optional knobs from the flat template
            self.settings["listeners"] = [
                self._normalize_listener(row, self.settings)
                for row in self.settings["listeners"]
            ]
        if backend is None:
            from app.cores.drivers.openvpn.backend import LocalOpenVPNBackend

            backend = LocalOpenVPNBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._device_meta: dict[str, dict[str, Any]] = {}
        self._usage = SessionUsageTracker()
        self._pki: dict[str, str] | None = None
        self._ca_fp: tuple[str, str] | None = None  # (pem, fingerprint) memo

    # ------------------------------------------------------------------ #
    # listener set (one openvpn process per inbound — xray-style)          #
    # ------------------------------------------------------------------ #
    _LISTENER_KEYS = (
        # per-listener knobs (flat settings stay the TEMPLATE for new
        # listeners created by the wizard's Add-Inbound flow)
        "port", "proto", "listen", "subnet", "netmask", "topology",
        "cipher", "cipher_fallback", "auth_digest", "compression",
        "redirect_gateway", "dns_servers", "extra_directives",
    )

    @classmethod
    def _listener_from_flat(cls, s: dict[str, Any]) -> dict[str, Any]:
        return {
            "tag": "openvpn",
            "port": int(s.get("port") or 1194),
            "proto": str(s.get("proto") or "udp"),
            "listen": str(s.get("listen") or "0.0.0.0"),
            "subnet": str(s.get("subnet") or "10.8.0.0"),
            "netmask": str(s.get("netmask") or "255.255.255.0"),
            "topology": str(s.get("topology") or "subnet"),
            "cipher": str(s.get("cipher") or "AES-256-GCM"),
            "cipher_fallback": str(s.get("cipher_fallback") or "AES-128-GCM"),
            "auth_digest": str(s.get("auth_digest") or ""),
            "compression": str(s.get("compression") or ""),
            "redirect_gateway": bool(s.get("redirect_gateway", True)),
            "dns_servers": list(s.get("dns_servers") or ["1.1.1.1", "8.8.8.8"]),
            "extra_directives": str(s.get("extra_directives") or ""),
        }

    @classmethod
    def _normalize_listener(cls, row: Any, s: dict[str, Any]) -> dict[str, Any]:
        template = cls._listener_from_flat(s)
        if not isinstance(row, dict):
            return template
        out = dict(template)
        for key in cls._LISTENER_KEYS:
            if row.get(key) is not None:
                out[key] = row[key]
        out["port"] = int(out["port"])
        out["dns_servers"] = list(out.get("dns_servers") or [])
        tag = str(row.get("tag") or "").strip()
        out["tag"] = tag or f"ovpn-{out['port']}-{out['proto']}"
        return out

    def _listeners(self) -> list[dict[str, Any]]:
        listeners = self.settings.get("listeners") or []
        if not listeners:
            listeners = [self._listener_from_flat(self.settings)]
        return [dict(l) for l in listeners]

    def _listener_mgmt_ports(self) -> dict[str, int]:
        """Deterministic management ports: an explicit per-listener
        'management_port' wins; otherwise base + 1-based ordinal. Never
        collides with another listener's mgmt port."""
        base = int(self.settings.get("management_port") or 17505)
        out: dict[str, int] = {}
        used: set[int] = set()
        for idx, listener in enumerate(self._listeners()):
            explicit = listener.get("management_port")
            port = (int(explicit) if explicit is not None and str(explicit) != ""
                    else base + idx + 1)
            out[listener["tag"]] = port
            used.add(port)
        return out

    def _granted_listeners(self, account: UserAccount) -> list[dict[str, Any]]:
        """Grant-aware view (same convention as sing-box): inbound_tags
        whitelists, excluded_inbounds blacklists."""
        wanted = set(account.settings.get("inbound_tags") or [])
        excluded = set(account.settings.get("excluded_inbounds") or [])
        out = [l for l in self._listeners() if not wanted or l["tag"] in wanted]
        return [l for l in out if l["tag"] not in excluded]

    def _validate_listener_set(self, listeners: list[dict[str, Any]]) -> None:
        """Cardinality/port/subnet uniqueness guards — a routing conflict is
        reported with BOTH offender names, never as a later boot mystery."""
        if not listeners:
            raise CoreError("openvpn needs at least ONE inbound (listener).")
        seen_tags: set[str] = set()
        seen_endpoints: dict[tuple[int, str], str] = {}
        seen_subnets: dict[str, str] = {}
        for listener in listeners:
            tag = listener["tag"]
            port = int(listener["port"])
            proto = str(listener["proto"])
            if not 1 <= port <= 65535:
                raise CoreError(f"openvpn listener '{tag}': port out of range ({port}).")
            if proto not in ("udp", "tcp"):
                raise CoreError(f"openvpn listener '{tag}': serves udp or tcp, not '{proto}'.")
            if tag in seen_tags:
                raise CoreError(f"duplicate openvpn inbound name '{tag}'.")
            endpoint = (port, proto)
            if endpoint in seen_endpoints:
                raise CoreError(
                    f"openvpn inbounds '{seen_endpoints[endpoint]}' and '{tag}' "
                    f"share {proto} port {port} — like xray, every inbound "
                    f"needs its OWN (port, protocol) pair."
                )
            subnet = str(listener.get("subnet") or "")
            if subnet in seen_subnets and subnet:
                raise CoreError(
                    f"openvpn inbounds '{seen_subnets[subnet]}' and '{tag}' "
                    f"share tunnel subnet {subnet} — two daemons announcing "
                    f"the same network kills client routing."
                )
            seen_tags.add(tag)
            seen_endpoints[endpoint] = tag
            if subnet:
                seen_subnets[subnet] = tag

    # ------------------------------------------------------------------ #
    # Config Studio bridge (single-listener engine; apply re-renders
    # server.conf, restarts when running, same validated path as Start)
    # ------------------------------------------------------------------ #
    def export_config_document(self) -> dict[str, Any]:
        """Studio seed: one entry per listener (xray-style); the core-wide
        knobs (auth mode / static creds) mirrored on every entry. Secrets
        are never exported — wizard write-only."""
        s = self.settings
        entries = []
        for listener in self._listeners():
            entries.append({
                "tag": listener["tag"],
                "protocol": "ovpn",
                "listen": listener["listen"],
                "port": int(listener["port"]),
                "transport": listener["proto"],
                "topology": listener["topology"],
                "cipher": listener["cipher"],
                "auth": listener["auth_digest"],
                "compression": listener["compression"],
                "auth_mode": s.get("auth_mode") or "management",
                "username": "",
                "password": "",
                "redirect_gateway": bool(listener["redirect_gateway"]),
                "dns": ", ".join(str(d) for d in (listener["dns_servers"] or [])),
                "subnet": listener["subnet"],
                "netmask": listener["netmask"],
                "has_static_credentials": bool(s.get("static_user")),
                "has_ca_certificate": bool(s.get("ca_crt_text")),
            })
        return {"inbounds": entries}

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Adopt the studio document's entries as THE listener set —
        xray-style multi-inbound: N entries, distinct tags, distinct
        (port, transport) pairs, distinct tunnel subnets (one openvpn
        process per entry). Auth-mode/static-creds are core-wide: entries
        may carry them, a CONFLICTING pair is a hard error naming the field
        and both tags — never silent last-write-wins. Apply re-renders all
        server.conf files and restarts the set when running."""
        inbounds = (document or {}).get("inbounds") or []
        if not inbounds:
            raise CoreError(
                "an openvpn core needs at least ONE inbound — the studio "
                "document carries none."
            )
        s = self.settings
        template = self._listener_from_flat(s)

        # 1) per-entry parse + structural validation (fail BEFORE mutating)
        listeners: list[dict[str, Any]] = []
        for ib in inbounds:
            if str(ib.get("protocol") or "ovpn") not in ("ovpn", "openvpn"):
                raise CoreError(f"an openvpn core cannot host a '{ib.get('protocol')}' listener.")
            tag = str(ib.get("tag") or "").strip()
            entry = dict(template)  # flat settings = template for omitted knobs
            if ib.get("port") is not None:
                try:
                    entry["port"] = int(ib["port"])
                except (TypeError, ValueError):
                    raise CoreError(
                        f"openvpn inbound '{tag or '?'}': invalid port {ib.get('port')!r}."
                    ) from None
            if ib.get("listen"):
                entry["listen"] = str(ib["listen"])
            transport = str(ib.get("transport") or ib.get("proto") or "").lower()
            if transport in ("udp", "tcp"):
                entry["proto"] = transport
            elif transport:
                raise CoreError(
                    f"openvpn inbound '{tag or '?'}' serves udp or tcp, not '{transport}'.")
            if ib.get("topology"):
                topology = str(ib["topology"])
                if topology not in ("subnet", "net30", "p2p"):
                    raise CoreError(f"unknown openvpn topology '{topology}' "
                                    "(subnet / net30 / p2p).")
                entry["topology"] = topology
            if ib.get("subnet"):
                entry["subnet"] = str(ib["subnet"]).strip()
            if ib.get("netmask"):
                netmask = str(ib["netmask"]).strip()
                parts = netmask.split(".")
                if len(parts) != 4 or any(
                        not p.isdigit() or not 0 <= int(p) <= 255 for p in parts):
                    raise CoreError(
                        f"openvpn inbound '{tag or '?'}': netmask '{netmask}' "
                        f"is not a dotted IPv4 mask.")
                entry["netmask"] = netmask
            if ib.get("cipher"):
                entry["cipher"] = str(ib["cipher"])
            if ib.get("cipher_fallback"):
                entry["cipher_fallback"] = str(ib["cipher_fallback"])
            if ib.get("auth") is not None:
                entry["auth_digest"] = str(ib["auth"])
            if ib.get("compression") is not None:
                compression = str(ib["compression"])
                if compression not in ("", "lz4-v2", "lzo"):
                    raise CoreError(f"unknown openvpn compression '{compression}'.")
                entry["compression"] = compression
            if ib.get("dns") is not None:
                entry["dns_servers"] = [d.strip() for d in str(ib["dns"]).split(",")
                                        if d.strip()]
            if ib.get("redirect_gateway") is not None:
                entry["redirect_gateway"] = bool(ib["redirect_gateway"])
            if str(ib.get("extra_directives") or ""):
                entry["extra_directives"] = str(ib["extra_directives"])
            entry["tag"] = tag or f"ovpn-{entry['port']}-{entry['proto']}"
            listeners.append(entry)
        self._validate_listener_set(listeners)

        # 2) core-wide knobs — identical values only; conflicts are named
        def _shared(field: str) -> Any:
            base_value: Any = None
            base_tag: str | None = None
            for ib, listener in zip(inbounds, listeners):
                value = ib.get(field)
                if value is None or value == "":
                    continue
                value = str(value).strip().lower() if field == "auth_mode" else value
                if base_tag is None:
                    base_tag, base_value = listener["tag"], value
                elif value != base_value:
                    raise CoreError(
                        f"'{field}' is a core-wide openvpn setting but inbound "
                        f"'{base_tag}' and inbound '{listener['tag']}' disagree — "
                        f"the PKI and the auth database are shared by every "
                        f"listener, so keep the value identical on all entries."
                    )
            return base_value

        auth_mode = _shared("auth_mode")
        if auth_mode in ("management", "static"):
            s["auth_mode"] = auth_mode
        elif auth_mode:
            raise CoreError(f"unknown openvpn auth_mode '{auth_mode}'.")
        username = _shared("username")
        if username:
            s["static_user"] = str(username)
        password = _shared("password")
        if password:
            s["static_pass"] = str(password)
        if s.get("auth_mode") == "static":
            # validated eagerly — a shared-cred server without the creds is
            # a brick (the install raises with a clear message)
            self._install_static_auth()
        # PKI uploads (CA / server cert / server key — operator-owned chains
        # replace the panel-generated PKI for EVERY listener); private key
        # never in the export
        for ib in inbounds:
            self._materialize_uploaded_pki(
                ca_pem=ib.get("ca_certificate") or ib.get("ca"),
                cert_pem=ib.get("certificate"),
                key_pem=ib.get("certificate_key"),
            )

        # 3) persist the set; legacy flat keys mirror the FIRST listener so
        #    pre-7.2 consumers (and the listener template) stay meaningful.
        s["listeners"] = [dict(l) for l in listeners]
        first = listeners[0]
        for key in self._LISTENER_KEYS:
            s[key] = first[key]
        await self._publish()

    def _materialize_uploaded_pki(self, *, ca_pem: Any, cert_pem: Any,
                                  key_pem: Any) -> None:
        """Write operator-uploaded PEMs into the work_dir PKI (validated as a
        MATCHING cert/key pair; idempotent — unchanged files are not
        rewritten, so no needless restart ripple)."""
        import os
        if not (ca_pem or cert_pem or key_pem):
            return
        if bool(cert_pem) != bool(key_pem):
            raise CoreError(
                "upload the server certificate AND private key together."
            )
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        work_dir = str(self.settings.get("work_dir") or ".")
        os.makedirs(work_dir, exist_ok=True)
        if cert_pem:
            try:
                cert_obj = x509.load_pem_x509_certificate(str(cert_pem).encode())
                key_obj = serialization.load_pem_private_key(
                    str(key_pem).encode(), password=None
                )
            except ValueError as exc:
                raise CoreError(f"uploaded certificate/key is not valid PEM: {exc}") from exc
            if (cert_obj.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                    != key_obj.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo)):
                raise CoreError(
                    "uploaded certificate does NOT match the uploaded private key."
                )
            from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
            try:
                ku = cert_obj.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                eku = cert_obj.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            except x509.ExtensionNotFound as exc:
                raise CoreError(
                    "uploaded OpenVPN server certificate needs keyUsage and "
                    "extendedKeyUsage=serverAuth (required by remote-cert-tls server)."
                ) from exc
            if not ku.digital_signature or ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                raise CoreError(
                    "uploaded OpenVPN server certificate is not authorized for serverAuth."
                )
            if ca_pem:
                try:
                    ca_obj = x509.load_pem_x509_certificate(str(ca_pem).encode())
                    cert_obj.verify_directly_issued_by(ca_obj)
                except ValueError as exc:
                    raise CoreError("uploaded server certificate is not signed by the uploaded CA.") from exc
            for name, text in (("server.crt", str(cert_pem)), ("server.key", str(key_pem))):
                self._write_if_changed(os.path.join(work_dir, name), text,
                                       0o600 if name.endswith(".key") else 0o644)
        if ca_pem:
            try:
                x509.load_pem_x509_certificate(str(ca_pem).encode())
            except ValueError as exc:
                raise CoreError(f"uploaded CA certificate is not valid PEM: {exc}") from exc
            self._write_if_changed(os.path.join(work_dir, "ca.crt"), str(ca_pem), 0o644)
        self._pki = None  # force ensure_pki/client-profile re-read

    @staticmethod
    def _write_if_changed(path: str, text: str, mode: int) -> None:
        import os
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                if fh.read() == text:
                    return
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    async def _publish(self) -> None:
        """Materialize the whole listener set into the backend; restart the
        set when running (apply semantics identical to xray: every inbound
        of the document is live afterwards)."""
        running = await asyncio.to_thread(self._backend.is_running)
        if not running:
            # stopped core: persist the materialized set anyway so Start
            # renders exactly what the studio last saved (offline-friendly,
            # same rule as wireguard since alpha.7.2)
            await asyncio.to_thread(self._backend.configure, self._listener_specs())
            return
        await asyncio.to_thread(self._backend.configure, self._listener_specs())
        # Register before restart opens listener sockets. Auto-reconnecting
        # clients can emit CONNECT immediately and must always receive a
        # client-auth/client-deny verdict (never hang at PUSH_REQUEST).
        await asyncio.to_thread(self._backend.set_auth_handler, self._authorize)
        await asyncio.to_thread(self._backend.restart)

    def _listener_specs(self) -> list[dict[str, Any]]:
        """configure() payload: fully rendered conf + hook per listener,
        with deterministic per-listener management ports and log paths."""
        mgmt_ports = self._listener_mgmt_ports()
        specs: list[dict[str, Any]] = []
        for listener in self._listeners():
            log_path = self._backend.disconnect_log_path(listener["tag"])
            specs.append({
                "tag": listener["tag"],
                "mgmt_port": mgmt_ports[listener["tag"]],
                "server_conf": self.render_server_conf(
                    listener,
                    hook_path=self._backend_hook_path(log_path, listener["tag"]),
                    mgmt_port=mgmt_ports[listener["tag"]],
                    log_path=log_path,
                ),
                "hook_script": self._render_hook(log_path),
                "network_hook_script": self._render_network_hook(listener),
            })
        return specs

    def _backend_hook_path(self, log_path: str, tag: str) -> str:
        return str(log_path).replace("disconnect-log.jsonl", "client-disconnect.sh")

    # ------------------------------------------------------------------ #
    # config rendering
    # ------------------------------------------------------------------ #
    def render_server_conf(self, listener: dict[str, Any], hook_path: str,
                           mgmt_port: int, log_path: str) -> str:
        """Render ONE listener's server.conf (one openvpn process each).
        PKI paths are absolute: the shared CA/certs live in work_dir while
        each process runs with its own per-listener cwd."""
        s = self.settings
        work_dir = str(s.get("work_dir") or ".")
        pushes = []
        if listener["redirect_gateway"]:
            pushes.append('push "redirect-gateway def1 bypass-dhcp"')
        pushes += [f'push "dhcp-option DNS {dns}"' for dns in listener["dns_servers"]]
        cipher = str(listener.get("cipher") or "AES-256-GCM")
        fallback = str(listener.get("cipher_fallback") or "AES-128-GCM")
        import os
        lines = [
            f"local {listener.get('listen') or '0.0.0.0'}",
            f"port {listener['port']}",
            f"proto {listener['proto']}",
            "dev tun",
            f"topology {listener.get('topology') or 'subnet'}",
            f"server {listener['subnet']} {listener['netmask']}",
            f"ifconfig-pool-persist {os.path.join(os.path.dirname(str(log_path)), 'ipp.txt')}",
            f"ca {os.path.join(work_dir, 'ca.crt')}",
            f"cert {os.path.join(work_dir, 'server.crt')}",
            f"key {os.path.join(work_dir, 'server.key')}",
            "dh none",
            f"tls-crypt {os.path.join(work_dir, 'ta.key')}",
            f"data-ciphers {cipher}:{fallback}",
            f"data-ciphers-fallback {fallback}",
            "tls-version-min 1.2",
            f"management 127.0.0.1 {int(mgmt_port)}",
        ]
        if listener["redirect_gateway"]:
            network_hook = os.path.join(os.path.dirname(str(log_path)), "network-hook.sh")
            lines += ["script-security 2", f"up {network_hook}",
                      f"down {network_hook}", "down-pre"]
        if str(listener.get("auth_digest") or ""):
            lines.append(f"auth {listener['auth_digest']}")
        compression = str(listener.get("compression") or "")
        if compression:
            lines += ["allow-compression yes", f"compress {compression}",
                      f'push "compress {compression}"']
        if str(s.get("auth_mode") or "management") == "static":
            # one shared username/password, verified by a root-owned script:
            # real auth-user-pass-verify (via-env), management interface stays
            # for status/usage but NOT for auth
            lines += [
                f"auth-user-pass-verify {self._static_auth_script_path()} via-env",
                self._client_cert_directive(),
                "username-as-common-name",
            ]
        else:
            lines += [
                "management-client-auth",
                self._client_cert_directive(),
                "username-as-common-name",
            ]
        lines += [
            f"client-disconnect {hook_path}",
            *pushes,
            "keepalive 10 60",
            "persist-key", "persist-tun",
            "verb 3",
        ]
        extra = str(listener.get("extra_directives") or "").strip()
        if extra:
            lines.append("# operator extra directives (studio)")
            lines += [ln.rstrip() for ln in extra.splitlines() if ln.strip()]
        lines.append("")
        return "\n".join(lines)

    def _client_cert_directive(self) -> str:
        """Version-gated client-cert directive (alpha.7.5 item 11).

        OpenVPN 2.6 REMOVED ``--client-cert-not-required`` — the daemon
        aborts with 'REMOVED OPTION: --client-cert-not-required, use
        ``--verify-client-cert none`` instead'. ``--verify-client-cert``
        itself exists since 2.4, therefore: a binary DETECTED as ≥2.4 (or
        an unparsed/unknown one — every supported distro ships ≥2.5 today)
        always gets the modern directive, a detected pre-2.4 binary keeps
        the legacy flag, and ``settings.openvpn_version`` overrides the
        probe for exotic hosts.
        """
        raw = str(self.settings.get("openvpn_version") or "").strip()
        if not raw:
            probe = getattr(self._backend, "version", None)
            if callable(probe):
                try:
                    raw = str(probe() or "").strip()
                except Exception:  # noqa: BLE001 — a failed probe means
                    raw = ""       # "unknown", and unknown = modern directive
        version: tuple[int, int] | None = None
        if raw:
            match = re.match(r"(\d+)\.(\d+)", raw)
            if match:
                version = (int(match.group(1)), int(match.group(2)))
        if version is not None and version < (2, 4):
            return "client-cert-not-required"
        return "verify-client-cert none"

    def _static_auth_script_path(self) -> str:
        import os
        return os.path.join(str(self.settings.get("work_dir") or "."),
                            "zagros-static-auth.sh")

    _STATIC_AUTH_SCRIPT = """#!/bin/sh
# zagros openvpn static auth — auth-user-pass-verify (via-env).
# Credentials live root-only 0600 next to this script; the daemon compares.
set -eu
creds="$(cat "$(dirname "$0")/.ovpn-static-auth")" || exit 1
want_user="${creds%%:*}"
want_pass="${creds#*:}"
[ "${username:-}" = "$want_user" ] && [ "${password:-}" = "$want_pass" ]
"""

    def _install_static_auth(self) -> None:
        """Root-owned verify script + 0600 credential file for static mode."""
        import os
        s = self.settings
        work_dir = str(s.get("work_dir") or ".")
        os.makedirs(work_dir, exist_ok=True)
        user, password = str(s.get("static_user") or ""), str(s.get("static_pass") or "")
        if not user or not password:
            raise CoreError(
                "openvpn static auth_mode needs username AND password "
                "(the wizard's Static Authentication section)."
            )
        if ":" in user or "\n" in user or "\n" in password:
            raise CoreError("static openvpn credentials may not contain ':' or newlines.")
        script = self._static_auth_script_path()
        with open(script + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(self._STATIC_AUTH_SCRIPT)
        os.chmod(script + ".tmp", 0o700)
        os.replace(script + ".tmp", script)
        creds = os.path.join(work_dir, ".ovpn-static-auth")
        with open(creds + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(f"{user}:{password}")
        os.chmod(creds + ".tmp", 0o600)
        os.replace(creds + ".tmp", creds)

    def _mgmt_addr(self) -> str:
        return f"127.0.0.1 {self.settings['management_port']}"

    def _render_hook(self, log_path: str) -> str:
        return _DISCONNECT_HOOK.format(log_path=log_path)

    @staticmethod
    def _render_network_hook(listener: dict[str, Any]) -> str:
        import ipaddress

        subnet = ipaddress.ip_network(
            f"{listener['subnet']}/{listener['netmask']}", strict=False)
        return _NETWORK_HOOK.format(subnet=str(subnet))

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        self._pki = await asyncio.to_thread(self._backend.ensure_pki)
        if str(self.settings.get("auth_mode") or "management") == "static":
            await asyncio.to_thread(self._install_static_auth)
        await asyncio.to_thread(self._backend.configure, self._listener_specs())
        await asyncio.to_thread(self._backend.set_auth_handler, self._authorize)
        await asyncio.to_thread(self._backend.start)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def restart(self) -> None:
        await asyncio.to_thread(self._backend.set_auth_handler, self._authorize)
        await asyncio.to_thread(self._backend.restart)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        health = HealthStatus.UNKNOWN
        version = await self.version()
        metrics = None
        if running:
            metrics = await asyncio.to_thread(self._backend.metrics)
            alive = await asyncio.to_thread(self._backend.management_alive)
            health = HealthStatus.HEALTHY if alive else HealthStatus.DEGRADED
        return CoreStatus(
            core_id=self.metadata.id, state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=health, core_version=version.version,
            version_reason=version.reason, metrics=metrics,
        )

    async def health_check(self) -> CoreStatus:
        return await self.status()

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def install(self) -> None:
        await asyncio.to_thread(self._backend.install_packages)

    async def uninstall(self, purge: bool = False) -> None:
        await asyncio.to_thread(self._backend.stop)

    # ------------------------------------------------------------------ #
    # live authentication (management-client-auth)
    # ------------------------------------------------------------------ #
    def _authorize(self, username: str, password: str, meta: dict[str, Any]) -> bool:
        account = self._accounts.get(username)
        allowed = bool(
            account and account.enabled
            and account.settings.get("password") == password
        )
        if allowed:
            self._device_meta[username] = {
                "platform": meta.get("platform"),
                "app_version": meta.get("client_version"),
                "seen_at": datetime.now(timezone.utc).isoformat(),
            }
        return allowed

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol != "ovpn":
            raise CoreError(f"OpenVPN core only serves protocol 'ovpn', got '{protocol}'.")

    def _provision_credentials(self, account: UserAccount) -> None:
        """Alpha.7.2 contract: provisioning NEVER fails on a missing
        password — in management auth mode the panel mints a secure random
        one IN PLACE (the grant path persists it back, same contract as
        sing-box). Static auth mode needs nothing per-user at all."""
        if str(self.settings.get("auth_mode") or "management") == "static":
            return
        if not account.settings.get("password"):
            account.settings["password"] = secrets.token_urlsafe(18)
            logger.info("openvpn: minted a random password for account '%s'.",
                        account.account_id)

    def _ensure_credentials(self, account: UserAccount) -> None:
        # static auth_mode authenticates EVERY client with the shared pair;
        # a per-user password is only mandatory in management auth mode
        if str(self.settings.get("auth_mode") or "management") == "static":
            return
        if not account.settings.get("password"):
            raise CoreError(f"OpenVPN account '{account.account_id}' needs settings.password.")

    async def _kill_if_connected(self, account_id: str) -> None:
        try:
            await asyncio.to_thread(self._backend.kill_client, account_id)
        except CoreError:
            pass  # mgmt down or never connected — desired state already updated

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        self._ensure_credentials(account)
        self._accounts[account.account_id] = account
        if not account.enabled:
            await self._kill_if_connected(account.account_id)

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        self._ensure_credentials(account)
        previous = self._accounts.get(account.account_id)
        self._accounts[account.account_id] = account
        password_changed = bool(
            previous
            and previous.settings.get("password") != account.settings.get("password")
        )
        if password_changed or not account.enabled:
            await self._kill_if_connected(account.account_id)  # force re-auth

    async def delete_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
        self._device_meta.pop(account_id, None)
        await self._kill_if_connected(account_id)

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await self._kill_if_connected(account_id)

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        for account in accounts:
            if account.protocol == "ovpn":
                self._provision_credentials(account)
        self._accounts = {a.account_id: a for a in accounts if a.protocol == "ovpn"}
        live = {a.account_id for a in self._accounts.values() if a.enabled}
        try:
            for client in await asyncio.to_thread(self._backend.status_clients):
                if client.common_name not in live:
                    await asyncio.to_thread(self._backend.kill_client, client.common_name)
        except CoreError:
            pass  # core down — next boot reconciles anyway

    # ------------------------------------------------------------------ #
    # durable live-session baselines
    # ------------------------------------------------------------------ #
    def usage_tracker_snapshot(
        self, account_ids: list[str] | None = None,
    ) -> dict[str, tuple[int, int]]:
        """Persist the wildcard CN session cursor used by interim+final merge.

        BaseCoreDriver only knew cumulative DeltaTracker snapshots. OpenVPN's
        SessionUsageTracker was therefore always persisted as an empty map;
        restarting the panel while a session existed could replay its complete
        status counter before the disconnect final arrived.
        """
        wanted = set(account_ids) if account_ids is not None else None
        # A disconnected account needs an explicit zero tombstone; otherwise
        # the baseline row from its last live poll survives forever and a
        # same-sized reconnect after panel restart is suppressed.
        out: dict[str, tuple[int, int]] = {
            account_id: (0, 0) for account_id in (wanted or set(self._accounts))
        }
        for key, totals in self._usage.session_snapshot().items():
            if not isinstance(key, tuple) or len(key) != 2 or key[1] != "*":
                continue
            account_id = str(key[0])
            if wanted is None or account_id in wanted:
                out[account_id] = totals
        return out

    def restore_usage_baselines(self, baselines: dict) -> None:
        self._usage.restore_sessions({
            (str(account_id), "*"): (int(totals[0]), int(totals[1]))
            for account_id, totals in (baselines or {}).items()
        })

    # ------------------------------------------------------------------ #
    # statistics: hook finals (authoritative) + status deltas (interim)
    # ------------------------------------------------------------------ #
    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        records: list[UsageRecord] = []

        def _wanted(cn: str) -> bool:
            return account_ids is None or cn in account_ids

        # 1) authoritative finals first (ordering matters: close sessions)
        finals = await asyncio.to_thread(self._backend.read_disconnect_log)
        for final in finals:
            if not _wanted(final.common_name):
                continue
            up, down = self._usage.close(
                (final.common_name, "*"), final.bytes_received, final.bytes_sent
            )
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=final.common_name,
                uplink_bytes=up, downlink_bytes=down,
            ))

        # 2) interim deltas of still-connected sessions
        try:
            clients = await asyncio.to_thread(self._backend.status_clients)
        except CoreError:
            clients = []
        sessions = await self._session_keys(clients)
        for client in clients:
            if not _wanted(client.common_name):
                continue
            up, down = self._usage.poll(
                sessions[client.session_key], client.bytes_received, client.bytes_sent
            )
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=client.common_name,
                uplink_bytes=up, downlink_bytes=down,
            ))
        return records

    async def _session_keys(self, clients: list[Any]) -> dict[tuple[str, str, str], tuple[str, str]]:
        """Map precise session keys ((cn, since, ip)) to the tracker key.

        ``SessionUsageTracker`` is keyed per (cn, "*") so a disconnect final
        closes the session regardless of which precise key the interim used;
        the newest poll wins the tracker quote. Documented in docs §13.3.
        """
        return {client.session_key: (client.common_name, "*") for client in clients}

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        sessions: list[DeviceSession] = []
        for client in await asyncio.to_thread(self._backend.status_clients):
            if account_ids is not None and client.common_name not in account_ids:
                continue
            meta = self._device_meta.get(client.common_name, {})
            sessions.append(DeviceSession(
                core_id=self.metadata.id,
                account_id=client.common_name,
                ip=client.real_ip or None,
                connected_at=self._parse_started(client.connected_since),
                metadata={
                    "virtual_ip": client.virtual_address,
                    "platform": meta.get("platform"),
                    "app_version": meta.get("app_version"),
                    "cipher": client.cipher,
                    "real_port": client.real_port,
                },
            ))
        return sessions

    @staticmethod
    def _parse_started(value: str) -> Any:
        if not value:
            return None
        try:
            from datetime import datetime

            return datetime.strptime(value, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    # ------------------------------------------------------------------ #
    # client config + delivery (one profile per granted listener)          #
    # ------------------------------------------------------------------ #
    def render_client_profile(self, account: UserAccount,
                              listener: dict[str, Any],
                              context: "DeliveryContext | None" = None) -> str:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        if self._pki is None:
            raise CoreError("PKI not initialized yet — start the core first.")
        s = self.settings
        from app.cores.delivery import resolve_delivery_host

        configured_host = listener.get("advertise_host") or s.get("advertise_host")
        host = (str(configured_host or "").strip() if context is None else
                resolve_delivery_host(
                    configured_host, context, listener.get("listen"),
                    allow_loopback=bool(s.get("allow_loopback_advertise", False)),
                ))
        if not host:
            raise CoreError(
                f"no public endpoint is configured for OpenVPN inbound '{listener['tag']}'")
        return "\n".join([
            "client",
            "dev tun",
            f"proto {listener['proto']}",
            f"remote {host} {listener['port']}",
            "resolv-retry infinite",
            "nobind",
            "persist-key", "persist-tun",
            "remote-cert-tls server",
            # Server auth is CA/certificate based, while CLIENT auth is the
            # panel's username/password management channel
            # (`verify-client-cert none`). OpenVPN Connect needs this explicit
            # import hint or it rejects a valid cert-less client profile.
            "setenv CLIENT_CERT 0",
            "auth-user-pass",
            "auth-nocache",
            f"data-ciphers {listener.get('cipher') or 'AES-256-GCM'}:"
            f"{listener.get('cipher_fallback') or 'AES-128-GCM'}",
            f"data-ciphers-fallback {listener.get('cipher_fallback') or 'AES-128-GCM'}",
            *([f"compress {listener['compression']}"]
              if str(listener.get("compression") or "") else []),
            "verb 3",
            "<ca>", self._pki["ca_crt"].strip(), "</ca>",
            "<tls-crypt>", self._pki["tls_crypt"].strip(), "</tls-crypt>",
            "",
        ])

    def _ca_fingerprint(self) -> str:
        """SHA-256 fingerprint of the shared CA certificate (DER, hex, short
        form) — memoized per PEM so the portal does not re-derive it for
        every listener section. A corrupt PKI is reported honestly, never
        swallowed."""
        if self._pki is None:
            return ""
        pem = str(self._pki.get("ca_crt") or "")
        if not pem.strip():
            return ""
        if self._ca_fp is None or self._ca_fp[0] != pem:
            import hashlib
            import ssl

            try:
                der = ssl.PEM_cert_to_DER_cert(pem)
            except ValueError as exc:
                raise CoreError(
                    f"openvpn: the provisioned CA certificate is not valid PEM ({exc})."
                ) from exc
            self._ca_fp = (pem, hashlib.sha256(der).hexdigest()[:16].upper())
        return self._ca_fp[1]

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """OpenVPN delivery: one section per GRANTED listener — downloadable
        .ovpn profile + auth credentials + server/security facts (xray-style
        one-entry-per-inbound; the PKI and the auth database are shared
        across them)."""
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryField,
            DeliveryProfile,
            DeliverySection,
        )

        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        self._ensure_credentials(account)
        static = str(self.settings.get("auth_mode") or "management") == "static"
        auth_fields = (
            [
                DeliveryField(key="username", label="Username (shared)",
                              value=str(self.settings.get("static_user") or "")),
                DeliveryField(key="password", label="Password (shared)",
                              value=str(self.settings.get("static_pass") or ""),
                              secret=True),
            ]
            if static
            else [
                DeliveryField(key="username", label="Username",
                              value=account.account_id),
                DeliveryField(key="password", label="Password",
                              value=str(account.settings["password"]),
                              secret=True),
            ]
        )
        sections: list[DeliverySection] = []
        advertise_host = str(self.settings.get("advertise_host") or "")
        for listener in self._granted_listeners(account):
            profile = self.render_client_profile(account, listener, context)
            cipher_line = (
                f"{listener.get('cipher') or 'AES-256-GCM'}:"
                f"{listener.get('cipher_fallback') or 'AES-128-GCM'}"
            )
            security_fields = [
                DeliveryField(key="server", label="Server",
                              value=f"{advertise_host}:{listener['port']}"),
                DeliveryField(key="transport", label="Transport",
                              value=str(listener["proto"]).upper()),
                DeliveryField(key="cipher", label="Data ciphers",
                              value=cipher_line),
                DeliveryField(key="tls", label="TLS",
                              value="tls-crypt · remote-cert-tls server"),
            ]
            ca_fp = self._ca_fingerprint()
            if ca_fp:
                security_fields.append(
                    DeliveryField(key="ca_fingerprint",
                                  label="CA fingerprint (SHA-256)",
                                  value=ca_fp))
            sections.append(DeliverySection(
                protocol="ovpn",
                title=f"{listener['tag']} · OpenVPN",
                engine="openvpn",
                inbound_tag=listener["tag"],
                artifacts=[
                    DeliveryArtifact(
                        kind=ArtifactKind.FILE,
                        label="OpenVPN profile",
                        content=profile,
                        filename=f"{account.username}-{listener['tag']}.ovpn",
                        mime="application/x-openvpn-profile",
                    ),
                    DeliveryArtifact(
                        kind=ArtifactKind.FIELDS,
                        label="Authentication",
                        fields=tuple(auth_fields),
                    ),
                    DeliveryArtifact(
                        kind=ArtifactKind.FIELDS,
                        label="Server & security",
                        fields=tuple(security_fields),
                    ),
                    DeliveryArtifact(
                        kind=ArtifactKind.NOTE,
                        label="How to connect",
                        note="Import the .ovpn profile into any OpenVPN client and "
                             "enter the username/password when prompted.",
                    ),
                ],
            ))
        return DeliveryProfile(core_id=self.metadata.id, sections=sections)

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        listeners = self._granted_listeners(account)
        if not listeners:
            raise CoreError(
                f"openvpn account '{account.account_id}' has no granted inbound."
            )
        profile = self.render_client_profile(account, listeners[0], node)
        static = str(self.settings.get("auth_mode") or "management") == "static"
        username = (str(self.settings.get("static_user") or "")
                    if static else account.account_id)
        password = (str(self.settings.get("static_pass") or "")
                    if static else str(account.settings["password"]))
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="ovpn",
            engine="openvpn",
            payload={
                "format": "ovpn", "profile": profile, "auth": "user-pass",
                "username": username, "password": password,
            },
            display_name=f"OpenVPN · {listeners[0]['tag']}",
        )
