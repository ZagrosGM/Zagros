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
import base64
import hashlib
import copy
import logging
import os
import secrets
from collections.abc import AsyncIterator
from typing import Any, ClassVar

logger = logging.getLogger("zagros.cores.drivers.singbox")

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
    # consolidated cores (alpha.7.2): the standalone hysteria2/tuic engines
    # folded into sing-box — the protocols are served natively, so account
    # management, usage accounting and delivery live here now.
    "hysteria2": {"password"},
    "tuic": {"uuid", "password"},
}
_PROTOCOLS = set(_INBOUND_KEYS)


def _x25519_keypair() -> tuple[str, str]:
    """(private, public) raw-base64url keys in the exact sing-box reality /
    Xray `x25519` output format. Backed by the project's own crypto module
    (fast C backend when available, audited pure-Python otherwise — never a
    hard dependency on the local wheel situation)."""
    from app.crypto import x25519

    private_key, public_key = x25519.generate_keypair()

    def enc(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return enc(private_key), enc(public_key)


class SingBoxDriver(BaseCoreDriver):
    """Driver for SagerNet sing-box (config-render + restart strategy)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="sing-box",
        name="sing-box",
        description=(
            "Universal proxy platform by SagerNet. Config-render driver; "
            "natively serves vless/vmess/trojan/shadowsocks plus the "
            "consolidated Hysteria2 and TUIC v5 protocols (alpha.7.2: the "
            "standalone hy2/tuic cores folded in — one verified matrix, "
            "unified per-user accounting), and still the richest native "
            "outbound set (wireguard, hysteria2, tuic, shadowsocks, socks, "
            "http) — the panel's prime chain target."
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
            "ports": {"vless": 10001, "vmess": 10002, "trojan": 10003, "shadowsocks": 10004,
                      "hysteria2": 4430, "tuic": 5443},
            "advertise_host": "127.0.0.1",
            "ss_method": "aes-128-gcm",
            "final_outbound": "direct",
            "geoip_db": "",
            "geosite_db": "",
            "stats_enabled": True,
            "stats_api": "127.0.0.1:19091",
        },
        homepage="https://github.com/SagerNet/sing-box",
        release_repo="SagerNet/sing-box",
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
        self._v2ray_supported: bool | None = None  # lazy binary probe cache
        self._stats_degrade_warned = False
        self._studio_doc: dict[str, Any] | None = None  # set by apply_studio_document
        self._studio_link_meta: dict[str, dict[str, Any]] = {}  # per-tag link metadata
        self._stats_error: str | None = None
        # alpha.7.2 consolidation: persisted alpha.7.1 settings rows carry a
        # `ports` map WITHOUT the hysteria2/tuic keys — deep-merge the seed
        # defaults so the derived (pre-studio) render path never KeyErrors.
        port_defaults = dict(self.metadata.default_settings.get("ports") or {})
        self.settings["ports"] = {**port_defaults, **(self.settings.get("ports") or {})}
        self._self_signed_tags: set[str] = set()  # tags whose cert the panel minted

    # ------------------------------------------------------------------ #
    # config rendering + publishing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _user_entry(account: UserAccount) -> dict[str, Any]:
        protocol = account.protocol
        entry: dict[str, Any] = {"name": account.account_id}
        if protocol == "hysteria2":
            # sing-box hysteria2 users are {name, password}
            entry["password"] = str(account.settings["password"])
        elif protocol in ("vless", "vmess"):
            entry["uuid"] = str(account.settings["id"])
            if protocol == "vless" and account.settings.get("flow"):
                entry["flow"] = account.settings["flow"]
        elif protocol == "tuic":
            # sing-box tuic users are {uuid, password} — NO name field
            # (the generic branch rendered a tuic user without uuid, which
            # the binary rejects with "missing uuid for user 0"; caught by
            # the wizard matrix probe against the real binary)
            entry = {
                "uuid": str(account.settings.get("uuid") or account.settings.get("id")),
                "password": str(account.settings["password"]),
            }
        else:
            entry["password"] = account.settings["password"]
        return entry

    def _render_inbounds(self) -> list[dict[str, Any]]:
        if self._studio_doc and self._studio_doc.get("inbounds"):
            return self._merge_studio_inbounds()
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
            ss_extra: dict[str, Any] = {}
            if protocol == "shadowsocks":
                ss_extra["method"] = self._ss_checked_method(str(self.settings["ss_method"]))
                psk = self._ss_server_psk()  # mandatory iPSK for 2022 ciphers
                if psk:
                    ss_extra["password"] = psk
            tls_extra: dict[str, Any] = {}
            if protocol in ("hysteria2", "tuic"):
                # TLS is MANDATORY for both protocols in sing-box (unlike the
                # classic four) — a derived listener mints the panel
                # self-signed pair exactly like the studio path does.
                tag = f"{protocol}-in"
                cert_path, key_path = self._studio_materialize_certificate(tag, None, None)
                self._self_signed_tags.add(tag)
                tls_extra["tls"] = {"enabled": True, "server_name": "",
                                    "certificate_path": cert_path, "key_path": key_path}
                if protocol == "tuic":
                    tls_extra["congestion_control"] = "bbr"
            inbounds.append({
                "type": protocol,
                "tag": f"{protocol}-in",
                "listen": self.settings["listen"],
                "listen_port": int(ports[protocol]),
                "users": users,
                **ss_extra,
                **tls_extra,
            })
        for (protocol, port), _ep in sorted(self._chain_listeners.items()):
            inbounds.append({
                "type": protocol,
                "tag": f"zg-chain-{protocol}-{port}",
                "listen": "127.0.0.1",
                "listen_port": port,
            })
        return inbounds

    # ------------------------------------------------------------------ #
    # Config Studio bridge — the applied document becomes the LISTENER truth,
    # users stay platform-driven (attached per protocol at render time)
    # ------------------------------------------------------------------ #


    def export_config_document(self) -> dict[str, Any]:
        """Studio seed: the current effective document (pure render — works
        equally when the core is stopped; this fixed the 422 wizard saw on a
        non-running sing-box)."""
        return self.render_config()

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Adopt the studio document: inbounds materialize on the binary
        (translation is STRICT — an unmappable key fails loudly instead of
        being silently dropped); restart only when running."""
        self._studio_doc = copy.deepcopy(document)
        rendered = self.render_config()
        await asyncio.to_thread(self._backend.apply_config, rendered)
        if await asyncio.to_thread(self._backend.is_running):
            await asyncio.to_thread(self._backend.restart)

    def _merge_studio_inbounds(self) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        self._studio_link_meta = {}
        for raw in self._studio_doc["inbounds"]:
            ib = self._studio_entry_to_native(raw)
            tag = str(ib.get("tag") or "")
            if tag.startswith("zg-chain-"):
                continue  # chain listeners are managed, never doc-owned
            # sing-box strictly rejects unknown fields — panel-side link
            # metadata (reality public key, client flow hint, …) must NOT
            # leak into the rendered document; keep it in the side map the
            # delivery path reads instead (probe vs real binary, alpha.7.1)
            if tag in self._self_signed_tags:
                ib["_self_signed_cert"] = True  # delivery emits insecure=1 honestly
            meta = {k: ib.pop(k) for k in list(ib) if k.startswith("_")}
            if meta:
                self._studio_link_meta[tag] = meta
            ptype = ib.get("type")
            if ptype in _PROTOCOLS:
                users = [
                    self._user_entry(a)
                    for a in self._accounts.values()
                    if a.protocol == ptype and a.enabled
                ]
                if users:
                    ib["users"] = users
                    merged.append(ib)
                # else: dead listener (no enabled user) — dropped honestly,
                # same rule as the derived rendering
            else:
                merged.append(ib)
        for (protocol, port), _ep in sorted(self._chain_listeners.items()):
            merged.append({
                "type": protocol,
                "tag": f"zg-chain-{protocol}-{port}",
                "listen": "127.0.0.1",
                "listen_port": port,
            })
        return merged

    #: protocols the wizard can materialize — verified live against
    #: sing-box 1.12.4 (`sing-box check` per offered combo)
    _STUDIO_PROTOCOLS = {
        "vless", "vmess", "trojan", "shadowsocks",
        "socks", "http", "mixed", "naive", "anytls", "hysteria2", "tuic",
    }

    #: Shadowsocks 2022 ciphers - their passwords ARE the AEAD keys and must
    #: be base64 PSKs of an exact byte size (verified live: a 2022 cipher
    #: with a legacy string password fails `sing-box check` "missing psk").
    #: The default ss_method stays aes-128-gcm (password = free-form string).
    _SS2022_PSK_BYTES: ClassVar[dict[str, int]] = {
        "2022-blake3-aes-128-gcm": 16,
        "2022-blake3-aes-256-gcm": 32,
    }
    #: methods the binary actually serves (verified per method against 1.12.4;
    #: 2022-blake3-chacha20-poly1305 is Xray-only and rejected here).
    _SS_SUPPORTED_METHODS: ClassVar[frozenset[str]] = frozenset({
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    })

    def _ss_checked_method(self, method: str) -> str:
        if method not in self._SS_SUPPORTED_METHODS:
            raise CoreError(
                f"sing-box does not implement shadowsocks method '{method}' "
                f"(verified against the real binary) — supported: "
                f"{sorted(self._SS_SUPPORTED_METHODS)}."
            )
        return method

    def _ss_server_psk(self, method: str | None = None) -> str | None:
        """Server-level identity PSK (iPSK) for Shadowsocks-2022 methods.

        sing-box rejects a 2022 inbound without it ("missing psk") and every
        client needs it (ss:// encodes ``method:iPSK:uPSK``). Generated once,
        persisted 0600 under work_dir per key-size, exactly like the
        tuic/hysteria2 bootstrap-secret convention. None for classic methods
        (the free-form per-user password suffices there).
        """
        method = str(method or self.settings.get("ss_method") or "aes-128-gcm")
        size = self._SS2022_PSK_BYTES.get(method)
        if not size:
            return None
        work_dir = str(self.settings.get("work_dir") or ".")
        path = os.path.join(work_dir, f".ss-2022-psk-{size}")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                stored = fh.read().strip()
            if stored:
                return stored
        os.makedirs(work_dir, exist_ok=True)
        psk = base64.b64encode(secrets.token_bytes(size)).decode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(psk + "\n")
        return psk

    def _normalize_account(self, account: UserAccount) -> UserAccount:
        """Derive engine-mandated credential material ONCE at the ingest
        boundary (create/update/sync), so render paths never re-mint and
        every consumer — listener, share link, delivery — sees the same
        values. UserAccount is frozen; normalization returns a NEW object.

        * ss with a 2022 method: ``password`` becomes a proper base64 PSK
          (deterministically expanded from the stored secret when it is not
          one already — the stored row/subscription keeps the ORIGINAL
          secret, so this must be a pure function of it);
        * uuid-carrying protocols (tuic): accept legacy ``id`` as ``uuid``.
        """
        if account.protocol == "shadowsocks":
            method = str(self.settings.get("ss_method") or "aes-128-gcm")
            need = self._SS2022_PSK_BYTES.get(method)
            secret = str(account.settings.get("password") or "")
            if need and secret:
                try:
                    raw = base64.b64decode(secret, validate=True)
                except Exception:
                    raw = b""
                if len(raw) != need:
                    digest = hashlib.sha256(secret.encode("utf-8")).digest()
                    account = account.model_copy(update={
                        "settings": {
                            **account.settings,
                            "password": base64.b64encode(digest[:need]).decode(),
                        }
                    })
        elif account.protocol == "tuic" and not account.settings.get("uuid"):
            legacy_id = account.settings.get("id")
            if legacy_id is not None:
                account = account.model_copy(update={
                    "settings": {**account.settings, "uuid": str(legacy_id)}
                })
        return account

    def _studio_entry_to_native(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Studio entry {tag, protocol, listen, port, …wizard fields} → native
        sing-box inbound. Every wizard field maps somewhere; anything
        unmappable raises CoreError (never silently ignored)."""
        if raw.get("type") and raw.get("listen_port"):
            return dict(raw)  # already native (edited in Advanced Mode)

        proto = str(raw.get("protocol") or raw.get("type") or "")
        if proto not in self._STUDIO_PROTOCOLS:
            raise CoreError(
                f"studio inbound '{raw.get('tag')}': sing-box has no server "
                f"inbound '{proto}' — WireGuard exists in sing-box only as an "
                "OUTBOUND (a WireGuard *listener* is the WireGuard core's job); "
                "redirect/tproxy/tun/shadowtls are transparent-proxy facilities, "
                "not per-user inbounds."
            )
        known = {"tag", "protocol", "listen", "port", "inbound_variant",
                 "transport", "security",
                 "path", "host", "headers", "service_name", "authority",
                 "sni", "alpn", "method", "flow", "fingerprint", "public_key",
                 "congestion_control", "zero_rtt", "up_mbps", "down_mbps", "obfs",
                 "cipher", "ports", "ipsec_psk", "certificate", "certificate_key",
                 "mode", "username", "password", "auth", "padding_scheme",
                 "masquerade"}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise CoreError(
                f"studio inbound '{raw.get('tag')}': fields not translatable "
                f"to a sing-box listener: {unknown} — edit raw JSON instead."
            )
        ib: dict[str, Any] = {
            "type": proto,
            "tag": raw["tag"],
            "listen": raw.get("listen") or self.settings["listen"],
            "listen_port": int(raw["port"]),
        }
        # transport — explicit selection wins (dynamic wizard sends it);
        # a transport sing-box cannot serve fails loudly instead of silently
        # degrading the listener to plain TCP
        net = str(raw.get("transport") or "").lower()
        security = str(raw.get("security") or "").lower()
        if proto == "shadowsocks" and net not in ("", "tcp"):
            raise CoreError(
                "sing-box shadowsocks inbounds have no transport field at all "
                "(TCP+UDP in-protocol) — pick VLESS/VMess/Trojan for ws/gRPC/h2."
            )
        if net == "xhttp" and proto not in ("hysteria2", "tuic"):
            raise CoreError(
                f"sing-box cannot serve a {proto} inbound over xhttp "
                f"(xhttp is Xray-only) — pick ws/httpupgrade/grpc/http instead."
            )
        # naive (HTTPS/2) and anytls have NO transport field physically (sing-box
        # struct literally lacks it — "unknown field transport", verified); the
        # wizard's transport pick for them is decorative and is dropped here
        skip_transport = proto in ("naive", "anytls")
        if net == "grpc" and not skip_transport or raw.get("service_name"):
            if not raw.get("service_name"):
                raise CoreError("gRPC inbound requires service_name")
            ib["transport"] = {"type": "grpc", "service_name": raw["service_name"]}
        elif net == "httpupgrade" and not skip_transport:
            ib["transport"] = {"type": "httpupgrade", "path": raw.get("path") or "/",
                               **({"host": raw["host"]} if raw.get("host") else {})}
        elif net == "http" and not skip_transport:
            _h = raw.get("host")
            ib["transport"] = {"type": "http",
                               **({"path": raw["path"]} if raw.get("path") else {}),
                               **({"host": [_h] if isinstance(_h, str) else _h} if _h else {})}
        elif net == "quic" and proto not in ("hysteria2", "tuic") and not skip_transport:
            # sing-box DOES have a generic quic transport, but it refuses to
            # boot it without TLS ("create server transport: quic: TLS
            # required", verified) — so it is only offered under TLS/REALITY.
            if security not in ("tls", "reality"):
                raise CoreError(
                    "a QUIC transport requires TLS or REALITY in sing-box."
                )
            ib["transport"] = {"type": "quic"}
        elif skip_transport:
            pass  # decorative transport choice (see above)
        elif net == "ws" or raw.get("path") is not None or raw.get("host"):
            headers = dict(raw.get("headers") or {})
            if raw.get("host"):
                headers["Host"] = raw["host"]
            ib["transport"] = {"type": "ws", "path": raw.get("path") or "/",
                               **({"headers": headers} if headers else {})}
        # security — explicit; reality is verified per-protocol below
        alpn = raw.get("alpn")
        if proto in ("socks", "mixed"):
            if security not in ("", "none"):
                raise CoreError(
                    f"sing-box {proto} inbounds do not carry a TLS section "
                    "(verified against the binary) — terminate TLS upstream or "
                    "pick the http inbound."
                )
        elif proto == "shadowsocks":
            if security not in ("", "none"):
                raise CoreError(
                    "sing-box shadowsocks inbounds do not carry a TLS section — "
                    "Shadowsocks IS the encryption layer itself."
                )
        elif proto == "trojan" and security in ("", "none"):
            raise CoreError(
                "Trojan without TLS is not offered — the protocol's identity IS "
                "the TLS layer; pick TLS or REALITY."
            )
        elif proto in ("hysteria2", "tuic") and security not in ("", "tls"):
            raise CoreError(
                f"TLS is mandatory for {proto} in sing-box (QUIC handshake is "
                f"TLS1.3); '{security}' is not servable — use the TLS security "
                "(the only one the wizard offers for these protocols)."
            )
        if proto == "naive" and not raw.get("username"):
            raise CoreError("naive (HTTPS/2 proxy) needs username+password users.")
        if security == "reality" or raw.get("public_key"):
            if proto in ("vmess", "shadowsocks"):
                raise CoreError(
                    f"REALITY is not offered for {proto} — clients only do the "
                    "REALITY handshake under VLESS/Trojan."
                )
            private, public = _x25519_keypair()
            sni = str(raw.get("sni") or "").split(":")[0]
            if not sni:
                raise CoreError("reality inbound needs a camouflage SNI")
            ib["tls"] = {
                "enabled": True,
                "server_name": sni,
                "reality": {
                    "enabled": True,
                    "handshake": {"server": sni, "server_port": 443},
                    "private_key": private,
                    "short_id": [secrets.token_hex(8)],
                },
                **({"alpn": alpn} if alpn else {}),
            }
            ib["_reality_public_key"] = public  # → side map (delivery), never rendered
        elif security == "tls" or proto in ("naive", "anytls", "hysteria2", "tuic"):
            cert_path, key_path = self._studio_materialize_certificate(
                str(raw["tag"]), raw.get("certificate"), raw.get("certificate_key"),
            )
            ib["tls"] = {
                "enabled": True,
                "server_name": raw.get("sni") or "",
                "certificate_path": cert_path,
                "key_path": key_path,
                **({"alpn": alpn} if alpn else {}),
            }
        # protocol specifics
        if proto == "shadowsocks":
            if raw.get("method"):
                ib["method"] = self._ss_checked_method(str(raw["method"]))
            psk = self._ss_server_psk(str(raw.get("method") or "") or None)
            if psk:
                ib["password"] = psk  # mandatory iPSK for 2022 ciphers
        if proto == "vless" and raw.get("flow"):
            ib["_client_flow"] = raw["flow"]  # client-level, link rendering
        if proto in ("socks", "http", "mixed", "naive"):
            if raw.get("username"):
                ib["users"] = [{
                    "username": str(raw["username"]),
                    "password": str(raw.get("password") or ""),
                }]
                if proto == "naive" and not raw.get("password"):
                    raise CoreError("naive users need a password.")
        if proto == "anytls":
            password = str(raw.get("password") or "")
            if not password:
                raise CoreError(
                    "anytls needs a listener password (its users authenticate "
                    "by password; per-user accounts stay a panel concern)."
                )
            ib["users"] = [{"name": str(raw.get("username") or raw["tag"]),
                            "password": password}]
            if raw.get("padding_scheme"):
                scheme = raw["padding_scheme"]
                ib["padding_scheme"] = (
                    scheme if isinstance(scheme, list)
                    else [s.strip() for s in str(scheme).splitlines() if s.strip()]
                )
        if proto == "hysteria2":
            for k in ("up_mbps", "down_mbps"):
                if raw.get(k) not in (None, ""):
                    ib[k] = int(raw[k])
            if raw.get("obfs"):
                ib["obfs"] = {"type": "salamander", "password": raw["obfs"]}
            if raw.get("masquerade"):
                ib["masquerade"] = str(raw["masquerade"])
        if proto == "tuic":
            if raw.get("congestion_control"):
                ib["congestion_control"] = raw["congestion_control"]
            if raw.get("zero_rtt"):
                # verified against the real binary: sing-box tuic inbounds
                # accept zero_rtt_handshake (1.12.4 + vendored 1.13.16,
                # `sing-box check` green on both)
                ib["zero_rtt_handshake"] = True
        return ib

    def _studio_materialize_certificate(
        self, tag: str, cert_pem: Any, key_pem: Any,
    ) -> tuple[str, str]:
        """Wizard TLS: uploaded PEM contents are written panel-side (uploads
        must come as a pair); blank = generate a self-signed certificate —
        the wizard help tells the operator to upload a real pair for
        production SNI."""
        if bool(cert_pem) != bool(key_pem):
            raise CoreError(
                f"TLS inbound '{tag}': upload certificate AND private key together."
            )
        import re as _re

        safe_tag = _re.sub(r"[^A-Za-z0-9_.-]+", "_", tag)
        cert_dir = str(self.settings.get("cert_dir") or
                       os.path.join(str(self.settings.get("work_dir") or "."), "certs"))
        cert_path = os.path.join(cert_dir, f"{safe_tag}.crt")
        key_path = os.path.join(cert_dir, f"{safe_tag}.key")
        if cert_pem:
            cert_text, key_text = str(cert_pem), str(key_pem)
            self._self_signed_tags.discard(tag)
        else:
            from app.utils.crypto import generate_certificate

            pair = generate_certificate()
            cert_text, key_text = pair["cert"], pair["key"]
            self._self_signed_tags.add(tag)
        os.makedirs(cert_dir, exist_ok=True)
        for path, text, mode in (
            (cert_path, cert_text, 0o644),
            (key_path, key_text, 0o600),
        ):
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    if fh.read() == text:
                        continue  # idempotent — no needless restart ripple
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(path, mode)
        return cert_path, key_path

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
        if self.settings.get("stats_enabled") and self._v2ray_api_supported():
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
        elif self.settings.get("stats_enabled"):
            self._stats_error = (
                "this sing-box build lacks the v2ray_api build tag — "
                "per-user accounting disabled (install a with_v2ray_api build)"
            )
            if not self._stats_degrade_warned:
                logger.warning(
                    "sing-box: stats_enabled but this build lacks the v2ray_api "
                    "build tag — starting WITHOUT per-user accounting; install "
                    "a build with -tags with_v2ray_api to restore it."
                )
                self._stats_degrade_warned = True
        return config

    def _v2ray_api_supported(self) -> bool:
        """Lazy one-shot probe, cached per binary (reset after install)."""
        if self._v2ray_supported is None:
            probe = getattr(self._backend, "probe_v2ray_support", None)
            if probe is None:
                self._v2ray_supported = True  # fakes/tests without a probe: legacy behavior
            else:
                try:
                    self._v2ray_supported = bool(probe())
                except Exception as exc:  # noqa: BLE001 — never block render
                    logger.warning("sing-box v2ray_api probe failed (%s) — assuming unsupported", exc)
                    self._v2ray_supported = False
        return self._v2ray_supported

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
        self._v2ray_supported = None  # binary changed: re-probe on next render

    async def update(self, version: str | None = None) -> str:
        await asyncio.to_thread(self._backend.install_binary)
        self._v2ray_supported = None
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

    @staticmethod
    def _provision_credentials(account: UserAccount) -> None:
        """Mint missing credentials IN PLACE (the settings dict is shared
        with the caller, so provisioning persists the generated material —
        the same contract the TUIC core used). No account may ever fail a
        grant for lack of credentials (batch item 10): the panel generates
        cryptographically random ones, the operator/subscription sees the
        same stored values forever after."""
        import secrets as _secrets
        import uuid as _uuid

        s = account.settings
        proto = account.protocol
        if proto in ("vless", "vmess") and not s.get("id"):
            s["id"] = str(_uuid.uuid4())
        elif proto == "tuic":
            if not (s.get("uuid") or s.get("id")):
                s["uuid"] = str(_uuid.uuid4())
            if not s.get("password"):
                s["password"] = _secrets.token_hex(16)
        elif proto in ("trojan", "shadowsocks", "hysteria2") and not s.get("password"):
            s["password"] = _secrets.token_urlsafe(18)

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        account = self._normalize_account(account)
        key = account.settings.get("id") or account.settings.get("password") \
            or account.settings.get("uuid")
        if account.enabled and not key:
            raise CoreError(
                f"Account '{account.account_id}' for '{account.protocol}' is missing credentials "
                f"({sorted(_INBOUND_KEYS[account.protocol])})."
            )
        self._accounts[account.account_id] = account
        await self._republish()

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._provision_credentials(account)
        self._accounts[account.account_id] = self._normalize_account(account)
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
        """Config-render cores converge best by rebuilding user state wholesale.

        Replay-time rows come from the encrypted store and ALWAYS carry their
        credentials already; provisioning still runs defensively (a row
        written by an older build without creds gets healed, not dropped)."""
        for a in accounts:
            self._provision_credentials(a)
        self._accounts = {
            a.account_id: self._normalize_account(a)
            for a in accounts
            if a.protocol in _PROTOCOLS
        }
        await self._republish()

    # ------------------------------------------------------------------ #
    # statistics — v2ray StatsService (experimental API)
    # ------------------------------------------------------------------ #
    def _stats_ready(self) -> bool:
        """True only when the rendered config actually carries a stats
        listener: accounting on AND this binary probe-confirmed the v2ray_api
        build tag. Anything less and there is physically nothing to dial."""
        return bool(self.settings.get("stats_enabled")) and self._v2ray_api_supported()

    async def _query_counters(self) -> dict[str, tuple[int, int]]:
        # Never dial a listener that was never rendered: the field error was
        # a raw "stats API unreachable / Connection refused" masking the real
        # cause (an upstream build without the tag). Short-circuit + keep the
        # coherent degrade message set at render time instead.
        if not self._stats_ready():
            return {}
        try:
            counters = await asyncio.to_thread(self._stats.query_user_counters)
        except Exception as exc:
            self._stats_error = (
                f"sing-box stats listener not answering on "
                f"{self.settings['stats_api']}: {exc} — the build supports the "
                f"v2ray API (probe passed) but the listener is not up; the "
                f"core may be running a stale config — restart it so the "
                f"rendered config applies."
            )
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
    # client config + delivery — composed from the RENDERED listeners so a
    # share link can never disagree with what the binary serves. Grant
    # selection (inbound_tags / excluded_inbounds) is honored per inbound;
    # the consolidated hysteria2/tuic protocols get the same treatment.
    # ------------------------------------------------------------------ #
    def _selected_inbounds(
        self, account: UserAccount
    ) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
        """(tag, native inbound, link-meta) triples this account may use.

        The render includes the account itself (temporarily, read-only):
        delivery only ever describes listeners that would actually serve the
        asking account — an account awaiting its first sync thus still gets
        a correct link set instead of an empty list."""
        injected = account.account_id not in self._accounts
        if injected:
            self._accounts = {**self._accounts, account.account_id: account}
        try:
            rendered = self.render_config()  # refreshes _studio_link_meta
        finally:
            if injected:
                self._accounts.pop(account.account_id, None)
        selected = account.settings.get("inbound_tags")
        selected = {str(t) for t in selected} if selected else None
        excluded = {str(t) for t in account.settings.get("excluded_inbounds") or []}
        out: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        for ib in rendered.get("inbounds", []):
            tag = str(ib.get("tag") or "")
            if tag.startswith("zg-chain-"):
                continue
            if ib.get("type") != account.protocol:
                continue
            if tag in excluded:
                continue
            if selected is not None and tag not in selected:
                continue
            out.append((tag, ib, dict(self._studio_link_meta.get(tag) or {})))
        return out

    def _compose_outbound(
        self, account: UserAccount, tag: str, ib: dict[str, Any], meta: dict[str, Any]
    ) -> dict[str, Any]:
        """Mirror one rendered listener into a client outbound fragment
        (share-link shape consumed by ``share_url_for_outbound``)."""
        proto = str(ib["type"])
        server = str(self.settings.get("advertise_host") or "").strip() \
            or str(ib.get("listen") or "").strip()
        if server in ("::", "0.0.0.0", "[::]", ""):
            raise CoreError(
                "no advertise_host configured for the sing-box core and the "
                f"inbound '{tag}' listens on a wildcard address — set "
                "advertise_host in the core settings so clients know where "
                "to connect."
            )
        outbound: dict[str, Any] = {
            "type": proto, "tag": f"{tag}-svc",
            "server": server, "server_port": int(ib.get("listen_port") or 0),
        }
        # credentials — exactly what the listener expects
        if proto in ("vless", "vmess"):
            outbound["uuid"] = str(account.settings.get("id") or account.settings.get("uuid"))
            flow = meta.get("_client_flow") or account.settings.get("flow")
            if proto == "vless" and flow:
                outbound["flow"] = flow
        elif proto == "tuic":
            outbound["uuid"] = str(account.settings.get("uuid") or account.settings.get("id"))
            outbound["password"] = str(account.settings["password"])
        else:  # trojan / shadowsocks / hysteria2
            outbound["password"] = str(account.settings["password"])
            if proto == "shadowsocks":
                method = str(ib.get("method") or self.settings["ss_method"])
                outbound["method"] = self._ss_checked_method(method)
                if ib.get("password"):
                    # SIP022 multi-user form: ss:// encodes method:iPSK:uPSK
                    outbound["password"] = f"{ib['password']}:{account.settings['password']}"
        # TLS — mirror the listener (reality pubkey rides the side map)
        tls = ib.get("tls") or {}
        if tls.get("enabled"):
            tls_out: dict[str, Any] = {"enabled": True}
            if tls.get("server_name"):
                tls_out["server_name"] = tls["server_name"]
            if tls.get("alpn"):
                tls_out["alpn"] = list(tls["alpn"])
            reality = tls.get("reality") or {}
            if reality.get("enabled"):
                tls_out["reality"] = {
                    "enabled": True,
                    "public_key": str(meta.get("_reality_public_key") or ""),
                    "short_id": (reality.get("short_id") or [""])[0],
                }
            if meta.get("_self_signed_cert") or tag in self._self_signed_tags:
                tls_out["insecure"] = True
            outbound["tls"] = tls_out
        else:
            outbound["tls"] = {"enabled": False}
        # transport — mirror the listener
        transport = ib.get("transport") or {}
        net = transport.get("type")
        if net in ("ws", "httpupgrade"):
            outbound["transport"] = {
                "type": net,
                "path": transport.get("path") or "/",
                **({"headers": transport["headers"]} if transport.get("headers") else {}),
                **({"host": transport["host"]} if transport.get("host") else {}),
            }
        elif net == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": transport.get("service_name") or "",
            }
        elif net == "http":
            outbound["transport"] = {
                "type": "http",
                **({"path": transport["path"]} if transport.get("path") else {}),
                **({"host": transport["host"]} if transport.get("host") else {}),
            }
        # protocol extras
        if proto == "hysteria2":
            obfs = ib.get("obfs") or {}
            if obfs.get("password"):
                outbound["obfs"] = {
                    "type": obfs.get("type") or "salamander",
                    "password": str(obfs["password"]),
                }
        if proto == "tuic" and ib.get("congestion_control"):
            outbound["congestion_control"] = ib["congestion_control"]
        return outbound

    @staticmethod
    def _protocol_display(protocol: str) -> str:
        return {"hysteria2": "Hysteria 2", "tuic": "TUIC v5"}.get(
            protocol, protocol.upper())

    async def describe_delivery(
        self, account: UserAccount, context: Any | None = None
    ) -> "DeliveryProfile":
        """One section per usable inbound (grant-filtered), each with its
        QR-able share link per protocol variant; credentials ride along once
        as a FIELDS artifact for manual client entry."""
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryField,
            DeliveryProfile,
            DeliverySection,
            ShareLinkError,
            share_url_for_outbound,
        )

        self._ensure_supported(account.protocol)
        account = self._normalize_account(account)
        triples = self._selected_inbounds(account)
        display = self._protocol_display(account.protocol)
        profile = DeliveryProfile(core_id=self.metadata.id)
        if not triples:
            section = DeliverySection(
                protocol=account.protocol,
                title=f"{self.metadata.name} · {display}",
                engine="sing-box",
                artifacts=[DeliveryArtifact(
                    kind=ArtifactKind.NOTE, label="Unavailable",
                    note=(
                        f"No sing-box inbound for protocol '{account.protocol}' "
                        "is assigned to this account — ask the administrator to "
                        "select one in the user's core access."
                    ),
                )],
            )
            profile.sections.append(section)
            return profile

        creds_fields: list[DeliveryField] = []
        if account.protocol in ("vless", "vmess", "tuic"):
            creds_fields.append(DeliveryField(
                key="uuid", label="UUID",
                value=str(account.settings.get("id") or account.settings.get("uuid")),
                secret=True))
        if account.protocol in ("trojan", "shadowsocks", "hysteria2", "tuic"):
            creds_fields.append(DeliveryField(
                key="password", label="Password",
                value=str(account.settings["password"]), secret=True))
        if account.protocol == "shadowsocks":
            method = str(self.settings["ss_method"])
            creds_fields.append(DeliveryField(key="method", label="Cipher", value=method))

        for index, (tag, ib, meta) in enumerate(triples):
            remark = f"{display} · {tag}"
            section = DeliverySection(
                protocol=account.protocol,
                title=f"{self.metadata.name} · {remark}",
                engine="sing-box",
                inbound_tag=tag,
            )
            outbound = self._compose_outbound(account, tag, ib, meta)
            try:
                link = share_url_for_outbound(outbound, remark)
            except ShareLinkError as exc:
                section.artifacts.append(DeliveryArtifact(
                    kind=ArtifactKind.NOTE, label=remark,
                    note=f"Share link unavailable: {exc}",
                ))
            else:
                section.artifacts.append(DeliveryArtifact(
                    kind=ArtifactKind.LINK, label=remark, content=link, qr=True,
                ))
            if index == 0 and creds_fields:
                section.artifacts.append(DeliveryArtifact(
                    kind=ArtifactKind.FIELDS, label="Credentials (manual setup)",
                    fields=creds_fields,
                ))
            profile.sections.append(section)
        return profile

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        """Sealed single-config view (first usable inbound) — kept for the
        generic ClientConfig consumers; the rich view is describe_delivery."""
        self._ensure_supported(account.protocol)
        account = self._normalize_account(account)
        triples = self._selected_inbounds(account)
        if not triples:
            raise CoreError(
                f"No sing-box inbound available for protocol '{account.protocol}' "
                "(grant selection empty or no such listener configured)."
            )
        tag, ib, meta = triples[0]
        display = self._protocol_display(account.protocol)
        outbound = self._compose_outbound(account, tag, ib, meta)
        return ClientConfig(
            core_id=self.metadata.id,
            protocol=account.protocol,
            engine="sing-box",
            payload={"outbounds": [outbound]},
            display_name=f"{display} · {tag}",
        )



