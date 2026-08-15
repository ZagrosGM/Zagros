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
import logging
import os
import random
import secrets
from collections import defaultdict
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

logger = logging.getLogger("zagros.cores.drivers.xray")

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
                "executable_path": {"type": "string", "default": "/var/lib/zagros/cores/xray/bin/xray"},
                "assets_path": {"type": "string", "default": "/var/lib/zagros/cores/xray/assets"},
                "config_path": {"type": "string", "default": "/var/lib/zagros/cores/xray/xray_config.json"},
            },
        },
        default_settings={
            "executable_path": "/var/lib/zagros/cores/xray/bin/xray",
            "assets_path": "/var/lib/zagros/cores/xray/assets",
            "config_path": "/var/lib/zagros/cores/xray/xray_config.json",
        },
        homepage="https://github.com/XTLS/Xray-core",
        release_repo="XTLS/Xray-core",
        studio_inbounds_path="/inbounds",
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: "Any | None" = None):
        super().__init__(settings)
        if backend is None:
            if self.settings.get("_runtime_mode") == "node":
                # Native agents must never import the panel's legacy database,
                # singleton Xray process, or Marzban-compatible node fan-out.
                from app.cores.drivers.xray.standalone import StandaloneXrayBackend

                backend = StandaloneXrayBackend(self.settings)
            else:
                from app.cores.drivers.xray.backend import LegacyXrayBackend

                backend = LegacyXrayBackend(self.settings)
        self._backend = backend
        from app.cores.stats import DeltaTracker

        self._deltas = DeltaTracker()
        self._managed_native_outbounds: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # helpers / policy
    # ------------------------------------------------------------------ #
    def export_config_document(self) -> dict[str, Any]:
        """Studio seed: the legacy engine's REAL current config document (the
        file xray actually runs — read from disk so the studio edits the true
        document, works while stopped). A never-initialised installation gets
        a complete minimal skeleton (the legacy ``XRayConfig`` cannot start
        from a bare ``{"inbounds": []}`` — it validates outbounds too)."""
        import json

        instance_settings = getattr(self, "settings", {})
        if instance_settings.get("_runtime_mode") == "node":
            XRAY_JSON = str(instance_settings.get("config_path") or "xray_config.json")
        else:
            try:
                from config import XRAY_JSON
            except Exception:  # noqa: BLE001 — stand-alone usage without host config
                XRAY_JSON = "xray_config.json"
        if not os.path.exists(XRAY_JSON):
            return {
                "log": {"loglevel": "warning"},
                "inbounds": [],
                "outbounds": [
                    {"protocol": "freedom", "tag": "DIRECT"},
                    {"protocol": "blackhole", "tag": "BLOCK"},
                ],
                "routing": {"domainStrategy": "IPIfNonMatch", "rules": []},
            }
        try:
            with open(XRAY_JSON, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError) as exc:
            raise CoreError(f"cannot read the legacy xray document '{XRAY_JSON}': {exc}") from exc

    # ------------------------------------------------------------------ #
    # Config Studio bridge (alpha.7.1) — the old gap: xray exported its
    # document but had NO apply path, so wizard-created inbounds lived only
    # in the studio store and never became real listeners (field report:
    # "inbound created in wizard does not appear / does nothing").
    #
    # Bridge contract: validate+translate STRICTLY in the driver (unknown
    # wizard fields and unmappable combos fail loudly), then hand the full
    # document to the backend which persists it, reloads the live catalog
    # singleton, and restarts a running core.
    # ------------------------------------------------------------------ #
    _STUDIO_PROTOCOLS = {
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "dokodemo-door",
    }
    # verified live against Xray 26.3.27 (`xray run -test` per cell):
    # REALITY is only constructible on RAW/XHTTP/gRPC transports, and only
    # makes protocol sense for VLESS/Trojan (the AES-auth protocols cannot do
    # the reality handshake); h2/quic/old-mKCP-header transports were removed
    # upstream ("migrated to XHTTP stream-one H2 & H3").
    _STUDIO_TRANSPORTS = {"tcp", "ws", "httpupgrade", "grpc", "xhttp", "mkcp"}
    _REALITY_PROTOCOLS = {"vless", "trojan"}
    _REALITY_TRANSPORTS = {"tcp", "xhttp", "grpc"}
    _STUDIO_KNOWN_FIELDS = {
        "tag", "protocol", "listen", "port", "transport", "security",
        "path", "host", "headers", "service_name", "authority", "mode",
        "sni", "alpn", "certificate", "certificate_key", "fingerprint",
        "public_key", "flow", "method",
        "address", "target_port", "auth", "username", "password",
        "mtu", "tti", "congestion",
        # alpha.7.5 item 4 — transport depth, all real xray mappings:
        # ws arbitrary headers; gRPC multiMode; RAW/TCP HTTP camouflage
        # (tcpSettings.header.type = "http" with full request/response).
        "multi_mode",
        "header_type", "http_method", "request_headers",
        "response_status", "response_reason", "response_headers",
        # alpha.7.5 item 6 — certificate-by-path wizard mode (validated
        # against the same PEM rules as pasted content).
        "certificate_path", "certificate_key_path",
    }

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Adopt the studio document as THE running xray configuration."""
        inbounds = (document or {}).get("inbounds")
        if not isinstance(inbounds, list) or not inbounds:
            raise CoreError(
                "the xray studio document must carry at least ONE inbound — "
                "xray cannot boot an empty listener set (legacy validation)."
            )
        translated = [self._studio_entry_to_native(dict(raw)) for raw in inbounds]
        tags = [str(ib.get("tag") or "") for ib in translated]
        if any(not t for t in tags) or len(set(tags)) != len(tags):
            raise CoreError("every inbound needs a unique, non-empty tag.")
        import copy as _copy

        doc = _copy.deepcopy(document)
        doc["inbounds"] = translated
        apply = getattr(self._backend, "apply_config_document", None)
        if apply is None:
            raise CoreError(
                "this xray backend cannot apply studio documents — upgrade the "
                "panel; the studio bridge ships in the core backend."
            )
        await asyncio.to_thread(apply, doc)

    def _studio_entry_to_native(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Wizard entry {tag, protocol, port, transport, security, …fields} →
        native xray inbound (``streamSettings`` shape exactly as the legacy
        ``XRayConfig._resolve_inbounds`` parses it back into the user
        catalog). Entries that already look native pass through untouched —
        that is how Advanced Mode edits survive the bridge."""
        if "streamSettings" in raw or "settings" in raw:
            return dict(raw)  # already native (Advanced Mode / seeded file)

        proto = str(raw.get("protocol") or "")
        if proto not in self._STUDIO_PROTOCOLS:
            raise CoreError(
                f"studio inbound '{raw.get('tag')}': protocol '{proto}' is not "
                f"an xray server inbound ({', '.join(sorted(self._STUDIO_PROTOCOLS))}). "
                "WireGuard is an OUTBOUND-only protocol in Xray (use the "
                "WireGuard core, or sing-box >= 1.11, for a WireGuard listener)."
            )
        unknown = sorted(set(raw) - self._STUDIO_KNOWN_FIELDS)
        if unknown:
            raise CoreError(
                f"studio inbound '{raw.get('tag')}': fields not translatable to "
                f"a native xray inbound: {unknown} — edit the raw document in "
                "Advanced Mode instead."
            )
        tag = str(raw.get("tag") or "").strip()
        if not tag:
            raise CoreError("studio inbound needs a non-empty tag.")
        try:
            port = int(raw["port"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CoreError(f"studio inbound '{tag}' needs a numeric port.") from exc
        transport = str(raw.get("transport") or "tcp").lower()
        security = str(raw.get("security") or "none").lower()
        certificate_keys = ("certificate", "certificate_key",
                            "certificate_path", "certificate_key_path")
        if security != "tls" and any(raw.get(key) for key in certificate_keys):
            raise CoreError(
                f"studio inbound '{tag}': certificate material is only valid "
                "when security=tls; clear the certificate fields for "
                f"security={security}."
            )
        if transport not in self._STUDIO_TRANSPORTS:
            raise CoreError(
                f"studio inbound '{tag}': transport '{transport}' is removed/not "
                "available in current Xray — supported: tcp, ws, httpupgrade, "
                "grpc, xhttp, mkcp (h2/quic were removed upstream in favour of "
                "XHTTP stream-one H2 & H3; old mKCP header/seed is gone too)."
            )
        if security == "reality" and (
            proto not in self._REALITY_PROTOCOLS
            or transport not in self._REALITY_TRANSPORTS
        ):
            raise CoreError(
                f"studio inbound '{tag}': REALITY requires VLESS/Trojan over "
                "TCP/XHTTP/gRPC (verified against the real binary: \"REALITY "
                "only supports RAW, XHTTP and gRPC\")."
            )
        if proto == "trojan" and security == "none":
            raise CoreError(
                f"studio inbound '{tag}': Trojan without TLS is not offered — "
                "the protocol's own identity IS the TLS layer; pick TLS or REALITY."
            )

        inbound: dict[str, Any] = {
            "tag": tag,
            "listen": raw.get("listen") or "0.0.0.0",
            "port": port,
            "protocol": proto,
            "settings": self._studio_protocol_settings(proto, raw),
            "streamSettings": self._studio_stream_settings(tag, raw),
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        }
        return inbound

    @staticmethod
    def _studio_protocol_settings(proto: str, raw: dict[str, Any]) -> dict[str, Any]:
        if proto in ("vless", "vmess", "trojan"):
            settings: dict[str, Any] = {"clients": []}
            if proto == "vless":
                settings["decryption"] = "none"
            return settings
        if proto == "shadowsocks":
            method = str(raw.get("method") or "")
            if method.startswith("2022-"):
                # verified against the real binary: ss-2022 multi-user needs
                # a server iPSK + per-user base64 PSK uPSKs and empty client
                # methods ("shadowsocks 2022 (multi-user): users must have
                # empty method"); legacy account passwords (token_urlsafe)
                # are structurally NOT 2022 uPSKs, so restarting with real
                # users would FATAL the live core. The sing-box core carries
                # full, verified ss-2022 support (iPSK persisted, per-user
                # PSKs normalized at ingest, ss:// iPSK:uPSK links).
                raise CoreError(
                    "shadowsocks 2022 ciphers need iPSK/uPSK key material the "
                    "legacy xray account store cannot supply (verified against "
                    "xray 26.3.27) — use the sing-box core for ss-2022; it is "
                    "fully supported there. Classic ciphers work natively here."
                )
            # per-user method+password live on each client entry; the panel
            # attaches users at restart/include_db_users time
            return {"clients": [], "network": "tcp,udp"}
        if proto == "socks":
            auth = str(raw.get("auth") or "noauth")
            settings = {"udp": True, "auth": auth}
            if auth == "password":
                user, password = raw.get("username"), raw.get("password")
                if not user or not password:
                    raise CoreError(
                        "a socks inbound with password auth needs username AND password."
                    )
                settings["accounts"] = [{"user": str(user), "pass": str(password)}]
            return settings
        if proto == "http":
            settings = {"allowTransparent": False}
            user, password = raw.get("username"), raw.get("password")
            if user or password:
                if not (user and password):
                    raise CoreError(
                        "an authenticated http inbound needs username AND password."
                    )
                settings["accounts"] = [{"user": str(user), "pass": str(password)}]
            return settings
        # dokodemo-door (port-forward; the DNS-relay preset targets resolver:53)
        address = str(raw.get("address") or "").strip()
        if not address:
            raise CoreError("a dokodemo-door inbound needs a target address.")
        try:
            target_port = int(raw.get("target_port") or 0)
        except (TypeError, ValueError) as exc:
            raise CoreError("dokodemo-door target port must be numeric.") from exc
        if not 1 <= target_port <= 65535:
            raise CoreError("dokodemo-door needs a target port between 1 and 65535.")
        return {"address": address, "port": target_port, "network": "tcp,udp"}

    def _studio_stream_settings(self, tag: str, raw: dict[str, Any]) -> dict[str, Any]:
        net = str(raw.get("transport") or "tcp").lower()
        stream: dict[str, Any] = {"network": net}
        path = raw.get("path")
        host = raw.get("host")
        if net == "ws":
            from app.studio.headers import parse_http_headers

            settings: dict[str, Any] = {"path": path or "/"}
            # alpha.7.5 item 4: arbitrary ws headers (the explicit Host field
            # wins over a pasted Host line — one source of truth per fact)
            headers = parse_http_headers(raw.get("headers"),
                                         context=f"ws inbound '{tag}'")
            if host:
                headers["Host"] = str(host)
            if headers:
                settings["headers"] = headers
            stream["wsSettings"] = settings
        elif net == "httpupgrade":
            settings = {"path": path or "/"}
            if host:
                settings["host"] = str(host)
            stream["httpupgradeSettings"] = settings
        elif net == "grpc":
            service = str(raw.get("service_name") or "")
            if not service:
                raise CoreError(f"gRPC inbound '{tag}' requires a service name.")
            settings = {"serviceName": service}
            if raw.get("authority"):
                settings["authority"] = str(raw["authority"])
            if raw.get("multi_mode"):
                settings["multiMode"] = True
            stream["grpcSettings"] = settings
        elif net == "xhttp":
            settings = {"path": path or "/"}
            if host:
                settings["host"] = str(host)
            if raw.get("mode"):
                settings["mode"] = str(raw["mode"])
            stream["xhttpSettings"] = settings
        elif net == "mkcp":
            # Xray >= 25 removed the header/seed levers ("migrated to
            # finalmask ... mkcp-original & mkcp-aes128gcm"); what remains is
            # the pure UDP transport with tuning fields.
            stream["network"] = "mkcp"
            settings = {}
            if raw.get("mtu"):
                settings["mtu"] = int(raw["mtu"])
            if raw.get("tti"):
                settings["tti"] = int(raw["tti"])
            if raw.get("congestion") is not None:
                settings["congestion"] = bool(raw["congestion"])
            stream["kcpSettings"] = settings
        elif net == "tcp":
            camouflage = self._studio_tcp_settings(tag, raw)
            if camouflage:
                stream["tcpSettings"] = camouflage
        else:
            raise CoreError(
                f"xray cannot serve transport '{net}' — supported: tcp, ws, "
                "httpupgrade, grpc, xhttp, mkcp."
            )
        stream.update(self._studio_security(tag, raw))
        return stream

    @staticmethod
    def _studio_tcp_settings(tag: str, raw: dict[str, Any]) -> dict[str, Any]:
        """RAW/TCP depth (alpha.7.5 item 4): Xray's real HTTP camouflage —
        ``tcpSettings.header.type = "http"`` with full request/response
        objects (method, paths, status line, arbitrary headers on both
        sides). ``header_type`` other than none/http is refused loudly."""
        from app.studio.headers import parse_http_headers

        header_type = str(raw.get("header_type") or "none").lower()
        if header_type in ("", "none"):
            # even 'none' may carry request-only facts from a pasted link —
            # any http fact with header_type none is a contradiction we name
            leftover = [k for k in ("http_method", "request_headers",
                                    "response_status", "response_reason",
                                    "response_headers") if raw.get(k)]
            if leftover:
                raise CoreError(
                    f"TCP inbound '{tag}': {leftover} require header_type=http "
                    "(plain RAW carries no HTTP layer).")
            return {}
        if header_type != "http":
            raise CoreError(
                f"TCP inbound '{tag}': header_type '{header_type}' is not an "
                "xray RAW header — supported: none, http (Xray removed the "
                "old udp/mkcp headers upstream).")
        if str(raw.get("security") or "").lower() == "reality":
            raise CoreError(
                f"TCP inbound '{tag}': REALITY already camouflages the stream — "
                "an extra RAW http header breaks the handshake (Xray refuses "
                "realitySettings + tcpSettings.header=http).")
        method = str(raw.get("http_method") or "GET").upper()
        if not method.isalpha():
            raise CoreError(f"TCP inbound '{tag}': http method '{method}' is invalid.")
        paths_raw = raw.get("path") or "/"
        paths = ([p.strip() for p in str(paths_raw).split(",") if p.strip()]
                 if isinstance(paths_raw, str) else list(paths_raw))
        if not paths or any(not p.startswith("/") for p in paths):
            raise CoreError(
                f"TCP inbound '{tag}': http camouflage paths must start with '/' "
                f"(comma separated), got {paths_raw!r}.")
        req_headers = parse_http_headers(raw.get("request_headers"),
                                         context=f"TCP/http inbound '{tag}' request")
        if raw.get("host"):
            req_headers.setdefault("Host", str(raw["host"]))
        resp_headers = parse_http_headers(raw.get("response_headers"),
                                          context=f"TCP/http inbound '{tag}' response")
        try:
            status = str(int(raw.get("response_status") or 200))
        except (TypeError, ValueError) as exc:
            raise CoreError(
                f"TCP inbound '{tag}': response_status must be numeric.") from exc
        reason = str(raw.get("response_reason") or "OK")
        if "\r" in reason or "\n" in reason:
            raise CoreError(f"TCP inbound '{tag}': response_reason cannot span lines.")
        return {
            "header": {
                "type": "http",
                "request": {
                    "method": method,
                    "path": paths,
                    "version": "1.1",
                    "headers": req_headers,
                },
                "response": {
                    "version": "1.1",
                    "status": status,
                    "reason": reason,
                    "headers": resp_headers,
                },
            }
        }

    def _studio_security(self, tag: str, raw: dict[str, Any]) -> dict[str, Any]:
        security = str(raw.get("security") or "none").lower()
        alpn = [a for a in (raw.get("alpn") or []) if a]
        if security == "none":
            return {"security": "none"}
        if security == "tls":
            sni = str(raw.get("sni") or "").strip()
            if not sni:
                raise CoreError(f"TLS inbound '{tag}' needs an SNI/certificate name.")
            # alpha.7.5 item 6 Mode B(path): operator-supplied PEM FILES on
            # the panel host — validated with the exact rules pasted content
            # gets, then referenced in place (no copy, no registry entry).
            cert_file = raw.get("certificate_path")
            key_file = raw.get("certificate_key_path")
            if cert_file or key_file:
                from app.studio.certs import CertificateError, validate_pem_pair_paths

                try:
                    validate_pem_pair_paths(str(cert_file or ""), str(key_file or ""),
                                            context=f"TLS inbound '{tag}'")
                except CertificateError as exc:
                    raise CoreError(str(exc)) from exc
                cert_path, key_path = str(cert_file), str(key_file)
                self._set_certificate_trust_marker(tag, cert_path)
            else:
                cert_pem = raw.get("certificate")
                key_pem = raw.get("certificate_key")
                cert_path, key_path = self._materialize_certificate(
                    tag, sni, cert_pem, key_pem)
            tls: dict[str, Any] = {
                "serverName": sni,
                "certificates": [{"certificateFile": cert_path, "keyFile": key_path}],
            }
            if alpn:
                tls["alpn"] = alpn
            return {"security": "tls", "tlsSettings": tls}
        if security == "reality":
            sni = str(raw.get("sni") or "").split(":")[0].strip()
            if not sni:
                raise CoreError(
                    f"Reality inbound '{tag}' needs a camouflage target (SNI) — "
                    "a TLSv1.3+h2 site the server masquerades as."
                )
            private, public = self._xray_x25519_keypair()
            import secrets as _secrets

            return {
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"{sni}:443",
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": private,
                    # the legacy catalog resolver reads publicKey back for
                    # share links; the extra key is documented in the bridge
                    # contract (Xray accepts it in the reality settings).
                    "publicKey": str(raw.get("public_key") or "") or public,
                    "shortIds": [_secrets.token_hex(8)],
                },
            }
        raise CoreError(f"unknown security '{security}' for inbound '{tag}'.")

    def _self_signed_marker(self, tag: str) -> str:
        import re as _re

        safe_tag = _re.sub(r"[^A-Za-z0-9_.-]+", "_", tag)
        cert_dir = self.settings.get("cert_dir") or "/var/lib/zagros/cores/xray/certs"
        return os.path.join(cert_dir, f"{safe_tag}.self-signed")

    def _set_certificate_trust_marker(self, tag: str, cert_path: str) -> None:
        """Persist whether delivery must opt into an untrusted TLS certificate."""
        from cryptography import x509

        marker = self._self_signed_marker(tag)
        try:
            with open(cert_path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
            self_signed = cert.subject == cert.issuer
        except (OSError, ValueError):
            self_signed = False
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        if self_signed:
            with open(marker + ".part", "w", encoding="ascii") as fh:
                fh.write("self-signed\n")
            os.chmod(marker + ".part", 0o600)
            os.replace(marker + ".part", marker)
        else:
            try:
                os.remove(marker)
            except FileNotFoundError:
                pass

    def _materialize_certificate(
        self, tag: str, sni: str,
        cert_pem: Any, key_pem: Any,
    ) -> tuple[str, str]:
        """Wizard certificate handling: uploads (PEM contents) are written to
        the panel-owned cert dir; when nothing is provided a self-signed
        certificate is generated there (honest default — the wizard help text
        tells the operator production TLS should upload a real cert pair)."""
        if bool(cert_pem) != bool(key_pem):
            raise CoreError(
                f"TLS inbound '{tag}': upload certificate AND private key together."
            )
        if cert_pem:
            # alpha.7.5 item 6: uploaded content now faces the SAME real
            # validation sing-box had (parse + match + expiry) — xray used
            # to write anything to disk and let the core die on it.
            from app.studio.certs import CertificateError, validate_pem_pair

            try:
                validate_pem_pair(str(cert_pem), str(key_pem),
                                  context=f"TLS inbound '{tag}'")
            except CertificateError as exc:
                raise CoreError(str(exc)) from exc
        import re as _re

        safe_tag = _re.sub(r"[^A-Za-z0-9_.-]+", "_", tag)
        cert_dir = self.settings.get("cert_dir") or "/var/lib/zagros/cores/xray/certs"
        cert_path = os.path.join(cert_dir, f"{safe_tag}.crt")
        key_path = os.path.join(cert_dir, f"{safe_tag}.key")
        if cert_pem:
            cert_text, key_text = str(cert_pem), str(key_pem)
        elif os.path.exists(cert_path) and os.path.exists(key_path):
            # self-signed default already materialized for this tag: REUSE it.
            # minting a fresh pair on every apply would rotate the server
            # identity under connected clients (and needlessly restart-ripple).
            self._set_certificate_trust_marker(tag, cert_path)
            return cert_path, key_path
        else:
            from app.utils.crypto import generate_certificate

            pair = generate_certificate()
            cert_text, key_text = pair["cert"], pair["key"]
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
        self._set_certificate_trust_marker(tag, cert_path)
        return cert_path, key_path


    @staticmethod
    def _xray_x25519_keypair() -> tuple[str, str]:
        """(private, public) raw-base64url x25519 keys — same encoding the
        sing-box driver and ``xray x25519`` CLI use (shared project crypto)."""
        import base64

        from app.crypto import x25519

        private_key, public_key = x25519.generate_keypair()

        def enc(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        return enc(private_key), enc(public_key)

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
        await self._ensure_binary_before_start()
        await asyncio.to_thread(self._backend.start)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def restart(self) -> None:
        await self._ensure_binary_before_start()
        await asyncio.to_thread(self._backend.restart)

    async def _ensure_binary_before_start(self) -> None:
        """Self-heal the classic 'Start fails with ENOENT /usr/local/bin/xray':
        the image ships no baked-in core binaries, so start triggers the
        driver's own installer once (pinned version honored) targeting the
        exact path the backend will exec, then proceeds with the real start."""
        getter = getattr(self._backend, "executable_path", None)
        if getter is None:
            return
        exe = getter()
        if exe and not os.path.exists(exe):
            logger.warning(
                "xray binary missing at %s — self-installing before start "
                "(release pin: %s)", exe, self.settings.get("release_version") or "latest")
            settings = dict(self.settings)
            settings["executable_path"] = exe
            await asyncio.to_thread(_install_xray, settings)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        version = await self.version()
        metrics = None
        if running:
            try:
                metrics = await asyncio.to_thread(self._backend.metrics)
            except CoreError:
                metrics = None
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=HealthStatus.HEALTHY if running else HealthStatus.UNKNOWN,
            core_version=version.version,
            version_reason=version.reason,
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
    # ------------------------------------------------------------------ #
    # legacy template variables ({SERVER_IP}/{USERNAME}/... + '*' salting)
    # ------------------------------------------------------------------ #
    @staticmethod
    async def _format_variables(account: UserAccount) -> dict:
        """The legacy share-generator variable set, resolved for THIS user.

        Marzban-parity: host remarks/addresses may embed ``{SERVER_IP}``,
        ``{USERNAME}``, ``{DATA_USAGE}``, ``{DAYS_LEFT}``… — the legacy sub
        link resolves them per user; the platform delivery path must render
        the SAME values or the two links diverge (a literal ``{SERVER_IP}``
        reached clients before this existed). When the legacy stack is not
        importable (bare driver unit tests) we degrade to the minimal set —
        never an exception into delivery rendering.
        """
        username = account.username or ""
        extra: dict[str, Any] = {"username": username, "used_traffic": 0}

        def _load() -> dict | None:
            from app.db import GetDB
            from app.db.crud import get_user as _get_user

            with GetDB() as db:
                row = _get_user(db, username)
            if row is None:
                return None
            return {
                "username": row.username,
                "status": row.status,
                "expire": row.expire,
                "used_traffic": row.used_traffic or 0,
                "data_limit": row.data_limit,
                "on_hold_expire_duration": row.on_hold_expire_duration,
            }

        try:
            loaded = await asyncio.to_thread(_load)
            if loaded is not None:
                extra = loaded
        except Exception:  # noqa: BLE001 — DB-less context: keep the defaults
            pass

        try:
            from app.subscription.share import setup_format_variables

            return setup_format_variables(extra)
        except Exception:  # noqa: BLE001 — legacy stack stubbed/unavailable
            return defaultdict(lambda: "<missing>", {
                "SERVER_IP": "", "SERVER_IPV6": "", "USERNAME": username,
                "DATA_USAGE": "0", "DATA_LIMIT": "∞", "DATA_LEFT": "∞",
                "DAYS_LEFT": "∞", "EXPIRE_DATE": "∞", "JALALI_EXPIRE_DATE": "∞",
                "TIME_LEFT": "∞", "STATUS_EMOJI": "", "STATUS_TEXT": "",
            })

    @staticmethod
    def _render_host_value(value: str | None, variables: Mapping[str, Any],
                           *, wild: bool = False) -> str | None:
        if not value:
            return value
        if wild:
            value = value.replace("*", secrets.token_hex(8))
        return value.format_map(variables)

    @staticmethod
    def _protocol_display(protocol: str) -> str:
        """Legacy remarks use the ENUM name (``Shadowsocks``), we only carry
        the value string — map back so both links are byte-equivalent."""
        try:
            from app.models.proxy import ProxyTypes

            return ProxyTypes(protocol).name
        except Exception:  # noqa: BLE001 — unknown protocol: honest fallback
            return protocol

    def _compose_outbound(
        self,
        protocol: str,
        settings: dict[str, Any],
        tag: str,
        inbound: dict[str, Any],
        host: dict[str, Any],
        variables: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the sing-box-shaped outbound fragment for one (inbound, host).

        Host fields go through the SAME template resolution as the legacy
        share generator: ``random.choice`` per render, ``*`` → random salt,
        ``{VAR}`` → per-user value (remark/address/path get format_map, sni/
        ws-Host get the salt only — exactly what /sub/ produces).
        """
        if variables is None:
            variables = defaultdict(lambda: "<missing>")
        settings = self._apply_flow_policy(settings, inbound)
        addresses = host.get("address") or []
        server = (self._render_host_value(random.choice(addresses), variables, wild=True)
                  if addresses else None)
        sni_list = host.get("sni") or inbound.get("sni") or []
        sni = (self._render_host_value(random.choice(sni_list), variables, wild=True)
               if sni_list else None)
        tls_level = host.get("tls") or inbound.get("tls", "none")

        outbound: dict[str, Any] = {
            "type": protocol,
            "tag": tag,
            "server": server,
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
                "server_name": sni,
                "alpn": [a for a in (host.get("alpn") or "").split(",") if a] or None,
                "utls": {
                    "enabled": bool(host.get("fingerprint")),
                    "fingerprint": host.get("fingerprint") or None,
                },
                # Wizard-generated certificates are deliberately self-signed.
                # Persist a sidecar marker so delivery remains connectable even
                # after panel/image restart; a CA-signed replacement removes it.
                "insecure": bool(host.get("allowinsecure")) or
                            os.path.exists(self._self_signed_marker(tag)),
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
            hostnames = host.get("host") or inbound.get("host") or []
            req_host = (self._render_host_value(random.choice(hostnames), variables, wild=True)
                        if hostnames else None)
            if host.get("use_sni_as_host") and sni:
                req_host = sni
            if host.get("path") is not None:
                path = (host["path"] or "").format_map(variables)
            else:
                path = (inbound.get("path") or "/").format_map(variables)
            transport.update(
                {"path": path, "headers": {"Host": req_host} if req_host else {}}
            )
        elif network in ("grpc", "gun"):
            # The legacy catalog stores grpcSettings.serviceName in `path`
            # and authority in the first `host` item. Omitting these from the
            # outbound made generated subscriptions dial TLS successfully but
            # speak raw VLESS to a gRPC listener, ending in immediate EOF.
            service_name = str(inbound.get("path") or "")
            if not service_name:
                raise CoreError(
                    f"Xray gRPC inbound '{tag}' has no service name in the live catalog"
                )
            transport["type"] = "grpc"
            transport["service_name"] = service_name
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
        variables = defaultdict(lambda: "<missing>",
                                await self._format_variables(account))
        variables["PROTOCOL"] = self._protocol_display(protocol)
        variables["TRANSPORT"] = inbound.get("network", "")
        outbound = self._compose_outbound(protocol, settings, tag, inbound,
                                          host, variables)
        remark = self._render_host_value(
            host.get("remark") or f"{protocol} · {tag}", variables)

        return ClientConfig(
            core_id=self.metadata.id,
            protocol=protocol,
            engine="sing-box",
            payload={"outbounds": [outbound]},
            display_name=remark,
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

        base_variables = await self._format_variables(account)
        for tag, inbound in targets.items():
            hosts = await asyncio.to_thread(self._backend.host_options, tag) or [{}]
            # per-(protocol, inbound) variables — same two the legacy
            # generator refreshes inside its loop
            variables = defaultdict(lambda: "<missing>", base_variables)
            variables["PROTOCOL"] = self._protocol_display(protocol)
            variables["TRANSPORT"] = inbound.get("network", "")
            for host in hosts:
                remark = self._render_host_value(
                    host.get("remark") or f"{protocol} · {tag}", variables)
                outbound = self._compose_outbound(
                    protocol, dict(settings), tag, inbound, host, variables
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
    _BASE_OUTBOUNDS = {"direct": "zg-direct", "block": "zg-block", "dns": "zg-dns"}

    def _rule_to_native(
        self, rule: RoutingRule, ctx: RouteContext
    ) -> tuple[dict | None, UnsupportedRule | None]:
        m = rule.matcher
        native: dict[str, Any] = {"type": "field"}
        if m.inbounds:
            native["inboundTag"] = m.inbounds
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

    async def translate_routing_rules(
        self, rules: list[RoutingRule], ctx: RouteContext
    ) -> TranslatedRoute:
        """Dry preview (no backend writes) used by the rule builder."""
        native_rules: list[dict] = []
        applied: list[str] = []
        unsupported: list[UnsupportedRule] = []
        for rule in rules:
            native, gap = self._rule_to_native(rule, ctx)
            if gap is not None:
                unsupported.append(gap)
            else:
                native_rules.append(native)
                applied.append(rule.name)
        return TranslatedRoute(
            core_id=self.metadata.id, applied=applied, unsupported=unsupported,
            payload={"routing": {"rules": native_rules, "domainStrategy": "IPIfNonMatch"}},
        )

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

        def need(*keys: str) -> UnsupportedOutbound | None:
            missing = [key for key in keys if s.get(key) in (None, "")]
            if not missing:
                return None
            return UnsupportedOutbound(
                name=name,
                reason=f"{kind.value} outbound is missing required setting(s): {', '.join(missing)}",
            )
        # Native cores enter every policy domain through a loopback SOCKS
        # gateway. This avoids VRF socket-demux ambiguity while service-core
        # packets still use fwmark/table directly.
        if s.get("_policy_socks_port"):
            return {
                "protocol": "socks", "tag": name,
                "settings": {"servers": [{
                    "address": "127.0.0.1",
                    "port": int(s["_policy_socks_port"]),
                    "udp": kind is not OutboundKind.SSH,
                }]},
            }, None
        # Compatibility fallback for externally supplied policy managers.
        if s.get("_policy_mark") is not None:
            sockopt: dict[str, Any] = {"mark": int(s["_policy_mark"])}
            if s.get("_policy_vrf"):
                sockopt["interface"] = str(s["_policy_vrf"])
            return {
                "protocol": "freedom", "tag": name,
                "streamSettings": {"sockopt": sockopt},
            }, None
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
            allowed = s.get("allowed_ips", ["0.0.0.0/0", "::/0"])
            if isinstance(allowed, str):
                allowed = [value.strip() for value in allowed.split(",") if value.strip()]
            local = s.get("local_address", [])
            if isinstance(local, str):
                local = [value.strip() for value in local.split(",") if value.strip()]
            peer: dict[str, Any] = {
                "publicKey": s["peer_public_key"],
                "endpoint": f"{s['server']}:{int(s['server_port'])}",
                "allowedIPs": allowed,
            }
            if s.get("preshared_key"):
                peer["preSharedKey"] = s["preshared_key"]
            if s.get("keepalive") is not None:
                peer["keepAlive"] = int(s["keepalive"])
            if s.get("reserved"):
                peer["reserved"] = s["reserved"]
            settings: dict[str, Any] = {
                "secretKey": s["private_key"], "peers": [peer],
                "address": local,
            }
            if s.get("mtu"):
                settings["mtu"] = int(s["mtu"])
            return {"protocol": "wireguard", "tag": name,
                    "settings": settings}, None
        if kind is OutboundKind.SSH:
            return None, UnsupportedOutbound(
                name=name,
                reason=(
                    "Xray has no SSH outbound codec; deploy through the managed "
                    "OpenSSH SOCKS application domain"
                ),
            )
        return None, UnsupportedOutbound(
            name=name,
            reason=f"xray has no native '{kind.value}' outbound (use a CORE chain to sing-box instead).",
        )

    async def _ensure_base_outbounds(self) -> None:
        base = [
            {"protocol": "freedom", "tag": self._BASE_OUTBOUNDS["direct"]},
            {"protocol": "blackhole", "tag": self._BASE_OUTBOUNDS["block"]},
            {"protocol": "dns", "tag": self._BASE_OUTBOUNDS["dns"]},
        ]
        # Base action targets and admin outbounds are one managed set. The old
        # second set_outbounds(base) call replaced every just-deployed custom
        # outbound, leaving route rules pointing at absent tags.
        await asyncio.to_thread(
            self._backend.set_outbounds,
            [*base, *self._managed_native_outbounds],
        )

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
        self._managed_native_outbounds = list(native)
        await self._ensure_base_outbounds()
        return TranslatedOutbound(core_id=self.metadata.id, applied=applied,
                                  unsupported=unsupported, payload=native)

    # ------------------------------------------------------------------ #
    # chain ingress (CHAIN_ROUTING)
    # ------------------------------------------------------------------ #
    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        inbounds = await self._inbounds()
        endpoints: list[ChainEndpoint] = []
        for tag, info in inbounds.items():
            if tag.startswith("zg-chain-"):
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
    # Optional exact-version pin (Simple install dialog version picker):
    # skips the REST API entirely and pulls /releases/download/<tag>/<asset>.
    pinned = None
    version = str(settings.get("release_version") or "").strip()
    if version:
        pinned = (version if version.startswith("v") else f"v{version}", asset)
    tag = install_from_github(
        repo="XTLS/Xray-core",
        target_executable=executable,
        asset_match=lambda name: name == asset,
        member_match=lambda m: m.rsplit("/", 1)[-1] in ("xray", "xray.exe"),
        direct_asset=asset,
        pinned=pinned,
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
