"""Delivery descriptors — how a user's connection material is presented.

This module is the contract between core drivers and **any** presentation
layer (Subscription Portal, Telegram bot, future admin 1-click exports).
A driver describes *what* it can hand to the user — share links, config
files, credential fields, QR payloads, honest notes — and presentation
layers simply render the description. **No presentation code may hardcode
driver ids or protocol names with special behavior**; everything flows
through these generic models.

Honesty rules:
* A driver only emits artifacts it can actually produce.
* If a share link cannot be built for an outbound, the presenter emits a
  NOTE explaining why instead of fabricating one.
* Fields marked ``secret=True`` are masked by UIs until the user reveals.
"""
from __future__ import annotations

import base64
import json
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from app.cores.types import ClientConfig, UserAccount


class ArtifactKind(str, Enum):
    LINK = "link"        # share URL (vless://, hy2://, tuic://, ss://, ...)
    FILE = "file"        # downloadable file (.ovpn, WireGuard .conf, ...)
    FIELDS = "fields"    # credential table (host/port/username/password/...)
    NOTE = "note"        # human-readable explanation / honest limitation

    def __str__(self) -> str:  # "link", not "ArtifactKind.LINK" (py>=3.11)
        return self.value


class DeliveryField(BaseModel):
    key: str                              # semantic id: host/port/username/password/...
    label: str                            # display label
    value: str
    secret: bool = False                  # masked in UI until revealed
    copyable: bool = True


class DeliveryArtifact(BaseModel):
    kind: ArtifactKind
    label: str
    content: str = ""                     # URL text / file text (empty for FIELDS/NOTE)
    filename: str | None = None           # suggested filename for FILE
    mime: str = "text/plain"
    fields: list[DeliveryField] = Field(default_factory=list)
    qr: bool = False                      # portal renders an inline QR of `content`
    note: str | None = None               # NOTE body or per-artifact hint

    def validate_shape(self) -> None:
        """Shape contract, enforced by the conformance tests."""
        if self.kind is ArtifactKind.LINK:
            assert "://" in self.content, f"LINK artifact '{self.label}' has no URL"
        if self.kind is ArtifactKind.FILE:
            assert self.filename and self.content, f"FILE artifact '{self.label}' incomplete"
        if self.kind is ArtifactKind.FIELDS:
            assert self.fields, f"FIELDS artifact '{self.label}' is empty"
        if self.kind is ArtifactKind.NOTE:
            assert self.note, f"NOTE artifact '{self.label}' is empty"


class DeliverySection(BaseModel):
    protocol: str                         # vless / wireguard / ovpn / l2tp / ssh / ...
    title: str                            # human section title ("WireGuard", "VLESS · Reality")
    engine: str                           # recommended client engine family
    artifacts: list[DeliveryArtifact] = Field(default_factory=list)
    note: str | None = None
    # (item 13): which core inbound produced this section — the
    # Host Settings engine keys its per-tag expansion on it. ``None`` on
    # tagless single-inbound presenters (the engine applies the only
    # defined tag unambiguously then).
    inbound_tag: str | None = None


class DeliveryProfile(BaseModel):
    """Everything one (user, core-account) pair can receive."""

    core_id: str
    sections: list[DeliverySection] = Field(default_factory=list)
    note: str | None = None

    def validate_shape(self) -> None:
        assert self.sections, "delivery profile has no sections"
        for section in self.sections:
            assert section.artifacts, f"section '{section.title}' has no artifacts"
            for artifact in section.artifacts:
                artifact.validate_shape()


class DeliveryContext(BaseModel):
    """Ambient information the presentation layer hands to drivers."""

    brand: str = "Zagros"
    # Public host used when a core still carries its historical loopback/
    # wildcard default. It comes from the configured subscription URL prefix
    # or, failing that, the actual public subscription request Host.
    public_host: str | None = None


def resolve_delivery_host(configured: object, context: DeliveryContext | None,
                          fallback: object = "", *,
                          allow_loopback: bool = False) -> str:
    """Resolve a client-dialable host without leaking core loopback defaults.

    Explicit non-loopback core settings win. Historical ``127.0.0.1`` /
    ``localhost`` values are placeholders unless the admin enables the
    core's ``allow_loopback_advertise`` escape hatch. Then use the portal's
    configured/request public host, followed by a non-wildcard listener.
    """
    import ipaddress

    def usable(value: object, *, loopback_ok: bool = False) -> str:
        host = str(value or "").strip().strip("[]")
        if not host or host in ("0.0.0.0", "::", "*"):
            return ""
        if host.lower() == "localhost":
            return host if loopback_ok else ""
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return host
        if address.is_unspecified:
            return ""
        if address.is_loopback and not loopback_ok:
            return ""
        return host

    direct = usable(configured, loopback_ok=allow_loopback)
    if direct:
        return direct
    ambient = usable(context.public_host if context else "")
    if ambient:
        return ambient
    return usable(fallback, loopback_ok=allow_loopback)


class ShareLinkError(ValueError):
    """Raised when an outbound cannot be encoded as a share link."""


# --------------------------------------------------------------------- #
# share-link rendering (sing-box style outbound fragment -> share URL)
# --------------------------------------------------------------------- #

def _query(params: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in params.items():
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, (list, tuple)):
            value = ",".join(str(v) for v in value)
        parts.append(f"{quote(str(key), safe='')}={quote(str(value), safe='')}")
    return "&".join(parts)


def _transport_params(transport: dict[str, Any], network: str,
                      params: dict[str, Any]) -> None:
    """path/host/serviceName params per transport — without them the client
    silently falls back to defaults and connects to the WRONG listener
    (the emitters added these only for ws; httpupgrade/grpc/h2
    links were broken)."""
    if network in ("ws", "httpupgrade"):
        params["path"] = transport.get("path") or "/"
        host = (transport.get("headers") or {}).get("Host") or transport.get("host")
        if isinstance(host, list):
            host = host[0] if host else None
        params["host"] = host
    elif network == "grpc":
        params["serviceName"] = transport.get("service_name")
    elif network == "http":
        params["path"] = transport.get("path")
        host = transport.get("host")
        if isinstance(host, list):
            host = host[0] if host else None
        params["host"] = host


def share_url_for_outbound(outbound: dict[str, Any], remark: str) -> str:
    """Encode a sing-box-shaped outbound fragment as a standard share link.

    Supported: ``vless``, ``vmess``, ``trojan``, ``shadowsocks``,
    ``hysteria2``, ``tuic``.
    Anything else raises :class:`ShareLinkError` — the presenter turns that
    into an honest NOTE artifact instead of guessing a URL scheme.
    """
    otype = outbound.get("type")
    server = outbound.get("server")
    port = outbound.get("server_port")
    if not server or not port:
        raise ShareLinkError(f"outbound lacks server/server_port: {outbound!r}")
    tls = outbound.get("tls") or {}
    transport = outbound.get("transport") or {"type": "tcp"}
    network = transport.get("type", "tcp")
    tag = quote(remark, safe="")

    if otype == "vless":
        uuid = outbound.get("uuid")
        if not uuid:
            raise ShareLinkError("vless outbound lacks uuid")
        params: dict[str, Any] = {
            "type": network, "encryption": "none",
        }
        if tls.get("enabled"):
            reality = tls.get("reality") or {}
            params["security"] = "reality" if reality.get("enabled") else "tls"
            params["sni"] = tls.get("server_name")
            params["alpn"] = tls.get("alpn")
            utls = tls.get("utls") or {}
            params["fp"] = utls.get("fingerprint") if utls.get("enabled") else None
            if reality.get("enabled"):
                params["pbk"] = reality.get("public_key")
                params["sid"] = reality.get("short_id")
            if tls.get("insecure"):
                params["allowInsecure"] = "1"
        else:
            params["security"] = "none"
        if outbound.get("flow"):
            params["flow"] = outbound["flow"]
        _transport_params(transport, network, params)
        return f"vless://{uuid}@{server}:{port}?{_query(params)}#{tag}"

    if otype == "vmess":
        uuid = outbound.get("uuid")
        if not uuid:
            raise ShareLinkError("vmess outbound lacks uuid")
        tls_on = bool(tls.get("enabled"))
        host = (transport.get("headers") or {}).get("Host") or transport.get("host") or ""
        if isinstance(host, list):
            host = host[0] if host else ""
        if network == "grpc":
            path = str(transport.get("service_name") or "")
        elif network in ("ws", "httpupgrade", "http"):
            path = str(transport.get("path") or "")
        else:
            path = ""
        doc = {
            "v": "2", "ps": remark, "add": server, "port": str(port),
            "id": uuid, "aid": "0", "scy": "auto",
            "net": network, "type": "none",
            "host": host,
            "path": path,
            "tls": "tls" if tls_on else "",
            "sni": tls.get("server_name", "") if tls_on else "",
            "alpn": ",".join(tls.get("alpn") or []) if tls_on else "",
            "fp": ((tls.get("utls") or {}).get("fingerprint") or "")
                  if tls_on and (tls.get("utls") or {}).get("enabled") else "",
        }
        raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return "vmess://" + base64.b64encode(raw).decode("ascii")

    if otype == "trojan":
        password = outbound.get("password")
        if password is None:
            raise ShareLinkError("trojan outbound lacks password")
        params = {"type": network}
        if tls.get("enabled"):
            params["security"] = "tls"
            params["sni"] = tls.get("server_name")
            params["alpn"] = tls.get("alpn")
            utls = tls.get("utls") or {}
            params["fp"] = utls.get("fingerprint") if utls.get("enabled") else None
            if tls.get("insecure"):
                params["allowInsecure"] = "1"
        else:
            params["security"] = "none"
        _transport_params(transport, network, params)
        return f"trojan://{quote(str(password), safe='')}@{server}:{port}?{_query(params)}#{tag}"

    if otype == "shadowsocks":
        method, password = outbound.get("method"), outbound.get("password")
        if not method or password is None:
            raise ShareLinkError("shadowsocks outbound lacks method/password")
        userinfo = base64.urlsafe_b64encode(
            f"{method}:{password}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{tag}"

    if otype == "hysteria2":
        password = outbound.get("password")
        if password is None:
            raise ShareLinkError("hysteria2 outbound lacks password")
        params = {}
        if tls.get("server_name"):
            params["sni"] = tls.get("server_name")
        obfs = outbound.get("obfs") or {}
        if obfs.get("password"):
            # only salamander exists in clients' obfs vocabulary today
            params["obfs"] = obfs.get("type") or "salamander"
            params["obfs-password"] = obfs["password"]
        if tls.get("alpn"):
            params["alpn"] = tls.get("alpn")
        if tls.get("insecure"):
            params["insecure"] = "1"
        return f"hy2://{quote(str(password), safe='')}@{server}:{port}?{_query(params)}#{tag}"

    if otype == "tuic":
        uuid, password = outbound.get("uuid"), outbound.get("password")
        if not uuid or password is None:
            raise ShareLinkError("tuic outbound lacks uuid/password")
        params = {"congestion_control": outbound.get("congestion_control") or "bbr",
                  "udp_relay_mode": "native"}
        if tls.get("server_name"):
            params["sni"] = tls.get("server_name")
        if tls.get("alpn"):
            params["alpn"] = tls.get("alpn")
        if tls.get("insecure"):
            params["allow_insecure"] = "1"
        auth = quote(str(uuid), safe="") + ":" + quote(str(password), safe="")
        return f"tuic://{auth}@{server}:{port}?{_query(params)}#{tag}"

    raise ShareLinkError(f"no share-link encoding implemented for '{otype}'")


# --------------------------------------------------------------------- #
# generic flattening: flat payloads -> FIELDS/NOTE artifacts
# --------------------------------------------------------------------- #

_SECRET_TOKENS = ("password", "secret", "private", "psk", "passphrase", "token")
_SECRET_EXACT = {"uuid", "id", "key"}
_FIELD_SKIP_KEYS = {"format", "profile", "url", "hint", "note"}
_NOTE_KEYS = ("hint", "note")


def is_secret_field(key: str) -> bool:
    """Generic masking rule (public keys stay visible by design)."""
    lowered = key.lower()
    if lowered.startswith("public"):
        return False
    if lowered in _SECRET_EXACT:
        return True
    if lowered.endswith("key") and not lowered.startswith("public"):
        return True
    return any(token in lowered for token in _SECRET_TOKENS)


def fields_from_mapping(
    mapping: dict[str, Any],
    *,
    skip: set[str] | frozenset[str] = _FIELD_SKIP_KEYS,
    labels: dict[str, str] | None = None,
) -> list[DeliveryField]:
    fields: list[DeliveryField] = []
    for key, value in mapping.items():
        if key in skip or value is None:
            continue
        if isinstance(value, (dict, list, tuple)):
            continue  # nested structures are not field-material
        label = (labels or {}).get(key) or key.replace("_", " ").strip().title()
        fields.append(DeliveryField(
            key=key, label=label, value=str(value),
            secret=is_secret_field(key),
        ))
    return fields


def profile_from_client_config(
    config: "ClientConfig",
    *,
    account: "UserAccount | None" = None,
) -> DeliveryProfile:
    """Generic presenter: derive a DeliveryProfile from a ClientConfig payload.

    Drivers without a bespoke ``describe_delivery`` get this honest default:
    share-URL payloads become QR-able LINKs, ``ini``/``ovpn`` profiles become
    downloadable FILEs, flat payloads become credential FIELD tables, and
    ``hint``/``note`` payload keys become NOTEs. Unknown payload shapes
    degrade to a NOTE naming the payload format — never to a fabricated link.
    """
    payload = config.payload
    section = DeliverySection(
        protocol=config.protocol,
        title=config.display_name or config.protocol,
        engine=config.engine,
    )
    profile = DeliveryProfile(core_id=config.core_id, sections=[section])
    base_name = account.username if account is not None else "config"

    if "outbounds" in payload:
        for outbound in payload["outbounds"]:
            remark = config.display_name or str(outbound.get("type", "link"))
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
        return profile

    fmt = payload.get("format")
    if fmt == "share-url":
        section.artifacts.append(DeliveryArtifact(
            kind=ArtifactKind.LINK, label=config.display_name or config.protocol,
            content=str(payload["url"]), qr=True,
        ))
    elif "profile" in payload:
        ext = "ovpn" if fmt == "ovpn" else "conf"
        section.artifacts.append(DeliveryArtifact(
            kind=ArtifactKind.FILE, label=config.display_name or "Configuration file",
            content=str(payload["profile"]),
            filename=f"{base_name}.{ext}",
            mime="application/x-openvpn-profile" if fmt == "ovpn" else "text/plain",
            qr=(fmt == "ini"),
        ))
    fields = fields_from_mapping(payload)
    if fields:
        section.artifacts.append(DeliveryArtifact(
            kind=ArtifactKind.FIELDS, label="Connection details", fields=fields,
        ))
    for note_key in _NOTE_KEYS:
        if payload.get(note_key):
            section.artifacts.append(DeliveryArtifact(
                kind=ArtifactKind.NOTE, label="Note", note=str(payload[note_key]),
            ))
            break
    if not section.artifacts:
        section.artifacts.append(DeliveryArtifact(
            kind=ArtifactKind.NOTE, label="Note",
            note="This core delivers its configuration only through the Zagros app.",
        ))
    return profile
