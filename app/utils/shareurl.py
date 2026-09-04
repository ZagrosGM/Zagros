"""Share-URL parser ("Import URL") for URL-based proxy protocols.

One Paste of ``vless://...`` / ``vmess://...`` / ``trojan://...`` /
``ss://...`` / ``hysteria2://...`` / ``tuic://...`` / ``anytls://...`` /
``naive+https://...`` / ``socks5://...`` / ``http(s)://...`` fills every
outbound field — address, port, UUID/password, security, flow, transport
(ws/gRPC/HTTP/HTTPUpgrade/KCP/SplitHTTP/QUIC/TCP), SNI, ALPN, fingerprint
and the full REALITY parameter set.

The output shape matches :class:`app.cores.outbounds.model.Outbound`
({kind, settings}) so the admin UI can drop the result straight into its
schema-driven form, and drivers translate the same keys at deploy time.

Pure stdlib — no network, no side effects.
"""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qsl, unquote, urlparse

from pydantic import BaseModel, Field

from app.cores.outbounds.model import OutboundKind

# query params that are recognized but not part of outbound settings
_META_PARAMS = {"type", "security", "encryption", "plugin", "plugin-opts"}

_TRANSPORT_KEYS = (
    "path", "host", "serviceName", "service_name", "authority",
    "headerType", "header_type", "seed", "mode", "extra",
)


class ParsedShareURL(BaseModel):
    kind: OutboundKind
    settings: dict = Field(default_factory=dict)
    name_hint: str = ""
    protocol: str = ""
    transport: str = "tcp"
    security: str = "none"


class ShareURLError(ValueError):
    """Unparseable or unsupported share link."""


def _b64url(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64std(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.b64decode(data + pad)


def _int(value: str | None, field: str) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError) as exc:
        raise ShareURLError(f"invalid {field}: {value!r}") from exc


def _urlparse(url: str):
    parsed = urlparse(url.strip())
    if not parsed.scheme:
        raise ShareURLError("the link has no protocol scheme (e.g. vless://)")
    return parsed


def _query(parsed) -> dict[str, str]:
    return {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}


def _fragment_name(parsed) -> str:
    return unquote(parsed.fragment).strip() if parsed.fragment else ""


# (item 13): v2rayN/sing-box share-link client hints that Host
# Settings can inject. Named-key passthrough ONLY — the format boundary
# stays strict; anything else is still dropped on parse.
_EXTRA_HINTS = ("fragment", "noise", "xmux")


def _apply_extra_hints(settings: dict, q: dict[str, str]) -> None:
    for hint in _EXTRA_HINTS:
        if q.get(hint):
            settings[hint] = q[hint]


def _split_userinfo_host(parsed, scheme: str):
    userinfo = parsed.username or ""
    host = parsed.hostname or ""
    if not host:
        raise ShareURLError(f"{scheme} link is missing a server address")
    port = parsed.port
    if port is None:
        raise ShareURLError(f"{scheme} link is missing a port")
    return unquote(userinfo), host, port


def _netmap(raw: str) -> str:
    m = {
        "": "tcp", "tcp": "tcp", "raw": "tcp",
        "ws": "ws", "websocket": "ws",
        "grpc": "grpc", "gun": "grpc",
        "http": "http", "h2": "http",
        "quic": "quic",
        "kcp": "kcp", "mkcp": "kcp",
        "httpupgrade": "httpupgrade",
        "splithttp": "splithttp", "xhttp": "splithttp",
    }
    return m.get(raw.lower(), raw.lower() or "tcp")


def _apply_transport(settings: dict, q: dict[str, str]) -> str:
    network = _netmap(q.get("type", q.get("network", "")))
    settings["network"] = network
    for key in _TRANSPORT_KEYS:
        if key in q and q[key] != "":
            normalized = {"service_name": "serviceName",
                          "header_type": "headerType"}.get(key, key)
            settings[normalized] = q[key]
    if network == "ws":
        settings.setdefault("path", q.get("path", "/"))
        if q.get("host"):
            settings["host"] = q["host"]
    elif network == "grpc":
        if q.get("serviceName"):
            settings["serviceName"] = q["serviceName"]
    return network


def _apply_security(settings: dict, q: dict[str, str]) -> str:
    security = (q.get("security") or "none").lower()
    settings["security"] = security
    for src, dst in (
        ("sni", "sni"), ("peer", "sni"), ("alpn", "alpn"), ("fp", "fingerprint"),
        ("pbk", "reality_public_key"), ("sid", "reality_short_id"),
        ("spx", "reality_spider_x"), ("allowInsecure", "allow_insecure"),
        ("insecure", "allow_insecure"),
    ):
        if src in q and q[src] != "":
            settings[dst] = q[src]
    if "allow_insecure" in settings:
        settings["allow_insecure"] = str(settings["allow_insecure"]).lower() in ("1", "true")
    return security


def _parse_vless(url: str) -> ParsedShareURL:
    parsed = _urlparse(url)
    uuid, host, port = _split_userinfo_host(parsed, "vless")
    if not uuid:
        raise ShareURLError("vless link is missing the UUID")
    q = _query(parsed)
    settings: dict = {"server": host, "server_port": port, "uuid": uuid}
    if q.get("flow"):
        settings["flow"] = q["flow"]
    if q.get("encryption"):
        settings["encryption"] = q["encryption"]
    transport = _apply_transport(settings, q)
    security = _apply_security(settings, q)
    _apply_extra_hints(settings, q)
    return ParsedShareURL(kind=OutboundKind.VLESS, settings=settings,
                          name_hint=_fragment_name(parsed), protocol="vless",
                          transport=transport, security=security)


def _parse_trojan(url: str) -> ParsedShareURL:
    parsed = _urlparse(url)
    password, host, port = _split_userinfo_host(parsed, "trojan")
    if not password:
        raise ShareURLError("trojan link is missing the password")
    q = _query(parsed)
    settings: dict = {"server": host, "server_port": port, "password": password}
    if q.get("flow"):
        settings["flow"] = q["flow"]
    transport = _apply_transport(settings, q)
    security = _apply_security(settings, q)
    if security == "none":
        # trojan is TLS-by-design; links that omit `security` still mean TLS
        settings["security"] = security = "tls"
        settings.setdefault("sni", q.get("sni") or q.get("peer") or host)
    _apply_extra_hints(settings, q)
    return ParsedShareURL(kind=OutboundKind.TROJAN, settings=settings,
                          name_hint=_fragment_name(parsed), protocol="trojan",
                          transport=transport, security=security)


def _parse_vmess(url: str) -> ParsedShareURL:
    parsed = _urlparse(url)
    if parsed.scheme == "vmess" and parsed.netloc and not parsed.path.strip("/"):
        # vmess://base64(json) — the canonical share format
        try:
            payload = json.loads(_b64std(parsed.netloc + parsed.path).decode())
        except Exception as exc:
            raise ShareURLError(f"invalid vmess base64 payload: {exc}") from exc
    else:
        raise ShareURLError("unsupported vmess link shape (expected base64 JSON)")

    settings: dict = {
        "server": payload.get("add") or payload.get("server") or "",
        "server_port": _int(payload.get("port"), "port"),
        "uuid": payload.get("id") or "",
    }
    if not settings["server"] or not settings["uuid"]:
        raise ShareURLError("vmess link is missing address or UUID")
    if str(payload.get("aid", "")).isdigit():
        settings["alter_id"] = int(payload["aid"])
    if payload.get("scy") or payload.get("security"):
        settings["cipher"] = payload.get("scy") or payload.get("security")
    qlike = {
        "type": payload.get("net", "tcp"),
        "path": payload.get("path", ""),
        "host": payload.get("host", ""),
        "serviceName": payload.get("path", "") if payload.get("net") == "grpc" else "",
        "security": "tls" if str(payload.get("tls", "")).lower() in ("tls", "true") else "none",
        "sni": payload.get("sni", ""),
        "alpn": payload.get("alpn", ""),
        "fp": payload.get("fp", ""),
        "headerType": payload.get("type", ""),
        "seed": payload.get("seed", ""),
    }
    qlike = {k: v for k, v in qlike.items() if v not in ("", None)}
    transport = _apply_transport(settings, qlike)
    security = _apply_security(settings, qlike)
    if payload.get("fragment"):
        settings["fragment"] = str(payload["fragment"])
    name = str(payload.get("ps") or payload.get("remarks") or "")
    return ParsedShareURL(kind=OutboundKind.VMESS, settings=settings,
                          name_hint=name, protocol="vmess",
                          transport=transport, security=security)


_SS_METHOD_RE = re.compile(r"^(?P<method>[a-z0-9\-]+(?:gcm|poly1305|cbc|ctr|xchacha20[a-z0-9\-]*)?)[:@]")


def _parse_ss(url: str) -> ParsedShareURL:
    raw = url.strip()
    parsed = _urlparse(raw)
    userinfo, host, port = parsed.username or "", parsed.hostname, parsed.port

    if not host or not port:
        # ss://base64(method:password@host:port)#name — legacy whole-link b64
        try:
            decoded = _b64std(parsed.netloc + parsed.path).decode()
        except Exception as exc:
            raise ShareURLError(f"invalid ss link: {exc}") from exc
        frag = parsed.fragment
        parsed = _urlparse(f"ss://{decoded}{('#' + frag) if frag else ''}")
        userinfo, host, port = parsed.username or "", parsed.hostname, parsed.port
    if not host or not port:
        raise ShareURLError("ss link is missing host or port")

    if parsed.password is None:
        # userinfo is base64("method:password")
        try:
            decoded_ui = _b64url(unquote(userinfo)).decode()
        except Exception as exc:
            raise ShareURLError(f"invalid ss credentials: {exc}") from exc
        if ":" not in decoded_ui:
            raise ShareURLError("ss credentials must be method:password")
        method, password = decoded_ui.split(":", 1)
    else:
        method, password = unquote(userinfo), unquote(parsed.password)

    settings: dict = {"server": host, "server_port": port,
                      "method": method, "password": password}
    q = _query(parsed)
    if q.get("plugin"):
        settings["plugin"] = q["plugin"]
        if q.get("plugin-opts"):
            settings["plugin_opts"] = q["plugin-opts"]
    return ParsedShareURL(kind=OutboundKind.SHADOWSOCKS, settings=settings,
                          name_hint=_fragment_name(parsed), protocol="shadowsocks",
                          transport="tcp", security="none")


def _parse_hysteria2(url: str) -> ParsedShareURL:
    parsed = _urlparse(url)
    password, host, port = _split_userinfo_host(parsed, "hysteria2")
    if not password:
        raise ShareURLError("hysteria2 link is missing the password")
    q = _query(parsed)
    settings: dict = {"server": host, "server_port": port, "password": password}
    if q.get("obfs"):
        settings["obfs"] = q["obfs"]
        if q.get("obfs-password"):
            settings["obfs_password"] = q["obfs-password"]
    if q.get("mport"):
        settings["port_hopping"] = q["mport"]
    _apply_security(settings, q)
    settings.setdefault("security", "tls")
    return ParsedShareURL(kind=OutboundKind.HYSTERIA2, settings=settings,
                          name_hint=_fragment_name(parsed), protocol="hysteria2",
                          transport="udp", security=str(settings.get("security")))


def _parse_tuic(url: str) -> ParsedShareURL:
    parsed = _urlparse(url)
    uuid, host, port = _split_userinfo_host(parsed, "tuic")
    if not uuid:
        raise ShareURLError("tuic link is missing the UUID")
    q = _query(parsed)
    settings: dict = {"server": host, "server_port": port, "uuid": uuid}
    if parsed.password:
        settings["password"] = unquote(parsed.password)
    for src, dst in (
        ("congestion_control", "congestion_control"), ("congestion", "congestion_control"),
        ("udp_relay_mode", "udp_relay_mode"), ("alpn", "alpn"), ("sni", "sni"),
        ("disable_sni", "disable_sni"), ("allow_insecure", "allow_insecure"),
    ):
        if q.get(src):
            settings[dst] = q[src]
    settings.setdefault("security", "tls")
    return ParsedShareURL(kind=OutboundKind.TUIC, settings=settings,
                          name_hint=_fragment_name(parsed), protocol="tuic",
                          transport="udp", security="tls")


def _parse_anytls(url: str) -> ParsedShareURL:
    """anytls-go URI scheme: ``anytls://password@host[:443]/?sni=&insecure=#name``
    (the password is percent-encoded; the port defaults to 443)."""
    parsed = _urlparse(url)
    password = unquote(parsed.username or "")
    host = parsed.hostname or ""
    if not host:
        raise ShareURLError("anytls link is missing a server address")
    if not password:
        raise ShareURLError("anytls link is missing the password")
    port = parsed.port if parsed.port is not None else 443
    q = _query(parsed)
    settings: dict = {"server": host, "server_port": port, "password": password,
                      "security": "tls"}
    for src, dst in (("sni", "sni"), ("alpn", "alpn"), ("fp", "fingerprint"),
                     ("insecure", "allow_insecure"), ("allowInsecure", "allow_insecure")):
        if q.get(src):
            settings[dst] = q[src]
    if "allow_insecure" in settings:
        settings["allow_insecure"] = str(settings["allow_insecure"]).lower() in ("1", "true")
    return ParsedShareURL(kind=OutboundKind.ANYTLS, settings=settings,
                          name_hint=_fragment_name(parsed), protocol="anytls",
                          transport="tcp", security="tls")


def _parse_userpass(url: str) -> ParsedShareURL:
    """Plain proxy URLs: ``socks5://user:pass@host:port#name``,
    ``http(s)://user:pass@host:port#name`` and NaïveProxy's
    ``naive+https://user:pass@host:port#name`` (its TLS name IS the host)."""
    parsed = _urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    if not host:
        raise ShareURLError(f"{scheme} link is missing a server address")
    default_port = {"https": 443, "naive+https": 443, "http": 80}.get(scheme)
    port = parsed.port if parsed.port is not None else default_port
    if port is None:
        raise ShareURLError(f"{scheme} link is missing a port")
    settings: dict = {"server": host, "server_port": port}
    if parsed.username:
        settings["username"] = unquote(parsed.username)
    if parsed.password is not None:
        settings["password"] = unquote(parsed.password)
    if scheme in ("socks", "socks5", "socks5h"):
        settings["version"] = "5"
        settings["security"] = "none"
        return ParsedShareURL(kind=OutboundKind.SOCKS, settings=settings,
                              name_hint=_fragment_name(parsed), protocol="socks",
                              transport="tcp", security="none")
    if scheme == "naive+https":
        if not settings.get("username") or settings.get("password") is None:
            raise ShareURLError("naive link needs user:password credentials")
        # no separate SNI: the TLS name IS the host (an SNI host override
        # therefore moves the host itself when the link is re-emitted)
        settings["security"] = "tls"
        return ParsedShareURL(kind=OutboundKind.NAIVE, settings=settings,
                              name_hint=_fragment_name(parsed), protocol="naive",
                              transport="tcp", security="tls")
    security = "tls" if scheme == "https" else "none"
    settings["security"] = security
    return ParsedShareURL(kind=OutboundKind.HTTP, settings=settings,
                          name_hint=_fragment_name(parsed), protocol="http",
                          transport="tcp", security=security)


_PARSERS = {
    "vless": _parse_vless,
    "trojan": _parse_trojan,
    "vmess": _parse_vmess,
    "ss": _parse_ss,
    "ss2022": _parse_ss,
    "shadowsocks": _parse_ss,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
    "anytls": _parse_anytls,
    "naive+https": _parse_userpass,
    "socks": _parse_userpass,
    "socks5": _parse_userpass,
    "socks5h": _parse_userpass,
    "http": _parse_userpass,
    "https": _parse_userpass,
}

SUPPORTED_SCHEMES = sorted(_PARSERS)


def parse_share_url(url: str) -> ParsedShareURL:
    """Parse a share link into {kind, settings}. Raises ShareURLError."""
    if not url or not url.strip():
        raise ShareURLError("empty link")
    scheme = url.strip().split(":", 1)[0].lower()
    parser = _PARSERS.get(scheme)
    if parser is None:
        raise ShareURLError(
            f"unsupported protocol '{scheme}' — supported: {', '.join(SUPPORTED_SCHEMES)}")
    return parser(url)
