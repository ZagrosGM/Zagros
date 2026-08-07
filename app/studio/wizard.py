"""Dynamic inbound-wizard blueprints — ONE source of truth for the
Core → Protocol → Transport → Security → fields flow.

History: the first wizard (alpha.6) hardcoded a single fixed protocol list in
the dashboard, so switching cores changed nothing and asking for e.g. VLESS
over HTTPUpgrade was impossible. This module turns the matrix into data the
dashboard stepper renders directly, per core ID, honoring what each engine
actually supports (xhttp exists only in Xray, REALITY only where the TLS
stack offers it, TUIC/Hysteria2 are QUIC-only, …).

Shape consumed by the dashboard (JSON):

    {
      "core_id": "singbox",
      "protocols": [{
        "id": "vless", "label": "VLESS", "default_port": 443,
        "transports": [{
          "id": "ws", "label": "WebSocket",
          "securities": [{
            "id": "tls", "label": "TLS",
            "fields": [FieldSpec, ...]
          }]
        }]
      }]
    }

FieldSpec: {key, label, type, required, default, options, placeholder, help}
with type ∈ string|int|bool|select|multiselect|password.
"""
from __future__ import annotations

from typing import Any

Field = dict[str, Any]
Security = dict[str, Any]
Transport = dict[str, Any]
Protocol = dict[str, Any]

# --------------------------------------------------------------------- #
# field libraries (reused across the matrix)
# --------------------------------------------------------------------- #

def _f(key: str, label: str, type_: str = "string", **kw: Any) -> Field:
    f: Field = {"key": key, "label": label, "type": type_}
    f.update({k: v for k, v in kw.items() if v is not None})
    return f


_FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"]
_ALPN = ["h2", "http/1.1", "h2,http/1.1", "h3"]

WS_FIELDS = [_f("path", "WebSocket path", placeholder="/ws", default="/ws"),
             _f("host", "Host header", placeholder="cdn.example.com")]
HUP_FIELDS = [_f("path", "HTTPUpgrade path", placeholder="/up", default="/up"),
              _f("host", "Host header", placeholder="cdn.example.com")]
GRPC_FIELDS = [_f("service_name", "gRPC service name", placeholder="grpc-service", required=True),
               _f("authority", "authority (optional)")]
XHTTP_FIELDS = [_f("path", "XHTTP path", placeholder="/xh", default="/xh"),
                _f("host", "Host header", placeholder="cdn.example.com"),
                _f("mode", "mode", "select", options=["auto", "packet-up", "stream-up"], default="auto")]
H2_FIELDS = [_f("path", "HTTP/2 path", placeholder="/h2", default="/h2"),
             _f("host", "HTTP/2 host", placeholder="cdn.example.com")]

SNI_FIELD = _f("sni", "SNI / certificate name", placeholder="panel.example.com", required=True)
ALPN_FIELD = _f("alpn", "ALPN", "multiselect", options=_ALPN, default=["h2", "http/1.1"])
TLS_EXTRA = [_f("certificate", "certificate (managed certs listed; blank = panel default)")]
REALITY_FIELDS = [
    _f("sni", "camouflage target (dest/SNI)", placeholder="www.microsoft.com", required=True,
       help="The server masquerades as this TLS site; it must be TLSv1.3 + h2 capable."),
    _f("fingerprint", "client fingerprint", "select", options=_FINGERPRINTS, default="chrome"),
    _f("public_key", "Reality public key (blank = auto-generated with the inbound)"),
]
FLOW_FIELD = _f("flow", "flow", "select",
                options=["xtls-rprx-vision"], required=False,
                help="recommended for VLESS + TCP + TLS/REALITY")
SS_FIELD = _f("method", "cipher", "select", required=True,
              options=["2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305",
                       "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                       "xchacha20-ietf-poly1305", "none"],
              default="2022-blake3-aes-128-gcm")


def _sec(id_: str, label: str, fields: list[Field]) -> Security:
    return {"id": id_, "label": label, "fields": fields}


def _tr(id_: str, label: str, securities: list[Security]) -> Transport:
    return {"id": id_, "label": label, "securities": securities}


def _proto(id_: str, label: str, default_port: int, transports: list[Transport]) -> Protocol:
    return {"id": id_, "label": label, "default_port": default_port, "transports": transports}


def _none(extra: list[Field] | None = None) -> Security:
    return _sec("none", "None", list(extra or []))


def _tls(extra: list[Field] | None = None) -> Security:
    return _sec("tls", "TLS", [SNI_FIELD, ALPN_FIELD, *TLS_EXTRA, *(extra or [])])


def _reality() -> Security:
    return _sec("reality", "REALITY", [*REALITY_FIELDS, FLOW_FIELD])


# --------------------------------------------------------------------- #
# modern engines: xray & sing-box share the proxy-protocol space but NOT
# the transport space (xhttp is Xray-only; sing-box uses plain "http")
# --------------------------------------------------------------------- #

def _modern_blueprint(*, xhttp: bool, h2_id: str, h2_label: str) -> list[Protocol]:
    transports = [
        _tr("tcp", "TCP (raw)", [_reality(), _tls(), _none()]),
        _tr("ws", "WebSocket", [_reality(), _tls(), _none()]),
        _tr("httpupgrade", "HTTPUpgrade", [_reality(), _tls(), _none()]),
        _tr("grpc", "gRPC", [_reality(), _tls(), _none()]),
    ]
    if xhttp:
        transports.append(_tr("xhttp", "XHTTP", [_reality(), _tls(), _none()]))
    else:
        transports.append(_tr(h2_id, h2_label, [_tls(), _none()]))

    vmess_transports = [
        _tr("tcp", "TCP (raw)", [_tls(), _none()]),
        _tr("ws", "WebSocket", [_tls(), _none()]),
        _tr("httpupgrade", "HTTPUpgrade", [_tls(), _none()]),
        _tr("grpc", "gRPC", [_tls(), _none()]),
        *([_tr("xhttp", "XHTTP", [_tls(), _none()])] if xhttp else
          [_tr(h2_id, h2_label, [_tls(), _none()])]),
    ]
    return [
        _proto("vless", "VLESS", 443, [
            # flow only works on raw TCP (+ TLS/REALITY) — honest matrix
            _tr("tcp", "TCP (raw)", [_reality(), _tls([FLOW_FIELD]), _none()]),
            *[t for t in transports if t["id"] != "tcp"],
        ]),
        _proto("vmess", "VMess", 8443, vmess_transports),
        _proto("trojan", "Trojan", 8443, [
            _tr(t["id"], t["label"], [_reality(), _tls()]) for t in transports
        ]),
        _proto("shadowsocks", "Shadowsocks", 8388, [
            _tr("tcp", "TCP+UDP (in-protocol)", [_none([SS_FIELD])]),
        ]),
    ]


# transport/security specific field attachments (applied at merge time)
_TRANSPORT_FIELDS: dict[str, list[Field]] = {
    "ws": WS_FIELDS,
    "httpupgrade": HUP_FIELDS,
    "grpc": GRPC_FIELDS,
    "xhttp": XHTTP_FIELDS,
    "http": H2_FIELDS,
    "h2": H2_FIELDS,
}


# --------------------------------------------------------------------- #
# QUIC engines
# --------------------------------------------------------------------- #

def _hy2_protocol() -> Protocol:
    return _proto("hysteria2", "Hysteria 2", 4430, [
        _tr("quic", "QUIC (UDP)", [_tls([
            _f("up_mbps", "up (Mbps)", "int", placeholder="0 = unlimited"),
            _f("down_mbps", "down (Mbps)", "int", placeholder="0 = unlimited"),
            _f("obfs", "obfs password", "password",
               help="salamander obfuscation; blank = disabled"),
        ])]),
    ])


def _tuic_protocol() -> Protocol:
    return _proto("tuic", "TUIC v5", 5443, [
        _tr("quic", "QUIC (UDP)", [_tls([
            _f("congestion_control", "congestion control", "select",
               options=["bbr", "cubic", "new_reno"], default="bbr"),
        ])]),
    ])


# --------------------------------------------------------------------- #
# OS-level engines
# --------------------------------------------------------------------- #

def _wireguard_blueprint() -> list[Protocol]:
    return [_proto("wireguard", "WireGuard", 51820, [
        _tr("udp", "UDP", [_none([
            _f("listen", "listen address (blank = all)", placeholder="0.0.0.0"),
        ])]),
    ])]


def _openvpn_blueprint() -> list[Protocol]:
    return [_proto("ovpn", "OpenVPN", 1194, [
        _tr("udp", "UDP", [_tls([
            _f("cipher", "cipher", "select",
               options=["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
               default="AES-256-GCM"),
        ])]),
        _tr("tcp", "TCP", [_tls([
            _f("cipher", "cipher", "select",
               options=["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
               default="AES-256-GCM"),
        ])]),
    ])]


def _softether_blueprint() -> list[Protocol]:
    """Hub-managed listeners: enabling/configuring them is one command away;
    the wizard models exactly the levers vpncmd offers."""
    return [
        _proto("l2tp", "L2TP/IPsec (hub)", 0, [
            _tr("udp", "UDP 500/4500/1701", [_none([
                _f("ipsec_psk", "IPsec pre-shared key", required=True),
            ])]),
        ]),
        _proto("sstp", "SSTP (hub)", 0, [
            _tr("tcp", "TCP 443 (hub listener)", [_tls()]),
        ]),
        _proto("pptp", "PPTP (hub)", 0, [
            _tr("tcp", "TCP 1723 (hub listener)", [_none()]),
        ]),
        _proto("ovpn", "OpenVPN clone (hub)", 0, [
            _tr("udp", "OpenVPN-compatible ports", [_none([
                _f("ports", "UDP ports (comma separated)", default="1194",
                   placeholder="1194,1195"),
            ])]),
        ]),
    ]


# --------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------- #

def blueprint_for(core_id: str) -> dict[str, Any]:
    """The wizard blueprint for one core; KeyError on unknown engine."""
    cid = core_id.lower()
    if cid == "xray":
        protocols = _modern_blueprint(xhttp=True, h2_id="h2", h2_label="HTTP/2")
    elif cid == "singbox":
        protocols = _modern_blueprint(xhttp=False, h2_id="http", h2_label="HTTP/2")
        # both hy2 + tuic exist natively under sing-box — one engine, all protocols
        protocols += [_hy2_protocol(), _tuic_protocol()]
    elif cid == "hysteria2":
        protocols = [_hy2_protocol()]
    elif cid == "tuic":
        protocols = [_tuic_protocol()]
    elif cid == "wireguard":
        protocols = _wireguard_blueprint()
    elif cid == "openvpn":
        protocols = _openvpn_blueprint()
    elif cid == "softether":
        protocols = _softether_blueprint()
    else:
        raise KeyError(core_id)
    for p in protocols:
        for t in p["transports"]:
            extra = _TRANSPORT_FIELDS.get(t["id"])
            if not extra:
                continue
            for s in t["securities"]:
                # transport fields come first, then security-specific ones;
                # avoid duplicating when the matrix already inlined them
                keys = {f["key"] for f in s["fields"]}
                s["fields"] = [*extra, *s["fields"]] if not keys & {f["key"] for f in extra} else s["fields"]
    return {"core_id": cid, "protocols": protocols}
