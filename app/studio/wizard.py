"""Dynamic inbound-wizard blueprints — ONE source of truth for the
Core → Protocol → Transport → Security → fields flow.

History: the first wizard (alpha.6) hardcoded a single fixed protocol list in
the dashboard, so switching cores changed nothing and asking for e.g. VLESS
over HTTPUpgrade was impossible. This module turns the matrix into data the
dashboard stepper renders directly, per core ID, honoring what each engine
actually supports.

The matrix is EMPIRICALLY PINNED (alpha.7.1): every offered
protocol × transport × security cell on xray/sing-box was rendered by the
real driver translator and validated against the real binary
(``xray run -test`` Xray 26.3.27, ``sing-box check`` 1.12.4):

* Xray: transports tcp/ws/httpupgrade/grpc/xhttp/mkcp — HTTP/2 and QUIC
  transports were REMOVED upstream ("migrated to XHTTP stream-one H2 & H3",
  old mKCP header/seed gone); REALITY only accepts VLESS/Trojan over
  RAW/XHTTP/gRPC; ss-2022 ciphers are refused here (legacy account material
  cannot be 2022 uPSKs — the sing-box core carries verified ss-2022).
* sing-box: no xhttp (Xray-only), no wireguard inbound (outbound-only in
  sing-box); shadowsocks has NO transport/tls sections at all; socks/mixed
  carry no TLS; naive REQUIRES TLS; generic quic transport requires TLS;
  2022-blake3-chacha20-poly1305 is Xray-only.

Anything not offered here still works through Advanced Mode (raw JSON), but
no matrix cell offered here may produce an unbootable config.

Shape consumed by the dashboard (JSON)::

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
with type ∈ string|int|bool|select|multiselect|password|textarea|file.
Secrets are write-only (apply keeps the stored value when left blank).
"""
from __future__ import annotations

import secrets

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

WS_FIELDS = [_f("path", "WebSocket path", placeholder="/ws", default="/ws", section="transport"),
             _f("host", "Host header", placeholder="cdn.example.com", section="transport"),
             _f("headers", "extra headers (one 'Name: value' per line)", "textarea",
                placeholder="X-Forwarded-For: 1.2.3.4\nSec-WebSocket-Protocol: chat",
                section="headers",
                help="merged into the ws handshake; the Host field above always "
                     "wins over a pasted Host line")]
HUP_FIELDS = [_f("path", "HTTPUpgrade path", placeholder="/up", default="/up", section="transport"),
              _f("host", "Host header", placeholder="cdn.example.com", section="transport")]
GRPC_FIELDS = [_f("service_name", "gRPC service name", placeholder="grpc-service", required=True, section="transport"),
               _f("authority", "authority (optional)", section="transport")]
GRPC_XRAY_EXTRA = [_f("multi_mode", "multiMode (separate up/down streams)", "bool",
                      default=False, section="transport",
                      help="xray grpcSettings.multiMode")]
# alpha.7.5 item 4 — RAW/TCP HTTP camouflage (xray tcpSettings.header.type =
# "http"): a real request/response pair Xray serves, NOT decoration. The
# translator refuses these facts with header_type=none.
XRAY_TCP_HTTP_FIELDS = [
    _f("header_type", "RAW/TCP header", "select", options=["none", "http"],
       default="none", section="transport",
       help="'http' makes the listener camouflage as an HTTP server "
            "(tcpSettings.header.type)"),
    _f("http_method", "camouflage request method", placeholder="GET", default="GET",
       section="headers", help="requires header_type = http"),
    _f("request_headers", "request headers (one 'Name: value' per line)", "textarea",
       placeholder="Accept: */*\nUser-Agent: curl/8.0", section="headers",
       help="requires header_type = http; the Host field (if set) is added"),
    _f("response_status", "response status code", "int", default=200, placeholder="200",
       section="headers"),
    _f("response_reason", "response reason phrase", placeholder="OK", default="OK",
       section="headers"),
    _f("response_headers", "response headers (one 'Name: value' per line)", "textarea",
       placeholder="Server: nginx\nContent-Type: text/html", section="headers"),
]
# sing-box http transport verb + header map (its V2Ray-transport http struct
# carries method/host/path/headers; method/headers were missing here)
SINGBOX_HTTP_EXTRA = [
    _f("http_method", "HTTP method", placeholder="GET", section="transport"),
    _f("headers", "extra headers (one 'Name: value' per line)", "textarea",
       placeholder="Accept: */*", section="headers"),
]
XHTTP_FIELDS = [_f("path", "XHTTP path", placeholder="/xh", default="/xh", section="transport"),
                _f("host", "Host header", placeholder="cdn.example.com", section="transport"),
                _f("mode", "mode", "select", options=["auto", "packet-up", "stream-up", "stream-one"],
                   default="auto", section="transport")]
H2_FIELDS = [_f("path", "HTTP/2 path", placeholder="/h2", default="/h2", section="transport"),
             _f("host", "HTTP/2 host", placeholder="cdn.example.com", section="transport")]
MKCP_FIELDS = [_f("mtu", "MTU", "int", default=1350, placeholder="1350", section="transport"),
               _f("tti", "TTI (ms)", "int", default=50, placeholder="50", section="transport"),
               _f("congestion", "congestion control", "bool", default=False, section="transport",
                  help="Header/seed were removed upstream (migrated to finalmask); "
                       "this is the pure mKCP UDP transport.")]

SNI_FIELD = _f("sni", "SNI / certificate name", placeholder="panel.example.com", required=True, section="tls")
ALPN_FIELD = _f("alpn", "ALPN", "multiselect", options=_ALPN, default=["h2", "http/1.1"], section="tls")
TLS_UPLOAD_FIELDS = [
    _f("certificate", "certificate (PEM)", "file", section="certificate",
       help="Paste a PEM certificate, or leave blank and the panel generates a "
            "self-signed one — upload a real pair for production domains."),
    _f("certificate_key", "private key (PEM)", "file", section="certificate",
       help="Paste the matching PEM private key (never stored in the studio "
            "document — written 0600 into the core's cert dir)."),
    # alpha.7.5 item 6 Mode B(path): reference PEM files on the panel host —
    # validated with the same rules as pasted content, never copied, never
    # registered in the Certificates store.
    _f("certificate_path", "certificate file path (on this server)", section="certificate",
       placeholder="/etc/letsencrypt/live/example.com/fullchain.pem",
       help="used with the key path below — takes precedence over pasted content"),
    _f("certificate_key_path", "private key file path (on this server)", section="certificate",
       placeholder="/etc/letsencrypt/live/example.com/privkey.pem",
       help="must match the certificate file (validated before applying)"),
]
REALITY_FIELDS = [
    _f("sni", "camouflage target (dest/SNI)", placeholder="www.microsoft.com", required=True, section="reality",
       help="The server masquerades as this TLS site; it must be TLSv1.3 + h2 capable."),
    _f("fingerprint", "client fingerprint", "select", options=_FINGERPRINTS, default="chrome", section="reality"),
    _f("public_key", "Reality public key (blank = auto-generated with the inbound)", section="reality"),
]
FLOW_FIELD = _f("flow", "flow", "select",
                options=["xtls-rprx-vision"], required=False, section="advanced",
                help="recommended for VLESS + TCP + TLS/REALITY")


def _ss_field(*, allow_2022: bool) -> Field:
    options = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
               "xchacha20-ietf-poly1305"]
    if allow_2022:
        options = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", *options]
    return _f("method", "cipher", "select", required=True, options=options,
              default=options[0], section="general")


def _sec(id_: str, label: str, fields: list[Field]) -> Security:
    return {"id": id_, "label": label, "fields": fields}


def _tr(id_: str, label: str, securities: list[Security]) -> Transport:
    return {"id": id_, "label": label, "securities": securities}


def _proto(
    id_: str, label: str, default_port: int, transports: list[Transport],
    *, fixed_port: bool = False, availability: str = "supported",
    reason: str | None = None,
) -> Protocol:
    return {
        "id": id_, "label": label, "default_port": default_port,
        "fixed_port": fixed_port, "transports": transports,
        "availability": availability, "reason": reason,
    }


def _none(extra: list[Field] | None = None) -> Security:
    return _sec("none", "None", list(extra or []))


def _tls(extra: list[Field] | None = None) -> Security:
    return _sec("tls", "TLS", [SNI_FIELD, ALPN_FIELD, *TLS_UPLOAD_FIELDS, *(extra or [])])


def _reality() -> Security:
    return _sec("reality", "REALITY", [*REALITY_FIELDS, FLOW_FIELD])


# --------------------------------------------------------------------- #
# transport builders per engine (the verified matrices)
# --------------------------------------------------------------------- #

def _xray_transports(*, reality: bool, tls_only: bool = False,
                     none_too: bool = True) -> list[Transport]:
    """Verified Xray matrix: REALITY only on RAW/XHTTP/gRPC."""
    out: list[Transport] = []
    for tid, label, fields in (
        ("tcp", "TCP (raw)", XRAY_TCP_HTTP_FIELDS),
        ("ws", "WebSocket", None),
        ("httpupgrade", "HTTPUpgrade", None),
        ("grpc", "gRPC", GRPC_XRAY_EXTRA),
        ("xhttp", "XHTTP", None),
        ("mkcp", "mKCP (UDP)", MKCP_FIELDS),
    ):
        secs: list[Security] = []
        if reality and tid in ("tcp", "xhttp", "grpc"):
            secs.append(_reality())
        if tls_only:
            secs.append(_tls())
        elif none_too:
            secs += [_tls(), _none()]
        else:
            secs.append(_none())
        if fields:
            for s in secs:
                s["fields"] = [*fields, *s["fields"]]
        out.append(_tr(tid, label, secs))
    return out


def _singbox_proxy_transports(*, reality: bool, none_too: bool = True) -> list[Transport]:
    """Verified sing-box matrix (vless/vmess/trojan): quic only under TLS/REALITY."""
    out: list[Transport] = []
    for tid, label, extra in (
        ("tcp", "TCP (raw)", None),
        ("ws", "WebSocket", None),
        ("httpupgrade", "HTTPUpgrade", None),
        ("grpc", "gRPC", None),
        ("http", "HTTP/2", SINGBOX_HTTP_EXTRA),
    ):
        if reality:
            secs = [_reality(), _tls()] + ([_none()] if none_too else [])
        else:
            secs = [_tls()] + ([_none()] if none_too else [])
        if extra:
            for s in secs:
                s["fields"] = [*extra, *s["fields"]]
        out.append(_tr(tid, label, secs))
    # generic quic transport exists but REFUSES to boot without TLS
    secs_q = [_tls()] + ([_reality()] if reality else [])
    out.append(_tr("quic", "QUIC", secs_q))
    return out


# --------------------------------------------------------------------- #
# xray (Xray-core)
# --------------------------------------------------------------------- #

def _xray_blueprint() -> list[Protocol]:
    return [
        _proto("vless", "VLESS", 443, _xray_transports(reality=True)),
        _proto("vmess", "VMess", 8443, _xray_transports(reality=False)),
        _proto("trojan", "Trojan", 8443,
               [t for t in _xray_transports(reality=True, tls_only=True)]),
        _proto("shadowsocks", "Shadowsocks", 8388,
               [_tr(t["id"], t["label"],
                    [_tls([*(MKCP_FIELDS if t["id"] == "mkcp" else []),
                           _ss_field(allow_2022=False)]),
                     _none([*(MKCP_FIELDS if t["id"] == "mkcp" else []),
                            _ss_field(allow_2022=False)])])
                for t in _xray_transports(reality=False)]),
        _proto("socks", "SOCKS5 proxy", 1080, [
            _tr("tcp", "TCP (local proxy)", [
                _tls(), _none([
                    _f("auth", "authentication", "select",
                       options=["noauth", "password"], default="noauth"),
                    _f("username", "username (when password auth)"),
                    _f("password", "password (when password auth)", "password"),
                ]),
            ]),
        ]),
        _proto("http", "HTTP proxy", 8080, [
            _tr("tcp", "TCP (local proxy)", [
                _tls(), _none([
                    _f("username", "username (optional)"),
                    _f("password", "password (optional)", "password"),
                ]),
            ]),
        ]),
        _proto("dokodemo-door", "Dokodemo (port-forward · DNS relay)", 8053, [
            _tr("tcp", "TCP+UDP forward", [
                _tls(), _none([
                    _f("address", "target address", placeholder="1.1.1.1",
                       required=True,
                       help="For a DNS relay use a resolver IP with target port 53."),
                    _f("target_port", "target port", "int", default=53, required=True),
                ]),
            ]),
        ]),
    ]


# --------------------------------------------------------------------- #
# sing-box
# --------------------------------------------------------------------- #

def _proxy_user_fields(*, required: bool) -> list[Field]:
    return [
        _f("username", "username" + ("" if required else " (optional)"), required=required),
        _f("password", "password" + ("" if required else " (optional)"), "password",
           required=required),
    ]


def _hy2_fields() -> list[Field]:
    return [
        _f("up_mbps", "up (Mbps)", "int", placeholder="0 = unlimited"),
        _f("down_mbps", "down (Mbps)", "int", placeholder="0 = unlimited"),
        _f("obfs", "obfs password", "password",
           help="salamander obfuscation; blank = disabled/unchanged"),
        _f("masquerade", "masquerade URL", placeholder="https://www.bing.com",
           help="non-hysteria traffic is answered like this site"),
    ]


def _hy2_protocol() -> Protocol:
    return _proto("hysteria2", "Hysteria 2", 4430, [
        _tr("quic", "QUIC (UDP)", [_tls(_hy2_fields())]),
    ])


def _tuic_protocol() -> Protocol:
    return _proto("tuic", "TUIC v5", 5443, [
        _tr("quic", "QUIC (UDP)", [_tls([
            _f("congestion_control", "congestion control", "select",
               options=["bbr", "cubic", "new_reno"], default="bbr"),
            _f("zero_rtt", "0-RTT handshake", "bool", default=False),
        ])]),
    ])


def _singbox_blueprint() -> list[Protocol]:
    return [
        _proto("vless", "VLESS", 443, _singbox_proxy_transports(reality=True)),
        _proto("vmess", "VMess", 8443, _singbox_proxy_transports(reality=False)),
        _proto("trojan", "Trojan", 8443,
               _singbox_proxy_transports(reality=True, none_too=False)),
        _proto("shadowsocks", "Shadowsocks", 8388, [
            _tr("tcp", "TCP+UDP (in-protocol)", [_none([_ss_field(allow_2022=True)])]),
        ]),
        _proto("socks", "SOCKS5 proxy", 1080, [
            _tr("tcp", "TCP (local proxy)", [_none(_proxy_user_fields(required=False))]),
        ]),
        _proto("http", "HTTP proxy", 8080, [
            _tr("tcp", "TCP (local proxy)", [
                _tls(_proxy_user_fields(required=False)),
                _none(_proxy_user_fields(required=False)),
            ]),
        ]),
        _proto("mixed", "Mixed (SOCKS+HTTP)", 1081, [
            _tr("tcp", "TCP (local proxy)", [_none(_proxy_user_fields(required=False))]),
        ]),
        _proto("naive", "NaiveProxy", 8446, [
            _tr("quic", "HTTPS/2 (implicit)", [_tls(_proxy_user_fields(required=True))]),
        ]),
        _proto("anytls", "AnyTLS", 8447, [
            _tr("tcp", "TCP", [_tls([
                _f("password", "listener password", "password", required=True),
                _f("padding_scheme", "padding scheme", "textarea",
                   placeholder="stop=8\n0=30-30\n1=100-400",
                   help="one per line, AnyTLS padding grammar (optional)"),
            ])]),
        ]),
        _hy2_protocol(),
        _tuic_protocol(),
    ]


# --------------------------------------------------------------------- #
# OS-level engines (single-listener studio contracts)
# --------------------------------------------------------------------- #

def _wireguard_blueprint() -> list[Protocol]:
    return [_proto("wireguard", "WireGuard", 51820, [
        _tr("udp", "UDP", [_none([
            _f("listen", "listen address", placeholder="0.0.0.0", default="0.0.0.0"),
            _f("mtu", "MTU (blank = kernel default)", "int", placeholder="1420"),
            _f("dns", "DNS servers (comma separated)", default="1.1.1.1",
               placeholder="1.1.1.1, 9.9.9.9"),
            _f("address", "tunnel subnet (Address)", default="10.66.66.0/24",
               placeholder="10.66.66.0/24", required=True),
            _f("endpoint", "public endpoint host", placeholder="vpn.example.com",
               help="written into delivered client configs (.conf / QR)"),
            _f("allowed_ips", "peer AllowedIPs default", default="0.0.0.0/0, ::/0",
               help="routed subnets on the client side"),
            _f("persistent_keepalive", "PersistentKeepalive (s)", "int", default=25),
            _f("preshared_keys", "per-peer preshared keys", "bool", default=True,
               help="recommended (post-quantum safety layer)"),
            _f("private_key", "server private key (blank = keep current)", "password",
               help="paste a base64 wireguard key ONLY to replace the server key; "
                    "the public key is derived and shown after applying"),
            _f("public_key", "server public key (derived — read only)", "string",
               help="filled automatically; clients authenticate the server with it"),
        ])]),
    ])]


def _openvpn_blueprint() -> list[Protocol]:
    return [_proto("ovpn", "OpenVPN", 1194, [
        _tr("udp", "UDP", [_none([
            _f("topology", "topology", "select",
               options=["subnet", "net30", "p2p"], default="subnet"),
            _f("subnet", "tunnel subnet (IPv4 network)", default="10.8.0.0",
               help="each inbound needs its OWN subnet (client routing)"),
            _f("netmask", "tunnel netmask", default="255.255.255.0"),
            _f("cipher", "data cipher", "select",
               options=["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
               default="AES-256-GCM"),
            _f("cipher_fallback", "fallback cipher", "select",
               options=["AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"],
               default="AES-128-GCM"),
            _f("auth", "HMAC auth digest (blank = omit)", "select",
               options=["", "SHA256", "SHA384", "SHA512"], default="",
               help="ignored by AEAD data ciphers; only set for legacy CBC setups"),
            _f("compression", "compression", "select",
               options=["", "lz4-v2", "lzo"], default="",
               help="off is safest (VORACLE); enable only when you know why"),
            _f("dns", "pushed DNS servers (comma separated)",
               default="1.1.1.1, 8.8.8.8"),
            _f("redirect_gateway", "redirect default gateway", "bool", default=True),
            _f("auth_mode", "authentication", "select",
               options=["management", "static"], default="management",
               help="management = per-user panel credentials · static = one shared "
                    "username/password pair"),
            _f("username", "static username (auth=static)"),
            _f("password", "static password (auth=static)", "password"),
            _f("ca_certificate", "CA certificate (PEM, optional)", "file",
               help="bring-your-own PKI: replaces the panel-generated CA"),
            _f("certificate", "server certificate (PEM, optional)", "file",
               help="must match the uploaded private key (validated)"),
            _f("certificate_key", "server private key (PEM, optional)", "file"),
            _f("extra_directives", "extra server.conf directives", "textarea",
               placeholder="max-clients 512\nsndbuf 393216",
               help="advanced, appended verbatim — one directive per line"),
        ])]),
        _tr("tcp", "TCP", [_none([
            _f("topology", "topology", "select",
               options=["subnet", "net30", "p2p"], default="subnet"),
            _f("subnet", "tunnel subnet (IPv4 network)", default="10.9.0.0",
               help="each inbound needs its OWN subnet (client routing)"),
            _f("netmask", "tunnel netmask", default="255.255.255.0"),
            _f("cipher", "data cipher", "select",
               options=["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
               default="AES-256-GCM"),
            _f("cipher_fallback", "fallback cipher", "select",
               options=["AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"],
               default="AES-128-GCM"),
            _f("auth", "HMAC auth digest (blank = omit)", "select",
               options=["", "SHA256", "SHA384", "SHA512"], default=""),
            _f("compression", "compression", "select",
               options=["", "lz4-v2", "lzo"], default=""),
            _f("dns", "pushed DNS servers (comma separated)",
               default="1.1.1.1, 8.8.8.8"),
            _f("redirect_gateway", "redirect default gateway", "bool", default=True),
            _f("auth_mode", "authentication", "select",
               options=["management", "static"], default="management"),
            _f("username", "static username (auth=static)"),
            _f("password", "static password (auth=static)", "password"),
            _f("ca_certificate", "CA certificate (PEM, optional)", "file"),
            _f("certificate", "server certificate (PEM, optional)", "file"),
            _f("certificate_key", "server private key (PEM, optional)", "file"),
            _f("extra_directives", "extra server.conf directives", "textarea",
               placeholder="max-clients 512"),
        ])]),
    ])]


def _ssh_blueprint() -> list[Protocol]:
    return [_proto("ssh", "SSH tunnel", 2022, [
        _tr("tcp", "TCP", [_none([
            _f("authentication", "authentication", "select",
               options=["both", "password", "publickey"], default="both",
               help="never lets you disable BOTH — the panel refuses an sshd "
                    "nobody could log into"),
            _f("password", "default account password (blank = keep)", "password",
               help="used for panel users provisioned without an own password"),
            _f("public_key", "default account public key (blank = keep)", "file",
               help="ssh-ed25519/ssh-rsa/… — installed for every tunnel account "
                    "via a panel-owned AuthorizedKeysFile"),
            _f("shell", "login shell", "select",
               options=["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/sbin/nologin"],
               default="/bin/bash"),
            _f("sftp", "SFTP subsystem", "bool", default=True),
            _f("max_sessions", "max sessions per connection", "int", default=10),
            _f("banner", "login banner text (blank = keep)", "textarea",
               placeholder="Welcome to this server"),
        ])]),
    ])]


def _softether_blueprint() -> list[Protocol]:
    """Capabilities of the supported SoftEther **stable** server line.

    Each selectable cell maps to a real vpncmd operation. PPTP remains visible
    as an explicit unsupported capability (the installed stable runtime has no
    PptpGet/PptpEnable command), never as a fake selectable inbound. EtherIP is
    absent from the simple wizard because enabling the server bit alone is insufficient:
    every router needs an EtherIpClientAdd identity mapping. It remains an
    Advanced/runtime capability, not a fake one-click inbound.
    """
    # SoftEther recommends at most nine characters for broad built-in L2TP
    # client compatibility. Choice is CSPRNG-backed; ~53 bits from this
    # unambiguous 64-symbol alphabet, visible/copyable/editable in the UI.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
    psk = "".join(secrets.choice(alphabet) for _ in range(9))
    return [
        _proto("softether", "Native SoftEther VPN", 5555, [
            _tr("tcp", "SoftEther VPN over HTTPS/TCP", [_none()]),
        ]),
        _proto("l2tp", "L2TP/IPsec", 1701, [
            _tr("udp", "UDP 500/4500/1701", [_none([
                _f("ipsec_psk", "IPsec pre-shared key", required=True,
                   default=psk, section="general",
                   help="secure random 9-character default; visible, copyable and editable"),
            ])]),
        ], fixed_port=True),
        _proto("l2tp_raw", "L2TP RAW (no IPsec)", 1701, [
            _tr("udp", "UDP 1701 (unencrypted)", [_none()]),
        ], fixed_port=True),
        _proto("sstp", "Microsoft SSTP compatibility", 443, [
            # SoftEther owns its server certificate. Generic Xray-style PEM
            # upload fields would be a lie here; certificate management is a
            # separate SoftEther server-certificate operation.
            _tr("tcp", "HTTPS/TCP 443", [_none()]),
        ]),
        _proto("ovpn", "OpenVPN compatibility", 1194, [
            _tr("udp", "UDP", [_none()]),
        ]),
        _proto(
            "pptp", "PPTP", 1723, [], fixed_port=True,
            availability="unsupported",
            reason=(
                "Unavailable because this SoftEther runtime does not expose "
                "PPTP (vpncmd PptpGet/PptpEnable are not commands)."
            ),
        ),
    ]


# --------------------------------------------------------------------- #
# registry — keyed by the CORES' canonical ids (their `metadata.id`),
# with accepted aliases. Field-reported bug (alpha.7.2 item 7): this used
# to key the sing-box blueprint on "singbox" while the real core id (and
# the dashboard URL) is "sing-box" — every wizard-schema fetch for the
# panel's primary core 404'd with "the wizard blueprint could not be
# loaded". Ids now resolve through one canonical map.
# --------------------------------------------------------------------- #

_BLUEPRINTS = {
    "xray": _xray_blueprint,
    "sing-box": _singbox_blueprint,
    "wireguard": _wireguard_blueprint,
    "openvpn": _openvpn_blueprint,
    "ssh": _ssh_blueprint,
    "softether": _softether_blueprint,
}

_ALIASES = {
    "singbox": "sing-box",
}


def wizard_supported(core_id: str) -> bool:
    """True when an inbound-wizard blueprint exists for this core id."""
    cid = _ALIASES.get(core_id.lower(), core_id.lower())
    return cid in _BLUEPRINTS


def blueprint_for(core_id: str) -> dict[str, Any]:
    """The wizard blueprint for one core, built dynamically per call
    (never a cached static blob); KeyError on a genuinely wizardless engine.
    The returned ``core_id`` is always the canonical id."""
    cid = _ALIASES.get(core_id.lower(), core_id.lower())
    builder = _BLUEPRINTS.get(cid)
    if builder is None:
        raise KeyError(core_id)
    protocols = builder()
    # transport field libraries ride along every security of that transport
    for p in protocols:
        for t in p["transports"]:
            extra = _TRANSPORT_FIELDS.get(t["id"])
            if not extra:
                continue
            for s in t["securities"]:
                keys = {f["key"] for f in s["fields"]}
                merged = [f for f in extra if f["key"] not in keys]
                s["fields"] = [*merged, *s["fields"]]
    return {"core_id": cid, "protocols": protocols}


# transport/security specific field attachments (applied at merge time)
_TRANSPORT_FIELDS: dict[str, list[Field]] = {
    "ws": WS_FIELDS,
    "httpupgrade": HUP_FIELDS,
    "grpc": GRPC_FIELDS,
    "xhttp": XHTTP_FIELDS,
    "http": H2_FIELDS,
    "h2": H2_FIELDS,
}
