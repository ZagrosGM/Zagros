"""Per-kind outbound profile schemas.

The admin UI used to hard-code a handful of fields per protocol — any
transport beyond the basics was simply unreachable. These JSON-Schema
documents describe EVERY field each outbound kind supports, including the
full transport matrix (TCP/KCP/WS/HTTP/gRPC/QUIC/HTTPUpgrade/SplitHTTP)
and the full security matrix (none/TLS/REALITY), so the SPA can build the
form from the schema instead of from a fixed template (bug fix #2 of the
outbounds item).

Shape is plain JSON Schema draft-07 (object/properties/required) plus the
UI hints `x-group` (basic/transport/security/auth) and `x-widget`
(text/password/textarea/number/select/toggle) the form builder reads.
"""
from __future__ import annotations

from app.cores.outbounds.model import (
    SOFTETHER_CLIENT_LIMITATION,
    OutboundKind,
)

_NETWORKS = ["tcp", "kcp", "ws", "http", "grpc", "quic",
             "httpupgrade", "splithttp"]
_SECURITIES = ["none", "tls", "reality"]


def _str(key, title, *, group, widget="text", default=None, hint=None,
         required=False, secret=False):
    prop: dict = {
        "type": "string", "title": title, "x-group": group,
        "x-widget": ("password" if secret and widget == "text" else widget),
    }
    if secret:
        prop["x-secret"] = True
    if default is not None:
        prop["default"] = default
    if hint:
        prop["description"] = hint
    return prop


def _num(key, title, *, group, default=None, hint=None, minimum=None, maximum=None):
    prop: dict = {"type": "integer", "title": title, "x-group": group,
                  "x-widget": "number"}
    if default is not None:
        prop["default"] = default
    if hint:
        prop["description"] = hint
    if minimum is not None:
        prop["minimum"] = minimum
    if maximum is not None:
        prop["maximum"] = maximum
    return prop


def _select(key, title, *, group, options, default=None, hint=None):
    prop: dict = {"type": "string", "title": title, "enum": list(options),
                  "x-group": group, "x-widget": "select"}
    if default is not None:
        prop["default"] = default
    if hint:
        prop["description"] = hint
    return prop


def _server_fields() -> dict:
    return {
        "server": _str("server", "server / address", group="basic",
                       hint="hostname or IP of the upstream server"),
        "server_port": _num("server_port", "port", group="basic",
                            minimum=1, maximum=65535),
    }


def _ppp_client_fields(*, default_port: int) -> dict:
    fields = _server_fields()
    fields["server_port"]["default"] = default_port
    fields.update({
        "username": _str("username", "PPP username", group="auth"),
        "password": _str("password", "PPP password", group="auth", secret=True),
        "mtu": _num("mtu", "PPP MTU", group="transport", default=1400,
                    minimum=1280, maximum=1500),
        "ipv6": {
            "type": "boolean", "title": "IPv6 (not supported)",
            "x-group": "basic", "x-widget": "toggle", "default": False,
        },
        "test_url": _str(
            "test_url", "HTTPS probe URL", group="basic",
            default="https://1.1.1.1/cdn-cgi/trace",
            hint=("Test establishes a fresh tunnel, measures 20-30 RTT samples, "
                  "then performs CA-validated HTTPS through it"),
        ),
        "probe_ca_pem": _str(
            "probe_ca_pem", "HTTPS probe CA certificate (optional)",
            group="security", widget="textarea",
            hint="Public CA PEM for a private probe origin; system trust is the default",
        ),
        "test_samples": _num(
            "test_samples", "steady-state RTT samples", group="basic",
            default=20, minimum=20, maximum=30,
        ),
    })
    return fields


def _policy_core_field() -> dict:
    return {
        "policy_core": _select(
            "policy_core", "service-source execution core", group="basic",
            options=["sing-box", "xray"], default="sing-box",
            hint=("kernel/TUN sources use the selected real core process; "
                  "Xray support is limited to Xray-native protocols"),
        )
    }


def _transport_fields(networks=_NETWORKS) -> dict:
    fields = {
        "network": _select("network", "transport", group="transport",
                           options=networks, default=networks[0]),
        # ws / http / httpupgrade / splithttp
        "path": _str("path", "path", group="transport", default="/",
                     hint="ws / http / httpupgrade / splithttp request path"),
        "host": _str("host", "host header", group="transport",
                     hint="Host header (ws / http / httpupgrade / splithttp)"),
        # grpc
        "serviceName": _str("serviceName", "gRPC service name", group="transport"),
        "authority": _str("authority", "gRPC authority", group="transport"),
        "mode": _select("mode", "gRPC mode", group="transport",
                        options=["gun", "multi"], default="gun"),
        # kcp
        "headerType": _str("headerType", "KCP header type", group="transport",
                           hint="none / srtp / utp / wechat-video / dtls / wireguard"),
        "seed": _str("seed", "KCP seed", group="transport", secret=True),
    }
    return fields


def _security_fields(securities=_SECURITIES) -> dict:
    return {
        "security": _select("security", "security", group="security",
                            options=securities, default=securities[0]),
        "sni": _str("sni", "SNI", group="security"),
        "alpn": _str("alpn", "ALPN", group="security",
                     hint="comma-separated, e.g. h2,http/1.1"),
        "fingerprint": _str("fingerprint", "TLS fingerprint (uTLS)", group="security",
                            hint="e.g. chrome, firefox, randomized"),
        "allow_insecure": {"type": "boolean", "title": "allow insecure",
                           "x-group": "security", "x-widget": "toggle",
                           "default": False},
        # REALITY
        "reality_public_key": _str("reality_public_key", "REALITY public key",
                                   group="security", secret=True),
        "reality_short_id": _str("reality_short_id", "REALITY short id", group="security"),
        "reality_spider_x": _str("reality_spider_x", "REALITY spiderX", group="security",
                                 default="/"),
    }


def _schema(properties, required=(), description="", *, supported=True,
            disabled_reason: str | None = None):
    doc = {"type": "object", "properties": properties,
           "required": sorted(set(required)), "x-supported": bool(supported)}
    if description:
        doc["description"] = description
    if disabled_reason:
        doc["x-disabled-reason"] = disabled_reason
    return doc


def _proxy_schema(*, id_field: str, id_title: str, flow: bool = True,
                  networks=_NETWORKS, securities=_SECURITIES,
                  extra: dict | None = None, description: str = ""):
    props = {
        **_server_fields(),
        **_policy_core_field(),
        id_field: _str(id_field, id_title, group="auth", secret=True),
        **_transport_fields(networks),
        **_security_fields(securities),
    }
    if flow:
        props["flow"] = _select("flow", "XTLS flow", group="auth",
                                options=["", "xtls-rprx-vision"], default="",
                                hint="only valid with tcp/kcp + tls/reality")
    if extra:
        props.update(extra)
    return _schema(props, required=("server", "server_port", id_field),
                   description=description)


_KIND_SCHEMAS: dict[OutboundKind, dict] = {
    OutboundKind.DIRECT: _schema({}, description="egress straight from this server"),
    OutboundKind.BLOCK: _schema({}, description="reject matching traffic"),
    OutboundKind.BLACKHOLE: _schema({}, description="silently drop matching traffic"),
    OutboundKind.DNS: _schema(
        {"address": _str("address", "resolver address", group="basic",
                         hint="empty = the core's internal resolver")},
        description="DNS handler outbound"),
    OutboundKind.SOCKS: _schema(
        {**_server_fields(), **_policy_core_field(),
         "version": _select("version", "socks version", group="basic",
                            options=["5", "4a", "4"], default="5"),
         "username": _str("username", "username (optional)", group="auth"),
         "password": _str("password", "password (optional)", group="auth", secret=True)},
        required=("server", "server_port")),
    OutboundKind.HTTP: _schema(
        {**_server_fields(), **_policy_core_field(),
         "username": _str("username", "username (optional)", group="auth"),
         "password": _str("password", "password (optional)", group="auth", secret=True)},
        required=("server", "server_port")),
    OutboundKind.VLESS: _proxy_schema(
        id_field="uuid", id_title="UUID",
        description="VLESS upstream (TLS/REALITY, every transport)"),
    OutboundKind.VMESS: _proxy_schema(
        id_field="uuid", id_title="UUID", flow=False,
        securities=["none", "tls"],
        extra={"alter_id": _num("alter_id", "alterId", group="auth", default=0,
                                minimum=0),
               "cipher": _select("cipher", "cipher", group="auth",
                                 options=["auto", "aes-128-gcm", "chacha20-poly1305",
                                          "none", "zero"], default="auto")},
        description="VMess upstream"),
    OutboundKind.TROJAN: _proxy_schema(
        id_field="password", id_title="password", flow=False,
        securities=["tls"],
        description="Trojan upstream (TLS mandatory)"),
    OutboundKind.SHADOWSOCKS: _schema(
        {**_server_fields(), **_policy_core_field(),
         "method": _select("method", "cipher", group="auth",
                           options=["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                    "2022-blake3-chacha20-poly1305",
                                    "aes-128-gcm", "aes-256-gcm",
                                    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"],
                           default="aes-256-gcm"),
         "password": _str("password", "password", group="auth", secret=True),
         "plugin": _str("plugin", "plugin (optional)", group="transport"),
         "plugin_opts": _str("plugin_opts", "plugin options (optional)", group="transport")},
        required=("server", "server_port", "method", "password"),
        description="Shadowsocks upstream"),
    OutboundKind.WIREGUARD: _schema(
        {**_server_fields(),
         "private_key": _str("private_key", "private key", group="auth", secret=True),
         "peer_public_key": _str("peer_public_key", "peer public key", group="auth"),
         "preshared_key": _str("preshared_key", "preshared key (optional)",
                               group="auth", secret=True),
         "local_address": _str("local_address", "local address(es) (CIDR)", group="basic",
                               hint="comma-separated, e.g. 172.16.0.2/32"),
         "allowed_ips": _str("allowed_ips", "peer AllowedIPs", group="basic",
                             default="0.0.0.0/0, ::/0", hint="comma-separated routes"),
         "dns": _str("dns", "DNS servers", group="basic",
                     hint="comma-separated"),
         "mtu": _num("mtu", "MTU", group="transport", default=1420,
                     minimum=576, maximum=9000),
         "keepalive": _num("keepalive", "persistent keepalive (s)", group="transport",
                           default=25, minimum=0)},
        required=("server", "server_port", "private_key", "peer_public_key"),
        description="WireGuard upstream"),
    OutboundKind.HYSTERIA2: _schema(
        {**_server_fields(),
         "password": _str("password", "password", group="auth", secret=True),
         "obfs": _select("obfs", "obfuscation", group="transport",
                         options=["", "salamander"], default=""),
         "obfs_password": _str("obfs_password", "obfs password", group="transport",
                               secret=True),
         "port_hopping": _str("port_hopping", "port hopping (20000-30000)", group="transport"),
         "sni": _str("sni", "SNI", group="security"),
         "alpn": _str("alpn", "ALPN", group="security"),
         "allow_insecure": {"type": "boolean", "title": "allow insecure",
                            "x-group": "security", "x-widget": "toggle",
                            "default": False}},
        required=("server", "server_port", "password"),
        description="Hysteria2 upstream (QUIC, always TLS)"),
    OutboundKind.TUIC: _schema(
        {**_server_fields(),
         "uuid": _str("uuid", "UUID", group="auth", secret=True),
         "password": _str("password", "password", group="auth", secret=True),
         "congestion_control": _select("congestion_control", "congestion control",
                                       group="transport",
                                       options=["bbr", "cubic", "new_reno"], default="bbr"),
         "udp_relay_mode": _select("udp_relay_mode", "UDP relay mode", group="transport",
                                   options=["native", "quic"], default="native"),
         "sni": _str("sni", "SNI", group="security"),
         "alpn": _str("alpn", "ALPN", group="security", default="h3"),
         "allow_insecure": {"type": "boolean", "title": "allow insecure",
                            "x-group": "security", "x-widget": "toggle",
                            "default": False}},
        required=("server", "server_port", "uuid", "password"),
        description="TUIC upstream (QUIC, always TLS)"),
    OutboundKind.OPENVPN: _schema(
        {**_server_fields(),
         "proto": _select("proto", "protocol", group="basic",
                          options=["udp", "tcp"], default="udp"),
         "username": _str("username", "username (auth-user-pass)", group="auth"),
         "password": _str("password", "password", group="auth", secret=True),
         "ca_pem": _str("ca_pem", "CA certificate (PEM)", group="auth",
                        widget="textarea"),
         "cert_pem": _str("cert_pem", "client certificate (PEM, optional)",
                          group="auth", widget="textarea"),
         "key_pem": _str("key_pem", "client key (PEM, optional)", group="auth",
                         widget="textarea", secret=True),
         "ovpn_content": _str("ovpn_content", "full .ovpn profile (paste/upload)",
                              group="basic", widget="textarea", secret=True,
                              hint="when present, it wins over the individual fields"),
         "cipher": _str("cipher", "cipher (e.g. AES-256-GCM)", group="transport"),
         "auth": _str("auth", "digest auth (e.g. SHA256)", group="transport")},
        description=("OpenVPN upstream — upload a profile or fill the pieces; "
                     "this is also the supported client for a SoftEther "
                     "OpenVPN-compatibility listener")),
    OutboundKind.SSH: _schema(
        {**_server_fields(),
         "username": _str("username", "username", group="auth"),
         "password": _str("password", "password", group="auth", secret=True),
         "private_key": _str("private_key", "private key (PEM, optional)",
                             group="auth", widget="textarea", secret=True),
         "host_key": _str("host_key", "server host key (optional)", group="auth")},
        required=("server", "server_port", "username"),
        description="SSH tunnel upstream"),
    OutboundKind.L2TP_IPSEC: {
        **_schema(
            {**_ppp_client_fields(default_port=1701),
             "ipsec_psk": _str(
                 "ipsec_psk", "IPsec pre-shared key", group="auth", secret=True),
             "ike_version": _select(
                 "ike_version", "IKE version", group="security",
                 options=["ikev1"], default="ikev1"),
             "ppp_authentication": _select(
                 "ppp_authentication", "PPP authentication", group="auth",
                 options=["mschapv2"], default="mschapv2")},
            required=("server", "server_port", "username", "password", "ipsec_psk"),
            description=(
                "Independent strongSwan/XFRM + xl2tpd/PPP client for a real "
                "L2TP/IPsec listener, including SoftEther-compatible peers")),
        "x-security-class": "compatibility",
        "x-peer-compatibility": ["softether"],
    },
    OutboundKind.L2TP_RAW: {
        **_schema(
            {**_ppp_client_fields(default_port=1701),
             "legacy_risk_ack": {
                 "type": "boolean", "title": "I accept unencrypted raw L2TP risk",
                 "x-group": "security", "x-widget": "toggle", "default": False,
             },
             "ppp_authentication": _select(
                 "ppp_authentication", "PPP authentication", group="auth",
                 options=["mschapv2"], default="mschapv2")},
            required=("server", "server_port", "username", "password",
                      "legacy_risk_ack"),
            description=(
                "Independent raw-L2TP PPP client. No IPsec or TLS; "
                "Legacy / Insecure acknowledgement is mandatory.")),
        "x-security-class": "legacy_insecure",
        "x-security-warning": "Raw L2TP provides no tunnel confidentiality.",
        "x-peer-compatibility": ["softether"],
    },
    OutboundKind.SSTP: {
        **_schema(
            {**_ppp_client_fields(default_port=443),
             "tls_server_name": _str(
                 "tls_server_name", "TLS certificate hostname / SNI", group="security",
                 hint="defaults to server; required when dialing an IP for a DNS certificate"),
             "ca_pem": _str(
                 "ca_pem", "private CA certificate (optional)", group="security",
                 widget="textarea", hint="system trust store is used when omitted"),
             "verify_certificate": {
                 "type": "boolean", "title": "verify TLS certificate (required)",
                 "x-group": "security", "x-widget": "toggle", "default": True,
             },
             "ppp_authentication": _select(
                 "ppp_authentication", "PPP authentication", group="auth",
                 options=["mschapv2"], default="mschapv2")},
            required=("server", "server_port", "username", "password"),
            description=(
                "Independent sstp-client/PPP provider. CA and hostname "
                "certificate validation can never be disabled.")),
        "x-security-class": "compatibility",
        "x-peer-compatibility": ["softether"],
    },
    OutboundKind.PPTP: {
        **_schema(
            {**_ppp_client_fields(default_port=1723),
             "legacy_risk_ack": {
                 "type": "boolean", "title": "I accept PPTP Legacy / Insecure risk",
                 "x-group": "security", "x-widget": "toggle", "default": False,
             },
             "ppp_authentication": _select(
                 "ppp_authentication", "PPP authentication", group="auth",
                 options=["mschapv2"], default="mschapv2"),
             "encryption": _select(
                 "encryption", "PPP encryption", group="security",
                 options=["mppe128"], default="mppe128")},
            required=("server", "server_port", "username", "password",
                      "legacy_risk_ack"),
            description=(
                "Independent pptp-linux/PPP provider on fixed TCP/1723 + GRE/47. "
                "Legacy / Insecure; never advertised as SoftEther.")),
        "x-security-class": "legacy_insecure",
        "x-security-warning": (
            "PPTP/MS-CHAPv2 is cryptographically obsolete. Use only for "
            "explicit legacy compatibility."),
        "x-peer-compatibility": ["accel-ppp", "reference-pptp"],
    },
    OutboundKind.SOFTETHER_NATIVE: _schema(
        {**_server_fields(),
         "hub": _str("hub", "Virtual Hub", group="basic",
                     hint="remote SoftEther Virtual Hub name"),
         "username": _str("username", "username", group="auth"),
         "password": _str("password", "password", group="auth", secret=True),
         "server_cert": _str(
             "server_cert", "pinned server certificate (PEM, optional)",
             group="security", widget="textarea",
             hint="when supplied, vpnclient enables exact server certificate verification"),
         "verify_server_certificate": {
             "type": "boolean", "title": "require pinned server certificate",
             "x-group": "security", "x-widget": "toggle", "default": False,
         },
         "dhcp_timeout": _num(
             "dhcp_timeout", "DHCP/connect timeout (seconds)", group="basic",
             default=45, minimum=10, maximum=180),
         "mtu": _num("mtu", "Virtual NIC MTU", group="transport",
                     default=1500, minimum=576, maximum=1500)},
        required=("server", "server_port", "hub", "username", "password"),
        description=(
            "Native SoftEther VPN Client — dedicated vpnclient process, Virtual "
            "NIC, DHCP lease and network namespace per outbound")),
    **{
        kind: _schema(
            {**_server_fields(),
             "username": _str("username", "username", group="auth"),
             "password": _str("password", "password", group="auth", secret=True)},
            required=("server", "server_port", "username"),
            description=f"{title} client (currently unavailable)",
            supported=False,
            disabled_reason=SOFTETHER_CLIENT_LIMITATION,
        )
        for kind, title in (
            (OutboundKind.SOFTETHER_L2TP, "SoftEther L2TP/IPsec"),
            (OutboundKind.SOFTETHER_L2TP_RAW, "SoftEther raw L2TP"),
            (OutboundKind.SOFTETHER_SSTP, "SoftEther SSTP"),
            (OutboundKind.SOFTETHER_PPTP, "PPTP"),
        )
    },
    OutboundKind.CORE: _schema(
        {"core_id": _str("core_id", "target core", group="basic",
                         hint="chain through another managed core instance"),
         "protocol": _select("protocol", "chain endpoint protocol", group="basic",
                             options=["socks", "http"], default="socks"),
         "port": _num("port", "preferred port (optional)", group="basic")},
        required=("core_id", ),
        description="chain into another panel core"),
}


def outbound_schemas(runtime=None) -> dict[str, dict]:
    """Return per-kind schemas enriched by the shared runtime capability matrix.

    ``x-supported`` is no longer a UI-only deny-list.  It is derived from the
    same contract used by API validation and the policy planner, including the
    distinction between unsupported, environment-limited and not-installed.
    """
    import copy

    from app.cores.capabilities import outbound_capabilities
    from app.cores.outbounds.model import LEGACY_SOFTETHER_OUTBOUND_KINDS

    capabilities = outbound_capabilities(runtime)
    result: dict[str, dict] = {}
    for kind, source in _KIND_SCHEMAS.items():
        # These historical IDs remain model-decodable for migration and safe
        # deletion only. Publishing even a disabled schema kept them visible in
        # the Create selector and falsely grouped independent providers under
        # SoftEther.
        if kind in LEGACY_SOFTETHER_OUTBOUND_KINDS:
            continue
        schema = copy.deepcopy(source)
        capability = capabilities[kind]
        schema["x-supported"] = capability.selectable
        schema["x-availability"] = capability.state.value
        schema["x-capability"] = capability.public()
        if capability.reason:
            schema["x-disabled-reason"] = capability.reason
        elif capability.selectable:
            schema.pop("x-disabled-reason", None)
        result[kind.value] = schema
    return result
