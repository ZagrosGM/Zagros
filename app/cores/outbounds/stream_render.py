"""f-panel-9: render TLS/REALITY + transport for proxy client outbounds.

The outbound form stores ``network / path / host / serviceName / mode /
security / sni / alpn / fingerprint / allow_insecure / reality_*`` (see
``app.cores.outbounds.profile_schema``), but both native renderers used to
emit bare address+port+credential outbound dicts — a TLS/REALITY upstream
then closes the raw connection and every routed user loses internet. Both
drivers now call the helpers in this module so a saved profile deploys
byte-for-byte like the same link in a standalone client.
"""
from __future__ import annotations

_BOOLISH = (True, "true", "True", 1, "1")


def _split_alpn(raw: object) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(item).strip() for item in raw if str(item).strip()]
    return [part.strip() for part in str(raw).split(",") if part.strip()]


def _truthy(raw: object) -> bool:
    return raw in _BOOLISH


# --------------------------------------------------------------------- #
# Xray (streamSettings)
# --------------------------------------------------------------------- #
def xray_stream_settings(s: dict) -> dict | None:
    """Build an Xray ``streamSettings`` document from stored settings.

    Returns None when nothing non-default is configured (plain tcp + no
    security), so legacy outbound rows render exactly as before.
    """
    network = str(s.get("network") or "tcp").strip().lower()
    security = str(s.get("security") or "none").strip().lower()
    stream: dict = {"network": network}

    # ---- transport ---- #
    if network == "ws":
        ws: dict = {"path": str(s.get("path") or "/")}
        if s.get("host"):
            ws["headers"] = {"Host": str(s["host"])}
        stream["wsSettings"] = ws
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": str(s.get("path") or "/"),
            **({"host": str(s["host"])} if s.get("host") else {}),
        }
    elif network == "splithttp":
        # Xray ≥ 24.12 renamed SplitHTTP to XHTTP (the bundled 26.x core
        # speaks xhttp); render the modern transport.
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {
            "path": str(s.get("path") or "/"),
            **({"host": str(s["host"])} if s.get("host") else {}),
        }
    elif network == "http":
        http: dict = {"path": str(s.get("path") or "/")}
        if s.get("host"):
            http["host"] = [part.strip() for part in str(s["host"]).split(",")
                            if part.strip()]
        stream["httpSettings"] = http
    elif network == "grpc":
        grpc: dict = {}
        if s.get("serviceName"):
            grpc["serviceName"] = str(s["serviceName"])
        if s.get("authority"):
            grpc["authority"] = str(s["authority"])
        if str(s.get("mode") or "").strip().lower() == "multi":
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc
    elif network == "kcp":
        kcp: dict = {}
        header_type = str(s.get("headerType") or "").strip()
        if header_type and header_type != "none":
            kcp["header"] = {"type": header_type}
        if s.get("seed"):
            kcp["seed"] = str(s["seed"])
        if kcp:
            stream["kcpSettings"] = kcp

    # ---- security ---- #
    server_name = str(s.get("sni") or s.get("server") or "").strip()
    if security == "tls":
        tls: dict = {}
        if server_name:
            tls["serverName"] = server_name
        alpn = _split_alpn(s.get("alpn"))
        if alpn:
            tls["alpn"] = alpn
        if s.get("fingerprint"):
            tls["fingerprint"] = str(s["fingerprint"])
        if _truthy(s.get("allow_insecure")):
            tls["allowInsecure"] = True
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality: dict = {}
        if server_name:
            reality["serverName"] = server_name
        if s.get("reality_public_key"):
            reality["publicKey"] = str(s["reality_public_key"])
        if s.get("reality_short_id"):
            reality["shortId"] = str(s["reality_short_id"])
        if s.get("fingerprint"):
            reality["fingerprint"] = str(s["fingerprint"])
        reality["spiderX"] = str(s.get("reality_spider_x") or "/")
        stream["security"] = "reality"
        stream["realitySettings"] = reality
    else:
        stream["security"] = "none"

    if (stream["network"] == "tcp" and stream["security"] == "none"
            and len(stream) == 2):
        return None
    return stream


# --------------------------------------------------------------------- #
# sing-box (tls + transport)
# --------------------------------------------------------------------- #
def singbox_tls_and_transport(s: dict) -> tuple[dict | None, dict | None]:
    """Build sing-box ``tls``/``transport`` blocks from stored settings.

    Returns ``(None, None)`` for plain tcp + no security so legacy rows
    render exactly as before.
    """
    security = str(s.get("security") or "none").strip().lower()
    network = str(s.get("network") or "tcp").strip().lower()
    server_name = str(s.get("sni") or s.get("server") or "").strip()

    tls: dict | None = None
    if security in ("tls", "reality") and server_name:
        tls = {"enabled": True, "server_name": server_name}
        alpn = _split_alpn(s.get("alpn"))
        if alpn:
            tls["alpn"] = alpn
        if _truthy(s.get("allow_insecure")):
            tls["insecure"] = True
        if s.get("fingerprint"):
            tls["utls"] = {"enabled": True,
                           "fingerprint": str(s["fingerprint"])}
        if security == "reality":
            tls["reality"] = {"enabled": True,
                              "public_key": str(s.get("reality_public_key") or ""),
                              "short_id": str(s.get("reality_short_id") or "")}

    transport: dict | None = None
    if network == "ws":
        transport = {"type": "ws", "path": str(s.get("path") or "/")}
        if s.get("host"):
            transport["headers"] = {"Host": str(s["host"])}
    elif network == "http":
        transport = {"type": "http", "path": str(s.get("path") or "/")}
        if s.get("host"):
            transport["host"] = [part.strip()
                                 for part in str(s["host"]).split(",")
                                 if part.strip()]
    elif network == "httpupgrade":
        transport = {"type": "httpupgrade", "path": str(s.get("path") or "/")}
        if s.get("host"):
            transport["host"] = str(s["host"])
    elif network == "grpc":
        transport = {"type": "grpc"}
        if s.get("serviceName"):
            transport["service_name"] = str(s["serviceName"])
        # sing-box 1.12+ models gun/multi as grpc ping/metadata only —
        # the legacy "mode" select has no direct mapping; nothing to emit.

    if tls is None and transport is None:
        return None, None
    return tls, transport
