"""Multi-format subscription rendering (spec §7/§8).

ONE source of truth — the user's merged multi-core share-link set
(PortalService.build_links) — rendered into the client formats:

* **Clash / Clash-Meta / Stash** (UA ``clash*``/``mihomo``/``stash`` or
  ``?format=clash[-meta]``): mihomo YAML — vless/vmess/trojan/ss plus the
  meta-only hysteria2/tuic.
* **sing-box** (UA ``sing-box``/``SFA/SFI/SFM`` or ``?format=sing-box``):
  a complete, directly importable sing-box 1.8+ JSON config.
* everything else (v2rayNG, Streisand, Nekobox/Nekoray, Shadowrocket,
  Quantumult…) keeps the Marzvan base64 link-list contract — those clients
  digest mixed-protocol link lists natively.

Honesty rules: exact-duplicate links collapse (spec: بدون تکرار), parsed
names stay unique, and anything a format genuinely cannot express (wg/l2tp/
sstp/pptp/openvpn material, unparseable links) is reported as YAML comments
/ a ``notes`` list — never silently dropped, never fabricated.
"""
from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def dedupe_links(links: list[str]) -> list[str]:
    """Order-preserving exact dedupe — spec: no repeated configs."""
    seen: set[str] = set()
    out: list[str] = []
    for link in links:
        if link not in seen:
            seen.add(link)
            out.append(link)
    return out


def parse_named(links: list[str]) -> tuple[list[tuple[str, Any]], list[str]]:
    """Parse share links into (unique-name, ParsedShareURL) pairs.

    Returns (parsed, skipped_notes): every unparsable link is named in the
    notes instead of vanishing quietly.
    """
    from app.utils.shareurl import ShareURLError, parse_share_url

    parsed: list[tuple[str, Any]] = []
    notes: list[str] = []
    used: dict[str, int] = {}
    for link in dedupe_links(links):
        try:
            ob = parse_share_url(link)
        except ShareURLError as exc:
            scheme = link.split("://", 1)[0] if "://" in link else link[:12]
            notes.append(f"skipped {scheme}: {exc}")
            continue
        base = (ob.name_hint or f"{ob.protocol} · {ob.settings.get('server', '?')}").strip()
        n = used.get(base, 0) + 1
        used[base] = n
        name = base if n == 1 else f"{base} #{n}"
        parsed.append((name, ob))
    return parsed, notes


# --------------------------------------------------------------------- #
# Clash-Meta (mihomo) — also what Stash imports
# --------------------------------------------------------------------- #

_CLASH_META_TYPES = {"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic",
                     "anytls", "socks", "http"}


class UnrepresentableLink(ValueError):
    """The link is valid but this client format has no construct for it —
    the caller keeps it on the link list/portal with the reason as a note."""


def _tcp_http_header(settings: dict[str, Any]) -> bool:
    return ((settings.get("network") or "tcp") in ("tcp", "raw")
            and str(settings.get("headerType") or "none") == "http")


def _clash_transport(settings: dict[str, Any], proxy: dict[str, Any]) -> None:
    network = settings.get("network") or "tcp"
    if _tcp_http_header(settings):
        # mihomo `http` network == xray RAW/TCP HTTP-header camouflage
        proxy["network"] = "http"
        opts: dict[str, Any] = {"method": "GET"}
        if settings.get("path"):
            opts["path"] = [p.strip() for p in str(settings["path"]).split(",") if p.strip()]
        if settings.get("host"):
            opts["headers"] = {"Host": [h.strip() for h in str(settings["host"]).split(",") if h.strip()]}
        proxy["http-opts"] = opts
        return
    if network == "ws":
        proxy["network"] = "ws"
        ws: dict[str, Any] = {}
        if settings.get("path"):
            ws["path"] = settings["path"]
        host = settings.get("host")
        if host:
            ws["headers"] = {"Host": host}
        proxy["ws-opts"] = ws
    elif network == "grpc":
        service = settings.get("serviceName") or settings.get("service_name")
        if service:
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": service}
    elif network == "http":
        # mihomo h2 transport (xray h2 / sing-box http): path + host list
        proxy["network"] = "h2"
        h2: dict[str, Any] = {}
        if settings.get("path"):
            h2["path"] = settings["path"]
        if settings.get("host"):
            h2["host"] = [h.strip() for h in str(settings["host"]).split(",") if h.strip()]
        proxy["h2-opts"] = h2
    elif network == "httpupgrade":
        # mihomo expresses HTTPUpgrade as ws with v2ray-http-upgrade
        proxy["network"] = "ws"
        ws: dict[str, Any] = {"v2ray-http-upgrade": True}
        if settings.get("path"):
            ws["path"] = settings["path"]
        if settings.get("host"):
            ws["headers"] = {"Host": settings["host"]}
        proxy["ws-opts"] = ws


def _clash_proxy(name: str, ob: Any) -> dict[str, Any] | None:
    s = ob.settings
    proto = ob.protocol
    server, port = s.get("server"), s.get("server_port")
    if not server or not port:
        return None
    base: dict[str, Any] = {"name": name, "server": server, "port": int(port)}

    if proto == "shadowsocks" or proto == "ss":
        return {**base, "type": "ss", "cipher": s.get("method") or "aes-128-gcm",
                "password": s.get("password") or "", "udp": True}
    if proto == "vmess":
        proxy = {**base, "type": "vmess", "uuid": str(s.get("uuid") or ""),
                 "alterId": int(s.get("alter_id") or 0),
                 "cipher": s.get("cipher") or "auto", "udp": True,
                 "tls": s.get("security") in ("tls", "reality")}
        if s.get("sni"):
            proxy["servername"] = s["sni"]
        _clash_transport(s, proxy)
        return proxy
    if proto == "vless":
        security = s.get("security") or "none"
        proxy = {**base, "type": "vless", "uuid": str(s.get("uuid") or ""),
                 "udp": True, "tls": security in ("tls", "reality")}
        if s.get("flow"):
            proxy["flow"] = s["flow"]
        if s.get("sni"):
            proxy["servername"] = s["sni"]
        if security == "reality":
            proxy["client-fingerprint"] = "chrome"
            proxy["reality-opts"] = {
                "public-key": s.get("reality_public_key") or "",
                **({"short-id": s["reality_short_id"]} if s.get("reality_short_id") else {}),
            }
        _clash_transport(s, proxy)
        return proxy
    if proto == "trojan":
        proxy = {**base, "type": "trojan", "password": s.get("password") or "",
                 "udp": True}
        if s.get("sni"):
            proxy["sni"] = s["sni"]
        _clash_transport(s, proxy)
        return proxy
    if proto == "hysteria2":
        proxy = {**base, "type": "hysteria2", "password": s.get("password") or ""}
        if s.get("sni"):
            proxy["sni"] = s["sni"]
        return proxy
    if proto == "tuic":
        proxy = {**base, "type": "tuic", "uuid": str(s.get("uuid") or ""),
                 "password": s.get("password") or "",
                 "congestion-controller": s.get("congestion_control") or "bbr",
                 "udp-relay-mode": "native"}
        if s.get("sni"):
            proxy["sni"] = s["sni"]
        return proxy
    if proto == "anytls":
        # mihomo ≥ 1.19.x anytls proxy: {type: anytls, password, sni, alpn,
        # skip-cert-verify, client-fingerprint}
        proxy = {**base, "type": "anytls", "password": s.get("password") or "",
                 "udp": True, "client-fingerprint": s.get("fingerprint") or "chrome"}
        if s.get("sni"):
            proxy["sni"] = s["sni"]
        if s.get("alpn"):
            proxy["alpn"] = [a for a in str(s["alpn"]).split(",") if a]
        if s.get("allow_insecure"):
            proxy["skip-cert-verify"] = True
        return proxy
    if proto in ("socks", "http"):
        proxy = {**base, "type": "socks5" if proto == "socks" else "http"}
        if s.get("username"):
            proxy["username"] = s["username"]
            proxy["password"] = s.get("password") or ""
        if proto == "http" and s.get("security") == "tls":
            proxy["tls"] = True
            if s.get("sni"):
                proxy["sni"] = s["sni"]
        if proto == "socks":
            proxy["udp"] = True
        return proxy
    return None


def to_clash_meta(links: list[str], extra_notes: list[str] | None = None) -> tuple[str, list[str]]:
    """mihomo YAML for the full multi-core link set; returns (yaml, notes)."""
    import yaml

    parsed, notes = parse_named(links)
    notes = list(extra_notes or []) + notes

    proxies: list[dict[str, Any]] = []
    names: list[str] = []
    for name, ob in parsed:
        if ob.protocol not in _CLASH_META_TYPES and ob.kind.value not in _CLASH_META_TYPES:
            notes.append(f"{name}: protocol '{ob.protocol}' has no clash-meta form — kept on the link list/portal")
            continue
        try:
            proxy = _clash_proxy(name, ob)
        except UnrepresentableLink as exc:
            notes.append(f"{name}: {exc} — kept on the link list/portal")
            continue
        if proxy is None:
            notes.append(f"{name}: incomplete link fields — kept on the link list/portal")
            continue
        proxies.append(proxy)
        names.append(name)

    doc: dict[str, Any] = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select",
             "proxies": names + (["DIRECT"] if names else ["DIRECT"])}
        ],
        "rules": ["MATCH,PROXY"],
    }
    body = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)
    comment = "".join(f"# {line}\n" for line in
                      (["generated by Zagros — merged multi-core subscription"] + notes))
    return comment + body, notes


# --------------------------------------------------------------------- #
# sing-box (SFA / SFI / SFM)
# --------------------------------------------------------------------- #

def _sb_tls(s: dict[str, Any], *, always: bool = False) -> dict[str, Any] | None:
    security = s.get("security") or "none"
    if security not in ("tls", "reality"):
        if not always:
            return None
        # hysteria2/tuic links carry NO `security` param, yet the protocols
        # are TLS-mandatory — a sing-box outbound without the tls block is
        # invalid (verified against the real binary: `sing-box check`
        # rejects it). Emit the mandatory TLS block with whatever link
        # params exist (sni/alpn/insecure ride the query string instead).
        security = "tls"
    tls: dict[str, Any] = {"enabled": True}
    if s.get("sni"):
        tls["server_name"] = s["sni"]
    alpn = s.get("alpn")
    if alpn:
        tls["alpn"] = [a for a in str(alpn).split(",") if a]
    if s.get("allow_insecure"):
        tls["insecure"] = True
    if security == "reality":
        tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
        tls["reality"] = {
            "enabled": True,
            "public_key": s.get("reality_public_key") or "",
            **({"short_id": s["reality_short_id"]} if s.get("reality_short_id") else {}),
        }
    return tls


def _sb_transport(s: dict[str, Any]) -> dict[str, Any] | None:
    network = s.get("network") or "tcp"
    if _tcp_http_header(s):
        # sing-box's v2ray `http` transport is a REAL HTTP/1.1 (h2 under
        # TLS) stream that checks the response status — not xray's fake
        # request/response header around a raw stream; a mapped outbound
        # would dial and fail, so the link is kept off this format honestly.
        raise UnrepresentableLink(
            "xray RAW/TCP HTTP-header camouflage (headerType=http) has no "
            "sing-box transport — use a v2rayN/xray or mihomo client")
    if network == "ws":
        tr: dict[str, Any] = {"type": "ws"}
        if s.get("path"):
            tr["path"] = s["path"]
        if s.get("host"):
            tr["headers"] = {"Host": s["host"]}
        return tr
    if network == "grpc":
        service = s.get("serviceName") or s.get("service_name")
        if service:
            return {"type": "grpc", "service_name": service}
    if network == "http":
        # v2ray http transport (sing-box TCP camouflage / xray h2): the
        # listener VERIFIES host+path — a client config without this block
        # speaks raw VLESS into an HTTP listener ("unknown version: 72")
        tr = {"type": "http"}
        if s.get("path"):
            tr["path"] = s["path"]
        if s.get("host"):
            tr["host"] = [h.strip() for h in str(s["host"]).split(",") if h.strip()]
        return tr
    if network == "httpupgrade":
        tr = {"type": "httpupgrade"}
        if s.get("path"):
            tr["path"] = s["path"]
        if s.get("host"):
            tr["host"] = s["host"]
        return tr
    return None


def _sb_outbound(name: str, ob: Any) -> dict[str, Any] | None:
    s = ob.settings
    proto = ob.protocol
    server, port = s.get("server"), s.get("server_port")
    if not server or not port:
        return None
    out: dict[str, Any] = {"tag": name, "server": server, "server_port": int(port)}

    if proto == "shadowsocks" or proto == "ss":
        out.update({"type": "shadowsocks", "method": s.get("method") or "aes-128-gcm",
                    "password": s.get("password") or ""})
    elif proto == "vmess":
        out.update({"type": "vmess", "uuid": str(s.get("uuid") or ""),
                    "security": s.get("cipher") or "auto"})
        if s.get("alter_id"):
            out["alter_id"] = int(s["alter_id"])
    elif proto == "vless":
        out.update({"type": "vless", "uuid": str(s.get("uuid") or "")})
        if s.get("flow"):
            out["flow"] = s["flow"]
    elif proto == "trojan":
        out.update({"type": "trojan", "password": s.get("password") or ""})
    elif proto == "hysteria2":
        out.update({"type": "hysteria2", "password": s.get("password") or ""})
    elif proto == "tuic":
        out.update({"type": "tuic", "uuid": str(s.get("uuid") or ""),
                    "password": s.get("password") or "",
                    "congestion_control": s.get("congestion_control") or "bbr"})
    elif proto == "anytls":
        out.update({"type": "anytls", "password": s.get("password") or ""})
    elif proto == "socks":
        out.update({"type": "socks", "version": "5"})
        if s.get("username"):
            out.update({"username": s["username"], "password": s.get("password") or ""})
    elif proto == "http":
        out["type"] = "http"
        if s.get("username"):
            out.update({"username": s["username"], "password": s.get("password") or ""})
    else:
        # naive has no sing-box OUTBOUND (client side lives in the naive
        # binary / Chromium network stack) — kept on the link list/portal
        return None

    tls = _sb_tls(s, always=proto in ("hysteria2", "tuic", "anytls"))
    if tls is not None and proto not in ("shadowsocks", "socks"):
        out["tls"] = tls
    transport = _sb_transport(s)
    if transport is not None:
        out["transport"] = transport
    return out


def to_sing_box(links: list[str], extra_notes: list[str] | None = None) -> tuple[str, list[str]]:
    """Complete sing-box 1.12+/1.13 config JSON; returns (json_text, notes).

    Renderer contract (verified with `sing-box check` against stock 1.12.4
    AND 1.13.16 on the consolidated protocol set): new-format DNS servers,
    the ``hijack-dns`` rule ACTION (the legacy ``dns``/``block`` special
    outbounds were removed upstream in 1.13 — emitting them produced an
    unbootable subscription config for every sing-box client).
    """
    parsed, notes = parse_named(links)
    notes = list(extra_notes or []) + notes

    outbounds: list[dict[str, Any]] = []
    tags: list[str] = []
    for name, ob in parsed:
        try:
            proxy = _sb_outbound(name, ob)
        except UnrepresentableLink as exc:
            notes.append(f"{name}: {exc} — kept on the link list/portal")
            continue
        if proxy is None:
            notes.append(f"{name}: protocol '{ob.protocol}' has no sing-box form — kept on the link list/portal")
            continue
        outbounds.append(proxy)
        tags.append(name)

    selector = {
        "type": "selector", "tag": "select",
        "outbounds": tags + ["direct"],
        **({"default": tags[0]} if tags else {}),
    }
    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "dns-local"}]},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in",
             "listen": "127.0.0.1", "listen_port": 2080},
        ],
        "outbounds": [
            selector,
            *outbounds,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [{"protocol": "dns", "action": "hijack-dns"}],
            "final": "select",
            "auto_detect_interface": True,
        },
    }
    return json.dumps(config, ensure_ascii=False, indent=2), notes
