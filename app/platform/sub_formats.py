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

_CLASH_META_TYPES = {"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic"}


def _clash_transport(settings: dict[str, Any], proxy: dict[str, Any]) -> None:
    network = settings.get("network") or "tcp"
    if network == "ws":
        proxy["network"] = "ws"
        ws: dict[str, Any] = {}
        if settings.get("path"):
            ws["path"] = settings["path"]
        host = settings.get("host")
        if host:
            ws["headers"] = {"Host": host}
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
        proxy = _clash_proxy(name, ob)
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
    if network == "ws":
        tr: dict[str, Any] = {"type": "ws"}
        if s.get("path"):
            tr["path"] = s["path"]
        if s.get("host"):
            tr["headers"] = {"Host": s["host"]}
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
    else:
        return None

    tls = _sb_tls(s, always=proto in ("hysteria2", "tuic"))
    if tls is not None and proto != "shadowsocks":
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
        proxy = _sb_outbound(name, ob)
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
