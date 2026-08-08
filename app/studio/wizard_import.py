"""Wizard «import from share link» (alpha.7.2, item 6).

Parses a client share link (vless/vmess/trojan/ss/hy2/tuic — the same
formats the portal emits) into a WIZARD-shaped spec the stepper can
prefill from: protocol × transport × security resolved against THIS
core's blueprint (never guessed — a cell the blueprint does not offer is
a named error listing the offered alternatives), and every parsed value
that maps onto a declared blueprint field prefills it. Values with no
declared field are honestly REPORTED (``unmapped``), not silently eaten.

The credentials baked into a client link (uuid / password) never become
listener settings — they belong to an ACCOUNT, not an inbound; they are
listed in ``unmapped`` so the operator understands what was dropped and
why.
"""
from __future__ import annotations

from typing import Any

from app.studio.wizard import blueprint_for
from app.utils.shareurl import ShareURLError, parse_share_url

#: share-link transport spellings → blueprint transport ids
_TRANSPORT_ALIASES = {
    "raw": "tcp",
    "splithttp": "xhttp",
    "kcp": "mkcp",
    "h2": "http",
    "udp": "quic",   # hysteria2/tuic links say udp; both blueprints call it quic
    "websocket": "ws",
    "gun": "grpc",
}

#: parsed settings key → blueprint field key, per topic
_FIELD_MAP = {
    "ws": {"path": "path", "host": "host"},
    "httpupgrade": {"path": "path", "host": "host"},
    "xhttp": {"path": "path", "host": "host", "mode": "mode"},
    "http": {"path": "path", "host": "host"},
    "grpc": {"serviceName": "service_name", "authority": "authority"},
    "mkcp": {},
    "quic": {},
    "tcp": {},
}

_SECURITY_MAP = {
    "none": "none", "tls": "tls", "reality": "reality",
    "auto": "none", "": "none",
}


class WizardImportError(ValueError):
    """The link cannot be mapped onto this core's wizard blueprint."""


def _resolve_cell(blueprint: dict[str, Any], protocol: str, transport: str,
                  security: str) -> tuple[dict, dict, dict]:
    """Locate the exact (protocol, transport, security) cell. No guessing:
    a miss raises with the offered alternatives spelled out."""
    proto = next((p for p in blueprint["protocols"] if p["id"] == protocol), None)
    if proto is None:
        offered = ", ".join(p["id"] for p in blueprint["protocols"])
        raise WizardImportError(
            f"protocol '{protocol}' is not offered by the "
            f"{blueprint['core_id']} wizard — offered: {offered}.")
    tr = next((t for t in proto["transports"] if t["id"] == transport), None)
    if tr is None:
        offered = ", ".join(t["id"] for t in proto["transports"])
        raise WizardImportError(
            f"{protocol} over '{transport}' is not offered by the "
            f"{blueprint['core_id']} wizard — offered transports: {offered}.")
    sec = next((s for s in tr["securities"] if s["id"] == security), None)
    if sec is None:
        offered = ", ".join(s["id"] for s in tr["securities"])
        raise WizardImportError(
            f"{protocol} over {transport} with security '{security}' is not "
            f"offered by the {blueprint['core_id']} wizard — offered: {offered}.")
    return proto, tr, sec


def import_link_spec(core_id: str, link: str) -> dict[str, Any]:
    """Share link → wizard prefill spec for `core_id`'s blueprint.

    Returns::

        {"tag": ..., "protocol": ..., "listen": None, "port": ...,
         "transport": ..., "security": ...,
         "settings": {<blueprint field key>: <value>},
         "unmapped": [{"key": ..., "value": ..., "reason": ...}],
         "source_name": <link remark, if any>}

    Raises WizardImportError (also on ShareURLError — normalized) with an
    operator-readable message; nothing is guessed.
    """
    try:
        parsed = parse_share_url(link)
    except ShareURLError as exc:
        raise WizardImportError(str(exc)) from exc

    blueprint = blueprint_for(core_id)  # KeyError → caller maps to 404
    settings = dict(parsed.settings)

    transport = _TRANSPORT_ALIASES.get(parsed.transport, parsed.transport)
    security = _SECURITY_MAP.get(str(parsed.security).lower())
    if security is None:
        raise WizardImportError(
            f"link security '{parsed.security}' cannot be mapped — the wizard "
            "knows none/tls/reality.")
    if parsed.protocol in ("hysteria2", "tuic") and security == "none":
        # these QUIC protocols are inherently TLS-only (a client link simply
        # omits the param — the parser's setdefault("security","tls") never
        # fires there), and both blueprints offer ONLY the tls cell
        security = "tls"
    _proto, tr, sec = _resolve_cell(blueprint, parsed.protocol, transport, security)

    declared = {f["key"]: f for f in sec["fields"]}
    mapped: dict[str, Any] = {}
    unmapped: list[dict[str, str]] = []

    port = settings.pop("server_port", None)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise WizardImportError(f"link port {port!r} is not a usable TCP/UDP port.")
    settings.pop("server", None)  # a CLIENT server address is not a listener fact
    for consumed in ("network", "security"):  # they selected the cell itself
        consumed_value = settings.pop(consumed, None)
        if consumed_value not in (None, ""):
            unmapped.append({"key": consumed, "value": str(consumed_value),
                             "reason": "selected the transport/security cell"})

    # transport-scoped keys (path/host/serviceName/…) via the topic map
    for src, dst in _FIELD_MAP.get(tr["id"], {}).items():
        value = settings.pop(src, None)
        if value in (None, ""):
            continue
        if dst in declared:
            mapped[dst] = value
        else:
            unmapped.append({"key": src, "value": str(value),
                             "reason": f"no '{dst}' field on this cell"})

    # security-scoped keys
    for src, dst in (("sni", "sni"), ("fingerprint", "fingerprint"),
                     ("reality_public_key", "public_key"), ("flow", "flow")):
        value = settings.pop(src, None)
        if value in (None, ""):
            continue
        if dst in declared:
            mapped[dst] = value
        else:
            unmapped.append({"key": src, "value": str(value),
                             "reason": f"no '{dst}' field on this cell"})
    alpn = settings.pop("alpn", None)
    if alpn:
        values = [a.strip() for a in str(alpn).split(",") if a.strip()]
        if "alpn" in declared:
            mapped["alpn"] = values
        else:
            unmapped.append({"key": "alpn", "value": str(alpn),
                             "reason": "no 'alpn' field on this cell"})

    # protocol-scoped keys
    for src, dst in (("method", "method"), ("obfs_password", "obfs"),
                     ("congestion_control", "congestion_control")):
        value = settings.pop(src, None)
        if value in (None, ""):
            continue
        if dst in declared:
            mapped[dst] = value
        else:
            unmapped.append({"key": src, "value": str(value),
                             "reason": f"no '{dst}' field on this cell"})

    # credentials belong to accounts (creating users), never to a listener
    for cred in ("uuid", "password", "reality_short_id", "reality_spider_x",
                 "port_hopping", "obfs", "disable_sni", "allow_insecure",
                 "plugin", "plugin_opts"):
        value = settings.pop(cred, None)
        if value in (None, ""):
            continue
        unmapped.append({"key": cred, "value": str(value),
                         "reason": "a client credential/flag, not a listener "
                                   "setting"})
    for key, value in settings.items():  # anything left: report honestly
        unmapped.append({"key": key, "value": str(value),
                         "reason": "not a wizard field"})

    name = parsed.name_hint.strip()
    return {
        "tag": name or f"{parsed.protocol}-{port}",
        "protocol": parsed.protocol,
        "listen": None,
        "port": port,
        "transport": tr["id"],
        "security": sec["id"],
        "settings": mapped,
        "unmapped": unmapped,
        "source_name": name,
    }
