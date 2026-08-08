"""Cross-core Host Settings engine (alpha.7.2, item 13).

Marzban's Host Settings let an admin define, per inbound, a LIST of host
variants (remark / address / port / sni / host header / path / security /
ALPN / fingerprint / fragment / noise / mux / allow-insecure …) and the
subscription then emits one config per (inbound × host) in priority order.
Until now that power existed only for the built-in xray core — through the
legacy ``hosts`` table and the legacy share generator, kept byte-parity by
the xray driver.

This module generalizes the same semantics to EVERY other core, honestly
and independently (not a copy of Marzban's generator):

* entries live in the P3 ``core_hosts`` table, keyed by
  ``(core_id, inbound_tag)`` — never shadowing the legacy xray path;
* expansion happens at the delivery layer: each driver's
  ``DeliveryProfile`` sections are expanded per matching host entry,
  matched by ``DeliverySection.inbound_tag``;
* LINK artifacts are *parsed* (``app.utils.shareurl.parse_share_url``),
  overridden field-by-field, and *re-emitted* per scheme — never
  string-patched — so the result stays a valid, re-parseable share link
  that flows unchanged into the clash / sing-box / share-list renderers;
* FILE artifacts (``.ovpn`` ``remote`` lines, WireGuard ``Endpoint =``)
  are cloned per entry when the entry actually changes address/port;
* FIELDS artifacts (credential tables) are cloned with host/port
  overrides under the same rule;
* nothing is silently dropped: fields an entry cannot express for the
  scheme at hand (e.g. an HTTP host header on a UDP protocol) are
  collected into a single honest NOTE artifact on the section.

Template semantics mirror the xray-parity path: comma lists pick one
random member per render (MultipleHost / MultipleSNI), ``*`` salts to
random hex (Wildcard), and ``{USERNAME}/{DATA_USAGE}/{DAYS_LEFT}/…``
resolve per subscriber through the same ``setup_format_variables`` the
legacy generator uses; ``{SERVER_IP}`` resolves to the artifact's own
server address (the only honest meaning available outside the xray core).
"""
from __future__ import annotations

import base64
import json
import logging
import random
import re
import secrets
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import quote

from app.cores.delivery import (
    ArtifactKind,
    DeliveryArtifact,
    DeliveryField,
    DeliveryProfile,
    DeliverySection,
)
from app.portal.models import PortalUserView
from app.utils.shareurl import ParsedShareURL
from app.utils.shareurl import parse_share_url as _parse

logger = logging.getLogger(__name__)

# security override values that mean "leave the inbound's own TLS alone"
_KEEP_SECURITY = {None, "", "inbound_default"}
_TLS_CAPABLE = {"vless", "trojan", "vmess", "hysteria2", "tuic"}
_REALITY_CAPABLE = {"vless"}
_PATH_TRANSPORTS = {"ws", "http", "httpupgrade", "splithttp"}
_HOST_TRANSPORTS = {"ws", "httpupgrade"}
# URI-level client hints (v2rayN/sing-box share-link conventions)
_XMUX_CAPABLE = {"vless", "trojan"}
_FRAGMENT_CAPABLE = {"vless", "trojan"}
_FIELDS_HOST_KEYS = {"host", "server", "address", "endpoint", "remote"}
_FIELDS_PORT_KEYS = {"port", "server_port"}


@dataclass(slots=True)
class HostEntry:
    """One admin-defined host variant (a ``core_hosts`` row, normalized).

    The full Marzban-parity field set (alpha.7.2 item 13).  Priority is the
    entry's position inside its (core_id, inbound_tag) list — the store
    persists it in the ``sort`` column and hands entries back in order.
    ``extras`` preserves *unrecognized* legacy attributes verbatim
    (round-trip through the admin API without loss).
    """

    remark: str = ""
    address: str = ""
    port: int | None = None
    sni: str | None = None
    host: str | None = None
    path: str | None = None
    security: str | None = None
    alpn: str | None = None
    fingerprint: str | None = None
    allowinsecure: bool | None = None
    is_disabled: bool = False
    mux_enable: bool = False
    fragment_setting: str | None = None
    noise_setting: str | None = None
    random_user_agent: bool = False
    use_sni_as_host: bool = False
    extras: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------- #
# template variables — parity with the xray path
# --------------------------------------------------------------------- #

def delivery_variables(user: PortalUserView) -> dict[str, Any]:
    """The legacy variable set for THIS subscriber (Marzban parity).

    Resolved through the same ``setup_format_variables`` the legacy share
    generator uses; when the legacy stack is unavailable (bare unit
    tests) degrade to the minimal honest set — never raise into delivery.
    """
    extra: dict[str, Any] = {
        "username": user.username,
        "status": user.status,
        "used_traffic": user.used_bytes or 0,
        "data_limit": user.data_limit_bytes,
        "expire": int(user.expire_at.timestamp()) if user.expire_at else None,
        "on_hold_expire_duration": None,
    }
    try:
        from app.subscription.share import setup_format_variables

        return setup_format_variables(extra)
    except Exception:  # noqa: BLE001 — legacy stack stubbed/unavailable
        return defaultdict(lambda: "<missing>", {"USERNAME": user.username})


def render_host_value(value: str | None, variables: Mapping[str, Any]) -> str | None:
    """comma random-pick → ``*`` salt → ``{VARS}`` — xray-parity order
    (MultipleHost/MultipleSNI only make sense on address/sni/host)."""
    if not value:
        return value
    parts = [p.strip() for p in str(value).split(",") if p.strip()]
    if len(parts) > 1:
        value = random.choice(parts)
    return render_host_single(value, variables)


def render_host_single(value: str | None, variables: Mapping[str, Any]) -> str | None:
    """``*`` salt → ``{VARS}`` — no comma split: for fields whose value
    legitimately CONTAINS commas (alpn preference lists, fragment/noise
    specs) or must stay literal (path, fingerprint)."""
    if not value:
        return value
    if "*" in value:
        value = value.replace("*", secrets.token_hex(8))
    try:
        return value.format_map(defaultdict(lambda: "<missing>", variables))
    except Exception:  # noqa: BLE001 — a broken template must not break the sub
        return value


def render_host_remark(value: str | None, variables: Mapping[str, Any]) -> str | None:
    """remark/labels: ``{VARS}`` only — a comma in a remark is text, never a
    multi-pick, and salting would rename the admin's label every render."""
    if not value:
        return value
    try:
        return value.format_map(defaultdict(lambda: "<missing>", variables))
    except Exception:  # noqa: BLE001
        return value


# --------------------------------------------------------------------- #
# link parsing & re-emission (parse → override → emit, never patched text)
# --------------------------------------------------------------------- #

def _q(params: dict[str, Any]) -> str:
    from app.cores.delivery import _query  # canonical encoder — one source

    return _query(params)


def _emit(parsed: ParsedShareURL, remark: str) -> str:
    """Re-emit a parsed share link after overrides, per scheme."""
    s = parsed.settings
    server, port = s.get("server"), s.get("server_port")
    tag = quote(remark, safe="")
    proto = parsed.protocol

    if proto == "vless":
        params: dict[str, Any] = {"type": s.get("network", "tcp"),
                                  "encryption": s.get("encryption", "none")}
        security = s.get("security", "none")
        params["security"] = security
        if security in ("tls", "reality"):
            params["sni"] = s.get("sni")
            params["alpn"] = s.get("alpn")
            params["fp"] = s.get("fingerprint")
        if security == "reality":
            params["pbk"] = s.get("reality_public_key")
            params["sid"] = s.get("reality_short_id")
            params["spx"] = s.get("reality_spider_x")
        if s.get("flow"):
            params["flow"] = s["flow"]
        _emit_transport_params(s, params)
        if s.get("allow_insecure") and security in ("tls", "reality"):
            params["allowInsecure"] = "1"
        _emit_client_hint_params(s, params, proto)
        return f"vless://{s['uuid']}@{server}:{port}?{_q(params)}#{tag}"

    if proto == "trojan":
        params = {"type": s.get("network", "tcp"), "security": s.get("security", "tls")}
        if params["security"] in ("tls", "reality"):
            params["sni"] = s.get("sni")
            params["alpn"] = s.get("alpn")
            params["fp"] = s.get("fingerprint")
        if params["security"] == "reality":
            params["pbk"] = s.get("reality_public_key")
            params["sid"] = s.get("reality_short_id")
            params["spx"] = s.get("reality_spider_x")
        if s.get("flow"):
            params["flow"] = s["flow"]
        _emit_transport_params(s, params)
        if s.get("allow_insecure"):
            params["allowInsecure"] = "1"
        _emit_client_hint_params(s, params, proto)
        return f"trojan://{quote(str(s['password']), safe='')}@{server}:{port}?{_q(params)}#{tag}"

    if proto == "vmess":
        payload: dict[str, Any] = {
            "v": "2", "ps": remark, "add": server, "port": str(port),
            "id": s.get("uuid", ""), "aid": str(s.get("alter_id", 0)),
            "scy": s.get("cipher", "auto"), "net": s.get("network", "tcp"),
            "type": s.get("headerType", "none") or "none",
            "host": s.get("host", ""), "path": s.get("path", ""),
            "tls": "tls" if s.get("security") == "tls" else "",
            "sni": s.get("sni", ""), "alpn": s.get("alpn", ""),
            "fp": s.get("fingerprint", ""),
        }
        if s.get("network") == "grpc":
            payload["path"] = s.get("serviceName", "")
        if s.get("seed"):
            payload["seed"] = s["seed"]
        if s.get("fragment"):
            payload["fragment"] = s["fragment"]
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        return f"vmess://{encoded}"

    if proto in ("shadowsocks", "ss"):
        cred = base64.urlsafe_b64encode(
            f"{s['method']}:{s['password']}".encode()).decode().rstrip("=")
        params = {}
        if s.get("plugin"):
            params["plugin"] = s["plugin"]
            if s.get("plugin_opts"):
                params["plugin-opts"] = s["plugin_opts"]
        qs = f"?{_q(params)}" if params else ""
        return f"ss://{cred}@{server}:{port}{qs}#{tag}"

    if proto in ("hysteria2", "hy2"):
        params = {}
        if s.get("sni"):
            params["sni"] = s["sni"]
        if s.get("obfs"):
            params["obfs"] = s["obfs"]
            if s.get("obfs_password"):
                params["obfs-password"] = s["obfs_password"]
        if s.get("port_hopping"):
            params["mport"] = s["port_hopping"]
        if s.get("alpn"):
            params["alpn"] = s["alpn"]
        if s.get("fingerprint"):
            params["fp"] = s["fingerprint"]
        if s.get("allow_insecure"):
            params["insecure"] = "1"
        return f"hy2://{quote(str(s['password']), safe='')}@{server}:{port}?{_q(params)}#{tag}"

    if proto == "tuic":
        params = {}
        for key in ("congestion_control", "udp_relay_mode", "alpn", "sni"):
            if s.get(key):
                params[key] = s[key]
        if s.get("allow_insecure"):
            params["allow_insecure"] = "1"
        auth = quote(str(s["uuid"]), safe="")
        if s.get("password"):
            auth += f":{quote(str(s['password']), safe='')}"
        return f"tuic://{auth}@{server}:{port}?{_q(params)}#{tag}"

    raise ValueError(f"no emitter for protocol '{proto}'")


def _emit_transport_params(s: dict[str, Any], params: dict[str, Any]) -> None:
    net = s.get("network", "tcp")
    if net in _PATH_TRANSPORTS and s.get("path") is not None:
        params["path"] = s.get("path")
    if net in _HOST_TRANSPORTS and s.get("host"):
        params["host"] = s["host"]
    if net == "grpc" and s.get("serviceName"):
        params["serviceName"] = s["serviceName"]
    if net == "tcp" and s.get("headerType") not in (None, "none"):
        params["headerType"] = s["headerType"]


def _emit_client_hint_params(s: dict[str, Any], params: dict[str, Any], proto: str) -> None:
    """v2rayN/sing-box share-link client hints (alpha.7.2 item 13)."""
    if proto in _FRAGMENT_CAPABLE:
        if s.get("fragment"):
            params["fragment"] = s["fragment"]
        if s.get("noise"):
            params["noise"] = s["noise"]
    if proto in _XMUX_CAPABLE and s.get("xmux"):
        params["xmux"] = s["xmux"]


# --------------------------------------------------------------------- #
# the engine
# --------------------------------------------------------------------- #

class HostSettingsEngine:
    """Expand delivery profiles by admin-defined host entries.

    Priority (item 13): entries are applied strictly in the order the
    entries list carries them — the store persists list order in the
    ``sort`` column — and emitted artifacts follow the same order.
    """

    def expand(
        self,
        profile: DeliveryProfile,
        entries_by_tag: Mapping[str, list[HostEntry]],
        variables: Mapping[str, Any],
    ) -> DeliveryProfile:
        """Return a NEW profile with sections expanded per host entry.

        Profiles whose sections carry no applicable entry pass through
        unchanged (zero-cost default — a core with no host entries behaves
        exactly as before).
        """
        if not entries_by_tag or not profile.sections:
            return profile

        # single-inbound cores (wireguard/ssh/softether…) render ONE
        # tagless section through the generic presenter; when the admin
        # defined entries under exactly one tag, they unambiguously mean
        # that section.
        default_tag: str | None = None
        if len(entries_by_tag) == 1:
            default_tag = next(iter(entries_by_tag))

        out_sections: list[DeliverySection] = []
        changed = False
        for section in profile.sections:
            tag = section.inbound_tag
            if tag is None and section.inbound_tag is None and default_tag is not None:
                if any(a.kind is not ArtifactKind.NOTE for a in section.artifacts):
                    tag = default_tag
            entries = [e for e in entries_by_tag.get(tag, []) if not e.is_disabled] \
                if tag and tag in entries_by_tag else []
            if not entries:
                out_sections.append(section)
                continue
            changed = True
            out_sections.append(self._expand_section(section, entries, variables))
        if not changed:
            # zero host entries matched — the original profile instance
            # passes through object-identical (nothing to re-validate)
            return profile
        return DeliveryProfile(core_id=profile.core_id,
                               sections=out_sections, note=profile.note)

    # ------------------------------------------------------------------ #
    def _expand_section(
        self,
        section: DeliverySection,
        entries: list[HostEntry],
        variables: Mapping[str, Any],
    ) -> DeliverySection:
        artifacts: list[DeliveryArtifact] = []
        inapplicable: list[str] = []
        for artifact in section.artifacts:
            if artifact.kind is ArtifactKind.LINK:
                artifacts.extend(self._expand_link(artifact, entries, variables,
                                                   inapplicable,
                                                   section_proto=section.protocol))
            elif artifact.kind is ArtifactKind.FILE:
                artifacts.extend(self._expand_file(artifact, entries, variables))
            elif artifact.kind is ArtifactKind.FIELDS:
                artifacts.extend(self._expand_fields(artifact, entries, variables))
            else:
                artifacts.append(artifact)
        if inapplicable:
            unique = sorted(set(inapplicable))
            artifacts.append(DeliveryArtifact(
                kind=ArtifactKind.NOTE, label="Host override notice",
                note="; ".join(unique),
            ))
        return section.model_copy(update={"artifacts": artifacts})

    # ------------------------------------------------------------------ #
    def _expand_link(
        self,
        artifact: DeliveryArtifact,
        entries: list[HostEntry],
        variables: Mapping[str, Any],
        inapplicable: list[str],
        *,
        section_proto: str | None = None,
    ) -> list[DeliveryArtifact]:
        try:
            parsed = _parse(artifact.content)
        except Exception as exc:  # noqa: BLE001 — honest: not expandable, keep as-is
            inapplicable.append(
                f"link '{artifact.label}' could not be parsed for host overrides "
                f"({exc}); original kept")
            return [artifact]

        out: list[DeliveryArtifact] = []
        proto = parsed.protocol
        for entry in entries:
            local = defaultdict(lambda: "<missing>", variables)
            local["SERVER_IP"] = parsed.settings.get("server", "")
            # per-link parity variables — the legacy generator refreshes
            # exactly these two inside its (protocol, inbound) loop
            local.setdefault("PROTOCOL", section_proto or proto)
            local["TRANSPORT"] = parsed.settings.get("network", "tcp")
            new = {**parsed.settings}
            name = entry.remark or entry.address or "host"

            def _r(value: str | None) -> str | None:
                return render_host_value(value, local)

            def _s(value: str | None) -> str | None:
                return render_host_single(value, local)

            if entry.address:
                new["server"] = _r(entry.address)
            if entry.port is not None:
                new["server_port"] = entry.port

            security = (entry.security or "").strip() or None
            if security not in _KEEP_SECURITY:
                security = security.lower()
                if security == "none":
                    if proto == "hysteria2":
                        inapplicable.append(
                            f"entry '{name}': security=none is not possible on "
                            "Hysteria2 (TLS is protocol-defined)")
                    else:
                        new["security"] = "none"
                        for k in ("sni", "alpn", "fingerprint",
                                  "reality_public_key", "reality_short_id",
                                  "fragment", "noise"):
                            new.pop(k, None)
                elif security == "tls":
                    if proto in _TLS_CAPABLE:
                        new["security"] = "tls"
                    else:
                        inapplicable.append(
                            f"entry '{name}': TLS is not applicable to {proto}")
                elif security == "reality":
                    if proto in _REALITY_CAPABLE:
                        new["security"] = "reality"
                    else:
                        inapplicable.append(
                            f"entry '{name}': REALITY is Xray-VLESS only, not {proto}")

            eff_security = new.get("security", "none")
            # TLS *effective* state: hysteria2/tuic are TLS-by-design — the
            # link's `security` param records the raw query state (usually
            # "none"), NOT the protocol's TLS truth
            tls_effective = (
                proto in ("hysteria2", "tuic")
                or eff_security in ("tls", "reality")
            )
            if entry.sni:
                if proto in _TLS_CAPABLE and tls_effective:
                    new["sni"] = _r(entry.sni)
                else:
                    inapplicable.append(
                        f"entry '{name}': SNI has no meaning for {proto}/{eff_security}")
            if entry.alpn:
                if proto in _TLS_CAPABLE and tls_effective:
                    new["alpn"] = _s(entry.alpn)
                else:
                    inapplicable.append(
                        f"entry '{name}': ALPN requires TLS")
            if entry.fingerprint:
                if proto in _TLS_CAPABLE and tls_effective:
                    new["fingerprint"] = _s(entry.fingerprint)
                else:
                    inapplicable.append(
                        f"entry '{name}': fingerprint requires TLS")
            if entry.host:
                if new.get("network") in _HOST_TRANSPORTS:
                    new["host"] = _r(entry.host)
                else:
                    inapplicable.append(
                        f"entry '{name}': an HTTP host header does not apply "
                        f"to {proto}/{new.get('network', 'tcp')}")
            elif entry.use_sni_as_host and new.get("sni"):
                # Marzban parity: reuse the effective SNI as the ws host —
                # even when the entry leaves `host` unset.
                if new.get("network") in _HOST_TRANSPORTS:
                    new["host"] = new["sni"]
            if entry.path:
                if new.get("network") in _PATH_TRANSPORTS:
                    new["path"] = _r(entry.path)
                else:
                    inapplicable.append(
                        f"entry '{name}': a path does not apply to "
                        f"{proto}/{new.get('network', 'tcp')}")
            if entry.allowinsecure is not None:
                if proto in ("vless", "trojan", "hysteria2", "tuic"):
                    new["allow_insecure"] = bool(entry.allowinsecure)
                else:
                    inapplicable.append(
                        f"entry '{name}': allowInsecure is not expressible on "
                        f"{proto} links")
            # ---- client-side extras (fragment / noise / mux / rua) ----
            tls_effective = new.get("security", "none") in ("tls", "reality")
            if entry.fragment_setting:
                if proto in _FRAGMENT_CAPABLE and tls_effective:
                    new["fragment"] = _s(entry.fragment_setting)
                else:
                    inapplicable.append(
                        f"entry '{name}': fragment needs TLS on vless/trojan")
            if entry.noise_setting:
                if proto in _FRAGMENT_CAPABLE and tls_effective:
                    new["noise"] = _s(entry.noise_setting)
                else:
                    inapplicable.append(
                        f"entry '{name}': noise needs TLS on vless/trojan")
            if entry.mux_enable:
                if proto in _XMUX_CAPABLE:
                    new["xmux"] = '{"enabled":true,"concurrency":8}'
                else:
                    inapplicable.append(
                        f"entry '{name}': mux is not expressible on {proto} links")
            if entry.random_user_agent:
                # share links have no user-agent knob anywhere — report,
                # don't fabricate a param no client parses.
                inapplicable.append(
                    f"entry '{name}': random user-agent applies to JSON "
                    "clients only; share links cannot express it")

            remark = render_host_remark(entry.remark, local) or artifact.label
            overridden = parsed.model_copy(update={"settings": new})
            try:
                link = _emit(overridden, remark)
            except Exception as exc:  # noqa: BLE001 — never fabricate a broken link
                inapplicable.append(
                    f"entry '{remark}': re-emitting the link failed ({exc})")
                continue
            out.append(DeliveryArtifact(kind=ArtifactKind.LINK, label=remark,
                                        content=link, qr=artifact.qr))
        return out

    # ------------------------------------------------------------------ #
    _OVPN_REMOTE = re.compile(r"(?m)^(\s*remote\s+)(\S+)([ \t]+\d+)?(.*)$")
    _WG_ENDPOINT = re.compile(r"(?m)^(\s*Endpoint\s*=\s*)(\S+?)(?::(\d+))?\s*$")

    def _expand_file(
        self,
        artifact: DeliveryArtifact,
        entries: list[HostEntry],
        variables: Mapping[str, Any],
    ) -> list[DeliveryArtifact]:
        out: list[DeliveryArtifact] = []
        for entry in entries:
            host = render_host_value(entry.address, variables) if entry.address else None
            if host is None and entry.port is None:
                continue  # nothing a file could take from this entry
            content = artifact.content
            if self._OVPN_REMOTE.search(content):
                def _ovpn(m: re.Match) -> str:
                    use_host = host or m.group(2)
                    port = m.group(3)
                    if entry.port is not None:
                        port = f" {entry.port}"
                    return f"{m.group(1)}{use_host}{port or ''}{m.group(4)}"
                content = self._OVPN_REMOTE.sub(_ovpn, content)
            elif self._WG_ENDPOINT.search(content):
                def _wg(m: re.Match) -> str:
                    use_host = host or m.group(2)
                    port = m.group(3)
                    if entry.port is not None:
                        port = str(entry.port)
                    return f"{m.group(1)}{use_host}:{port}" if port else \
                        f"{m.group(1)}{use_host}"
                content = self._WG_ENDPOINT.sub(_wg, content)
            else:
                continue  # unknown file shape — never patch blindly
            label = render_host_remark(entry.remark, variables) or artifact.label
            stem = artifact.filename or "config"
            stem = re.sub(r"[^A-Za-z0-9._-]+", "-", label) + \
                ("" if "." not in stem else "." + stem.rsplit(".", 1)[1])
            out.append(DeliveryArtifact(
                kind=ArtifactKind.FILE, label=label, content=content,
                filename=stem, mime=artifact.mime,
            ))
        return out

    # ------------------------------------------------------------------ #
    def _expand_fields(
        self,
        artifact: DeliveryArtifact,
        entries: list[HostEntry],
        variables: Mapping[str, Any],
    ) -> list[DeliveryArtifact]:
        out: list[DeliveryArtifact] = []
        for entry in entries:
            host = render_host_value(entry.address, variables) if entry.address else None
            if host is None and entry.port is None:
                continue
            fields: list[DeliveryField] = []
            for f in artifact.fields:
                if host is not None and f.key.lower() in _FIELDS_HOST_KEYS:
                    fields.append(f.model_copy(update={"value": host}))
                elif entry.port is not None and f.key.lower() in _FIELDS_PORT_KEYS:
                    fields.append(f.model_copy(update={"value": str(entry.port)}))
                else:
                    fields.append(f)
            label = render_host_remark(entry.remark, variables) or artifact.label
            out.append(DeliveryArtifact(kind=ArtifactKind.FIELDS, label=label,
                                        fields=fields, note=artifact.note))
        return out
