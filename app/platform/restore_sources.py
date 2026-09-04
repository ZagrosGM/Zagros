"""Read a foreign panel's database into a Zagros migration snapshot.

Restore supports four sources:

``zagros``
    Our own archive — restored as-is, no mapping needed.
``marzban`` / ``pasarguard``
    SQLAlchemy panels whose schema Zagros already understands
    (users / proxies / hosts / admins / nodes). Pasarguard is a fork of that
    schema, so the same reader serves both, table by table, tolerating
    columns that only one of them has.
``3x-ui``
    A Go panel with a completely different shape: clients live inside the
    ``inbounds.settings`` JSON (or in a ``clients`` table on newer builds),
    traffic in ``client_traffics``, and panel logins in ``users``.

Everything is normalised into :class:`~app.persistence.legacy_reader.LegacySnapshot`
so one honest code path — ``build_migration_plan`` + ``LegacyImportService`` —
does the actual import for all three.
"""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
import string
from pathlib import Path
from typing import Any, Iterable

from app.persistence.legacy_reader import LegacySnapshot
from app.platform.restore_errors import (  # noqa: F401  (re-exported)
    RestoreError,
    RestoreSourceError,
)

SOURCES: tuple[str, ...] = ("zagros", "marzban", "pasarguard", "3x-ui")
FOREIGN_SOURCES: tuple[str, ...] = ("marzban", "pasarguard", "3x-ui")

# Zagros usernames: 3–32 chars of [a-z0-9_]
_USERNAME_OK = re.compile(r"[^a-z0-9_]+")
_USERNAME_MIN = 3
_USERNAME_MAX = 32

_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".sqlitedb")
_DUMP_SUFFIXES = (".sql",)
_DUMP_NAMES = {"db_backup.sql", "backup.sql", "marzban.sql"}
# Names that betray a 3x-ui archive rather than a Marzban-shaped one.
_3XUI_TABLES = {"inbounds", "client_traffics"}
_MARZBAN_TABLES = {"users", "admins", "proxies"}


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def _table_names(db_path: Path) -> set[str]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=15)
    try:
        return {row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()


def identify_database(db_path: Path) -> dict[str, Any]:
    """Guess which panel a SQLite file belongs to, with the evidence."""
    try:
        tables = _table_names(db_path)
    except sqlite3.Error as exc:
        return {"source": None, "confidence": 0.0, "evidence": [f"unreadable: {exc}"]}
    has_3xui = len(_3XUI_TABLES & tables)
    has_marzban = len(_MARZBAN_TABLES & tables)
    if has_3xui and "client_traffics" in tables:
        return {"source": "3x-ui", "confidence": 1.0 if has_3xui == 2 else 0.7,
                "evidence": sorted(_3XUI_TABLES & tables)}
    if has_marzban:
        return {"source": "marzban", "confidence": 0.6 + 0.2 * has_marzban,
                "evidence": sorted(_MARZBAN_TABLES & tables)}
    return {"source": None, "confidence": 0.0, "evidence": sorted(tables)[:10]}


def find_databases(root: Path) -> list[Path]:
    """Every SQLite-looking file inside an extracted archive."""
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in _DB_SUFFIXES or path.name in {"x-ui.db", "db.sqlite3"}:
            found.append(path)
    return found


def find_dumps(root: Path) -> list[Path]:
    """SQL dumps inside an extracted archive (Marzban's backup format)."""
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in _DUMP_SUFFIXES or path.name.lower() in _DUMP_NAMES:
            found.append(path)
    return found


def pick_database(root: Path, source: str) -> Path:
    """Choose the database for *source*, preferring an exact-name match."""
    candidates = find_databases(root)
    if not candidates:
        raise RestoreSourceError(
            f"no SQLite database found in the archive (looked under {root})")
    preferred = {"3x-ui": ("x-ui.db",), "marzban": ("db.sqlite3", "marzban.db"),
                 "pasarguard": ("db.sqlite3", "pasarguard.db")}.get(source, ())
    for name in preferred:
        for candidate in candidates:
            if candidate.name == name:
                return candidate
    # fall back to the largest file — the panel DB is never the smallest one
    return max(candidates, key=lambda p: p.stat().st_size)


# --------------------------------------------------------------------------- #
# username normalisation
# --------------------------------------------------------------------------- #
def sanitize_username(raw: str, taken: set[str]) -> tuple[str, str | None]:
    """Map an arbitrary identifier onto a legal, unique Zagros username.

    Returns ``(username, note)`` where *note* records the original value when it
    had to be changed — silence here would lose the user's identity.
    """
    base = _USERNAME_OK.sub("_", (raw or "").strip().lower()).strip("_")
    if len(base) < _USERNAME_MIN:
        base = (base + "user")[:_USERNAME_MIN]
    candidate = base[:_USERNAME_MAX]
    if candidate not in taken:
        taken.add(candidate)
        return candidate, (None if candidate == raw else f"imported from '{raw}'")
    index = 2
    while f"{candidate[:_USERNAME_MAX - 3]}_{index}" in taken:
        index += 1
    suffixed = f"{candidate[:_USERNAME_MAX - 3]}_{index}"
    taken.add(suffixed)
    return suffixed, f"imported from '{raw}' (renamed: name taken)"


def _generated_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# --------------------------------------------------------------------------- #
# 3x-ui
# --------------------------------------------------------------------------- #
def _rows(con: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    try:
        cur = con.execute(f"SELECT * FROM {table}")  # noqa: S608 - fixed table names
    except sqlite3.Error:
        return []
    columns = [d[0] for d in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def _json_field(value: Any, default: Any) -> Any:
    if not value:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _clients_from_settings(inbounds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Older 3x-ui builds keep clients inside ``inbounds.settings`` JSON."""
    clients: list[dict[str, Any]] = []
    for inbound in inbounds:
        settings = _json_field(inbound.get("settings"), {}) or {}
        for client in (settings.get("clients") or []):
            if not isinstance(client, dict):
                continue
            merged = dict(client)
            merged["_inbound_id"] = inbound.get("id")
            merged["_protocol"] = inbound.get("protocol")
            merged["_remark"] = inbound.get("remark") or inbound.get("tag")
            clients.append(merged)
    return clients


def _client_inbound_index(con: sqlite3.Connection) -> dict[Any, list[dict[str, Any]]]:
    """client id -> the inbounds it belongs to.

    Newer 3x-ui builds moved the link into ``client_inbounds``; older ones kept
    the clients inside ``inbounds.settings``. Both are handled, because an
    export that silently loses its protocol produces users with no proxy —
    which is exactly what "the users did not import" looked like.
    """
    tables = {row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    index: dict[Any, list[dict[str, Any]]] = {}
    if "client_inbounds" in tables:
        inbounds = {row.get("id"): row for row in _rows(con, "inbounds")}
        for link in _rows(con, "client_inbounds"):
            inbound = inbounds.get(link.get("inbound_id"))
            if inbound is None:
                continue
            entry = dict(inbound)
            override = (link.get("flow_override") or "").strip()
            if override:
                entry["_flow_override"] = override
            index.setdefault(link.get("client_id"), []).append(entry)
    return index


def _xui_inbound_tag(inbound: dict[str, Any]) -> str:
    """The xray tag an imported 3x-ui inbound gets on this panel.

    3x-ui's own tags are machine names (``inbound-3000``, ``in-3000-tcp``);
    the remark is what the operator recognises — but remarks carry flags,
    spaces and Persian text, and the tag is a JSON identity that must stay
    stable and shell/URL safe. Keep 3x-ui's tag when it has one; otherwise
    derive one from the port.
    """
    tag = str(inbound.get("tag") or "").strip()
    if tag:
        return tag
    return f"xui-{inbound.get('protocol') or 'in'}-{inbound.get('port') or inbound.get('id')}"


# xray wizard protocols the importer can materialize (mirrors the xray
# driver's studio set minus dokodemo-door which carries no clients)
_XUI_IMPORTABLE_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}


def _xui_inbound_spec(inbound: dict[str, Any]) -> dict[str, Any] | None:
    """One 3x-ui ``inbounds`` row → a wizard-shaped inbound spec.

    Returns ``None`` for rows that cannot become a per-user xray inbound on
    this panel (wireguard/dokodemo/socks/http/mixed rows have no client
    list to import). Anything the wizard cannot express (a REALITY key
    pair, sockopt/proxy-protocol tuning, an exotic transport) is reported in
    ``notes`` rather than silently dropped — the operator re-adds it by hand
    knowing exactly what is missing.
    """
    protocol = str(inbound.get("protocol") or "").strip().lower()
    if protocol not in _XUI_IMPORTABLE_PROTOCOLS:
        return None
    try:
        port = int(inbound.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        return None
    stream = _json_field(inbound.get("stream_settings"), {}) or {}
    if not isinstance(stream, dict):
        stream = {}
    notes: list[str] = []
    settings: dict[str, Any] = {}

    network = str(stream.get("network") or "tcp").strip().lower()
    if network == "raw":
        network = "tcp"
    if network == "kcp":
        network = "mkcp"
    if network in ("h2", "http"):
        # xray removed the h2 transport upstream ("migrated to XHTTP")
        notes.append("h2/http transport is no longer served by xray — imported as xhttp")
        network = "xhttp"
    if network == "splithttp":
        network = "xhttp"
    if network not in ("tcp", "ws", "httpupgrade", "grpc", "xhttp", "mkcp"):
        notes.append(f"transport '{network}' cannot be imported — created as tcp")
        network = "tcp"
    settings["transport"] = network

    def _section(*names: str) -> dict[str, Any]:
        for name in names:
            value = stream.get(name)
            if isinstance(value, dict):
                return value
        return {}

    if network == "ws":
        ws = _section("wsSettings")
        settings["path"] = str(ws.get("path") or "/")
        host = ws.get("host") or (ws.get("headers") or {}).get("Host") or ""
        if host:
            settings["host"] = str(host)
    elif network == "httpupgrade":
        hu = _section("httpupgradeSettings")
        settings["path"] = str(hu.get("path") or "/")
        if hu.get("host"):
            settings["host"] = str(hu["host"])
    elif network == "grpc":
        grpc = _section("grpcSettings")
        settings["service_name"] = str(grpc.get("serviceName") or "grpc")
        if grpc.get("authority"):
            settings["authority"] = str(grpc["authority"])
        if grpc.get("multiMode"):
            settings["multi_mode"] = True
    elif network == "xhttp":
        xh = _section("xhttpSettings", "splithttpSettings", "httpSettings")
        settings["path"] = str(xh.get("path") or "/")
        host = xh.get("host") or ""
        if isinstance(host, list):
            host = host[0] if host else ""
        if host:
            settings["host"] = str(host)
        if xh.get("mode") in ("auto", "packet-up", "stream-up", "stream-one"):
            settings["mode"] = xh["mode"]
    elif network == "mkcp":
        kcp = _section("kcpSettings")
        for src, dst in (("mtu", "mtu"), ("tti", "tti")):
            if kcp.get(src):
                settings[dst] = int(kcp[src])
        if kcp.get("congestion") is not None:
            settings["congestion"] = bool(kcp["congestion"])
        if kcp.get("seed") or (kcp.get("header") or {}).get("type", "none") != "none":
            notes.append("mKCP seed/header obfuscation was removed upstream — imported without it")
    elif network == "tcp":
        tcp = _section("tcpSettings", "rawSettings")
        header = tcp.get("header") if isinstance(tcp.get("header"), dict) else {}
        if header.get("type") == "http":
            request = header.get("request") if isinstance(header.get("request"), dict) else {}
            settings["header_type"] = "http"
            paths = request.get("path") or ["/"]
            settings["path"] = ",".join(str(p) for p in paths) if isinstance(paths, list) else str(paths)
            headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
            host = headers.get("Host") or headers.get("host") or ""
            if isinstance(host, list):
                host = host[0] if host else ""
            if host:
                settings["host"] = str(host)
            if request.get("method"):
                settings["http_method"] = str(request["method"])

    security = str(stream.get("security") or "none").strip().lower()
    if security == "tls":
        tls = _section("tlsSettings")
        sni = str(tls.get("serverName") or "").strip()
        certs = tls.get("certificates") if isinstance(tls.get("certificates"), list) else []
        cert = next((c for c in certs if isinstance(c, dict)), {})
        if cert.get("certificateFile") and cert.get("keyFile"):
            # the files live on the OLD host; referencing them here would
            # fail validation — the panel mints a self-signed pair instead
            notes.append(
                f"TLS certificate files {cert.get('certificateFile')} are not part "
                "of the backup — a self-signed certificate is used; upload the "
                "real pair in the inbound editor")
        if not sni:
            sni = str(cert.get("certificateFile") or "").rsplit("/", 1)[-1].split(".")[0] or "localhost"
            notes.append("TLS inbound without serverName — SNI defaulted; set it in the inbound editor")
        settings["security"] = "tls"
        settings["sni"] = sni
        alpn = [a for a in (tls.get("alpn") or []) if a]
        if alpn:
            settings["alpn"] = alpn
    elif security == "reality":
        reality = _section("realitySettings")
        names = reality.get("serverNames") if isinstance(reality.get("serverNames"), list) else []
        dest = str(reality.get("dest") or reality.get("target") or "")
        sni = str((names[0] if names else "") or dest.split(":")[0] or "")
        if not sni:
            notes.append("REALITY inbound without serverNames/dest — imported as plain TLS-less tcp")
            settings["security"] = "none"
        else:
            settings["security"] = "reality"
            settings["sni"] = sni
            inner = reality.get("settings") if isinstance(reality.get("settings"), dict) else {}
            fp = str(inner.get("fingerprint") or "chrome")
            settings["fingerprint"] = fp
            notes.append(
                "REALITY key pair is re-generated on this panel (private keys are "
                "not carried over) — clients need the new subscription link")
        if network not in ("tcp", "xhttp", "grpc"):
            notes.append(f"REALITY is not servable over {network} — security downgraded to none")
            settings["security"] = "none"
            settings.pop("sni", None)
            settings.pop("fingerprint", None)
    else:
        settings["security"] = "none"
    if protocol == "trojan" and settings["security"] == "none":
        # xray trojan without TLS is refused by the wizard blueprint
        settings["security"] = "tls"
        settings.setdefault("sni", "localhost")
        notes.append("trojan needs TLS — a self-signed certificate is used; upload the real pair")
    if protocol == "shadowsocks":
        proto_settings = _json_field(inbound.get("settings"), {}) or {}
        method = str(proto_settings.get("method") or "").strip()
        if method.startswith("2022-"):
            notes.append(f"shadowsocks-2022 cipher {method} is not importable on xray — "
                         "created with aes-128-gcm")
            method = "aes-128-gcm"
        settings["method"] = method or "aes-128-gcm"
        settings["security"] = "none"
        settings.pop("sni", None)
    sockopt = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
    if sockopt.get("acceptProxyProtocol"):
        notes.append("sockopt.acceptProxyProtocol is not carried by the wizard — re-enable "
                     "it in Advanced Mode if a proxy-protocol front sits before xray")
    proto_settings = _json_field(inbound.get("settings"), {}) or {}
    if protocol == "vless":
        flows = {str(c.get("flow") or "") for c in (proto_settings.get("clients") or [])
                 if isinstance(c, dict)}
        if "xtls-rprx-vision" in flows and network == "tcp" and settings["security"] in ("tls", "reality"):
            settings["flow"] = "xtls-rprx-vision"
    return {
        "tag": _xui_inbound_tag(inbound),
        "remark": str(inbound.get("remark") or "").strip(),
        "protocol": protocol,
        "port": port,
        "listen": None,
        "enabled": bool(inbound.get("enable", True)),
        "settings": settings,
        "notes": notes,
        "source_id": inbound.get("id"),
    }


def _settings_for(protocol: str, client: dict[str, Any],
                  inbound: dict[str, Any] | None) -> dict[str, Any]:
    """The credential this panel stores for the protocol.

    3x-ui spreads the credential across columns (``uuid``/``password``/
    ``flow``/``security``) instead of the settings JSON Marzban uses, so the
    proxy settings have to be rebuilt per protocol.
    """
    proto = (protocol or "").strip().lower()
    uuid = client.get("uuid") or client.get("password") or ""
    flow = ((inbound or {}).get("_flow_override")
            or client.get("flow") or "").strip()
    if proto == "vless":
        return {"id": uuid, "flow": flow}
    if proto == "vmess":
        return {"id": uuid}
    if proto == "trojan":
        return {"password": client.get("password") or uuid}
    if proto == "shadowsocks":
        from app.models.proxy import canonical_ss_method

        return {"password": client.get("password") or uuid,
                "method": canonical_ss_method(client.get("security")) or "chacha20-ietf-poly1305"}
    return {"id": uuid}


# Both user tables (panel + platform) declare ``note`` as VARCHAR(500); MySQL
# rejects longer values outright (1406 "Data too long"), so a note built from
# imported material is trimmed here instead of failing the whole import.
NOTE_MAX_LEN = 500


def _fit_note(note: str | None) -> str | None:
    if not note:
        return None
    note = str(note)
    if len(note) <= NOTE_MAX_LEN:
        return note
    return note[: NOTE_MAX_LEN - 1].rstrip() + "…"


def _summarize_client_ips(raw: Any, limit: int = 5) -> str:
    """``inbound_client_ips.ips`` → a short, human-readable IP list.

    Modern 3x-ui stores a JSON array of ``{"ip", "timestamp"}`` objects (one
    per seen address); older builds a JSON list of strings or a plain comma
    list. Dumping the raw JSON into the note overflowed the column.
    """
    if raw in (None, "", b""):
        return ""
    ips: list[str] = []
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, list):
        for item in parsed:
            ip = item.get("ip") if isinstance(item, dict) else item
            if ip and str(ip) not in ips:
                ips.append(str(ip))
    else:
        for piece in text.replace(";", ",").split(","):
            piece = piece.strip().strip('"[]')
            if piece and piece not in ips:
                ips.append(piece)
    if not ips:
        return ""
    shown = ", ".join(ips[:limit])
    return shown + (f" (+{len(ips) - limit} more)" if len(ips) > limit else "")


def read_3x_ui(db_path: Path) -> tuple[LegacySnapshot, dict[str, Any]]:
    """Map an ``x-ui.db`` onto a :class:`LegacySnapshot` + an import report."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    snapshot = LegacySnapshot()
    notes: dict[str, Any] = {"renamed_users": [], "generated_admin_passwords": {},
                             "skipped": [], "unsupported": []}
    try:
        tables = {row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        inbounds = _rows(con, "inbounds")
        traffic = {row.get("email"): row for row in _rows(con, "client_traffics")}
        if not traffic and "client_global_traffics" in tables:
            traffic = {row.get("email"): row
                       for row in _rows(con, "client_global_traffics")}
        limits_ip = {row.get("client_email"): row.get("ips")
                     for row in (_rows(con, "inbound_client_ips")
                                 if "inbound_client_ips" in tables else [])}

        link_index = _client_inbound_index(con)
        clients: list[dict[str, Any]]
        if "clients" in tables:
            clients = _rows(con, "clients")
            _assign_inbound_metadata(clients, inbounds, link_index)
        else:
            clients = _clients_from_settings(inbounds)
            for client in clients:
                client.setdefault("_links", [])

        # per-protocol listener tags the importer will materialize — used to
        # BIND each client to exactly the inbounds the source assigned it
        # (3x-ui ``client_inbounds``): the proxy is stored once per protocol
        # and the OTHER listeners of that protocol are excluded, so an
        # imported user never silently inherits every listener of the
        # protocol the panel has — or will ever add (the 3x-ui import
        # \"assigned inbounds\" bug: the sub links served unrelated
        # inbounds to every imported user).
        importable_tags: dict[str, list[str]] = {}
        for row in inbounds:
            spec = _xui_inbound_spec(row)
            if spec is None:
                continue
            importable_tags.setdefault(spec["protocol"], []).append(spec["tag"])

        taken: set[str] = set()
        for index, client in enumerate(clients, start=1):
            email = (client.get("email") or "").strip()
            if not email:
                notes["skipped"].append(f"client #{index}: no email — SKIPPED")
                continue
            username, note = sanitize_username(email, taken)
            if note:
                notes["renamed_users"].append({"username": username, "note": note})
            traffic_row = traffic.get(email) or {}
            used = int(traffic_row.get("up") or 0) + int(traffic_row.get("down") or 0)
            # newer builds keep the cap on the client row, in gigabytes
            total_gb = client.get("total_gb") or client.get("totalGB") or 0
            total = int(traffic_row.get("total") or 0) or int(
                float(total_gb or 0) * 1024 ** 3)
            expiry_ms = int(traffic_row.get("expiry_time")
                            or client.get("expiry_time")
                            or client.get("expiryTime") or 0)
            enabled = bool(traffic_row.get("enable", client.get("enable", True)))
            limit_ip = (client.get("limit_ip") if client.get("limit_ip") is not None
                        else client.get("limitIp") or 0)
            ips = _summarize_client_ips(limits_ip.get(email))
            device_limit = int(limit_ip) if str(limit_ip).isdigit() and int(limit_ip) > 0 else None

            user_id = index
            snapshot.users.append({
                "id": user_id,
                "username": username,
                "status": "active" if enabled else "disabled",
                "note": _fit_note(note or f"imported from 3x-ui ({email})"
                                  + (f"; last IPs: {ips}" if ips else "")),
                "data_limit": total or None,
                "download_limit_mbps": 0,
                "upload_limit_mbps": 0,
                "expire": (expiry_ms // 1000) if expiry_ms > 0 else None,
                "created_at": None,
                "used_traffic": used,
                "data_limit_reset_strategy": "no_reset",
                "device_limit": device_limit,
            })

            # One proxy per protocol, not per inbound: the panel stores the
            # credential once and selects inbounds by excluding them. Three
            # identical vless rows (one per inbound) would be three identical
            # entries in the user's configuration.
            links = client.get("_links") or []
            if not links and client.get("_protocol"):
                links = [client]
            seen: set[str] = set()
            for link in links:
                protocol = (link.get("protocol") or client.get("_protocol") or "").lower()
                if not protocol or protocol in seen:
                    continue
                seen.add(protocol)
                proxy = {
                    "id": len(snapshot.proxies) + 1,
                    "user_id": user_id,
                    "type": protocol,
                    "settings": _settings_for(protocol, client, link),
                }
                # Bind the proxy to the source's assignment: every other
                # listener of this protocol is excluded. A client linked to
                # ONE inbound of a three-inbound panel must not be served by
                # all three — that leak is what made imported users' sub
                # links show inbounds (and credentials) that were never
                # theirs. Clients the source never linked explicitly keep the
                # Marzban semantics (empty exclusions = all listeners).
                linked = {
                    _xui_inbound_tag(entry)
                    for entry in links
                    if entry.get("tag") and (entry.get("protocol") or "").lower() == protocol
                }
                candidates = importable_tags.get(protocol) or []
                if linked and candidates:
                    excluded = [t for t in candidates if t not in linked]
                    if excluded:
                        proxy["excluded_inbounds"] = excluded
                        notes.setdefault("restricted", []).append(
                            f"{username}: {protocol} is bound to "
                            f"{', '.join(sorted(linked))} — "
                            f"{len(excluded)} other listener(s) excluded")
                snapshot.proxies.append(proxy)

        # inbounds: 3x-ui keeps the LISTENERS in its database (Marzban keeps
        # them in xray_config.json). Without them the imported users have
        # credentials for inbounds that do not exist on this panel — "the
        # users came over but none of them can connect". Each becomes a
        # wizard-shaped spec the importer materializes on the xray core.
        sub_hosts = (_rows(con, "hosts") if "hosts" in tables else [])
        for inbound in inbounds:
            spec = _xui_inbound_spec(inbound)
            if spec is not None:
                snapshot.inbounds.append(spec)
                for note in spec.get("notes") or []:
                    notes["unsupported"].append(f"{spec['tag']}: {note}")

        # hosts: what the SUBSCRIPTION advertises per inbound. Newer 3x-ui
        # builds keep real host rows (address/port/path/host header/sni —
        # a CDN front, typically) in ``hosts``; those are the entry points
        # the users actually connect through. Older builds have no such
        # table — fall back to one row per inbound. ``listen`` is the bind
        # address ("" or 0.0.0.0 — never a public name), so a missing
        # address means "this server" ({SERVER_IP}), exactly like the panel's
        # own default host row.
        tag_of = {row.get("id"): _xui_inbound_tag(row) for row in inbounds}
        covered: set[Any] = set()
        for row in sorted(sub_hosts, key=lambda r: (r.get("inbound_id") or 0,
                                                     r.get("sort_order") or 0,
                                                     r.get("id") or 0)):
            tag = tag_of.get(row.get("inbound_id"))
            if not tag:
                continue
            covered.add(row.get("inbound_id"))
            security = str(row.get("security") or "").strip().lower()
            snapshot.hosts.append({
                "remark": row.get("remark") or tag,
                "address": (row.get("address") or "").strip() or "{SERVER_IP}",
                "port": row.get("port") or None,
                "sni": (row.get("sni") or "").strip() or None,
                "host": (row.get("host_header") or "").strip() or None,
                "path": (row.get("path") or "").strip() or None,
                # 3x-ui "same" = follow the inbound (Marzban inbound_default)
                "security": security if security in ("tls", "none") else "inbound_default",
                "alpn": None,
                "fingerprint": (row.get("fingerprint") or "").strip() or None,
                "inbound_tag": tag,
                "allowinsecure": bool(row.get("allow_insecure")),
                "is_disabled": bool(row.get("is_disabled")),
                "mux_enable": False,
                "random_user_agent": False,
            })
        for inbound in inbounds:
            if inbound.get("id") in covered:
                continue
            stream = _json_field(inbound.get("stream_settings"), {}) or {}
            ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
            reality = (stream.get("realitySettings")
                       if isinstance(stream.get("realitySettings"), dict) else {})
            snapshot.hosts.append({
                "remark": inbound.get("remark") or inbound.get("tag") or "",
                "address": "{SERVER_IP}",
                "port": inbound.get("port"),
                "sni": (reality.get("serverNames") or [None])[0] if reality else None,
                "host": ((ws.get("headers") or {}).get("Host") or ws.get("host") or None)
                        if ws else None,
                "path": ws.get("path") if ws else None,
                "security": "inbound_default",
                "alpn": None,
                "fingerprint": None,
                "inbound_tag": _xui_inbound_tag(inbound),
                "allowinsecure": False,
                "is_disabled": not bool(inbound.get("enable", True)),
                "mux_enable": False,
                "random_user_agent": False,
            })

        # panel admins: the hash scheme is not ours — issue a fresh password
        for row in _rows(con, "users"):
            username = (row.get("username") or "").strip()
            if not username:
                continue
            clean, _ = sanitize_username(username, set())
            password = _generated_password()
            snapshot.admins.append({
                "username": clean,
                "hashed_password": "",       # filled in at apply time
                "generated_password": password,
                "is_sudo": True,
                "telegram_id": None,
            })
            notes["generated_admin_passwords"][clean] = password
    finally:
        con.close()
    return snapshot, notes


def _assign_inbound_metadata(clients: list[dict[str, Any]],
                             inbounds: list[dict[str, Any]],
                             link_index: dict[Any, list[dict[str, Any]]] | None = None
                             ) -> None:
    """Attach each client to the inbound(s) that serve it.

    Newer 3x-ui builds drop the ``inbound_id`` column from ``clients`` and keep
    the link in ``client_inbounds``; looking only for the column (as we did)
    left every client without a protocol.
    """
    by_id = {row.get("id"): row for row in inbounds}
    for client in clients:
        links = (link_index or {}).get(client.get("id")) or []
        if not links:
            inbound = by_id.get(client.get("inbound_id"))
            links = [inbound] if inbound else []
        client["_links"] = [dict(link) for link in links]
        for link in links:
            if link.get("protocol"):
                client["_protocol"] = link.get("protocol")
            if link.get("remark") or link.get("tag"):
                client["_remark"] = link.get("remark") or link.get("tag")


# --------------------------------------------------------------------------- #
# Marzban / Pasarguard
# --------------------------------------------------------------------------- #
def read_marzban_like(db_path: Path) -> tuple[LegacySnapshot, dict[str, Any]]:
    """Read a Marzban-shaped SQLite database tolerantly.

    Pasarguard adds/drops columns relative to Marzban, so the reader selects
    ``*`` per table and keeps whatever is there, instead of naming columns.
    """
    from app.persistence import legacy_reader

    reader = getattr(legacy_reader, "read_legacy_sqlite", None)
    if reader is None:  # pragma: no cover - defensive
        raise RestoreSourceError("legacy reader is unavailable in this build")
    snapshot = reader(db_path)
    tables = _table_names(db_path)
    notes = {"tables": sorted(tables), "skipped": [], "generated_admin_passwords": {}}
    from app.persistence.migration import is_verifiable_hash

    for admin in snapshot.admins:
        # A hash we cannot verify is worse than a password we issue: replace it
        # and hand the operator the new one. (bcrypt — Marzban's own scheme —
        # is kept, so those admins keep their existing password.)
        if not is_verifiable_hash(admin.get("hashed_password")):
            password = _generated_password()
            admin["generated_password"] = password
            notes["generated_admin_passwords"][admin.get("username", "")] = password
    return snapshot, notes


def read_snapshot(source: str, db_path: Path) -> tuple[LegacySnapshot, dict[str, Any]]:
    if source == "3x-ui":
        return read_3x_ui(db_path)
    if source in ("marzban", "pasarguard"):
        return read_marzban_like(db_path)
    if source == "zagros":
        # An engine the archive's files cannot simply replace (MySQL): the
        # rows are imported instead of the file being copied.
        return read_zagros_platform(db_path)
    raise RestoreSourceError(f"unsupported restore source: {source}")


# --------------------------------------------------------------------------- #
# Zagros platform database
# --------------------------------------------------------------------------- #
def read_zagros_platform(db_path: Path) -> tuple[LegacySnapshot, dict[str, Any]]:
    """Read a Zagros *platform* database (``db/zagros.sqlite3``).

    Used when the archive's database cannot simply be copied into place —
    a panel running MySQL, most of all. The rows are read out and pushed
    through the same migration pipeline a foreign panel goes through, so the
    result is a working panel on whatever engine it happens to run.
    """
    from app.persistence.migration import is_verifiable_hash

    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    snapshot = LegacySnapshot()
    notes: dict[str, Any] = {"generated_admin_passwords": {}, "skipped": [],
                             "source_tables": []}
    try:
        tables = {row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        notes["source_tables"] = sorted(tables)
        if "users" not in tables and "admins" not in tables:
            raise RestoreSourceError(
                "this is not a Zagros platform database (no users/admins table)")

        usage = {}
        if "user_usage" in tables:
            for row in _rows(con, "user_usage"):
                usage[int(row.get("user_id") or 0)] = (
                    int(row.get("uplink_bytes") or 0)
                    + int(row.get("downlink_bytes") or 0))

        taken: set[str] = set()
        for row in (_rows(con, "users") if "users" in tables else []):
            username, note = sanitize_username(row.get("username") or "", taken)
            if note:
                notes["skipped"].append(f"{username}: {note}")
            expire = row.get("expire_at")
            snapshot.users.append({
                "id": row.get("id"),
                "username": username,
                "status": row.get("status") or "active",
                "note": row.get("note") or f"imported from a Zagros archive",
                "data_limit": row.get("data_limit_bytes"),
                "download_limit_mbps": row.get("download_limit_mbps") or 0,
                "upload_limit_mbps": row.get("upload_limit_mbps") or 0,
                "expire": expire,
                "created_at": row.get("created_at"),
                "used_traffic": usage.get(int(row.get("id") or 0), 0),
                "data_limit_reset_strategy": row.get("data_limit_reset_strategy")
                                            or "no_reset",
                "device_limit": row.get("device_limit"),
            })

        for row in (_rows(con, "admins") if "admins" in tables else []):
            username = (row.get("username") or "").strip()
            if not username:
                continue
            entry = {
                "username": username,
                "hashed_password": row.get("password_hash") or "",
                "is_sudo": bool(row.get("is_sudo")),
                "telegram_id": row.get("telegram_id"),
            }
            if not is_verifiable_hash(entry["hashed_password"]):
                password = _generated_password()
                entry["generated_password"] = password
                notes["generated_admin_passwords"][username] = password
            snapshot.admins.append(entry)

        if "core_hosts" in tables:
            for row in _rows(con, "core_hosts"):
                snapshot.hosts.append({
                    "remark": row.get("remark") or "",
                    "address": row.get("address"),
                    "port": row.get("port"),
                    "sni": row.get("sni"),
                    "host": row.get("host_header"),
                    "path": row.get("path"),
                    "security": row.get("security"),
                    "alpn": row.get("alpn"),
                    "fingerprint": row.get("fingerprint"),
                    "inbound_tag": row.get("inbound_tag"),
                    "allowinsecure": False,
                    "is_disabled": False,
                    "mux_enable": False,
                    "random_user_agent": False,
                })
    finally:
        con.close()
    return snapshot, notes
