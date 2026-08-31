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

SOURCES: tuple[str, ...] = ("zagros", "marzban", "pasarguard", "3x-ui")
FOREIGN_SOURCES: tuple[str, ...] = ("marzban", "pasarguard", "3x-ui")

# Zagros usernames: 3–32 chars of [a-z0-9_]
_USERNAME_OK = re.compile(r"[^a-z0-9_]+")
_USERNAME_MIN = 3
_USERNAME_MAX = 32

_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".sqlitedb")
# Names that betray a 3x-ui archive rather than a Marzban-shaped one.
_3XUI_TABLES = {"inbounds", "client_traffics"}
_MARZBAN_TABLES = {"users", "admins", "proxies"}


class RestoreSourceError(RuntimeError):
    """Raised when an archive cannot be attributed to a supported source."""


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
        limits_ip = {row.get("client_email"): row.get("ips")
                     for row in (_rows(con, "inbound_client_ips")
                                 if "inbound_client_ips" in tables else [])}

        clients: list[dict[str, Any]]
        if "clients" in tables:
            clients = _rows(con, "clients")
            _assign_inbound_metadata(clients, inbounds)
        else:
            clients = _clients_from_settings(inbounds)

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
            total = int(traffic_row.get("total") or client.get("totalGB") or 0)
            expiry_ms = int(traffic_row.get("expiry_time")
                            or client.get("expiryTime")
                            or client.get("expiry_time") or 0)
            enabled = bool(traffic_row.get("enable", client.get("enable", True)))
            limit_ip = client.get("limitIp") or client.get("limit_ip") or 0
            ips = limits_ip.get(email)
            device_limit = int(limit_ip) if str(limit_ip).isdigit() and int(limit_ip) > 0 else None

            user_id = index
            snapshot.users.append({
                "id": user_id,
                "username": username,
                "status": "active" if enabled else "disabled",
                "note": note or f"imported from 3x-ui ({email})"
                        + (f"; allowed IPs: {ips}" if ips else ""),
                "data_limit": total or None,
                "download_limit_mbps": 0,
                "upload_limit_mbps": 0,
                "expire": (expiry_ms // 1000) if expiry_ms > 0 else None,
                "created_at": None,
                "used_traffic": used,
                "data_limit_reset_strategy": "no_reset",
                "device_limit": device_limit,
            })
            protocol = (client.get("_protocol") or "").lower()
            settings = {k: v for k, v in client.items()
                        if not k.startswith("_") and k not in
                        {"enable", "email", "totalGB", "expiryTime", "limitIp"}}
            snapshot.proxies.append({
                "id": index,
                "user_id": user_id,
                "type": protocol,
                "settings": settings,
            })

        # hosts: one per inbound, so restored links point at the same entry points
        for inbound in inbounds:
            stream = _json_field(inbound.get("stream_settings"), {}) or {}
            snapshot.hosts.append({
                "remark": inbound.get("remark") or inbound.get("tag") or "",
                "address": (inbound.get("listen") or "").strip() or None,
                "port": inbound.get("port"),
                "sni": (stream.get("realitySettings", {}).get("serverNames") or [None])[0]
                       if isinstance(stream.get("realitySettings"), dict) else None,
                "host": (stream.get("wsSettings", {}).get("headers", {}) or {}).get("Host")
                        if isinstance(stream.get("wsSettings"), dict) else None,
                "path": (stream.get("wsSettings", {}) or {}).get("path")
                        if isinstance(stream.get("wsSettings"), dict) else None,
                "security": stream.get("security"),
                "alpn": None,
                "fingerprint": None,
                "inbound_tag": inbound.get("remark") or inbound.get("tag"),
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
                             inbounds: list[dict[str, Any]]) -> None:
    """Attach protocol/remark to clients read from the newer ``clients`` table."""
    by_id = {row.get("id"): row for row in inbounds}
    for client in clients:
        inbound = by_id.get(client.get("inbound_id"))
        if inbound:
            client["_protocol"] = inbound.get("protocol")
            client["_remark"] = inbound.get("remark") or inbound.get("tag")


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
    for admin in snapshot.admins:
        # A hash we cannot verify is worse than a password we issue: replace it
        # and hand the operator the new one.
        if not admin.get("hashed_password"):
            password = _generated_password()
            admin["generated_password"] = password
            notes["generated_admin_passwords"][admin.get("username", "")] = password
    return snapshot, notes


def read_snapshot(source: str, db_path: Path) -> tuple[LegacySnapshot, dict[str, Any]]:
    if source == "3x-ui":
        return read_3x_ui(db_path)
    if source in ("marzban", "pasarguard"):
        return read_marzban_like(db_path)
    raise RestoreSourceError(f"unsupported restore source: {source}")
