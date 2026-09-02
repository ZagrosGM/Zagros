"""Pure helpers for the SoftEther driver (no IO — fixture-testable).

  * :func:`parse_user_get` — `UserGet` key|value table → per-user cumulative
    traffic counters (unicast + broadcast total sizes, both directions).
  * :func:`parse_user_list` / :func:`parse_session_list` — `/CSV` output of
    UserList / SessionList (header-driven, column-order safe).

Direction note (real routed-client evidence): SoftEther's SessionGet/UserGet
labels follow the hub/Internet side, not the English direction one might infer
from the client socket. ``Outgoing`` advances for client upload and
``Incoming`` advances for client download. The driver exposes those as client
uplink/downlink respectively; known independent payload tests pin this mapping.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UserStatistics:
    """Cumulative traffic of one hub user (all time, per UserGet)."""

    username: str
    incoming_bytes: int                 # Internet/hub → client (user downlink)
    outgoing_bytes: int                 # client → Internet/hub (user uplink)
    num_logins: int = 0
    expires_at: str | None = None


@dataclass(frozen=True, slots=True)
class SEUser:
    username: str
    logins: int = 0
    transfer_bytes: int = 0             # informational (UserList column)


@dataclass(frozen=True, slots=True)
class SESession:
    session_name: str
    username: str
    source_host: str                    # client hostname/IP (device identity)
    raw: dict[str, str]


@dataclass(frozen=True, slots=True)
class SessionStatistics:
    """Live counters of one active SoftEther session (``SessionGet``).

    ``UserGet`` only commits these bytes when the session disconnects. Adding
    active SessionGet counters to the completed UserGet total yields one
    monotonic effective counter that works both during and after a session.
    """

    session_name: str
    username: str
    incoming_bytes: int
    outgoing_bytes: int


@dataclass(frozen=True, slots=True)
class IPsecServices:
    """Server IPsec service state per `IPsecGet`."""

    l2tp: bool                          # L2TP over IPsec server function
    l2tp_raw: bool                      # Raw L2TP (without IPsec)
    etherip: bool                       # EtherIP / L2TPv3 over IPsec
    psk: str                            # current pre-shared key ("" when unset)
    default_hub: str                    # default Virtual HUB ("" when unset)

    @property
    def any_enabled(self) -> bool:
        return self.l2tp or self.l2tp_raw or self.etherip


@dataclass(frozen=True, slots=True)
class CloneServers:
    """Server-wide protocol clone switches per `OpenVpnGet` / `SstpGet`."""

    openvpn: bool                       # OpenVPN clone server function
    openvpn_ports: tuple[int, ...]      # UDP ports the clone listens on
    sstp: bool                          # MS-SSTP clone server function


_BOOL_TRUE = {"yes", "enable", "enabled", "true", "on"}
_EMPTY_PRINTS = {"", "none", "(none)", "(empty)", "-", "--"}


def parse_ipsec_get(text: str) -> IPsecServices:
    """Parse the `IPsecGet` console table.

    Rows print as ``Label | Value`` with localized labels, so rows are
    matched by stable keyword, not by exact string. Booleans accept
    yes/no/enable/disable/true/false (localized SEC_YES/SEC_NO variants
    still start with the ASCII word in every shipped hamcore).
    """
    flags: dict[str, str] = {}
    for raw in (text or "").splitlines():
        if "|" not in raw:
            continue
        label, _, value = raw.rpartition("|")
        flags[label.strip().lower()] = value.strip()

    def _find(*needles: str) -> str:
        for key, value in flags.items():
            if any(n in key for n in needles):
                return value
        return ""

    def _bool(value: str) -> bool:
        return value.strip().lower().split(" ")[0].rstrip(".") in _BOOL_TRUE

    psk = _find("pre-shared key", "psk")
    hub = _find("default virtual hub", "default hub", "defaulthub")
    return IPsecServices(
        l2tp=_bool(_find("l2tp over ipsec")),
        l2tp_raw=_bool(_find("raw l2tp")),
        etherip=_bool(_find("etherip")),
        psk="" if psk.strip().lower() in _EMPTY_PRINTS else psk,
        default_hub="" if hub.strip().lower() in _EMPTY_PRINTS else hub,
    )


_SIZE_LABEL = re.compile(r"^([\d,]+)\s+bytes$", re.IGNORECASE)


def _table_rows(text: str) -> dict[str, str]:
    """``Label | Value`` rows of a vpncmd console table, label lower-cased."""
    rows: dict[str, str] = {}
    for raw in (text or "").splitlines():
        if "|" not in raw:
            continue
        label, _, value = raw.rpartition("|")
        rows[label.strip().lower()] = value.strip()
    return rows


def _table_bool(rows: dict[str, str], *needles: str) -> bool:
    for key, value in rows.items():
        if any(n in key for n in needles):
            return value.strip().lower().split(" ")[0].rstrip(".") in _BOOL_TRUE
    return False


def parse_openvpn_get(text: str) -> tuple[bool, tuple[int, ...]]:
    """Parse the `OpenVpnGet` console table → (enabled, udp ports).

    Labels are localized ("OpenVPN Clone Server Enabled", "UDP Port List"),
    so rows are matched by keyword; the port list is comma/space separated.
    """
    rows = _table_rows(text)
    enabled = _table_bool(rows, "clone server enabled", "openvpn")
    ports: list[int] = []
    for key, value in rows.items():
        if "port" in key:
            for token in re.split(r"[,\s]+", value):
                if token.isdigit() and 1 <= int(token) <= 65535:
                    ports.append(int(token))
            break
    return enabled, tuple(ports)


def parse_sstp_get(text: str) -> bool:
    """Parse the `SstpGet` console table → enabled."""
    return _table_bool(_table_rows(text), "clone server enabled", "sstp")


def _bytes(value: str) -> int:
    match = _SIZE_LABEL.match(value.strip())
    return int(match.group(1).replace(",", "")) if match else 0


def parse_user_get(text: str) -> UserStatistics:
    """Parse `UserGet` output (two-column `Item | Value` table)."""
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        if "|" not in raw:
            continue
        left, _, right = raw.partition("|")
        key = left.strip(" -")
        if not key or set(left.strip()) <= {"-"}:
            continue
        fields[key.lower()] = right.strip()

    def _get(*names: str) -> str:
        for name in names:
            for key, value in fields.items():
                if key.startswith(name.lower()):
                    return value
        return ""

    incoming = _bytes(_get("Incoming Unicast Total Size")) + \
        _bytes(_get("Incoming Broadcast Total Size"))
    outgoing = _bytes(_get("Outgoing Unicast Total Size")) + \
        _bytes(_get("Outgoing Broadcast Total Size"))
    try:
        logins = int(_get("Number of Logins").replace(",", "") or 0)
    except ValueError:
        logins = 0
    expires = _get("Expiration Date") or _get("Expire Date") or None
    return UserStatistics(
        username=_get("User Name"),
        incoming_bytes=incoming,
        outgoing_bytes=outgoing,
        num_logins=logins,
        expires_at=expires or None,
    )


def _csv_rows(text: str) -> list[dict[str, str]]:
    """Parse `/CSV` output; skip comment/empty lines SoftEther may prepend."""
    reader = None
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stream = io.StringIO(line)
        if reader is None:
            header = next(csv.reader(stream))
            reader = header
            continue
        values = next(csv.reader(stream))
        rows.append({h: (values[i] if i < len(values) else "")
                     for i, h in enumerate(reader)})
    return rows


def parse_session_get(text: str) -> SessionStatistics:
    """Parse live ``SessionGet`` directional byte counters.

    SoftEther prints ``Incoming/Outgoing Data Size`` while a session is
    active. They are not reflected in ``UserGet`` until disconnect, which is
    why polling UserGet alone left long-lived L2TP/SSTP sessions at zero.
    """
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        if "|" not in raw:
            continue
        left, _, right = raw.partition("|")
        key = left.strip(" -")
        if not key or set(left.strip()) <= {"-"}:
            continue
        fields[key.lower()] = right.strip()

    def _get(*names: str) -> str:
        for name in names:
            for key, value in fields.items():
                if key.startswith(name.lower()):
                    return value
        return ""

    return SessionStatistics(
        session_name=_get("Session Name"),
        username=(_get("User Name (Database)")
                  or _get("User Name (Authentication)")),
        incoming_bytes=_bytes(_get("Incoming Data Size")),
        outgoing_bytes=_bytes(_get("Outgoing Data Size")),
    )


def parse_user_list(text: str) -> list[SEUser]:
    users: list[SEUser] = []
    for row in _csv_rows(text):
        name = row.get("User Name", "").strip()
        if not name:
            continue
        try:
            logins = int((row.get("Number of Logins") or "0").replace(",", ""))
        except ValueError:
            logins = 0
        users.append(SEUser(username=name, logins=logins))
    return users


def parse_session_list(text: str) -> list[SESession]:
    sessions: list[SESession] = []
    for row in _csv_rows(text):
        session = row.get("Session Name", "").strip()
        if not session:
            continue
        username = (row.get("User Name") or row.get("User name") or "").strip()
        source = (row.get("Source Host Name") or row.get("Hostname")
                  or row.get("Source IP Address") or "").strip()
        sessions.append(SESession(
            session_name=session, username=username,
            source_host=source or None or "", raw=row,
        ))
    return sessions
