"""Pure helpers for the SoftEther driver (no IO — fixture-testable).

  * :func:`parse_user_get` — `UserGet` key|value table → per-user cumulative
    traffic counters (unicast + broadcast total sizes, both directions).
  * :func:`parse_user_list` / :func:`parse_session_list` — `/CSV` output of
    UserList / SessionList (header-driven, column-order safe).

Direction note (documented assumption): SoftEther reports statistics from
the *server's* point of view — "Incoming" = bytes received FROM the client
(the user's uplink), "Outgoing" = sent TO the client (the user's downlink).
Quota totals are direction-independent; the up/down split follows this
convention consistently across the panel.
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
    incoming_bytes: int                 # client → server  (user uplink)
    outgoing_bytes: int                 # server → client  (user downlink)
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
class IPsecServices:
    """Server IPsec service state per `IPsecGet` (alpha.7.5 item 7)."""

    l2tp: bool                          # L2TP over IPsec server function
    l2tp_raw: bool                      # Raw L2TP (without IPsec)
    etherip: bool                       # EtherIP / L2TPv3 over IPsec
    psk: str                            # current pre-shared key ("" when unset)
    default_hub: str                    # default Virtual HUB ("" when unset)

    @property
    def any_enabled(self) -> bool:
        return self.l2tp or self.l2tp_raw or self.etherip


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
