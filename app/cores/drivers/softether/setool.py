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
