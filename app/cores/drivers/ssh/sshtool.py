"""Pure helpers for the SSH tunnel driver (no IO — fixture-testable).

  * :func:`parse_ps_sshd` — `ps` output → live sshd sessions per user.
  * :func:`sanitize_username` — account_id → safe unix username (accounts are
    prefixed so panel users can never collide with system users).

  * :const:`ACCT_CHAIN` + :func:`parse_acct_counters` — per-UID byte
    accounting through an iptables owner-match chain (alpha.7.4, item 5).

Accounting design — REAL bytes, no fabrication: xt_owner can identify only
locally-created OUTPUT sockets. It therefore provides forwarding uplink but
cannot see data sent on the root-created accepted SSH socket and must never be
claimed as a bidirectional total. SFTP/SCP uses a separate decrypted stream
proxy with kernel-credential attribution; it reports cumulative upload and
download independently. The driver combines these sources and persists its
baseline across recorder ticks/restarts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_SAFE_USER = re.compile(r"^[a-z_][a-z0-9_\-]{0,31}$")
# sshd child process for an authenticated session:
#   "sshd: alice@notty"   (port-forwarding / -N tunnels)
#   "sshd: alice@pts/0"   (interactive)
# The privilege-separated parent looks like "sshd: alice [priv]" and runs
# as root+user pair — we only count the user-owned "@..." rows.
_SSHD_SESSION = re.compile(r"sshd:\s(?P<user>[^@\s\[]+)@(?P<tty>\S+)")


def sanitize_username(account_id: str) -> str:
    """Map a panel account id to a safe, panel-namespaced unix username."""
    clean = re.sub(r"[^a-z0-9_\-]", "-", account_id.lower())
    candidate = clean if clean.startswith("zg-") else "zg-" + clean
    candidate = candidate[:32]
    if not _SAFE_USER.match(candidate):
        raise ValueError(f"cannot derive a safe unix username from '{account_id}'")
    return candidate


@dataclass(frozen=True, slots=True)
class SSHSession:
    user: str
    pid: int
    elapsed_seconds: int
    terminal: str                       # "notty" (tunnels) or "pts/N"


def parse_ps_sshd(text: str) -> list[SSHSession]:
    """Parse `ps -eo user=,pid=,etimes=,args=` output for sshd sessions."""
    sessions: list[SSHSession] = []
    for raw in text.splitlines():
        line = raw.strip()
        match = _SSHD_SESSION.search(line)
        if match is None:
            continue
        head = line[:match.start()].split()
        if len(head) < 3:
            continue  # user, pid, etimes
        owner, pid, etimes = head[0], head[1], head[2]
        if owner != match.group("user"):
            continue  # skip the root-owned [priv] stage rows
        sessions.append(SSHSession(
            user=match.group("user"),
            pid=int(pid),
            elapsed_seconds=int(etimes),
            terminal=match.group("tty"),
        ))
    return sessions


# --------------------------------------------------------------------- #
# iptables owner-match accounting (see module honesty note)
# --------------------------------------------------------------------- #

#: dedicated accounting chain name — panel-namespaced so cleanup can never
#: touch unrelated firewall state.
ACCT_CHAIN = "ZG-SSH-ACCT"

_UID_RULE = re.compile(r"owner UID match (?P<uid>\d+)")


def parse_acct_counters(text: str) -> dict[int, int]:
    """Parse `iptables -L ZG-SSH-ACCT -n -v -x` output → {uid: bytes}.

    Row shape (per-account accounting rule):
    ``   17 34675360 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 1001``
    Column 2 is the EXACT kernel byte counter (``-x`` keeps it un-abbreviated).
    """
    counters: dict[int, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        match = _UID_RULE.search(line)
        if match is None:
            continue
        head = line.split()
        if len(head) < 2 or not head[1].isdigit():
            continue
        counters[int(match.group("uid"))] = int(head[1])
    return counters
