"""Pure helpers for the SSH tunnel driver (no IO — fixture-testable).

  * :func:`parse_ps_sshd` — `ps` output → live sshd sessions per user.
  * :func:`sanitize_username` — account_id → safe unix username (accounts are
    prefixed so panel users can never collide with system users).

  * :const:`ACCT_CHAIN` + :func:`parse_acct_counters` — per-UID byte
    accounting through an iptables owner-match chain.

Accounting design — REAL bytes, no fabrication: the production backend reads
the accepted encrypted SSH transport's kernel ``bytes_received`` and
``bytes_sent`` counters, maps its dropped-UID sshd-session PID to the account,
and persists live-socket baselines. This covers generic -L/-R/-D forwarding
bidirectionally without guessing payload size. SFTP/SCP's decrypted collector
is a fallback when transport introspection is unavailable and is never added
to an already-authoritative transport total. The legacy xt_owner chain remains
only as an explicitly uplink-only compatibility fallback.
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
_SSHD_SESSION = re.compile(
    r"(?:sshd|sshd-session):\s(?P<user>[^@\s\[]+)(?:@(?P<tty>\S+))?\s*$"
)


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
            terminal=match.group("tty") or "notty",
        ))
    return sessions


# --------------------------------------------------------------------- #
# iptables owner-match accounting (see module honesty note)
# --------------------------------------------------------------------- #

#: Dedicated accounting chains — panel-namespaced so cleanup can never touch
#: unrelated firewall state. ACCT_CHAIN counts account-owned OUTPUT packets;
#: ACCT_MARK_CHAIN assigns conntrack identity; ACCT_INPUT_CHAIN counts reverse
#: packets from the same forwarding connection.
ACCT_CHAIN = "ZG-SSH-ACCT"
ACCT_MARK_CHAIN = "ZG-SSH-MARK"
ACCT_INPUT_CHAIN = "ZG-SSH-ACCT-IN"

# Keep clear of policy-routing marks (0x2... return, 0x4... bypass). Linux
# account UIDs fit comfortably in 24 bits on supported hosts.
_ACCT_MARK_PREFIX = 0x10000000
_ACCT_MARK_MASK = 0x1FFFFFFF

_UID_RULE = re.compile(r"owner UID match (?P<uid>\d+)")
_MARK_RULE = re.compile(r"(?:connmark|CONNMARK) match (?P<mark>0x[0-9a-fA-F]+|\d+)")


def forwarding_mark(uid: int) -> int:
    """Stable, reversible conntrack mark for one Unix account UID."""
    if uid < 0 or uid > 0x00FFFFFF:
        raise ValueError("SSH accounting UID is outside the supported 24-bit range")
    return _ACCT_MARK_PREFIX | uid


def uid_from_forwarding_mark(mark: int) -> int | None:
    if mark & 0x1F000000 != _ACCT_MARK_PREFIX:
        return None
    return mark & 0x00FFFFFF


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


def parse_connmark_counters(text: str) -> dict[int, int]:
    """Parse reverse-direction connmark counters → ``{uid: bytes}``.

    iptables-nft and iptables-legacy capitalize the match name differently;
    both retain the exact hexadecimal mark in ``-L -v -x`` output.
    """
    counters: dict[int, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        match = _MARK_RULE.search(line)
        if match is None:
            continue
        head = line.split()
        if len(head) < 2 or not head[1].isdigit():
            continue
        mark = int(match.group("mark"), 0)
        uid = uid_from_forwarding_mark(mark)
        if uid is not None:
            counters[uid] = int(head[1])
    return counters
