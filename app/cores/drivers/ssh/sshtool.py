"""Pure helpers for the SSH tunnel driver (no IO — fixture-testable).

  * :func:`parse_ps_sshd` — `ps` output → live sshd sessions per user.
  * :func:`sanitize_username` — account_id → safe unix username (accounts are
    prefixed so panel users can never collide with system users).

Honesty note: per-user traffic accounting is *not* implementable correctly
with mainstream tools (iptables owner-match sees egress only; conntrack has
no user identity) — so the driver does not claim USAGE_ACCOUNTING at all
instead of reporting half-truth numbers.
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
    candidate = clean if clean.startswith("mz-") else "mz-" + clean
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
