"""Wizard listen-port suggestion.

The wizard must never default to a famous port (443): every fresh create
gets a RANDOM five-digit port that collides with NOTHING the panel can
observe — ports bound on this host (parsed from /proc, best effort) plus
ports already taken by any managed core's studio document. The choice is
deterministic per wizard-open (the dashboard holds it; re-opening the
wizard draws anew), user-clearable, and standard 1–65535 validation still
applies on submit.
"""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Iterable

PORT_MIN = 10000   # exactly five digits…
PORT_MAX = 65535   # …and inside the registered/dynamic TCP+UDP range

_PROC_FILES = ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6")


def parse_proc_net_listeners(text: str) -> set[int]:
    """Ports from /proc/net/{tcp,udp} text rows — local_address hex field.

    Listening state (0A) for TCP; for UDP every bound socket (no LISTEN
    state exists) since a bound UDP port cannot be reused either.
    """
    ports: set[int] = set()
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local, state = parts[1], parts[3]
        try:
            port = int(local.rsplit(":", 1)[1], 16)
        except (IndexError, ValueError):
            continue
        if state == "0A" or state not in ("0A",):  # LISTEN or (UDP) bound row
            if 0 < port <= 65535:
                ports.add(port)
    return ports


def host_listening_ports(paths: Iterable[str] = _PROC_FILES) -> set[int]:
    """Best-effort union of currently-bound ports (missing /proc = empty,
    never fatal — e.g. non-Linux dev hosts)."""
    out: set[int] = set()
    for path in paths:
        try:
            out |= parse_proc_net_listeners(Path(path).read_text())
        except OSError:
            continue
    return out


async def studio_used_ports(runtime) -> set[int]:
    """Ports of every inbound across all managed cores' studio documents —
    a port the panel itself already serves somewhere is NOT a suggestion."""
    used: set[int] = set()
    try:
        core_ids = runtime.core_manager.list_cores()
    except Exception:  # noqa: BLE001
        return used
    for core_id in core_ids:
        try:
            doc = await runtime.studio_store.get_document(core_id)
        except Exception:  # noqa: BLE001 — one bad doc must not break the pick
            continue
        for item in (doc or {}).get("inbounds") or []:
            if isinstance(item, dict):
                try:
                    port = int(item.get("port"))
                except (TypeError, ValueError):
                    continue
                used.add(port)
    return used


def suggest_port(excluded: Iterable[int], *, rng: secrets.SystemRandom | None = None,
                 lo: int = PORT_MIN, hi: int = PORT_MAX) -> int:
    """One random five-digit port outside ``excluded``; deterministic
    linear-probe fallback if random draws keep colliding (never hangs)."""
    rng = rng or secrets.SystemRandom()
    skip = set(excluded)
    for _ in range(64):
        candidate = rng.randint(lo, hi)
        if candidate not in skip:
            return candidate
    start = rng.randint(lo, hi)
    span = hi - lo + 1
    for step in range(span):
        candidate = lo + ((start - lo + step) % span)
        if candidate not in skip:
            return candidate
    raise RuntimeError("no free port left in the suggestion range")
