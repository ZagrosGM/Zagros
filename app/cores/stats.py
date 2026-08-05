"""Counter math shared by every usage-reporting driver.

Two honest primitives (no magic):
  * :class:`DeltaTracker` — cumulative counters (xray stats, hysteria API)
    → non-negative per-read deltas; survives counter resets (core restart).
  * :class:`SessionUsageTracker` — session-scoped accounting (openvpn,
    wireguard, ssh): live counters give *interim* deltas, and a final
    counter delivered at disconnect closes the session — without the
    interim and the final ever being double counted.

Both keep their baselines in memory; the recorder job (Phase 4) persists
them so panel restarts don't double-count either (documented in docs §13).
"""
from __future__ import annotations

from dataclasses import dataclass


class DeltaTracker:
    """Turn cumulative (up, down) counters into deltas since the last read."""

    def __init__(self) -> None:
        self._baseline: dict[object, tuple[int, int]] = {}

    def observe(self, key: object, uplink: int, downlink: int) -> tuple[int, int]:
        """Return (delta_up, delta_down); negative movement (reset) → 0."""
        base_up, base_down = self._baseline.get(key, (0, 0))
        delta_up = max(0, uplink - base_up)
        delta_down = max(0, downlink - base_down)
        self._baseline[key] = (uplink, downlink)
        return delta_up, delta_down

    def forget(self, key: object) -> None:
        self._baseline.pop(key, None)


@dataclass(frozen=True, slots=True)
class _SessionState:
    uplink: int
    downlink: int


class SessionUsageTracker:
    """Session-keyed accounting with authoritative disconnect finals."""

    def __init__(self) -> None:
        self._sessions: dict[object, _SessionState] = {}

    def poll(self, key: object, uplink: int, downlink: int) -> tuple[int, int]:
        """Interim delta for a *live* session counter."""
        last = self._sessions.get(key, _SessionState(0, 0))
        delta = (
            max(0, uplink - last.uplink),
            max(0, downlink - last.downlink),
        )
        self._sessions[key] = _SessionState(max(uplink, last.uplink), max(downlink, last.downlink))
        return delta

    def close(self, key: object, final_uplink: int, final_downlink: int) -> tuple[int, int]:
        """Final delta at disconnect; removes the session baseline.

        Delta is computed against the last interim value, then the session is
        forgotten — a reconnection starting at 0 can never produce negative
        or double-counted traffic afterwards.
        """
        last = self._sessions.pop(key, _SessionState(0, 0))
        return (
            max(0, final_uplink - last.uplink),
            max(0, final_downlink - last.downlink),
        )

    def active_sessions(self) -> list[object]:
        return list(self._sessions)
