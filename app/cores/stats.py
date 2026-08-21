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

    @staticmethod
    def _delta(current: int, previous: int) -> int:
        """Growth of a cumulative counter, including a provider reset.

        A lower value is not "negative traffic": the provider restarted and
        ``current`` bytes have already crossed the new counter generation.
        Returning zero here silently lost everything between the reset and the
        first poll.  Treat the new value as growth while still never emitting a
        negative delta.
        """
        current = max(0, int(current))
        previous = max(0, int(previous))
        return current - previous if current >= previous else current

    def observe(self, key: object, uplink: int, downlink: int) -> tuple[int, int]:
        """Return growth since the previous read, reset-safe and non-negative."""
        base_up, base_down = self._baseline.get(key, (0, 0))
        uplink, downlink = max(0, int(uplink)), max(0, int(downlink))
        delta_up = self._delta(uplink, base_up)
        delta_down = self._delta(downlink, base_down)
        self._baseline[key] = (uplink, downlink)
        return delta_up, delta_down

    def forget(self, key: object) -> None:
        self._baseline.pop(key, None)

    # ---- restart-safety (recorder job persists these) ----
    def baseline_snapshot(self, keys: list[object] | None = None) -> dict[object, tuple[int, int]]:
        """Current cumulative baselines — saved by the recorder so a panel
        restart resumes accounting instead of re-emitting full counters."""
        if keys is None:
            return dict(self._baseline)
        return {k: v for k, v in self._baseline.items() if k in keys}

    def restore(self, baseline: dict[object, tuple[int, int]]) -> None:
        """Hand back a persisted snapshot (boot-time, before the first read)."""
        self._baseline.update(baseline)


@dataclass(frozen=True, slots=True)
class _SessionState:
    uplink: int
    downlink: int


class SessionUsageTracker:
    """Session-keyed accounting with authoritative disconnect finals."""

    def __init__(self) -> None:
        self._sessions: dict[object, _SessionState] = {}

    def poll(self, key: object, uplink: int, downlink: int) -> tuple[int, int]:
        """Interim delta for a live session counter.

        Some providers reuse a logical account/session key after reconnect.
        When its raw counter drops, this is a new counter generation and the
        new value must be emitted rather than suppressed until it catches the
        previous session's total.
        """
        last = self._sessions.get(key, _SessionState(0, 0))
        uplink, downlink = max(0, int(uplink)), max(0, int(downlink))
        delta = (
            DeltaTracker._delta(uplink, last.uplink),
            DeltaTracker._delta(downlink, last.downlink),
        )
        self._sessions[key] = _SessionState(uplink, downlink)
        return delta

    # ---- restart-safety (interim session counters) ----
    def session_snapshot(self) -> dict[object, tuple[int, int]]:
        return {k: (v.uplink, v.downlink) for k, v in self._sessions.items()}

    def restore_sessions(self, snapshot: dict[object, tuple[int, int]]) -> None:
        self._sessions.update({k: _SessionState(*v) for k, v in snapshot.items()})

    def close(self, key: object, final_uplink: int, final_downlink: int) -> tuple[int, int]:
        """Final delta at disconnect; removes the session baseline.

        Delta is computed against the last interim value, then the session is
        forgotten — a reconnection starting at 0 can never produce negative
        or double-counted traffic afterwards.
        """
        last = self._sessions.pop(key, _SessionState(0, 0))
        return (
            DeltaTracker._delta(final_uplink, last.uplink),
            DeltaTracker._delta(final_downlink, last.downlink),
        )

    def active_sessions(self) -> list[object]:
        return list(self._sessions)
