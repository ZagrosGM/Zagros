"""Tests for the shared primitives extracted in the v2 refactor:
ManagedProcess, DeltaTracker, SessionUsageTracker.

Run: pytest tests/cores/test_process_stats.py -v   OR   python tests/cores/test_process_stats.py
"""
from __future__ import annotations

import sys
import time
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores.exceptions import CoreError  # noqa: E402
from app.cores.process import ManagedProcess  # noqa: E402
from app.cores.stats import DeltaTracker, SessionUsageTracker  # noqa: E402


def test_delta_tracker_basic_and_reset_accounts_new_generation() -> None:
    tracker = DeltaTracker()
    assert tracker.observe("u1", 100, 1000) == (100, 1000)     # first read: since start
    assert tracker.observe("u1", 150, 1000) == (50, 0)
    assert tracker.observe("u1", 150, 1000) == (0, 0)          # flat -> zero, no double count
    assert tracker.observe("u1", 10, 5) == (10, 5)             # reset: bytes in new generation count
    assert tracker.observe("u1", 30, 5) == (20, 0)             # ...then resumes forward
    tracker.forget("u1")
    assert tracker.observe("u1", 7, 7) == (7, 7)               # forgotten baseline restarts


def test_session_tracker_interim_then_final_no_double_count() -> None:
    tracker = SessionUsageTracker()
    key = ("alice", "2026-08-04T10:00", "203.0.113.5:51234")
    assert tracker.poll(key, 100, 1000) == (100, 1000)         # interim
    assert tracker.poll(key, 400, 1000) == (300, 0)            # interim
    # disconnect hook delivers the session's authoritative final counters:
    assert tracker.close(key, 500, 1100) == (100, 100)         # only what was missing
    # new session starts at 0 -> no negative, no leftovers from the old one
    new_key = ("alice", "2026-08-04T11:00", "203.0.113.5:51235")
    assert tracker.poll(new_key, 42, 42) == (42, 42)
    # A provider that reuses its account-level key on reconnect must account
    # the first counters of the new generation instead of waiting until they
    # exceed the previous session.
    reused = ("bob", "*")
    assert tracker.poll(reused, 1000, 2000) == (1000, 2000)
    assert tracker.poll(reused, 7, 9) == (7, 9)
    # close on a session never polled -> full final
    assert tracker.close("ghost", 9, 9) == (9, 9)


def test_managed_process_lifecycle_and_logs() -> None:
    proc = ManagedProcess(
        ["sh", "-c", "echo start-$PPID; for i in 1 2 3; do echo line-$i; sleep 0.15; done"],
        log_buffer=10,
    )
    assert not proc.is_running
    proc.start()
    assert proc.is_running and proc.pid
    code = proc.wait(timeout=5)
    time.sleep(0.3)                                            # let capture drain
    assert code == 0
    assert not proc.is_running
    logs = proc.logs()
    assert any("line-3" in line for line in logs) and len(logs) == 4

    # double start is a hard error
    proc2 = ManagedProcess(["sh", "-c", "sleep 0.3"])
    proc2.start()
    try:
        proc2.start()
        raise AssertionError("double start must raise CoreError")
    except CoreError:
        pass
    finally:
        proc2.stop()
    assert not proc2.is_running

    # missing executable is reported, not swallowed
    try:
        ManagedProcess(["/definitely/not/a/real/binary-mz"]).start()
        raise AssertionError("missing binary must raise CoreError")
    except CoreError:
        pass


def test_managed_process_metrics_shape() -> None:
    from app.cores.types import CoreMetrics

    proc = ManagedProcess(["sh", "-c", "sleep 0.4"])
    proc.start()
    try:
        metrics = proc.metrics()
        assert isinstance(metrics, CoreMetrics)
        assert metrics.memory_bytes >= 0 and metrics.cpu_percent >= 0
    finally:
        proc.stop()


def _run_all() -> None:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except BaseException:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    _run_all()
