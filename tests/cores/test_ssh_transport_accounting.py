"""Bidirectional SSH transport accounting regressions.

The production collector reads accepted sshd transport sockets, maps the
non-root sshd-session PID to its Unix UID, and persists cumulative encrypted
wire bytes. These tests pin parsing, direction, delta, and restart behavior;
real known-payload evidence belongs to the VPS gate.
"""
from __future__ import annotations

import stat
import subprocess

from app.cores.drivers.ssh.backend import LocalSystemSSHBackend


def test_ss_snapshot_maps_dropped_uid_and_wire_directions(tmp_path, monkeypatch) -> None:
    backend = LocalSystemSSHBackend({"work_dir": str(tmp_path)})
    backend._transport_ports = {48302}
    output = """ESTAB 0 0 109.248.161.249:48302 203.0.113.9:40400 users:((\"sshd-session\",pid=22,fd=7),(\"sshd-session\",pid=33,fd=7))
\t bbr bytes_sent:1069481 bytes_acked:1069481 bytes_received:269282 segs_out:102
"""
    monkeypatch.setattr("app.cores.drivers.ssh.backend.shutil.which",
                        lambda name: "/usr/sbin/ss" if name == "ss" else None)
    monkeypatch.setattr(
        "app.cores.drivers.ssh.backend.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, ""),
    )
    monkeypatch.setattr(backend, "_pid_uid", lambda pid: 1001 if pid == 33 else None)
    snapshot = backend._transport_snapshot()
    assert snapshot == {"48302:22,33": (1001, 269282, 1069481)}


def test_transport_deltas_persist_without_restart_double_count(tmp_path, monkeypatch) -> None:
    backend = LocalSystemSSHBackend({"work_dir": str(tmp_path)})
    states = iter([
        {"48302:22,33": (1001, 100, 500)},
        {"48302:22,33": (1001, 300, 900)},
        {"48302:22,33": (1001, 300, 900)},
    ])
    monkeypatch.setattr(backend, "_transport_snapshot", lambda: next(states))
    backend._transport_collect_once()
    backend._transport_collect_once()
    assert backend.transport_acct_read() == {1001: (300, 900)}
    assert stat.S_IMODE((tmp_path / "transport-usage.json").stat().st_mode) == 0o600

    # Recreate the backend as a Panel/core restart would. Persisted live socket
    # baselines prevent charging the same still-open transport a second time.
    restored = LocalSystemSSHBackend({"work_dir": str(tmp_path)})
    states2 = iter([
        {"48302:22,33": (1001, 300, 900)},
        {"48302:22,33": (1001, 425, 1200)},
        {"48302:22,33": (1001, 425, 1200)},
    ])
    monkeypatch.setattr(restored, "_transport_snapshot", lambda: next(states2))
    restored._transport_collect_once()
    restored._transport_collect_once()
    assert restored.transport_acct_read() == {1001: (425, 1200)}


def test_fresh_host_agent_snapshot_is_used_inside_container(tmp_path) -> None:
    import json
    import time

    backend = LocalSystemSSHBackend({"work_dir": str(tmp_path)})
    (tmp_path / "host-transport-usage.json").write_text(json.dumps({
        "version": 1,
        "updated_at": int(time.time()),
        "totals": {"1001": [123, 456]},
        "live": {},
    }))
    backend.transport_acct_start({2022})
    assert backend._host_transport is True
    assert backend.transport_acct_read() == {1001: (123, 456)}
    assert json.loads((tmp_path / "accounting-listeners.json").read_text()) == [2022]
    assert stat.S_IMODE((tmp_path / "accounting-listeners.json").stat().st_mode) == 0o600


def test_transport_forget_removes_deleted_uid_and_private_state(tmp_path) -> None:
    backend = LocalSystemSSHBackend({"work_dir": str(tmp_path)})
    backend._transport_totals = {1001: (10, 20), 1002: (30, 40)}
    backend._transport_live = {
        "a": (1001, 10, 20),
        "b": (1002, 30, 40),
    }
    backend.transport_acct_forget(1001)
    assert backend._transport_totals == {1002: (30, 40)}
    assert backend._transport_live == {"b": (1002, 30, 40)}
    assert stat.S_IMODE((tmp_path / "transport-usage.json").stat().st_mode) == 0o600
