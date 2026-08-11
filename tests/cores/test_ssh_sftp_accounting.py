"""Real local Unix-socket + stream proxy accounting for OpenSSH SFTP."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from app.cores.drivers.ssh.backend import LocalSystemSSHBackend


def test_sftp_stream_proxy_reports_both_directions_and_persists(tmp_path):
    backend = LocalSystemSSHBackend({"work_dir": str(tmp_path)})
    socket_path = backend.sftp_acct_start()

    # Deterministic stand-in for the OpenSSH sftp-server process. This does
    # not fake accounting: production's actual wrapper, bidirectional pumps,
    # Unix datagram, SO_PASSCRED UID attribution and persisted backend state
    # all run unchanged.
    tools = tmp_path / "tools"
    tools.mkdir()
    server = tools / "sftp-server"
    server.write_text("#!/bin/sh\ncat\n")
    server.chmod(0o755)
    payload = (b"sftp-upload-block-" * 8192)
    env = {
        **os.environ,
        "PATH": f"{tools}:{os.environ.get('PATH', '')}",
        "SSH_ORIGINAL_COMMAND": "internal-sftp",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "app.cores.drivers.ssh.sftp_accounting",
         socket_path],
        input=payload, capture_output=True, env=env, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert proc.stdout == payload

    uid = os.getuid()
    deadline = time.monotonic() + 3
    counters = {}
    while time.monotonic() < deadline:
        counters = backend.sftp_acct_read()
        if uid in counters:
            break
        time.sleep(0.05)
    assert counters[uid] == (len(payload), len(payload))
    backend.sftp_acct_stop()

    # A panel/backend restart resumes cumulative state and never re-bills the
    # whole transfer as a fresh counter.
    restored = LocalSystemSSHBackend({"work_dir": str(tmp_path)})
    assert restored.sftp_acct_read()[uid] == (len(payload), len(payload))
    assert (tmp_path / "sftp-usage.json").stat().st_mode & 0o777 == 0o600


def test_dropin_uses_forcecommand_without_duplicate_subsystem(tmp_path):
    backend = LocalSystemSSHBackend({
        "work_dir": str(tmp_path),
        "dropin_path": str(tmp_path / "zagros.conf"),
        "listeners": [{"tag": "ssh-main", "port": 22022}],
        "sftp": True,
    })
    text = backend.render_dropin()
    assert "Subsystem sftp" not in text
    assert "Match User zg-*" in text
    assert "ForceCommand" in text and "sftp_accounting.py" in text
    assert "Match all" in text
