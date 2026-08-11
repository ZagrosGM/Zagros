"""OpenSSH ForceCommand helper for exact SFTP/SCP-stream byte accounting.

The SSH transport is already decrypted when subsystem bytes cross this
process' stdin/stdout, so both upload and download are observable without
packet guesses, xt_owner, or private-key access. A kernel-authenticated Unix
socket receiver in LocalSystemSSHBackend attributes the final delta from the
sender UID and persists cumulative counters.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import threading


def _sftp_server() -> str:
    found = shutil.which("sftp-server")
    if found:
        return found
    for path in ("/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server"):
        if os.path.exists(path):
            return path
    raise FileNotFoundError("OpenSSH sftp-server is not installed")


def _command() -> list[str] | None:
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
    if original in ("internal-sftp", "sftp"):
        return [_sftp_server()]
    if "sftp-server" in original:
        argv = shlex.split(original)
        argv[0] = _sftp_server()
        return argv
    # Modern scp uses SFTP and reaches the branches above. Preserve legacy
    # scp, shell and arbitrary commands byte-identically; do not force them
    # through a protocol-unaware proxy.
    return None


def _report(socket_path: str, uplink: int, downlink: int) -> None:
    payload = json.dumps({"uplink": max(0, uplink),
                          "downlink": max(0, downlink)},
                         separators=(",", ":")).encode()
    if len(payload) > 512:
        return
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1)
        sock.sendto(payload, socket_path)
    except OSError:
        # Accounting unavailability must never corrupt a user's SFTP stream.
        pass
    finally:
        sock.close()


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    socket_path = sys.argv[1]
    argv = _command()
    if argv is None:
        original = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
        shell = os.environ.get("SHELL") or "/bin/sh"
        if original:
            os.execv(shell, [shell, "-c", original])
        os.execv(shell, [shell, "-l"])

    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr.buffer,
        close_fds=True,
    )
    assert proc.stdin is not None and proc.stdout is not None
    totals = {"uplink": 0, "downlink": 0}

    def write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]

    def upload() -> None:
        try:
            while True:
                # BufferedReader.read(N) may wait for N bytes, deadlocking on
                # SFTP's small request/response handshake. os.read forwards
                # whatever the pipe currently has.
                chunk = os.read(sys.stdin.fileno(), 65536)
                if not chunk:
                    break
                write_all(proc.stdin.fileno(), chunk)
                totals["uplink"] += len(chunk)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def download() -> None:
        try:
            while True:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                write_all(sys.stdout.fileno(), chunk)
                totals["downlink"] += len(chunk)
        except (BrokenPipeError, OSError):
            pass

    up = threading.Thread(target=upload, daemon=True)
    down = threading.Thread(target=download, daemon=True)
    up.start(); down.start()
    rc = proc.wait()
    down.join(timeout=5)
    _report(socket_path, totals["uplink"], totals["downlink"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
