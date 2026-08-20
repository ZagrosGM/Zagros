from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app.cores.exceptions import CoreError
from app.cores.routing.softether_client import parse_account_status, run_vpncmd_pty


def test_account_status_parser_returns_real_directional_counters() -> None:
    status = parse_account_status(
        """
Session Status                          |Connection Completed (Session Established)
Session Name                            |SID-ALICE-9
Outgoing Data Size                      |11,796 bytes
Incoming Data Size                      |1,234,567 bytes
"""
    )
    assert status == {
        "connected": True,
        "state": "Connection Completed (Session Established)",
        "session": "SID-ALICE-9",
        "uplink_bytes": 11796,
        "downlink_bytes": 1234567,
    }


def _fake_vpncmd(path: Path, *, fail: bool = False) -> None:
    error = "Error occurred. (Error code: 9)\r\n" if fail else (
        "Session Status|Connection Completed\r\n"
        "Outgoing Data Size|7 bytes\r\nIncoming Data Size|9 bytes\r\n"
        "The command completed successfully.\r\n"
    )
    path.write_text(
        """import os,sys
os.write(1,b'Password: ')
password=sys.stdin.readline().strip()
os.write(1,b'VPN Client>')
for line in sys.stdin:
 command=line.strip()
 if command=='exit': break
 os.write(1,command.encode()+b'\\r\\n')
 os.write(1,RESULT.encode())
 os.write(1,b'VPN Client>')
""".replace("RESULT", repr(error))
    )


def test_pty_channel_redacts_admin_and_command_secrets(tmp_path: Path) -> None:
    script = tmp_path / "vpncmd.py"
    _fake_vpncmd(script)
    output = run_vpncmd_pty(
        [sys.executable, str(script)],
        administrator_password="admin-secret-123",
        commands=["AccountPasswordSet edge /PASSWORD:user-secret-456 /TYPE:standard"],
        secrets=["user-secret-456"],
        timeout=3,
    )
    assert "admin-secret-123" not in output
    assert "user-secret-456" not in output
    assert "/PASSWORD:REDACTED" in output


def test_pty_channel_executes_dynamic_followups_in_same_process(tmp_path: Path) -> None:
    script = tmp_path / "vpncmd.py"
    _fake_vpncmd(script)
    seen: list[str] = []

    def followup(transcript: str) -> list[str]:
        seen.append(transcript)
        return ["UserPasswordSet 1.alice /PASSWORD:user-secret-456"]

    output = run_vpncmd_pty(
        [sys.executable, str(script)],
        administrator_password="admin-secret-123",
        commands=["UserList"],
        secrets=["user-secret-456"],
        followup_factory=followup,
        timeout=3,
    )
    assert len(seen) == 1 and "UserList" in seen[0]
    assert "UserPasswordSet 1.alice" in output
    assert "user-secret-456" not in output
    assert "admin-secret-123" not in output


def test_pty_channel_reports_only_verb_and_numeric_error(tmp_path: Path) -> None:
    script = tmp_path / "vpncmd.py"
    _fake_vpncmd(script, fail=True)
    with pytest.raises(CoreError, match=r"AccountPasswordSet.*error code 9") as caught:
        run_vpncmd_pty(
            [sys.executable, str(script)],
            administrator_password="admin-secret-123",
            commands=["AccountPasswordSet edge /PASSWORD:user-secret-456 /TYPE:standard"],
            secrets=["user-secret-456"],
            timeout=3,
        )
    assert "user-secret-456" not in str(caught.value)
    assert "admin-secret-123" not in str(caught.value)


def test_pty_channel_refuses_newline_injection(tmp_path: Path) -> None:
    with pytest.raises(CoreError, match="newline"):
        run_vpncmd_pty(
            [os.fspath(tmp_path / "missing")],
            commands=["NicCreate safe\nAccountDelete victim"],
        )
