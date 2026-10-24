"""Private PTY command channel and parsers for SoftEther VPN Client.

SoftEther's stable ``vpncmd`` drops queued commands when its password prompt is
fed through a plain pipe on some Linux builds.  Passing ``/PASSWORD`` or a
secret-bearing ``/CMD`` in argv would expose credentials through ``/proc``.
This module therefore drives the real interactive client over a private PTY:
argv contains only executable/namespace facts, terminal echo is disabled, and
all returned text is redacted before it can reach a caller or exception.
"""
from __future__ import annotations

import os
import pty
import re
import select
import subprocess
import termios
import threading
import time
from collections.abc import Callable, Sequence

from app.cores.exceptions import CoreError

_MAX_OUTPUT = 1024 * 1024
_ERROR_CODE = re.compile(r"Error occurred\. \(Error code: (\d+)\)", re.I)
_SECRET_SWITCH = re.compile(r"(/(?:PASSWORD|SECRET|PSK):)(?:\"[^\"]*\"|\S+)", re.I)
_SERVER_UNREACHABLE = re.compile(
    rb"Connection to the server failed|Cannot connect to the server", re.I)

# SoftEther's management listener refuses logins that arrive in a burst: a
# handful of vpncmd sessions started within the same second make the server
# answer "Connection to the server failed" even though the socket is up. The
# panel fans out feature edits, account reconciliation and the usage recorder
# from several threads, so without serialisation a healthy server looked dead
# ("inbound creation 422", "usage never recorded", 60 failed boot retries).
_LOGIN_LOCK = threading.Lock()
_MIN_LOGIN_INTERVAL = 0.6
_TRANSIENT_ATTEMPTS = 6


class SoftEtherTransientLoginError(CoreError):
    """The management listener refused a login because it was overloaded.

    Retryable: the same call succeeds once the login burst has drained.
    """


def _redact(text: str, secrets: Sequence[str]) -> str:
    safe = text
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        safe = safe.replace(secret, "REDACTED")
    return _SECRET_SWITCH.sub(r"\1REDACTED", safe)


def run_vpncmd_pty(
    argv: Sequence[str],
    *,
    commands: Sequence[str],
    administrator_password: str = "",
    prompt: str = "VPN Client",
    secrets: Sequence[str] = (),
    timeout: float = 30.0,
    followup_factory: Callable[[str], Sequence[str]] | None = None,
) -> str:
    """Serialised, retrying wrapper around one PTY-managed vpncmd session.

    SoftEther drops rapid successive management logins (see
    ``SoftEtherTransientLoginError``); every caller shares one lock and a
    minimum inter-login interval, and a rejected login is retried with
    backoff instead of surfacing as a bogus credential/endpoint failure.
    """
    last_error: Exception | None = None
    with _LOGIN_LOCK:
        for attempt in range(1, _TRANSIENT_ATTEMPTS + 1):
            _throttle_login()
            try:
                return _run_vpncmd_pty_once(
                    argv,
                    commands=commands,
                    administrator_password=administrator_password,
                    prompt=prompt,
                    secrets=secrets,
                    timeout=timeout,
                    followup_factory=followup_factory,
                )
            except SoftEtherTransientLoginError as exc:
                last_error = exc
                if attempt == _TRANSIENT_ATTEMPTS:
                    raise
                time.sleep(min(1.0 * attempt, 3.0))
    raise CoreError(str(last_error) if last_error else "vpncmd did not run")


_LOGIN_LAST = [0.0]


def _throttle_login() -> None:
    elapsed = time.monotonic() - _LOGIN_LAST[0]
    if elapsed < _MIN_LOGIN_INTERVAL:
        time.sleep(_MIN_LOGIN_INTERVAL - elapsed)
    _LOGIN_LAST[0] = time.monotonic()


def _run_vpncmd_pty_once(
    argv: Sequence[str],
    *,
    commands: Sequence[str],
    administrator_password: str = "",
    prompt: str = "VPN Client",
    secrets: Sequence[str] = (),
    timeout: float = 30.0,
    followup_factory: Callable[[str], Sequence[str]] | None = None,
) -> str:
    """Execute commands against a real vpncmd prompt without argv secrets.

    The function accepts only already-tokenized, secret-free ``argv``. Command
    text and administrator credentials travel over the PTY after their prompts
    appear. Output is bounded and redacted before return. Any vpncmd command
    error is reported by verb + numeric code only. ``followup_factory`` may
    derive one bounded mutation list from the completed initial transcript;
    both phases stay in the same authenticated vpncmd session.
    """

    if not commands:
        raise CoreError("vpncmd interactive command list is empty")
    if "\n" in administrator_password or "\r" in administrator_password:
        raise CoreError("SoftEther client administrator password contains a newline")

    def validate_command(command: str) -> None:
        if not command.strip() or "\n" in command or "\r" in command:
            raise CoreError("vpncmd client command is empty or contains a newline")

    for command in commands:
        validate_command(command)

    master, slave = pty.openpty()
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    process = subprocess.Popen(
        [str(item) for item in argv],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave)
    data = bytearray()
    prompt_re = re.compile(
        rb"(?:" + re.escape(prompt.encode()) + rb")(?:/[^>\r\n]*)?>"
    )

    def read_more(wait: float = 0.2) -> None:
        ready, _, _ = select.select([master], [], [], wait)
        if not ready:
            return
        try:
            chunk = os.read(master, 65536)
        except OSError:
            return
        data.extend(chunk)
        if len(data) > _MAX_OUTPUT:
            raise CoreError("vpncmd output exceeded the bounded one-megabyte limit")

    def wait_for(pattern: re.Pattern[bytes], start: int, label: str) -> None:
        deadline = time.monotonic() + timeout
        while pattern.search(bytes(data[start:])) is None:
            if process.poll() is not None:
                raise CoreError(f"vpncmd exited before {label}")
            if time.monotonic() >= deadline:
                raise CoreError(f"vpncmd timed out waiting for {label}")
            read_more()

    try:
        # A fresh client has no administrator password and may present the
        # command prompt directly. A persisted/password-protected service asks
        # first; handle either state without sending a speculative blank line.
        login_start = 0
        password_re = re.compile(rb"Password:")
        deadline = time.monotonic() + timeout
        while (password_re.search(bytes(data)) is None
               and prompt_re.search(bytes(data)) is None):
            if process.poll() is not None:
                if b"Connection has been established with VPN Server" in data:
                    # The TCP endpoint is correct; vpncmd rejected the selected
                    # hub/admin context before presenting a prompt. Surface a
                    # semantic login failure so callers do not fall through to
                    # unrelated localhost ports (often the panel on TCP/443).
                    raise CoreError("vpncmd server or hub login rejected")
                # ``Connection to the server failed`` here means the listener
                # refused a login burst it is rate-limiting, not that the
                # endpoint is wrong: mark it retryable so the wrapper can back
                # off instead of reporting a bogus credential failure.
                if _SERVER_UNREACHABLE.search(bytes(data)):
                    raise SoftEtherTransientLoginError(
                        "vpncmd management login was refused by the server "
                        "(rate-limited connection attempt)")
                raise CoreError("vpncmd exited during client login")
            if time.monotonic() >= deadline:
                raise CoreError("vpncmd timed out during client login")
            read_more()
        if password_re.search(bytes(data)) is not None:
            auth_start = len(data)
            os.write(master, (administrator_password + "\n").encode())
            denied_re = re.compile(rb"Access has been denied", re.IGNORECASE)
            deadline = time.monotonic() + timeout
            while prompt_re.search(bytes(data[auth_start:])) is None:
                if denied_re.search(bytes(data[auth_start:])) is not None:
                    raise CoreError("vpncmd authentication rejected")
                if process.poll() is not None:
                    raise CoreError(
                        "vpncmd exited before client prompt after authentication"
                    )
                if time.monotonic() >= deadline:
                    raise CoreError(
                        "vpncmd timed out waiting for client prompt after authentication"
                    )
                read_more()

        def execute(command: str) -> None:
            validate_command(command)
            start = len(data)
            os.write(master, (command + "\n").encode())
            wait_for(prompt_re, start, f"completion of {command.split()[0]}")
            segment = _redact(
                bytes(data[start:]).decode("utf-8", errors="replace"),
                [administrator_password, *secrets],
            )
            error = _ERROR_CODE.search(segment)
            if error:
                raise CoreError(
                    f"vpncmd client command '{command.split()[0]}' failed "
                    f"(error code {error.group(1)})"
                )

        for command in commands:
            execute(command)
        if followup_factory is not None:
            # Some reconciliations must inspect one live inventory and decide
            # which mutations are necessary without opening a second vpncmd
            # connection. SoftEther rate-limits rapid localhost logins; keeping
            # discovery + mutation in one authenticated PTY is deterministic,
            # avoids sleeps/retry loops, and preserves command-level errors.
            transcript = _redact(
                bytes(data).decode("utf-8", errors="replace"),
                [administrator_password, *secrets],
            )
            for command in followup_factory(transcript):
                execute(command)
        os.write(master, b"exit\n")
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=3)
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)

    if process.returncode not in (0, None):
        raise CoreError(f"vpncmd interactive client exited with rc={process.returncode}")
    return _redact(
        bytes(data).decode("utf-8", errors="replace"),
        [administrator_password, *secrets],
    )


def parse_account_status(text: str) -> dict[str, int | str | bool]:
    """Extract connection and exact transport counters from AccountStatusGet."""

    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "|" not in line:
            continue
        key, value = line.split("|", 1)
        values[key.strip()] = value.strip()

    state = values.get("Session Status", "")

    def integer(label: str) -> int:
        raw = values.get(label, "0")
        digits = re.sub(r"[^0-9]", "", raw)
        return int(digits or 0)

    return {
        "connected": state.lower().startswith("connection completed"),
        "state": state or "unknown",
        "session": values.get("Session Name", ""),
        "uplink_bytes": integer("Outgoing Data Size"),
        "downlink_bytes": integer("Incoming Data Size"),
    }
