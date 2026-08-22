"""OpenVPN Management Interface client — the real protocol, not a wrapper.

Protocol facts this models (openvpn ``--management 127.0.0.1 PORT``):
  * single TCP channel; server greets with ``>INFO:...``
  * commands are line-based; responses end with ``END`` (multi-line) or a
    single ``SUCCESS:`` / ``ERROR:`` line
  * with ``--management-client-auth`` the server streams ``>CLIENT:CONNECT``
    / ``>CLIENT:REAUTH`` events followed by ``>CLIENT:ENV,key=value`` lines
    (including ``username``, ``password``, ``IV_PLAT``, ``IV_VER``) and BLOCKS
    the handshake until we answer ``client-auth`` / ``client-auth-nt`` or
    ``client-deny`` — the panel *is* the authentication authority.

The line router (:meth:`_feed_line`) is transport-independent, which is how
tests drive full auth sessions and command round-trips without sockets.
"""
from __future__ import annotations

import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import Callable

from app.cores.exceptions import CoreError

logger = logging.getLogger("zagros.cores.drivers.openvpn.mgmt")

@dataclass(frozen=True, slots=True)
class AuthDecision:
    allow: bool
    config_lines: tuple[str, ...] = ()
    reason: str = "denied"


AuthHandler = Callable[["AuthRequest"], bool | AuthDecision]


@dataclass(slots=True)
class AuthRequest:
    """One pending client handshake, awaiting the panel's verdict."""

    cid: int
    kid: int
    reauth: bool
    env: dict[str, str] = field(default_factory=dict)

    @property
    def username(self) -> str:
        return self.env.get("username", "")

    @property
    def password(self) -> str:
        return self.env.get("password", "")

    @property
    def platform(self) -> str | None:
        return self.env.get("IV_PLAT") or None

    @property
    def client_version(self) -> str | None:
        return self.env.get("IV_VER") or None


@dataclass(frozen=True, slots=True)
class StatusClient:
    """One row of the CLIENT_LIST section of ``status 3``."""

    common_name: str
    username: str
    real_ip: str
    real_port: int
    virtual_address: str
    bytes_received: int                 # client → server  == user UPLINK
    bytes_sent: int                     # server → client  == user DOWNLINK
    connected_since: str
    cid: str = ""
    cipher: str = ""

    @property
    def session_key(self) -> tuple[str, str, str]:
        """Unique per (user, session-start) — reconnects never alias."""
        return (self.common_name, self.connected_since, self.real_ip)


def parse_status3(text: str) -> list[StatusClient]:
    """Parse ``status 3`` output into client rows (header-driven, column-safe)."""
    clients: list[StatusClient] = []
    columns: list[str] = []
    for raw in text.splitlines():
        fields = raw.split("\t")
        if not fields:
            continue
        if fields[0] == "HEADER" and len(fields) > 1 and fields[1] == "CLIENT_LIST":
            columns = fields[2:]
        elif fields[0] == "CLIENT_LIST" and columns:
            row = dict(zip(columns, fields[1:], strict=False))

            def _to_int(value: str | None) -> int:
                try:
                    return int(value or 0)
                except ValueError:
                    return 0

            real_ip, _, real_port = (row.get("Real Address") or "").rpartition(":")
            clients.append(
                StatusClient(
                    common_name=row.get("Common Name", ""),
                    username=row.get("Username", row.get("Common Name", "")),
                    real_ip=real_ip,
                    real_port=_to_int(real_port),
                    virtual_address=row.get("Virtual Address", ""),
                    bytes_received=_to_int(row.get("Bytes Received")),
                    bytes_sent=_to_int(row.get("Bytes Sent")),
                    connected_since=row.get("Connected Since", ""),
                    cid=row.get("Client ID", ""),
                    cipher=row.get("Data Channel Cipher", ""),
                )
            )
    return clients


@dataclass(frozen=True, slots=True)
class DisconnectRecord:
    """Authoritative final counters of one finished session (hook-written)."""

    common_name: str
    bytes_received: int
    bytes_sent: int
    duration_seconds: int
    ended_at: int


class ManagementClient:
    """Line-routed management client: one socket, interleaved commands/events."""

    def __init__(self, writer: Callable[[str], None] | None = None):
        self._writer = writer
        self._sock: socket.socket | None = None
        self._reader_thread: threading.Thread | None = None
        self._cond = threading.Condition()
        self._response: list[str] = []
        self._awaiting = False
        self._auth_handler: AuthHandler | None = None
        self._pending: dict[int, AuthRequest] = {}
        self._active_cid: int | None = None

    # ------------------------------------------------------------------ #
    # production wiring
    # ------------------------------------------------------------------ #
    def connect(self, host: str, port: int, *, password: str | None = None, timeout: float = 5.0) -> None:
        self._sock = socket.create_connection((host, port), timeout=timeout)
        if password is not None:
            self._write(password)
        # create_connection's timeout remains attached to the socket. The
        # management channel is intentionally long-lived and often idle; if
        # left in place, recv() raises socket.timeout after a few seconds, the
        # reader thread exits silently, and later CLIENT/PUSH events pile up
        # unread forever. Keep the connect deadline, then switch to blocking
        # mode before starting the permanent reader.
        self._sock.settimeout(None)
        self._writer = self._write
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _write(self, line: str) -> None:
        if self._sock is None:
            raise CoreError("management client is not connected.")
        self._sock.sendall(line.encode() + b"\n")

    def _read_loop(self) -> None:
        assert self._sock is not None
        try:
            buffer = b""
            while True:
                chunk = self._sock.recv(65536)
                if not chunk:
                    break
                buffer += chunk
                *lines, buffer = buffer.split(b"\n")
                for raw in lines:
                    self._feed_line(raw.decode(errors="replace").rstrip("\r"))
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # commands
    # ------------------------------------------------------------------ #
    def command(self, cmd: str, *, timeout: float = 30.0) -> str:
        with self._cond:
            self._response.clear()
            self._awaiting = True
        (self._writer or self._write)(cmd)
        with self._cond:
            if not self._cond.wait_for(lambda: not self._awaiting, timeout=timeout):
                self._awaiting = False
                raise CoreError(f"management command timed out: {cmd!r}")
            text = "\n".join(self._response)
        if text.startswith("ERROR:"):
            raise CoreError(text)
        return text

    # ------------------------------------------------------------------ #
    # auth events
    # ------------------------------------------------------------------ #
    def set_auth_handler(self, handler: AuthHandler | None) -> None:
        self._auth_handler = handler

    def authorize(
        self, request: AuthRequest, decision: bool | AuthDecision, *,
        reason: str = "denied",
    ) -> None:
        write = self._writer or self._write
        result = (decision if isinstance(decision, AuthDecision)
                  else AuthDecision(bool(decision), reason=reason))
        if result.allow:
            write(f"client-auth-nt {request.cid} {request.kid}" if request.reauth
                  else f"client-auth {request.cid} {request.kid}")
            if not request.reauth:
                for line in result.config_lines:
                    if "\n" in line or "\r" in line:
                        raise CoreError("OpenVPN client-auth config line contains newline")
                    write(line)
                write("END")
        else:
            write(f'client-deny {request.cid} {request.kid} "{result.reason}"')

    # ------------------------------------------------------------------ #
    # line routing (transport-independent core)
    # ------------------------------------------------------------------ #
    def _feed_line(self, line: str) -> None:
        if line.startswith(">"):
            self._handle_event(line[1:])
            return
        with self._cond:
            self._response.append(line)
            if line == "END" or line.startswith(("SUCCESS:", "ERROR:", "IGNORE:")):
                self._awaiting = False
                self._cond.notify_all()

    def _handle_event(self, body: str) -> None:
        if body.startswith(("CLIENT:CONNECT,", "CLIENT:REAUTH,")):
            reauth = body.startswith("CLIENT:REAUTH,")
            _kind, cid, kid = body.split(",", 2)
            self._pending[int(cid)] = AuthRequest(cid=int(cid), kid=int(kid), reauth=reauth)
            self._active_cid = int(cid)
        elif body.startswith("CLIENT:DISCONNECT"):
            try:
                cid = int(body.split(",")[1])
            except (IndexError, ValueError):
                return
            self._pending.pop(cid, None)
        elif body.startswith("CLIENT:ENV,"):
            payload = body[len("CLIENT:ENV,"):]
            if payload == "END":
                request = self._pending.pop(self._active_cid, None)  # type: ignore[arg-type]
                if request is not None:
                    if self._auth_handler is None:
                        # Fail closed, but always ANSWER. Silently dropping a
                        # complete CONNECT request leaves OpenVPN waiting for
                        # management auth and the client frozen at PUSH_REQUEST.
                        logger.error(
                            "no OpenVPN auth handler for cid=%s; denying instead of hanging",
                            request.cid,
                        )
                        self.authorize(request, False,
                                       reason="authentication handler unavailable")
                        return
                    try:
                        allow = self._auth_handler(request)
                    except Exception:  # noqa: BLE001 - never hang the handshake
                        logger.exception("auth handler crashed; denying cid=%s", request.cid)
                        allow = False
                    self.authorize(request, allow)
            elif self._active_cid in self._pending and "=" in payload:
                key, _, value = payload.partition("=")
                self._pending[self._active_cid].env[key] = value  # type: ignore[index]
