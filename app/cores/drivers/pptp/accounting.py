"""Durable accounting adapter for the independent ACCEL-PPP PPTP provider.

Live raw counters come from ACCEL-PPP ``show sessions``.  The pppd_compat
ip-down hook supplies authoritative finals.  A small provider-owned SQLite
ledger advances cumulative account totals transactionally, so interim and
final values cannot be counted twice and panel/daemon restarts do not replay
old traffic.
"""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True, slots=True)
class PptpSession:
    ifname: str
    username: str
    calling_sid: str = ""
    assigned_ip: str = ""
    session_id: str = ""
    state: str = "active"
    compression: str = ""
    uptime_seconds: int = 0
    rx_bytes: int = 0  # received by server: client uplink
    tx_bytes: int = 0  # sent by server: client downlink


class PptpAccountingLedger:
    """Cumulative totals plus last-observed raw values for active sessions."""

    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(Path(path).parent, 0o700)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        os.chmod(self.path, 0o600)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        for suffix in ("-wal", "-shm"):
            candidate = self.path + suffix
            if os.path.exists(candidate):
                os.chmod(candidate, 0o600)
        return db

    def _init(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS totals (
                    account_id TEXT PRIMARY KEY,
                    uplink INTEGER NOT NULL DEFAULT 0 CHECK(uplink >= 0),
                    downlink INTEGER NOT NULL DEFAULT 0 CHECK(downlink >= 0)
                );
                CREATE TABLE IF NOT EXISTS active (
                    generation TEXT NOT NULL,
                    ifname TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    uplink INTEGER NOT NULL CHECK(uplink >= 0),
                    downlink INTEGER NOT NULL CHECK(downlink >= 0),
                    PRIMARY KEY(generation, ifname)
                );
                """
            )
        os.chmod(self.path, 0o600)
        for suffix in ("-wal", "-shm"):
            candidate = self.path + suffix
            if os.path.exists(candidate):
                os.chmod(candidate, 0o600)

    @staticmethod
    def _delta(current: int, previous: int) -> int:
        """Cumulative growth across an in-generation raw counter reset."""
        current, previous = max(0, int(current)), max(0, int(previous))
        return current - previous if current >= previous else current

    @staticmethod
    def _add(db: sqlite3.Connection, account_id: str, up: int, down: int) -> None:
        db.execute(
            """INSERT INTO totals(account_id,uplink,downlink) VALUES(?,?,?)
               ON CONFLICT(account_id) DO UPDATE SET
                 uplink=uplink+excluded.uplink,
                 downlink=downlink+excluded.downlink""",
            (account_id, max(0, int(up)), max(0, int(down))),
        )

    def observe(self, generation: str, sessions: Iterable[PptpSession]) -> dict[str, tuple[int, int]]:
        """Advance totals from real live raw counters and return cumulative totals."""
        rows = [session for session in sessions if session.state == "active"]
        with self._connect() as db:
            # A new daemon generation cannot still own old interfaces. Their
            # already-observed bytes are in totals; discard only the baselines.
            db.execute("DELETE FROM active WHERE generation <> ?", (generation,))
            for session in rows:
                previous = db.execute(
                    "SELECT account_id,uplink,downlink FROM active "
                    "WHERE generation=? AND ifname=?",
                    (generation, session.ifname),
                ).fetchone()
                prev_up = int(previous[1]) if previous and previous[0] == session.username else 0
                prev_down = int(previous[2]) if previous and previous[0] == session.username else 0
                self._add(
                    db, session.username,
                    self._delta(session.rx_bytes, prev_up),
                    self._delta(session.tx_bytes, prev_down),
                )
                db.execute(
                    """INSERT INTO active(generation,ifname,account_id,uplink,downlink)
                       VALUES(?,?,?,?,?) ON CONFLICT(generation,ifname) DO UPDATE SET
                         account_id=excluded.account_id,
                         uplink=excluded.uplink,
                         downlink=excluded.downlink""",
                    (generation, session.ifname, session.username,
                     max(0, session.rx_bytes), max(0, session.tx_bytes)),
                )
            return self._totals(db)

    def record_final(
        self, generation: str, ifname: str, account_id: str,
        bytes_received: int, bytes_sent: int,
    ) -> None:
        """Close one session, adding only bytes not emitted by interim polls."""
        if not generation or not ifname or not account_id:
            return
        with self._connect() as db:
            previous = db.execute(
                "SELECT account_id,uplink,downlink FROM active "
                "WHERE generation=? AND ifname=?",
                (generation, ifname),
            ).fetchone()
            prev_up = int(previous[1]) if previous and previous[0] == account_id else 0
            prev_down = int(previous[2]) if previous and previous[0] == account_id else 0
            self._add(
                db, account_id,
                self._delta(bytes_received, prev_up),
                self._delta(bytes_sent, prev_down),
            )
            db.execute(
                "DELETE FROM active WHERE generation=? AND ifname=?",
                (generation, ifname),
            )

    def totals(self) -> dict[str, tuple[int, int]]:
        with self._connect() as db:
            return self._totals(db)

    @staticmethod
    def _totals(db: sqlite3.Connection) -> dict[str, tuple[int, int]]:
        return {
            str(account): (int(up), int(down))
            for account, up, down in db.execute(
                "SELECT account_id,uplink,downlink FROM totals"
            ).fetchall()
        }

    def forget_account(self, account_id: str, *, purge_totals: bool = False) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM active WHERE account_id=?", (account_id,))
            if purge_totals:
                db.execute("DELETE FROM totals WHERE account_id=?", (account_id,))


def hook_from_environment(db_path: str, generation_path: str, ifname: str) -> None:
    """Entry used by the mode-0700 pppd_compat ip-down hook."""
    try:
        generation = Path(generation_path).read_text(encoding="ascii").strip()
        account_id = os.environ.get("PEERNAME", "")
        received = int(os.environ.get("BYTES_RCVD", "0") or 0)
        sent = int(os.environ.get("BYTES_SENT", "0") or 0)
    except (OSError, ValueError):
        return
    PptpAccountingLedger(db_path).record_final(
        generation, ifname, account_id, received, sent
    )
