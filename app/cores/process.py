"""ManagedProcess — the single process-spawning primitive every driver reuses.

Before this existed, each daemon backend (sing-box, openvpn, hysteria2, ...)
re-implemented: Popen, log ring-buffer capture, terminate→kill, psutil metrics,
and "is it alive". One implementation now serves them all (DRY, SRP); backends
compose it instead of inheriting or copying it.
"""
from __future__ import annotations

import logging
import subprocess
import threading
from collections import deque
from collections.abc import Mapping, Sequence

from app.cores.exceptions import CoreError
from app.cores.types import CoreMetrics

logger = logging.getLogger("zagros.cores.process")


class ManagedProcess:
    """Start/stop/restart a child process with log capture and metrics."""

    def __init__(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        log_buffer: int = 200,
        stop_timeout: float = 10.0,
    ) -> None:
        if not argv:
            raise ValueError("ManagedProcess requires a non-empty argv.")
        self.argv = list(argv)
        self.cwd = cwd
        self.env = dict(env) if env else None
        self.stop_timeout = stop_timeout
        self._process: subprocess.Popen | None = None
        self._logs: deque[str] = deque(maxlen=log_buffer)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        with self._lock:
            if self.is_running:
                raise CoreError(f"Process '{self.argv[0]}' is already running.")
            try:
                self._process = subprocess.Popen(
                    self.argv,
                    cwd=self.cwd,
                    env=self.env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                )
            except FileNotFoundError as exc:
                raise CoreError(f"Executable not found: '{self.argv[0]}'.") from exc
            threading.Thread(target=self._capture_logs, daemon=True).start()
        logger.info("Process started: %s (pid=%s)", self.argv[0], self._process.pid)

    def stop(self) -> None:
        with self._lock:
            proc = self._process
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=self.stop_timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
            self._process = None

    def restart(self) -> None:
        self.stop()
        self.start()

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process is not None else None

    # ------------------------------------------------------------------ #
    # observability
    # ------------------------------------------------------------------ #
    def logs(self, tail: int = 200) -> list[str]:
        return list(self._logs)[-tail:]

    def metrics(self) -> CoreMetrics:
        metrics = CoreMetrics()
        try:
            import psutil

            if self.is_running and self._process is not None:
                proc = psutil.Process(self._process.pid)
                metrics.cpu_percent = proc.cpu_percent(interval=None)
                metrics.memory_bytes = proc.memory_info().rss
        except Exception:  # noqa: BLE001 - metrics are best-effort
            pass
        return metrics

    def wait(self, timeout: float | None = None) -> int | None:
        proc = self._process
        if proc is None:
            return None
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #
    def _capture_logs(self) -> None:
        proc = self._process
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            self._logs.append(line.rstrip())
