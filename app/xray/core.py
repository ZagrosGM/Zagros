import atexit
import logging
import os
import re
import subprocess
import threading
from collections import deque
from contextlib import contextmanager

from app import logger
from app.xray.config import XRayConfig
from config import DEBUG


class XRayCore:
    def __init__(self,
                 executable_path: str = "/var/lib/zagros/cores/xray/bin/xray",
                 assets_path: str = "/var/lib/zagros/cores/xray/assets"):
        self.executable_path = executable_path
        self.assets_path = assets_path

        # Zagros ships no baked-in core binaries: a missing xray executable
        # must NEVER prevent the panel from booting (multi-core drivers
        # self-install on demand). Degrade to version=None and let the
        # already-guarded start path report the core as down honestly.
        try:
            self.version = self.get_version()
        except (OSError, subprocess.SubprocessError) as exc:
            self.version = None
            logging.getLogger("uvicorn.error").warning(
                "xray binary not usable at '%s' (%s) — Start will restore it "
                "through the shared installer into the persistent core path.",
                executable_path, exc)
        self.process = None
        self.restarting = False

        self._logs_buffer = deque(maxlen=100)
        self._temp_log_buffers = {}
        self._on_start_funcs = []
        self._on_stop_funcs = []
        self._env = {
            "XRAY_LOCATION_ASSET": assets_path
        }

        atexit.register(lambda: self.stop() if self.started else None)

    def get_version(self):
        cmd = [self.executable_path, "version"]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8')
        m = re.match(r'^Xray (\d+\.\d+\.\d+)', output)
        if m:
            return m.groups()[0]

    def get_x25519(self, private_key: str = None):
        cmd = [self.executable_path, "x25519"]
        if private_key:
            cmd.extend(['-i', private_key])
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8')
        m = re.match(r'Private key: (.+)\nPublic key: (.+)', output)
        if m:
            private, public = m.groups()
            return {
                "private_key": private,
                "public_key": public
            }

    def __capture_process_logs(self):
        def capture_and_debug_log():
            while self.process:
                output = self.process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)
                    logger.debug(output)

                elif not self.process or self.process.poll() is not None:
                    break

        def capture_only():
            while self.process:
                output = self.process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)

                elif not self.process or self.process.poll() is not None:
                    break

        # daemon=True (zagros hard-fork hardening): these threads block in
        # readline() for the whole lifetime of the xray process; a non-daemon
        # capture thread pins interpreter shutdown forever whenever a consumer
        # exits without an explicit stop() (observed in CI: pytest printed its
        # summary, the process then hung in threading._shutdown). Log capture
        # must never hold the interpreter hostage.
        if DEBUG:
            threading.Thread(target=capture_and_debug_log, daemon=True).start()
        else:
            threading.Thread(target=capture_only, daemon=True).start()

    @contextmanager
    def get_logs(self):
        buf = deque(self._logs_buffer, maxlen=100)
        buf_id = id(buf)
        try:
            self._temp_log_buffers[buf_id] = buf
            yield buf
        finally:
            del self._temp_log_buffers[buf_id]
            del buf

    @property
    def started(self):
        if not self.process:
            return False

        if self.process.poll() is None:
            return True

        return False

    def _ensure_binary(self) -> None:
        if os.path.isfile(self.executable_path) and os.access(
                self.executable_path, os.X_OK):
            return
        # The legacy singleton starts before CoreManager attaches the built-in
        # driver. Use that driver's shared, checksum-aware installer directly,
        # targeting the mounted data tree so an image update never discards it.
        from app.cores.drivers.xray.driver import _install_xray

        _install_xray({
            "executable_path": self.executable_path,
            "assets_path": self.assets_path,
            "release_version": "",
        })
        self.version = self.get_version()

    def start(self, config: XRayConfig):
        if self.started is True:
            raise RuntimeError("Xray is started already")
        self._ensure_binary()

        if config.get('log', {}).get('logLevel') in ('none', 'error'):
            config['log']['logLevel'] = 'warning'

        cmd = [
            self.executable_path,
            "run",
            '-config',
            'stdin:'
        ]
        self.process = subprocess.Popen(
            cmd,
            env=self._env,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True
        )
        self.process.stdin.write(config.to_json())
        self.process.stdin.flush()
        self.process.stdin.close()
        logger.warning(f"Xray core {self.version} started")

        self.__capture_process_logs()

        # execute on start functions (daemons: a stuck one-shot callback must
        # never block interpreter shutdown; see __capture_process_logs note)
        for func in self._on_start_funcs:
            threading.Thread(target=func, daemon=True).start()

    def stop(self):
        if not self.started:
            return

        self.process.terminate()
        self.process = None
        logger.warning("Xray core stopped")

        # execute on stop functions (daemons: same reasoning as start funcs)
        for func in self._on_stop_funcs:
            threading.Thread(target=func, daemon=True).start()

    def restart(self, config: XRayConfig):
        if self.restarting is True:
            return

        try:
            self.restarting = True
            logger.warning("Restarting Xray core...")
            self.stop()
            self.start(config)
        finally:
            self.restarting = False

    def on_start(self, func: callable):
        self._on_start_funcs.append(func)
        return func

    def on_stop(self, func: callable):
        self._on_stop_funcs.append(func)
        return func
