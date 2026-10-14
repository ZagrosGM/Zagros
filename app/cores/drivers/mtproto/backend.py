"""Local MTProto proxy runtime boundary (vendored, patched alexbers daemon).

The panel ships ``vendor/mtprotoproxy.py`` — the upstream alexbers/mtprotoproxy
daemon with two surgical Zagros patches (both upstreamable):

* ``PORTS`` list — several proxy ports (inbounds) on ONE process;
* per-user ad tag — ``USERS`` entries may be ``{"secret": <32hex>, "tag":
  <32hex>}``; the promoted-channel tag is attached per connection instead of
  globally, so every panel user gets their own ad tag on the SAME port.

Process management follows the PPTP core pattern: a ``ManagedProcess`` child
python, a rendered ``config.py`` in the work dir, and honest status from the
daemon's own Prometheus exporter (per-user octets + live connections).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
import shutil
import signal
import socket
import urllib.request
from pathlib import Path
from typing import Any

from app.cores.exceptions import CoreError
from app.cores.process import ManagedProcess

VENDOR_DIR = Path(__file__).resolve().parent / "vendor"
DAEMON_VERSION = "3.1.304-zagros.3"  # upstream base + zagros patches (PORTS, per-user ad tag, PUBLIC_IP preset)

_TAG_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SECRET_RE = re.compile(r"^[0-9a-fA-F]{32}$")


class LocalMtprotoBackend:
    """One python child process serving every inbound port + accounts."""

    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings
        self.work_dir = str(settings.get("work_dir") or
                            "/var/lib/zagros/cores/mtproto")
        self.config_path = os.path.join(self.work_dir, "config.py")
        self.log_path = os.path.join(self.work_dir, "proxy.log")
        self.metrics_port = int(settings.get("metrics_port") or 23456)
        self.generation_path = os.path.join(self.work_dir, "generation")
        self._proc: ManagedProcess | None = None

    # ------------------------------------------------------------------ #
    def _ensure_dir(self) -> None:
        os.makedirs(self.work_dir, mode=0o750, exist_ok=True)
        marker = Path(self.generation_path)
        if not marker.exists():
            marker.write_text("0", encoding="ascii")

    def generation(self) -> int:
        try:
            return int(Path(self.generation_path).read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return 0

    def accounts_on_disk(self) -> dict[str, dict[str, str]]:
        """The driver's account store (work_dir/accounts.json) — the source
        the config renderer uses. Falls back to parsing the rendered config
        for pre-store deployments."""
        try:
            return json.loads(
                Path(self.work_dir, "accounts.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        try:
            text = Path(self.config_path).read_text(encoding="utf-8")
        except OSError:
            return {}
        accounts: dict[str, dict[str, str]] = {}
        for m in re.finditer(
                r'"([^"]+)":\s*\{"secret":\s*"([0-9a-f]{32})",'
                r'\s*"tag":\s*"([0-9a-f]{0,32})"\}', text):
            accounts[m.group(1)] = {"secret": m.group(2), "tag": m.group(3)}
        return accounts

    def save_accounts(self, accounts: dict[str, dict[str, str]]) -> None:
        """Atomically persist the account store next to the rendered config."""
        self._ensure_dir()
        tmp = Path(self.work_dir, "accounts.json.tmp")
        tmp.write_text(json.dumps(accounts, indent=1, sort_keys=True),
                       encoding="utf-8")
        tmp.replace(Path(self.work_dir, "accounts.json"))

    def _public_ip_presets(self) -> tuple[str | None, str | None]:
        """(ipv4, ipv6) presets for the daemon's PUBLIC_IPV4/PUBLIC_IPV6.

        Resolves settings.advertise_host (IP literal or hostname) with a
        small per-process cache; (None, None) when unknown — the daemon
        then falls back to its own (blocking, often unreachable) lookup
        services."""
        cached = getattr(self, "_advertise_cache", None)
        if cached is not None and cached[0] == str(
                self.settings.get("advertise_host") or ""):
            return cached[1], cached[2]
        host = str(self.settings.get("advertise_host") or "").strip()
        v4: str | None = None
        v6: str | None = None
        if host:
            try:
                import ipaddress as _ip
                addr = _ip.ip_address(host)
                if addr.version == 6:
                    v6 = str(addr)
                else:
                    v4 = str(addr)
            except ValueError:
                try:
                    import socket as _s
                    infos = _s.getaddrinfo(host, None, proto=_s.IPPROTO_TCP)
                    for family, _typ, _proto, _canon, sockaddr in infos:
                        ip = sockaddr[0]
                        if family == _s.AF_INET6 and v6 is None and ":" in ip:
                            v6 = ip
                        elif family == _s.AF_INET and v4 is None:
                            v4 = ip
                except OSError:
                    pass
        self._advertise_cache = (host, v4, v6)
        return v4, v6

    def render_config(self, inbounds: list[dict[str, Any]],
                      accounts: list[dict[str, Any]]) -> str:
        """Render config.py. ``accounts`` = [{'account_id','secret','tag'}]."""
        ports = sorted({int(ib["port"]) for ib in inbounds if ib.get("port")})
        if not ports:
            raise CoreError("MTProto core needs at least one inbound port")
        public4, public6 = self._public_ip_presets()
        lines = ["USERS = {"]
        for a in accounts:
            lines.append('    "%s": {"secret": "%s", "tag": "%s"},' % (
                a["account_id"], a["secret"], a.get("tag") or ""))
        lines.append("}")
        users_block = "\n".join(lines)
        return (
            "# Rendered by the Zagros panel — do not edit.\n"
            f"PORT = {ports[0]}\n"
            f"PORTS = {ports!r}\n"
            f"{users_block}\n"
            "USERS_TAGS = {}\n"          # patched daemon derives them from USERS
            f"PUBLIC_IPV4 = {public4!r}\n"
            f"PUBLIC_IPV6 = {public6!r}\n"
            "AD_TAG = \"\"\n"
            "USE_MIDDLE_PROXY = True\n"  # required for ad-tag delivery
            f"METRICS_PORT = {self.metrics_port}\n"
            "METRICS_LISTEN_ADDR_IPV4 = \"127.0.0.1\"\n"
            "METRICS_LISTEN_ADDR_IPV6 = None\n"
            "STATS_PRINT_PERIOD = 6 * 60 * 60\n"
            "MODES = {\"classic\": True, \"secure\": True, \"tls\": True}\n"
        )

    def write_config(self, inbounds: list[dict[str, Any]],
                     accounts: list[dict[str, Any]]) -> None:
        self._ensure_dir()
        tmp = self.config_path + ".tmp"
        Path(tmp).write_text(self.render_config(inbounds, accounts),
                             encoding="utf-8")
        os.replace(tmp, self.config_path)

    def bump_generation(self) -> None:
        Path(self.generation_path).write_text(
            str(self.generation() + 1), encoding="ascii")

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self._ensure_dir()
        if not Path(self.config_path).exists():
            raise CoreError("MTProto config is not rendered yet — save an inbound first")
        if self.is_running():
            return
        python = shutil.which("python3") or shutil.which("python")
        if not python:
            raise CoreError("no python3 available on this host")
        # the vendored daemon imports the config via runpy.run_module, which
        # resolves through sys.path — the script dir (vendor/) wins over the
        # cwd, so the work dir must be on PYTHONPATH explicitly.
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [self.work_dir, env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
        # argv[1] = explicit config path — the daemon's own "launch with own
        # config" mode (runpy.run_path); no cwd/sys.path trickery needed.
        self._proc = ManagedProcess(
            [python, "-u", str(VENDOR_DIR / "mtprotoproxy.py"),
             str(self.config_path)],
            cwd=self.work_dir, env=env,
        )
        self._proc.start()
        # crash-latch: give the daemon a moment and fail LOUD with its own
        # log tail instead of reporting a phantom "running" state.
        time.sleep(1.5)
        if not self._proc.is_running:
            tail = "; ".join(self._proc.logs(20))
            raise CoreError(f"MTProto daemon exited immediately: {tail}")

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.stop()
            self._proc = None
        # a daemon leaked by a crashed panel/test process still holds the
        # ports — stop() must leave NOTHING listening from this work dir
        self._sweep_orphans()

    def _sweep_orphans(self) -> None:
        """SIGTERM (then SIGKILL after a 3s grace) any vendored daemon whose
        cwd is OUR work dir but which this backend does not own."""
        try:
            out = subprocess_run(["pgrep", "-f", "mtprotoproxy.py"])
        except Exception:  # noqa: BLE001 — stop must never raise
            return
        work = Path(self.work_dir).resolve()
        for token in out.split():
            try:
                pid = int(token)
            except ValueError:
                continue
            try:
                if Path(f"/proc/{pid}/cwd").resolve() != work:
                    continue
                os.kill(pid, signal.SIGTERM)
                for _ in range(30):
                    if not Path(f"/proc/{pid}").exists():
                        break
                    time.sleep(0.1)
                else:
                    os.kill(pid, signal.SIGKILL)
            except OSError:  # already gone / permission — nothing to do
                continue

    def is_running(self) -> bool:
        if self._proc is not None and self._proc.is_running:
            return True
        # adopted child from a previous panel boot: match the vendored daemon
        try:
            out = subprocess_run(["pgrep", "-f",
                                  "mtprotoproxy.py"])
            for pid in out.split():
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as fh:
                        cmdline = fh.read().decode(errors="replace")
                    if "mtprotoproxy.py" in cmdline:
                        cwd_link = Path(f"/proc/{pid}/cwd")
                        if cwd_link.resolve() == Path(self.work_dir).resolve():
                            return True
                except OSError:
                    continue
        except Exception:  # noqa: BLE001 — status must never raise
            pass
        return False

    def reload(self) -> None:
        """SIGUSR2 → the daemon re-reads config.py without dropping clients."""
        pid = self.child_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGUSR2)
                return
            except OSError:
                pass
        # no live child (or adopted one died): full restart
        self.stop()
        self.start()

    def child_pid(self) -> int | None:
        if self._proc is not None and self._proc.is_running:
            return self._proc._process.pid
        try:
            out = subprocess_run(["pgrep", "-f", "mtprotoproxy.py"])
            for pid in out.split():
                try:
                    cwd_link = Path(f"/proc/{pid}/cwd")
                    if cwd_link.resolve() == Path(self.work_dir).resolve():
                        return int(pid)
                except (OSError, ValueError):
                    continue
        except Exception:  # noqa: BLE001
            pass
        return None

    def logs(self, tail: int = 200) -> list[str]:
        try:
            lines = Path(self.log_path).read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        return lines[-tail:]

    # ------------------------------------------------------------------ #
    def fetch_prometheus_metrics(self) -> str:
        """Scrape the daemon's own exporter (127.0.0.1 only)."""
        url = f"http://127.0.0.1:{self.metrics_port}/metrics"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 — surfaced as CoreError by caller
            raise CoreError(f"mtproto metrics unreachable: {exc}") from exc


def subprocess_run(argv: list[str]) -> str:
    import subprocess
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return proc.stdout or ""
    except Exception:  # noqa: BLE001
        return ""
