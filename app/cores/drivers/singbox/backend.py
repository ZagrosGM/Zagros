"""Process & config boundary for the sing-box driver.

sing-box has no per-user management API, so this backend does the two things
that *are* possible, well: (1) atomically render & validate the JSON config
(``sing-box check``) and (2) own the process lifecycle via the shared
:class:`ManagedProcess` primitive. Tests inject a fake — no binary needed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from app.cores.exceptions import CoreError
from app.cores.process import ManagedProcess
from app.cores.types import CoreMetrics

logger = logging.getLogger("zagros.cores.drivers.singbox")

#: Zagros-vendored stats-enabled builds live as release assets here (see
#: ``.github/workflows/vendor-singbox.yml`` — compiled from the upstream tag
#: with its OWN Makefile release tag-list plus ``with_v2ray_api``).
_VENDOR_REPO = "ZagrosGM/Zagros"


def _vendored_checksum(version: str, asset: str, *, timeout: float = 20.0) -> str | None:
    """Expected sha256 for a vendored stats-enabled asset, from the vendor
    release's ``sha256sums.txt``. ``None`` when no vendor release exists for
    this version (fallback to the upstream build is then the honest path)."""
    import urllib.error
    import urllib.request

    url = (f"https://github.com/{_VENDOR_REPO}/releases/download/"
           f"vendor-singbox-{version}/sha256sums.txt")
    req = urllib.request.Request(url, headers={"User-Agent": "zagros-panel"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode()
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == asset:
            return parts[0]
    return None


@runtime_checkable
class SingBoxBackend(Protocol):
    def apply_config(self, config: dict[str, Any]) -> None:
        """Validate (when possible) + atomically persist the rendered config."""
        ...

    def start(self) -> None: ...
    def stop(self) -> None: ...
    def restart(self) -> None: ...
    def is_running(self) -> bool: ...
    def version(self) -> str | None: ...
    def metrics(self) -> CoreMetrics: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...


@runtime_checkable
class TrafficStatsSource(Protocol):
    """Per-user cumulative counters from sing-box's experimental v2ray API.

    Only builds carrying the ``with_v2ray_api`` tag serve it — and upstream
    stopped shipping that tag in official releases entirely (verified
    1.9.7→1.13.16), which is why Zagros vendors its own build. The server
    speaks the v2fly StatsService; users are enumerable counters of the form
    ``user>>><name>>>>traffic>>>uplink``. The vendored xray_api package is
    reused here purely as a *protocol client* — this is not a dependency on
    the Xray core.
    """

    def query_user_counters(self) -> dict[str, tuple[int, int]]:
        """Return ``{user_name: (uplink_bytes, downlink_bytes)}`` cumulative."""
        ...


class V2RayStatsSource:
    """Production TrafficStatsSource over gRPC (lazy-imports xray_api).

    DIALECT NEGOTIATION (alpha.7.4 — the field «unknown service
    xray.app.stats.command.StatsService»): sing-box ≥ 1.12 registers its
    StatsService as ``v2ray.core.app.stats.command.StatsService`` (see
    ``experimental/v2rayapi/stats.go`` at every tag 1.12.x–1.13.x: the init()
    renames the ServiceDesc) while ≤ 1.11 and the Xray core itself answer
    ``xray.app.stats.command.StatsService``. The wire schema is byte-identical
    (Stat{name:1,value:2}, QueryStatsRequest{pattern:1,reset:2},
    QueryStatsResponse{stat:1}), so the vendored protobuf messages query BOTH
    dialects; the first dialect that answers is cached for the process.
    """

    _DIALECTS = (
        "xray.app.stats.command.StatsService",
        "v2ray.core.app.stats.command.StatsService",
    )

    def __init__(self, address: str):
        host, _, port = address.rpartition(":")
        self._address = (host or "127.0.0.1", int(port))
        self._dialect: str | None = None

    def _query_stats(self, channel: Any, dialect: str, pattern: str,
                     pb2: Any) -> Any:
        method = channel.unary_unary(
            f"/{dialect}/QueryStats",
            request_serializer=pb2.QueryStatsRequest.SerializeToString,
            response_deserializer=pb2.QueryStatsResponse.FromString,
        )
        return method(pb2.QueryStatsRequest(pattern=pattern, reset=False),
                      timeout=15)

    def query_user_counters(self) -> dict[str, tuple[int, int]]:
        try:
            import grpc
            from xray_api.proto.app.stats.command import command_pb2
        except ImportError as exc:  # pragma: no cover - packaging guard
            raise CoreError(
                "xray_api (gRPC stats client) is not available — sing-box "
                "per-user accounting needs the v2ray StatsService client."
            ) from exc
        host, port = self._address
        channel = grpc.insecure_channel(f"{host}:{port}")
        try:
            # settled dialect first; before settlement try each known dialect
            dialects = ([self._dialect] if self._dialect
                        else list(self._DIALECTS))
            response = None
            last_unimplemented: Exception | None = None
            for dialect in dialects:
                try:
                    response = self._query_stats(channel, dialect, "user>>>",
                                                 command_pb2)
                except grpc.RpcError as exc:
                    if exc.code() == grpc.StatusCode.UNIMPLEMENTED:
                        last_unimplemented = exc
                        if self._dialect is None:
                            continue  # unknown dialect → try the next one
                    raise CoreError(
                        f"sing-box stats API unreachable: "
                        f"{exc.details() or exc}"
                    ) from exc
                self._dialect = dialect
                break
            if response is None:
                raise CoreError(
                    "sing-box stats API unreachable: the listener answers "
                    "gRPC but knows none of the StatsService dialects "
                    f"({', '.join(self._DIALECTS)}) — "
                    f"{last_unimplemented.details() if last_unimplemented else '?'}"
                )
            counters: dict[str, tuple[int, int]] = {}
            for stat in response.stat:
                parts = stat.name.split(">>>")
                if len(parts) != 4 or parts[0] != "user":
                    continue  # only user>>><name>>>>traffic>>><uplink|downlink>
                up, down = counters.get(parts[1], (0, 0))
                if parts[3] == "uplink":
                    up = int(stat.value)
                else:
                    down = int(stat.value)
                counters[parts[1]] = (up, down)
            return counters
        finally:
            channel.close()


class LocalSingBoxBackend:
    """Production backend: config renderer + :class:`ManagedProcess`."""

    def __init__(self, settings: dict[str, Any]):
        self.settings = settings
        self.work_dir = settings.get("work_dir", ".")
        os.makedirs(self.work_dir, exist_ok=True)
        configured = str(settings.get("executable_path") or "sing-box")
        if os.path.basename(configured) == configured:
            # SELF_INSTALL writes a bare executable into the persistent core
            # work_dir. The install-time backend updated only its own argv;
            # after a panel/container restart a fresh backend looked on PATH,
            # ignored the still-present binary and marked the core ERROR until
            # the operator pressed Reinstall. Prefer the persistent artifact,
            # then a real system package, and otherwise keep the persistent
            # path as the future install target.
            persistent = os.path.abspath(os.path.join(self.work_dir, configured))
            self.executable = (persistent if os.path.isfile(persistent)
                               else (shutil.which(configured) or persistent))
        else:
            self.executable = configured
        self.config_path = settings.get(
            "config_path", os.path.join(self.work_dir, "sing-box.json")
        )
        os.makedirs(os.path.dirname(os.path.abspath(self.config_path)), exist_ok=True)
        self._log_buffer = int(settings.get("log_buffer", 200))
        self._proc = self._make_proc()

    def _make_proc(self) -> ManagedProcess:
        return ManagedProcess(
            [self.executable, "run", "-c", self.config_path],
            cwd=self.work_dir,
            log_buffer=self._log_buffer,
        )

    def install_binary(self) -> str:
        """Install sing-box; bare executable names are resolved inside
        work_dir (CWD is not on PATH, so a relative target would leave the
        process unstartable). Rebuilds the managed process afterwards so
        argv picks up the real path.

        Installs the **pinned** release from settings (``release_version``,
        default below) — reproducible and immune to GitHub API rate limits;
        set it empty to track the latest release instead.

        Binary source (alpha.7.1): NO official sing-box build (verified
        1.9.7→1.13.16) ships the ``with_v2ray_api`` tag, so per-user
        accounting is impossible on upstream binaries. Zagros therefore
        vendors its own build of the SAME upstream tag compiled with the
        official release tag-list plus ``with_v2ray_api`` (reproducible by
        ``.github/workflows/vendor-singbox.yml``; sha256 published in the
        vendor release and verified before install). Order: vendored build →
        upstream build (accounting then degrades, honestly, via the probe).
        """
        from app.cores.github_install import host_arch, host_os, install_from_github

        system, arch = host_os(), host_arch()
        suffix = ".zip" if system == "windows" else ".tar.gz"
        bare = os.path.basename(self.executable) == self.executable
        target = (os.path.join(os.path.abspath(self.work_dir), self.executable)
                  if bare else self.executable)
        version = self.settings.get("release_version", "1.12.4") or None
        source = "upstream"
        tag: str | None = None
        if version:
            vendored_asset = f"sing-box-{version}-v2rayapi-{system}-{arch}{suffix}"
            checksum = _vendored_checksum(version, vendored_asset)
            if checksum:
                tag = install_from_github(
                    repo=_VENDOR_REPO,
                    target_executable=target,
                    asset_match=lambda name: name == vendored_asset,
                    member_match=lambda m: m.endswith("sing-box.exe") if system == "windows"
                    else (m.endswith("/sing-box") or m == "sing-box"),
                    pinned=(f"vendor-singbox-{version}", vendored_asset),
                    sha256=checksum,
                )
                source = "vendor"
            else:
                logger.info(
                    "no vendored stats-enabled sing-box build for %s/%s v%s — "
                    "falling back to the official build (per-user accounting "
                    "will probe-degrade if the API is absent)",
                    system, arch, version,
                )
                tag = install_from_github(
                    repo="SagerNet/sing-box",
                    target_executable=target,
                    asset_match=lambda n: f"-{system}-{arch}" in n and n.endswith(suffix),
                    member_match=lambda m: m.endswith("sing-box.exe") if system == "windows"
                    else (m.endswith("/sing-box") or m == "sing-box"),
                    pinned=(f"v{version}", f"sing-box-{version}-{system}-{arch}{suffix}"),
                )
        else:
            tag = install_from_github(
                repo="SagerNet/sing-box",
                target_executable=target,
                asset_match=lambda n: f"-{system}-{arch}" in n and n.endswith(suffix),
                member_match=lambda m: m.endswith("sing-box.exe") if system == "windows"
                else (m.endswith("/sing-box") or m == "sing-box"),
            )
        if target != self.executable:
            self.executable = target
            if not self._proc.is_running:
                self._proc = self._make_proc()
        if source == "vendor" and not self.probe_v2ray_support():
            # the whole point of the vendored build IS the stats API — a probe
            # failure here means our packaging is broken; say so, loudly,
            # instead of silently degrading the feature we just promised.
            raise CoreError(
                "the vendored stats-enabled sing-box build failed its "
                "v2ray_api probe after install — refusing to run a build that "
                "cannot deliver per-user accounting. Report this as a "
                "vendor-build bug."
            )
        return tag

    # ------------------------------------------------------------------ #
    # config
    # ------------------------------------------------------------------ #
    def apply_config(self, config: dict[str, Any]) -> None:
        tmp_path = f"{self.config_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2, ensure_ascii=False)
        if self._binary_available():
            proc = subprocess.run(
                [self.executable, "check", "-c", tmp_path],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                os.unlink(tmp_path)
                # sing-box reports config errors on stderr, sometimes stdout
                detail = (proc.stderr or proc.stdout or "").strip()
                raise CoreError(f"sing-box rejected the rendered config: {detail}")
        os.replace(tmp_path, self.config_path)

    def _binary_available(self) -> bool:
        try:
            subprocess.run([self.executable, "version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    def probe_v2ray_support(self) -> bool:
        """True iff THIS sing-box build includes the experimental v2ray API.

        Official builds dropped the `with_v2ray_api` build tag in 1.12, so a
        config rendered with the block FATALs at start ("v2ray api is not
        included in this build — rebuild with -tags with_v2ray_api"). Probe
        the actual binary (`sing-box check` on a minimal config); never trust
        version folklore.
        """
        if not self._binary_available():
            return False
        probe = {
            "log": {"level": "warning"},
            "inbounds": [{
                "type": "mixed", "tag": "zg-probe",
                "listen": "127.0.0.1", "listen_port": 0,
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "experimental": {
                "v2ray_api": {
                    "listen": "127.0.0.1:0",
                    "stats": {"enabled": True, "outbounds": ["direct"], "users": []},
                },
            },
        }
        tmp_path = f"{self.config_path}.v2probe"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(probe, fh)
            proc = subprocess.run(
                [self.executable, "check", "-c", tmp_path],
                capture_output=True, text=True, timeout=15,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("sing-box v2ray_api probe could not run (%s) — assuming unsupported", exc)
            return False
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        detail = f"{proc.stderr or ''}\n{proc.stdout or ''}"
        if "v2ray api is not included" in detail:
            return False
        return proc.returncode == 0

    # ------------------------------------------------------------------ #
    # process (delegated)
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if not self._binary_available():
            raise CoreError(
                f"sing-box binary not found at '{self.executable}' — "
                f"run install() first or fix core settings."
            )
        self._proc.start()
        logger.warning("sing-box started (pid=%s)", self._proc.pid)

    @staticmethod
    def _expected_listeners(config: dict[str, Any]) -> set[tuple[str, int]]:
        expected: set[tuple[str, int]] = set()
        for inbound in config.get("inbounds") or []:
            port = int(inbound.get("listen_port") or 0)
            if not port:
                continue
            kind = str(inbound.get("type") or "")
            if kind in ("hysteria2", "tuic"):
                expected.add(("udp", port))
            elif kind == "shadowsocks":
                expected |= {("tcp", port), ("udp", port)}
            else:
                expected.add(("tcp", port))
        return expected

    def wait_listeners(self, config: dict[str, Any], timeout: float = 10.0) -> None:
        """Do not report RUNNING until every rendered listener is bound."""
        expected = self._expected_listeners(config)
        if not expected:
            return
        ss = shutil.which("ss")
        if ss is None:
            raise CoreError("'ss' (iproute2) is required to verify sing-box listeners")
        deadline = time.monotonic() + timeout
        missing = set(expected)
        while time.monotonic() < deadline:
            if not self._proc.is_running:
                tail = " | ".join(self._proc.logs(20)) or "no process output"
                raise CoreError(f"sing-box exited before binding listeners: {tail}")
            proc = subprocess.run([ss, "-H", "-lntu"], capture_output=True,
                                  text=True, timeout=5)
            found: set[tuple[str, int]] = set()
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    columns = line.split()
                    if len(columns) < 5:
                        continue
                    network = "udp" if columns[0].startswith("udp") else "tcp"
                    address = columns[4]
                    try:
                        port = int(address.rsplit(":", 1)[1])
                    except (IndexError, ValueError):
                        continue
                    found.add((network, port))
            missing = expected - found
            if not missing:
                return
            time.sleep(0.1)
        tail = " | ".join(self._proc.logs(20)) or "no process output"
        raise CoreError(
            f"sing-box did not bind rendered listeners within {timeout:g}s; "
            f"missing={sorted(missing)}; process output: {tail}"
        )

    def stop(self) -> None:
        self._proc.stop()

    def restart(self) -> None:
        self._proc.restart()

    def is_running(self) -> bool:
        return self._proc.is_running

    def version(self) -> str | None:
        try:
            out = subprocess.check_output(
                [self.executable, "version"], text=True, timeout=10
            )
            match = re.search(r"sing-box version ([\d.]+)", out)
            return match.group(1) if match else None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    def metrics(self) -> CoreMetrics:
        return self._proc.metrics()

    def logs(self, tail: int = 200) -> Sequence[str]:
        return self._proc.logs(tail)
