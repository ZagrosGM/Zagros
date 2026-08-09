"""Backend boundary for the SoftEther driver.

  * :class:`SoftEtherBackend` — Protocol: hub user/session management via
    the official `vpncmd` management CLI.
  * :class:`LocalSoftEtherBackend` — production implementation; every change
    applies instantly to the live server (SoftEther has full runtime
    management — no restart semantics, honest HOT_RELOAD).
"""
from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import time
from typing import Protocol, runtime_checkable

from app.cores.drivers.softether.setool import (
    IPsecServices,
    SESession,
    UserStatistics,
    parse_ipsec_get,
    parse_session_list,
    parse_user_get,
    parse_user_list,
)
from app.cores.exceptions import CoreError

logger = logging.getLogger("zagros.cores.drivers.softether")

#: a permanently-past date used to suspend users natively (honest switch):
_SUSPENDED_EXPIRES = "2000/01/01 00:00:00"


@runtime_checkable
class SoftEtherBackend(Protocol):
    def reachable(self) -> bool: ...
    def user_create(self, username: str, note: str = "") -> None: ...
    def user_delete(self, username: str) -> None: ...
    def user_password_set(self, username: str, password: str) -> None: ...
    def user_expires_set(self, username: str, expires: str | None) -> None: ...
    def suspend_user(self, username: str) -> None: ...
    def user_get(self, username: str) -> UserStatistics: ...
    def user_list(self) -> list[str]: ...
    def session_list(self) -> list[SESession]: ...
    def session_disconnect(self, session_name: str) -> None: ...
    def ipsec_psk(self) -> str | None: ...
    def ipsec_get(self) -> IPsecServices: ...
    def ipsec_services_set(self, *, l2tp: bool, l2tp_raw: bool, etherip: bool,
                           psk: str, default_hub: str) -> None: ...


class LocalSoftEtherBackend:
    """vpncmd-based backend (localhost hub administration)."""

    def __init__(self, settings: dict):
        self.vpncmd = settings.get("executable_path", "vpncmd")
        self.server = settings.get("server", "localhost")
        self.hub = settings.get("hub", "DEFAULT")
        self.password = settings.get("admin_password", "")
        self.timeout = float(settings.get("vpncmd_timeout", 30.0))

    # ------------------------------------------------------------------ #
    # command plumbing
    # ------------------------------------------------------------------ #
    def _cmd(self, command: str, *, csv: bool = False) -> str:
        if shutil.which(self.vpncmd) is None:
            raise CoreError(
                "vpncmd not found — press Install for this core (or run its "
                "install_packages()): apt 'softether-vpnserver' on supported "
                "distros, otherwise the official GitHub release is fetched."
            )
        argv = [
            self.vpncmd, self.server, "/SERVER", f"/HUB:{self.hub}",
            f"/PASSWORD:{self.password}",
        ]
        if csv:
            argv.append("/CSV")
        # vpncmd 5.x /CMD one-shot tokenizes argv NATIVELY: pass every token
        # as its own argv element. The 4.x-era form — the entire command as
        # ONE quoted string («"UserCreate e2e /GROUP: ..."») — dies with
        # '"UserCreate": Command not found' on the 5.2 developer edition
        # (verified live against a real source-built vpncmd 5.02.5187).
        argv += ["/CMD", *shlex.split(command)]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout
            )
        except subprocess.TimeoutExpired as exc:
            raise CoreError(f"vpncmd timed out on '{command}'.") from exc
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise CoreError(f"vpncmd '{command}' failed (rc={proc.returncode}): {out.strip()[:400]}")
        error_line = next(
            (line.strip() for line in out.splitlines()
             if line.strip().startswith("Error") or "error occurred" in line.lower()),
            None,
        )
        if error_line:
            raise CoreError(f"vpncmd '{command}' failed: {error_line}")
        return proc.stdout or ""

    # ------------------------------------------------------------------ #
    # IPsec server functions (L2TP/IPsec, raw L2TP, EtherIP)
    #
    # alpha.7.4 bug (field report "vpncmd 'IPsecEnable /L2TP:no ...
    # /DEFAULTHUB:DEFAULT' failed (rc=38)"): upstream PsIPsecEnable
    # declares ALL FIVE arguments — including /PSK: — with CmdEvalNotEmpty,
    # so a missing/empty PSK fails vpncmd's LOCAL validation and the tool
    # exits ERR_INVALID_PARAMETER (38) BEFORE any RPC runs — even when the
    # intent is to disable every service. The argument string is also
    # passed through shlex.split here (5.x one-shot tokenizes natively),
    # so embedded whitespace needs real quoting. Every IPsecEnable issued
    # by this backend therefore carries the full 5-argument form with a
    # non-empty PSK + hub, validated locally first so a bad value never
    # half-commands the server. (alpha.7.5 item 7)
    # ------------------------------------------------------------------ #

    def ipsec_get(self) -> IPsecServices:
        """Current server IPsec state (authoritative — used to converge
        without clobbering the stored PSK or the default hub)."""
        return parse_ipsec_get(self._cmd("IPsecGet"))

    def ipsec_services_set(self, *, l2tp: bool, l2tp_raw: bool, etherip: bool,
                           psk: str, default_hub: str) -> None:
        """Full-form `IPsecEnable` — mirrors vpncmd's own local validation."""
        psk = (psk or "").strip()
        hub = (default_hub or "").strip()
        if not psk:
            raise CoreError(
                "IPsecEnable needs a non-empty pre-shared key — vpncmd "
                "validates /PSK: locally (ERR_INVALID_PARAMETER, rc=38) even "
                "when every service is being disabled."
            )
        if not hub:
            raise CoreError("IPsecEnable needs a non-empty default hub name.")
        if any(ch in psk for ch in ('"', "\n", "\r")) or '"' in hub:
            raise CoreError(
                "IPsec PSK/hub contains characters that cannot be encoded "
                "as a vpncmd argument (quote/newline) — refused locally."
            )
        yn = lambda b: "yes" if b else "no"  # noqa: E731
        psk_arg = f'"{psk}"' if any(ch.isspace() for ch in psk) else psk
        self._cmd(
            f"IPsecEnable /L2TP:{yn(l2tp)} /L2TPRAW:{yn(l2tp_raw)} "
            f"/ETHERIP:{yn(etherip)} /PSK:{psk_arg} /DEFAULTHUB:{hub}"
        )

    # ------------------------------------------------------------------ #
    # setup — real SELF_INSTALL (3-stage chain, alpha.7.2)
    # ------------------------------------------------------------------ #
    # Every package manager present on the host gets an honest attempt —
    # "didn't try dnf" was a field failure pattern. Candidates that do not
    # exist on a distro fail fast and are REPORTED in the final error.
    _PKG_MANAGERS: tuple[tuple[str, list[str], list[str] | None], ...] = (
        ("apt-get", ["apt-get", "install", "-y", "softether-vpnserver"],
         ["apt-get", "update"]),  # containers ship empty lists — refresh first
        ("dnf", ["dnf", "install", "-y", "softether-vpnserver"], None),
        ("yum", ["yum", "install", "-y", "softether-vpnserver"], None),
        ("pacman", ["pacman", "-S", "--noconfirm", "softether-vpnserver"], None),
        ("apk", ["apk", "add", "softether-vpnserver"], None),
    )

    # toolchain for the source-build stage, per manager (best effort; the
    # exact package names of the mainstream distros). pkg-config/pkgconf is
    # REQUIRED — SoftEther's cmake locates OpenSSL through it and dies with
    # "Could NOT find PkgConfig" otherwise (field report alpha.7.3).
    _BUILD_DEPS: dict[str, tuple[list[str] | None, list[str]]] = {
        "apt-get": (["apt-get", "update"],
                    ["apt-get", "install", "-y", "build-essential", "cmake",
                     "pkg-config", "libsodium-dev",
                     "libssl-dev", "zlib1g-dev", "libreadline-dev", "libncurses-dev"]),
        "dnf": (None, ["dnf", "install", "-y", "gcc", "gcc-c++", "make", "cmake",
                       "pkgconf-pkg-config", "libsodium-devel",
                       "openssl-devel", "zlib-devel", "readline-devel", "ncurses-devel"]),
        "yum": (None, ["yum", "install", "-y", "gcc", "gcc-c++", "make", "cmake",
                       "pkgconf-pkg-config", "libsodium-devel",
                       "openssl-devel", "zlib-devel", "readline-devel", "ncurses-devel"]),
        "pacman": (None, ["pacman", "-S", "--noconfirm", "base-devel", "cmake",
                          "pkgconf", "libsodium",
                          "openssl", "zlib", "readline", "ncurses"]),
        "apk": (None, ["apk", "add", "build-base", "cmake", "pkgconf",
                       "libsodium-dev",
                       "openssl-dev", "zlib-dev", "readline-dev", "ncurses-dev"]),
    }

    _INSTALL_ROOT = "/usr/local/softether"

    def install_packages(self) -> str:
        """Install SoftEther VPN Server for real; returns a human description.

        Strategy chain (first success wins, EVERY attempt reported):
        1. The host's package manager — apt/dnf/yum/pacman/apk are ALL
           probed; success is verified by locating the vpnserver binary,
           not by the package tool's exit code.
        2. Official GitHub release binary (SoftEtherVPN/SoftEtherVPN): the
           latest STABLE release is resolved live (zero hardcoded version).
        3. Full source build from that same latest stable tag — toolchain
           installed via the package manager, cmake build, artifacts laid
           out under /usr/local/softether and symlinked onto PATH.
        Raises CoreError with the per-stage detail when everything failed.
        """
        errors: list[str] = []
        for manager, argv, refresh in self._PKG_MANAGERS:
            if shutil.which(manager) is None:
                continue
            try:
                if refresh:
                    self._run(refresh, timeout=600)
                self._run(argv, timeout=900)
                if self.server_binary():
                    return f"installed softether-vpnserver via {manager}"
                errors.append(
                    f"{manager}: install completed but vpnserver not found on PATH")
            except CoreError as exc:
                errors.append(f"{manager}: {exc}")
        try:
            return self._install_from_github()
        except Exception as exc:  # noqa: BLE001 — report every attempt
            errors.append(f"github-release: {exc}")
        try:
            return self._install_from_source()
        except Exception as exc:  # noqa: BLE001 — report every attempt
            errors.append(f"source-build: {exc}")
        raise CoreError(
            "could not self-install SoftEther VPN Server — attempts: "
            + " | ".join(errors or ["no strategy applicable on this host"])
        )

    def _link_on_path(self, root: str) -> None:
        # WRAPPER scripts, not symlinks (field failure alpha.7.4): SoftEther
        # locates hamcore.se2/lang.config relative to its own argv[0] path —
        # started through a symlink in /usr/local/bin it dies with
        # 'hamcore.se2 is missing or broken'. A wrapper exec's the REAL path,
        # so the resource lookup stays anchored at the install root.
        for name in ("vpnserver", "vpncmd"):
            real = os.path.join(root, name)
            link = os.path.join("/usr/local/bin", name)
            try:
                if os.path.lexists(link):
                    os.remove(link)
                with open(link, "w", encoding="utf-8") as fh:
                    fh.write(f"#!/bin/sh\nexec \"{real}\" \"$@\"\n")
                os.chmod(link, 0o755)
            except OSError as exc:
                logger.warning("softether PATH wrapper %s failed: %s", link, exc)

    def _install_from_github(self) -> str:
        from app.cores.github_install import host_arch, host_os, install_from_github

        system, arch = host_os(), host_arch()
        if system != "linux" or arch not in ("amd64", "arm64"):
            raise CoreError(f"no official SoftEther build for {system}/{arch}")
        arch_bits = ("x64-64bit",) if arch == "amd64" else ("arm64-64bit",)
        root = self._INSTALL_ROOT
        os.makedirs(root, exist_ok=True)
        try:
            tag = install_from_github(
                repo="SoftEtherVPN/SoftEtherVPN",
                target_executable=os.path.join(root, "vpnserver"),
                # BOTH upstream naming generations, never one hardcoded
                # filename: current 5.x lines ship no Linux binary at all
                # (Windows .exe bundles + the official source tarball only),
                # older 4.x lines shipped linux tarballs.
                asset_match=lambda n: (
                    n.startswith("softether-vpnserver-")
                    and n.endswith(".tar.gz")
                    and "linux" in n.lower()
                    and any(bit in n for bit in arch_bits)
                ),
                member_match=lambda m: m.rsplit("/", 1)[-1] == "vpnserver",
                extra_members={
                    "vpncmd": os.path.join(root, "vpncmd"),
                    "hamcore.se2": os.path.join(root, "hamcore.se2"),
                },
            )
        except CoreError as exc:
            raise CoreError(f"{exc} → source-build stage follows") from exc
        os.chmod(os.path.join(root, "vpncmd"), 0o755)
        self._link_on_path(root)
        return f"installed SoftEther {tag} from GitHub releases"

    def _ensure_build_deps(self) -> None:
        for manager, (refresh, argv) in self._BUILD_DEPS.items():
            if shutil.which(manager) is None:
                continue
            try:
                if refresh:
                    self._run(refresh, timeout=600)
                self._run(argv, timeout=1800)
                return
            except CoreError as exc:
                raise CoreError(f"build toolchain via {manager} failed: {exc}") from exc
        raise CoreError(
            "no supported package manager to install the build toolchain "
            "(need: c/c++ compiler, cmake, openssl+zlib+readline+ncurses dev)."
        )

    # alpha.7.5 item 10 — the source build must be CONTROLLED, CACHED and
    # OBSERVABLE (field report: install pinned the host at 100% CPU with
    # zero visible progress and re-downloaded/re-compiled everything on
    # every retry):
    #: parallelism ceiling (env ZAGROS_SOFTETHER_BUILD_JOBS overrides) —
    #: a full-throttle --parallel <all cores> starves the panel and live
    #: VPN traffic on small VPS hosts
    _BUILD_JOBS_CAP = 4
    #: only what the panel actually installs — building the default target
    #: set also compiles+links vpnclient/vpnbridge/vpntest (≈40% waste)
    _BUILD_TARGETS = ("cedar", "mayaqua", "hamcore-archive-build",
                      "vpnserver", "vpncmd")

    def _build_jobs(self) -> int:
        override = os.environ.get("ZAGROS_SOFTETHER_BUILD_JOBS", "").strip()
        if override:
            try:
                return max(1, min(int(override), 16))
            except ValueError:
                logger.warning("invalid ZAGROS_SOFTETHER_BUILD_JOBS=%r — default",
                               override)
        return max(1, min(os.cpu_count() or 2, self._BUILD_JOBS_CAP))

    def _src_cache_root(self) -> str | None:
        """Stable source-tree cache root (a retry RESUMES the previous
        download/build instead of restarting it). None = no usable cache
        location → caller falls back to a throwaway temp dir (never a fake
        cache that silently keeps failing state)."""
        override = os.environ.get("ZAGROS_SOFTETHER_SRC_CACHE", "").strip()
        candidates = [override] if override else [
            "/var/lib/zagros/cache/softether", "/tmp/zagros-softether-cache"]
        for root in candidates:
            try:
                os.makedirs(root, mode=0o755, exist_ok=True)
                probe = os.path.join(root, ".probe")
                with open(probe, "w", encoding="utf-8") as fh:
                    fh.write("ok")
                os.remove(probe)
                return root
            except OSError:
                continue
        return None

    def _download(self, url: str, dest: str, *, timeout: float = 900.0) -> int:
        """Chunked download with real logged progress (item 10 — the panel
        previously sat silent through a >100 MB fetch)."""
        import urllib.request

        request = urllib.request.Request(
            url, headers={"User-Agent": "zagros-panel/install"})
        written = 0
        next_mark = 8 * 1024 * 1024
        deadline = time.monotonic() + timeout
        # download into a temp sibling and RENAME on success — a failed or
        # interrupted fetch must never leave a partial file at the final
        # path, or the "retry performs a fresh download" promise breaks
        # (the cache layer would try to extract the truncated file).
        part = dest + ".part"
        try:
            with urllib.request.urlopen(request, timeout=120) as response, \
                    open(part, "wb") as fh:
                while True:
                    if time.monotonic() > deadline:
                        raise CoreError(
                            f"download timed out after {int(timeout)} s ({url}) — "
                            "retry to resume (the partial build tree is cached)")
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    fh.write(chunk)
                    written += len(chunk)
                    if written >= next_mark:
                        logger.info("softether source download: %.1f MB…",
                                    written / 1048576)
                        next_mark = written + 8 * 1024 * 1024
            os.replace(part, dest)
        finally:
            try:
                os.remove(part)
            except OSError:
                pass
        logger.info("softether source download complete: %.1f MB",
                    written / 1048576)
        return written

    def _run_streamed(self, argv: list[str], *, timeout: float) -> str:
        """Long-stage runner with REAL streamed progress: cmake/make emit
        `[ NN%] Building …` / `Built target …` lines — every such line is
        logged as it happens (the panel previously captured output blindly
        for up to an hour). The last lines are kept for the error tail.
        select()-driven so a totally SILENT hang also hits the timeout —
        a blocking readline() would wait forever on an output-less child."""
        import select

        nice = shutil.which("nice")
        cmd = ([nice, "-n", "10"] if nice else []) + argv
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except FileNotFoundError as exc:
            raise CoreError(f"cannot run '{argv[0]}': not found") from exc
        tail: list[str] = []
        buf = b""
        deadline = time.monotonic() + timeout

        def _emit(line: bytes) -> None:
            clean = line.decode("utf-8", "replace").rstrip()
            tail.append(clean)
            del tail[:-30]
            if "%]" in clean or clean.startswith("Built target"):
                logger.info("softether build: %s", clean)

        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        try:
            while True:
                ready, _, _ = select.select([fd], [], [], 0.25)
                if ready:
                    chunk = os.read(fd, 65536)
                    if chunk:
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            _emit(line)
                        continue
                    break  # EOF — child closed its output
                if proc.poll() is not None:
                    # exited but stream may still hold buffered bytes
                    chunk = os.read(fd, 65536)
                    if chunk:
                        buf += chunk
                        continue
                    break
                if time.monotonic() > deadline:
                    proc.kill()
                    raise CoreError(
                        f"'{argv[0]}' timed out after {int(timeout)} s — the "
                        "cached build tree survives, retry resumes it")
            if buf.strip():
                _emit(buf)
            rc = proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
        if rc != 0:
            detail = " | ".join(tail[-6:]) or "no output"
            raise CoreError(f"'{' '.join(argv)}' failed (rc={rc}): {detail}")
        return "\n".join(tail)

    def _install_from_source(self) -> str:
        """Last-resort: compile the latest STABLE tag from source. The tag
        is resolved live from GitHub (no version is ever hardcoded).

        alpha.7.5 item 10 controls:
          * build deps are ensured exactly once BEFORE any compile;
          * the source tree + cmake build dir live in a STABLE cache
            (env ZAGROS_SOFTETHER_SRC_CACHE / /var/lib/zagros/cache/
            softether) so a retry resumes instead of re-downloading and
            re-compiling;
          * the build is bounded (<=4 jobs, niced) and TARGETED (only
            cedar/mayaqua/hamcore/vpnserver/vpncmd — not client/bridge/
            vpntest);
          * download + compile stream REAL progress into the panel log.
        """
        import tarfile
        import tempfile

        from app.cores.github_install import fetch_latest_release

        self._ensure_build_deps()
        release = fetch_latest_release("SoftEtherVPN/SoftEtherVPN")
        tag = str(release.get("tag_name") or "").strip()
        if not tag:
            raise CoreError("could not resolve the latest SoftEther release tag.")
        # Prefer the OFFICIAL source tarball published as a release asset
        # (SoftEtherVPN-<tag>.tar.xz) — discovered from the release's own
        # asset list, never a hardcoded filename; fall back to the
        # auto-generated tag archive when no such asset exists.
        official = next(
            (a for a in release.get("assets", [])
             if str(a.get("name", "")).startswith("SoftEtherVPN-")
             and str(a.get("name", "")).endswith(".tar.xz")),
            None,
        )
        if official is not None and official.get("browser_download_url"):
            url = str(official["browser_download_url"])
        else:
            url = ("https://github.com/SoftEtherVPN/SoftEtherVPN/"
                   f"archive/refs/tags/{tag}.tar.gz")

        cache_root = self._src_cache_root()
        if cache_root:
            work = os.path.join(cache_root, tag)
            persistent = True
        else:
            work = tempfile.mkdtemp(prefix="zagros-softether-src-")
            persistent = False
        os.makedirs(work, exist_ok=True)
        tarball = os.path.join(work, "src.pkg")
        extract_done = os.path.join(work, ".extracted")
        build_dir = os.path.join(work, "build")
        try:
            if os.path.exists(tarball) and os.path.exists(extract_done):
                logger.info("softether source cache hit (%s) — skipping "
                            "download/extract", work)
            else:
                if not os.path.exists(tarball):
                    self._download(url, tarball)
                try:
                    with tarfile.open(tarball, "r:*") as tar:  # gz AND xz
                        tar.extractall(work, filter="data")
                except (tarfile.TarError, EOFError, OSError) as exc:
                    # corrupt/partial cache — drop it so the NEXT retry
                    # re-downloads cleanly instead of looping on junk
                    for junk in (tarball, extract_done):
                        try:
                            os.remove(junk)
                        except OSError:
                            pass
                    raise CoreError(
                        f"source tarball unusable ({exc}) — cache cleared, "
                        "retry performs a fresh download") from exc
                with open(extract_done, "w", encoding="utf-8") as fh:
                    fh.write(tag)
            roots = [d for d in os.listdir(work)
                     if os.path.isdir(os.path.join(work, d))
                     and d not in ("__pycache__", "build")]
            if len(roots) != 1:
                # cache from another layout/tag — clear and restart cleanly
                if persistent:
                    shutil.rmtree(work, ignore_errors=True)
                    raise CoreError(
                        "source cache layout mismatch — cleared; retry for a "
                        "fresh download")
                raise CoreError(f"unexpected source tarball layout: {roots!r}")
            src_dir = os.path.join(work, roots[0])
            self._run(["cmake", "-S", src_dir, "-B", build_dir,
                       "-DCMAKE_BUILD_TYPE=Release"], timeout=900)
            jobs = self._build_jobs()
            logger.info("softether build starting: %d job(s), targets %s "
                        "(bounded + niced — the panel and live tunnels stay "
                        "responsive)", jobs, ", ".join(self._BUILD_TARGETS))
            self._run_streamed(
                ["cmake", "--build", build_dir, "--parallel", str(jobs),
                 "--target", *self._BUILD_TARGETS], timeout=3600)
            root = self._INSTALL_ROOT
            os.makedirs(root, exist_ok=True)
            for name in ("vpnserver", "vpncmd", "hamcore.se2"):
                built = os.path.join(build_dir, name)
                if not os.path.exists(built):
                    raise CoreError(f"cmake build did not produce '{name}'")
                shutil.copy2(built, os.path.join(root, name))
            os.chmod(os.path.join(root, "vpnserver"), 0o755)
            os.chmod(os.path.join(root, "vpncmd"), 0o755)
            # cmake builds cedar/mayaqua as SHARED libs and bakes the temp
            # build dir into RUNPATH (field failure alpha.7.4: daemon died
            # with "libcedar.so: cannot open shared object file" once the
            # temp tree was cleaned). Ship the libs next to the binaries
            # and register the path with the dynamic loader.
            libs = sorted(
                name for name in os.listdir(build_dir)
                if name.startswith(("libcedar.so", "libmayaqua.so"))
                and os.path.isfile(os.path.join(build_dir, name))
            )
            for name in libs:
                shutil.copy2(os.path.join(build_dir, name),
                             os.path.join(root, name))
            if libs:
                conf = "/etc/ld.so.conf.d/zagros-softether.conf"
                try:
                    with open(conf, "w", encoding="utf-8") as fh:
                        fh.write(root + "\n")
                except OSError as exc:
                    raise CoreError(
                        f"cannot register {root} with the dynamic loader "
                        f"({conf}: {exc}) — run as root or add the path to "
                        "ld.so.conf manually, else vpnserver cannot start."
                    ) from exc
                ldconfig = shutil.which("ldconfig") or next(
                    (p for p in ("/sbin/ldconfig", "/usr/sbin/ldconfig")
                     if os.path.exists(p)),
                    None,
                )
                if ldconfig is None:
                    raise CoreError(
                        "ldconfig not found on this host — register "
                        f"{root} in /etc/ld.so.conf.d/ and refresh the "
                        "loader cache manually, else vpnserver cannot start."
                    )
                try:
                    self._run([ldconfig], timeout=60)
                except CoreError as exc:
                    raise CoreError(
                        f"ldconfig failed ({exc}) — vpnserver would not find "
                        "libcedar/libmayaqua at start."
                    ) from exc
            self._link_on_path(root)
            if persistent:
                # success marker: a later retry skips download+extract and
                # `cmake --build` short-circuits on up-to-date targets
                try:
                    with open(os.path.join(work, ".complete"), "w",
                              encoding="utf-8") as fh:
                        fh.write(tag)
                except OSError:
                    pass
                logger.info("softether source tree cached at %s (retry "
                            "resumes instantly)", work)
        finally:
            if not persistent:
                shutil.rmtree(work, ignore_errors=True)
        return f"built SoftEther {tag} from source (cmake)"

    def _run(self, argv: list[str], *, timeout: float = 120.0) -> str:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise CoreError(f"executable not found: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CoreError(f"command timed out: {' '.join(argv)}") from exc
        if proc.returncode != 0:
            detail = ((proc.stderr or "") + (proc.stdout or "")).strip()
            raise CoreError(f"command failed {' '.join(argv)}: {detail[:300]}")
        return proc.stdout or ""

    def server_binary(self) -> str | None:
        """Path of the vpnserver daemon binary, PATH first then known layouts."""
        hit = shutil.which("vpnserver")
        if hit:
            return hit
        for candidate in ("/usr/local/bin/vpnserver", "/usr/local/softether/vpnserver",
                          "/usr/lib/softether/vpnserver", "/usr/libexec/softether/vpnserver"):
            if os.path.exists(candidate):
                return candidate
        return None

    def server_start(self) -> None:
        """Launch the SoftEther daemon (it self-forks); idempotent by design —
        callers check reachable() first, and the daemon itself refuses
        double-starts harmlessly."""
        binary = self.server_binary()
        if binary is None:
            raise CoreError(
                "vpnserver binary not found — install the core first "
                "(Install action on the Cores page)."
            )
        self._run([binary, "start"], timeout=60)

    # ------------------------------------------------------------------ #
    # Protocol implementation
    # ------------------------------------------------------------------ #
    def reachable(self) -> bool:
        try:
            self._cmd("ServerInfoGet")
            return True
        except CoreError:
            return False

    def user_create(self, username: str, note: str = "") -> None:
        self._cmd(f'UserCreate {username} /GROUP: /REALNAME:"{note}" /NOTE:panel')

    def user_delete(self, username: str) -> None:
        self._cmd(f"UserDelete {username}")

    def user_password_set(self, username: str, password: str) -> None:
        self._cmd(f"UserPasswordSet {username} /PASSWORD:{password}")

    def user_expires_set(self, username: str, expires: str | None) -> None:
        if expires is None:
            self._cmd(f"UserExpiresSet {username} /EXPIRES:none")
        else:
            self._cmd(f'UserExpiresSet {username} /EXPIRES:"{expires}"')

    def suspend_user(self, username: str) -> None:
        self._cmd(f'UserExpiresSet {username} /EXPIRES:"{_SUSPENDED_EXPIRES}"')

    def user_get(self, username: str) -> UserStatistics:
        return parse_user_get(self._cmd(f"UserGet {username}"))

    def user_list(self) -> list[str]:
        return [u.username for u in parse_user_list(self._cmd("UserList", csv=True))]

    def session_list(self) -> list[SESession]:
        return parse_session_list(self._cmd("SessionList", csv=True))

    def session_disconnect(self, session_name: str) -> None:
        self._cmd(f"SessionDisconnect {session_name}")

    def ipsec_psk(self) -> str | None:
        return None  # optional: IPsecEnable inspection (kept honest: unset)
