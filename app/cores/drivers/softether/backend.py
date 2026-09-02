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
import re
import shutil
import subprocess
import time
from typing import Protocol, runtime_checkable

from app.cores.drivers.softether.setool import (
    CloneServers,
    parse_openvpn_get,
    parse_sstp_get,
    IPsecServices,
    SESession,
    SessionStatistics,
    UserStatistics,
    parse_ipsec_get,
    parse_session_get,
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
    def version(self) -> str | None: ...
    def user_create(self, username: str, note: str = "") -> None: ...
    def user_delete(self, username: str) -> None: ...
    def user_password_set(self, username: str, password: str) -> None: ...
    def user_expires_set(self, username: str, expires: str | None) -> None: ...
    def suspend_user(self, username: str) -> None: ...
    def user_get(self, username: str) -> UserStatistics: ...
    def users_get(self, usernames: list[str]) -> dict[str, UserStatistics]: ...
    def user_list(self) -> list[str]: ...
    def users_reconcile(self, accounts: list[tuple[str, str, str, bool]],
                        delete: list[str]) -> None: ...
    def session_list(self) -> list[SESession]: ...
    def session_get(self, session_name: str) -> SessionStatistics: ...
    def session_disconnect(self, session_name: str) -> None: ...
    def sstp_sessions_active(self) -> bool: ...
    def ipsec_psk(self) -> str | None: ...
    def ipsec_get(self) -> IPsecServices: ...
    def ipsec_services_set(self, *, l2tp: bool, l2tp_raw: bool, etherip: bool,
                           psk: str, default_hub: str) -> None: ...
    def clone_servers_get(self) -> CloneServers:
        """Current OpenVPN / SSTP clone-server switches (server-wide)."""
        ...
    def openvpn_clone_set(self, *, enabled: bool, ports: list[int]) -> None:
        """`OpenVpnEnable yes|no /PORTS:...` — the UDP clone listener switch."""
        ...
    def sstp_clone_set(self, *, enabled: bool) -> None:
        """`SstpEnable yes|no` — the MS-SSTP clone switch on TCP/443."""
        ...
    def secure_nat_ensure(self, *, hub_name: str | None = None) -> None:
        """Ensure a Virtual Hub has SecureNAT + DHCP enabled."""
        ...
    def routed_tap_ensure(self, *, device: str, subnet: str,
                          gateway: str, hub_name: str | None = None) -> str: ...
    def routed_tap_disable(self, *, device: str,
                           hub_name: str | None = None) -> None: ...
    def hub_list(self) -> list[str]: ...
    def hub_create(self, hub_name: str, password: str) -> None: ...
    def hub_delete(self, hub_name: str) -> None: ...
    def hub_user_create(self, hub_name: str, username: str,
                        password: str) -> None: ...
    def hub_user_delete(self, hub_name: str, username: str) -> None: ...
    def recover_fresh_server_password(self) -> bool:
        """Restore a persisted admin password onto a fresh blank server."""
        ...


class LocalSoftEtherBackend:
    """vpncmd-based backend (localhost hub administration)."""

    def __init__(self, settings: dict):
        self.vpncmd = settings.get("executable_path", "vpncmd")
        self.server = settings.get("server", "localhost")
        self.hub = settings.get("hub", "DEFAULT")
        self.password = settings.get("admin_password", "")
        self.timeout = float(settings.get("vpncmd_timeout", 30.0))
        self.protocol_backoff = float(settings.get("protocol_backoff_seconds", 10.0))
        # The panel container is recreated on every image upgrade. SoftEther's
        # daemon configuration lives beside vpnserver, so /usr/local was both
        # a binary-loss and a configuration-loss boundary. New installs use
        # the mounted data root; an explicit install_root remains available
        # for direct-host/package deployments.
        if settings.get("install_root"):
            self._INSTALL_ROOT = str(settings["install_root"])

    # ------------------------------------------------------------------ #
    # command plumbing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _safe_command(command: str) -> str:
        """Redact vpncmd command secrets before errors or logs.

        Authentication and commands are transported over the child's stdin;
        this remains a defence-in-depth boundary for vpncmd output and error
        messages, which can repeat a rejected command.
        """
        safe = re.sub(
            r"(?i)(/(?:PSK|PASSWORD):)(?:\"[^\"]*\"|\S+)",
            r"\1<redacted>", command,
        )
        # ServerPasswordSet takes a positional password (unlike user/account
        # password commands). Redact that form too before any error or log.
        return re.sub(
            r"(?i)(\bServerPasswordSet\s+)(?:\"[^\"]*\"|\S+)",
            r"\1<redacted>", safe,
        )

    @staticmethod
    def _usable_executable(path: str) -> bool:
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            return False
        # Panel wrappers are tiny `exec "<real>" "$@"` scripts. A leftover
        # wrapper whose old container/temp target vanished is not an install.
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                head = fh.read(512)
            if head.startswith("#!") and "exec " in head:
                import re

                match = re.search(r"\bexec\s+[\"']?([^\"'\s]+)", head)
                if match and os.path.isabs(match.group(1)):
                    return os.path.isfile(match.group(1))
        except OSError:
            return False
        return True

    def vpncmd_binary(self) -> str | None:
        """Resolve vpncmd across explicit, persistent and package installs."""
        configured = str(self.vpncmd or "vpncmd")
        if os.path.sep in configured and self._usable_executable(configured):
            return configured
        for candidate in (
            os.path.join(self._INSTALL_ROOT, "vpncmd"),
            shutil.which(configured) or "",
            "/usr/local/softether/vpncmd",  # pre-fix direct-host compatibility
            "/usr/lib/softether/vpncmd",
            "/usr/libexec/softether/vpncmd",
        ):
            if candidate and self._usable_executable(candidate):
                return candidate
        return None

    def server_command_inventory(self) -> set[str]:
        """Read the live server's command surface without mutating features."""
        from app.cores.drivers.softether.capabilities import (
            parse_server_command_inventory,
        )

        return parse_server_command_inventory(self._cmd("Help", hub=False))

    @staticmethod
    def _validate_hub_name(value: str) -> str:
        name = str(value or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,31}", name):
            raise CoreError(
                "SoftEther hub name must be 1-31 ASCII letters, digits, '_' or '-'"
            )
        return name

    @staticmethod
    def _validate_user_name(value: str) -> str:
        name = str(value or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", name):
            raise CoreError(
                "SoftEther user name must be 1-64 safe ASCII characters"
            )
        return name

    @staticmethod
    def _validate_secret_arg(value: str, *, label: str) -> str:
        secret = str(value or "")
        # vpncmd's interactive command parser cannot losslessly represent a
        # quote/newline inside /PASSWORD.  Refuse rather than execute a partial
        # command.  Spaces are quoted and all command text is redacted before
        # it can enter an error/log record.
        if not secret or len(secret) > 128 or any(ch in secret for ch in ('"', "\r", "\n")):
            raise CoreError(f"SoftEther {label} is empty, too long, or not safely encodable")
        return f'"{secret}"' if any(ch.isspace() for ch in secret) else secret

    @staticmethod
    def _csv_payload(result: str) -> str:
        """Return only the contiguous CSV table from a vpncmd PTY transcript.

        Primary and explicitly-selected hubs both print a human login banner,
        command prompt and trailing prompt around `/CSV` output. Keeping either
        prompt makes the generic CSV parser invent a fake user/header.
        """
        lines = result.splitlines()
        first = next((index for index, line in enumerate(lines) if "," in line), None)
        if first is None:
            return result
        table: list[str] = []
        for line in lines[first:]:
            if "," not in line:
                break
            table.append(line)
        return "\n".join(table) + ("\n" if table else "")

    def _cmd(self, command: str, *, csv: bool = False,
             hub: bool = True, hub_name: str | None = None) -> str:
        """Run a hub-scoped or entire-server vpncmd command.

        IPsec/SSTP/OpenVPN/listener switches require server-admin context and
        must omit ``/HUB``.  Normal account operations use the configured hub;
        managed isolated policy hubs pass ``hub_name`` explicitly.  The latter
        is essential for disposable verification: changing ``self.hub`` would
        redirect production account operations to the test hub and made the
        previous harness fall back to ``DEFAULT``.
        """
        safe = self._safe_command(command)
        executable = self.vpncmd_binary()
        if executable is None:
            raise CoreError(
                "vpncmd not found — the core will repair its persistent "
                "runtime on Start; use Install only if automatic recovery "
                "reports that no package/cache source is available."
            )
        argv = [executable, self.server, "/SERVER"]
        selected_hub: str | None = None
        switch_hub_after_server_auth = False
        if hub:
            selected_hub = self._validate_hub_name(hub_name or self.hub)
            if hub_name is None:
                # Existing primary-hub behavior: authenticate directly to the
                # configured hub (backward compatible with deployed servers).
                argv.append(f"/HUB:{selected_hub}")
            else:
                # A newly created isolated hub has its own random admin secret.
                # Do not persist that secret and do not pretend the server-admin
                # password is the hub password. Authenticate at server scope,
                # then select the hub with vpncmd's `Hub` command; server admin
                # authority can manage every hub safely this way.
                switch_hub_after_server_auth = True
        if csv:
            argv.append("/CSV")
        # Never place authentication material OR a secret-bearing command in
        # argv. Stable vpncmd can discard queued commands after a password read
        # from a plain PIPE; use the bounded no-echo PTY channel shared with the
        # native client lifecycle and wait for each real prompt instead.
        if any(ch in self.password for ch in ("\r", "\n")):
            raise CoreError("SoftEther administrator password contains a newline.")
        if any(ch in command for ch in ("\r", "\n")):
            raise CoreError("vpncmd command contains a newline.")
        from app.cores.routing.softether_client import run_vpncmd_pty

        commands = ([f"Hub {selected_hub}"]
                    if switch_hub_after_server_auth else [])
        commands.append(command)
        try:
            result = run_vpncmd_pty(
                argv,
                commands=commands,
                administrator_password=self.password,
                prompt="VPN Server",
                timeout=self.timeout,
            )
        except CoreError as exc:
            raise CoreError(
                f"vpncmd '{safe}' failed: {self._safe_command(str(exc))}") from exc
        if csv:
            # UserList must reflect live identity before an idempotent account
            # reconcile; a banner-as-header made it empty and caused duplicate
            # UserCreate/error 66. Strip both leading and trailing PTY text.
            result = self._csv_payload(result)
        return result

    # ------------------------------------------------------------------ #
    # IPsec server functions (L2TP/IPsec, raw L2TP, EtherIP)
    #
    # bug (field report "vpncmd 'IPsecEnable /L2TP:no...
    # /DEFAULTHUB:DEFAULT' failed (rc=38)"): upstream PsIPsecEnable
    # declares ALL FIVE arguments — including /PSK: — with CmdEvalNotEmpty,
    # so a missing/empty PSK fails vpncmd's LOCAL validation and the tool
    # exits ERR_INVALID_PARAMETER (38) BEFORE any RPC runs — even when the
    # intent is to disable every service. Commands are fed through vpncmd's
    # interactive stdin parser, so embedded whitespace still needs real
    # quoting. Every IPsecEnable issued by this backend therefore carries the
    # full 5-argument form with a non-empty PSK + hub, validated locally first
    # so a bad value never half-commands the server.
    # ------------------------------------------------------------------ #

    def ipsec_get(self) -> IPsecServices:
        """Current server IPsec state (authoritative — used to converge
        without clobbering the stored PSK or the default hub)."""
        return parse_ipsec_get(self._cmd("IPsecGet", hub=False))

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
            f"/ETHERIP:{yn(etherip)} /PSK:{psk_arg} /DEFAULTHUB:{hub}",
            hub=False,
        )

    # ------------------------------------------------------------------ #
    # Clone servers (OpenVPN on UDP, MS-SSTP on TCP/443)
    #
    # A freshly installed vpn_server.config ships with BOTH clone servers
    # enabled: SoftEther takes UDP/1194 and answers SSTP on 443 before the
    # operator has asked for anything. That is exactly the port the real
    # OpenVPN core binds by default, so "install SoftEther, then start
    # OpenVPN" died with EADDRINUSE until someone switched the clone off by
    # hand. These verbs let the driver converge the switches to the
    # operator's feature set on every start.
    # ------------------------------------------------------------------ #

    def clone_servers_get(self) -> CloneServers:
        openvpn, ports = parse_openvpn_get(self._cmd("OpenVpnGet", hub=False))
        sstp = parse_sstp_get(self._cmd("SstpGet", hub=False))
        return CloneServers(openvpn=openvpn, openvpn_ports=ports, sstp=sstp)

    def openvpn_clone_set(self, *, enabled: bool, ports: list[int]) -> None:
        clean = sorted({int(p) for p in ports if 1 <= int(p) <= 65535}) or [1194]
        self._cmd(
            f"OpenVpnEnable {'yes' if enabled else 'no'} "
            f"/PORTS:{','.join(str(p) for p in clean)}",
            hub=False,
        )

    def sstp_clone_set(self, *, enabled: bool) -> None:
        self._cmd(f"SstpEnable {'yes' if enabled else 'no'}", hub=False)

    def hub_list(self) -> list[str]:
        """Return live Virtual Hub names without changing the configured hub."""
        import csv
        import io

        rows = csv.reader(io.StringIO(self._cmd("HubList", csv=True, hub=False)))
        names: list[str] = []
        for row in rows:
            if not row:
                continue
            first = str(row[0]).strip()
            if not first or first.lower() in {
                "virtual hub name", "hub name", "the command completed successfully.",
            }:
                continue
            # /CSV rows have at least the hub name and state/type columns.
            if len(row) >= 2 and re.fullmatch(r"[A-Za-z0-9_-]{1,31}", first):
                names.append(first)
        return sorted(set(names))

    def _lifecycle_quiet(self) -> None:
        """Respect SoftEther's localhost management DoS window.

        Hub/bridge/user creation is necessarily a short sequence of vpncmd
        RPCs.  The server can otherwise accept HubCreate, then let the next
        UserCreate hang until the client timeout.  A bounded quiet window makes
        that sequence deterministic instead of retrying a half-created hub.
        """
        if self.protocol_backoff > 0:
            time.sleep(min(self.protocol_backoff, 10.0))

    def hub_create(self, hub_name: str, password: str) -> None:
        hub_name = self._validate_hub_name(hub_name)
        if hub_name in self.hub_list():
            raise CoreError(f"SoftEther hub '{hub_name}' already exists")
        password_arg = self._validate_secret_arg(password, label="hub password")
        self._cmd(
            f"HubCreate {hub_name} /PASSWORD:{password_arg}", hub=False)
        self._lifecycle_quiet()
        if hub_name not in self.hub_list():
            raise CoreError(f"SoftEther created no observable hub '{hub_name}'")

    def hub_delete(self, hub_name: str) -> None:
        hub_name = self._validate_hub_name(hub_name)
        if hub_name not in self.hub_list():
            return
        self._cmd(f"HubDelete {hub_name}", hub=False)
        self._lifecycle_quiet()
        if hub_name in self.hub_list():
            raise CoreError(f"SoftEther hub '{hub_name}' still exists after deletion")

    def hub_user_create(self, hub_name: str, username: str,
                        password: str) -> None:
        hub_name = self._validate_hub_name(hub_name)
        username = self._validate_user_name(username)
        password_arg = self._validate_secret_arg(password, label="user password")
        self._cmd(
            f'UserCreate {username} /GROUP: /REALNAME:"Zagros managed policy source" '
            "/NOTE:zagros-managed-policy-hub",
            hub_name=hub_name,
        )
        self._lifecycle_quiet()
        try:
            self._cmd(
                f"UserPasswordSet {username} /PASSWORD:{password_arg}",
                hub_name=hub_name,
            )
            self._lifecycle_quiet()
        except Exception:
            try:
                self._cmd(f"UserDelete {username}", hub_name=hub_name)
            except Exception:  # noqa: BLE001 - preserve credential failure
                pass
            raise

    def hub_user_delete(self, hub_name: str, username: str) -> None:
        hub_name = self._validate_hub_name(hub_name)
        username = self._validate_user_name(username)
        try:
            self._cmd(f"UserDelete {username}", hub_name=hub_name)
            self._lifecycle_quiet()
        except CoreError as exc:
            if not any(marker in str(exc).lower() for marker in
                       ("not found", "not exist", "no such")):
                raise

    def routed_tap_ensure(
        self, *, device: str = "zgsoft", subnet: str = "192.168.30.0/24",
        gateway: str = "192.168.30.254", hub_name: str | None = None,
    ) -> str:
        """Expose hub client packets to Linux instead of userspace NAT.

        SecureNAT's DHCP server remains available, but its Virtual NAT is
        disabled and advertises the host TAP address as gateway. This is the
        only honest way to classify L2TP/SSTP/native sessions in netfilter.
        Returns the Linux interface name created by SoftEther.
        """
        import ipaddress
        import re

        target_hub = self._validate_hub_name(hub_name or self.hub)
        network = ipaddress.ip_network(subnet, strict=False)
        gateway_ip = ipaddress.ip_address(gateway)
        if network.version != 4 or gateway_ip not in network:
            raise CoreError("SoftEther routed TAP needs an IPv4 gateway inside its subnet")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,10}", device):
            raise CoreError("SoftEther TAP device id must be 1-10 safe characters")
        start = str(network.network_address + 10)
        end = str(network.broadcast_address - 10)
        mask = str(network.netmask)
        # Server-wide bridge. Existing is success; any other failure is real.
        try:
            self._cmd(
                f"BridgeCreate {target_hub} /DEVICE:{device} /TAP:yes", hub=False)
        except CoreError as exc:
            if not any(word in str(exc).lower() for word in
                       ("already", "exist", "duplicate")):
                raise
        for command in ("SecureNatEnable", "DhcpEnable", "NatDisable"):
            try:
                self._cmd(command, hub_name=target_hub)
            except CoreError as exc:
                if not any(word in str(exc).lower() for word in
                           ("already", "enabled", "disabled")):
                    raise
        self._cmd(
            f"DhcpSet /START:{start} /END:{end} /MASK:{mask} "
            f"/EXPIRE:7200 /GW:{gateway} /DNS:1.1.1.1 /DNS2:8.8.8.8 "
            "/DOMAIN:none /LOG:no",
            hub_name=target_hub,
        )
        return f"tap_{device}"

    def routed_tap_disable(self, *, device: str = "zgsoft",
                           hub_name: str | None = None) -> None:
        """Return one hub to SecureNAT and remove only its policy bridge."""
        target_hub = self._validate_hub_name(hub_name or self.hub)
        try:
            self._cmd("NatEnable", hub_name=target_hub)
        except CoreError as exc:
            if not any(word in str(exc).lower() for word in ("already", "enabled")):
                raise
        try:
            self._cmd(
                f"BridgeDelete {target_hub} /DEVICE:{device}", hub=False)
        except CoreError as exc:
            if not any(word in str(exc).lower() for word in
                       ("not found", "not exist", "none")):
                raise

    def secure_nat_ensure(self, *, hub_name: str | None = None) -> None:
        """Enable the hub's self-contained NAT and DHCP service idempotently.

        This is the production-safe default for a VPS with no LAN bridge. A
        successful L2TP/CHAP session otherwise reaches PPP and dies with
        "Could not determine local IP address" because no DHCP lease exists.
        """
        target_hub = self._validate_hub_name(hub_name or self.hub)
        for command in ("SecureNatEnable", "DhcpEnable"):
            try:
                self._cmd(command, hub_name=target_hub)
            except CoreError as exc:
                text = str(exc).lower()
                if not any(marker in text for marker in
                           ("already", "enabled", "exist")):
                    raise CoreError(
                        f"SoftEther hub '{target_hub}' cannot enable Virtual "
                        f"NAT/DHCP via {command}: {exc}"
                    ) from exc
        # Read back real pool facts. The output includes START/END/MASK/GW/DNS
        # addresses; fewer than four valid IPv4 values means clients still
        # cannot receive a usable lease and the apply must fail honestly.
        status = self._cmd("DhcpGet", hub_name=target_hub)
        import ipaddress
        import re

        valid: list[str] = []
        for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
                                    status):
            try:
                ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            valid.append(candidate)
        if len(set(valid)) < 4:
            raise CoreError(
                f"SoftEther SecureNAT is enabled on hub '{target_hub}', but "
                "DhcpGet did not report a complete lease pool (start/end/"
                "mask/gateway). Configure DhcpSet or disable secure_nat and "
                "provide a real external DHCP/local bridge."
            )

    def recover_fresh_server_password(self) -> bool:
        """Apply the persisted admin password to a demonstrably blank server.

        Alpha.7.7 kept vpn_server.config in the replaceable container layer.
        On the first fixed upgrade a fresh daemon may therefore answer with an
        empty password while SQL still contains the operator's password. We
        probe blank authority first; only that proves this is a fresh server
        rather than an incorrect credential against valuable existing state.
        """
        desired = str(self.password or "")
        if not desired:
            return False
        self.password = ""
        try:
            self._cmd("ServerInfoGet", hub=False)  # fail closed unless blank works
            if any(ch in desired for ch in ('"', "\n", "\r")):
                raise CoreError(
                    "persisted SoftEther admin password contains characters "
                    "that cannot be encoded for automatic recovery"
                )
            password_arg = (f'"{desired}"' if any(ch.isspace() for ch in desired)
                            else desired)
            self._cmd(f"ServerPasswordSet {password_arg}", hub=False)
        except CoreError:
            return False
        finally:
            self.password = desired
        return self.reachable()

    # ------------------------------------------------------------------ #
    # setup — real SELF_INSTALL (3-stage chain)
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
    # "Could NOT find PkgConfig" otherwise (field report).
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

    # Persist across Docker image replacement. ``vpn_server.config`` is
    # stored beside vpnserver by SoftEther itself, so this is runtime state,
    # not merely a re-downloadable executable directory.
    _INSTALL_ROOT = "/var/lib/zagros/cores/softether/runtime"

    def install_packages(self) -> str:
        """Install SoftEther once, under an inter-process build lock.

        Fast path is the official architecture-specific **stable** bundle.
        It contains precompiled vpnserver/vpncmd object archives, so the host
        only performs the two final links instead of compiling the entire 5.x
        developer tree. Distro packages and the controlled source build are
        fallbacks. Every completed stage is verified by a real executable.
        """
        cache = self._src_cache_root() or "/tmp/zagros-softether-cache"
        os.makedirs(cache, exist_ok=True)
        lock_path = os.path.join(cache, ".install.lock")
        # flock is process-wide and is released by the kernel on interruption;
        # a second API worker waits rather than downloading/building again.
        import fcntl

        with open(lock_path, "a+", encoding="utf-8") as lock:
            self._set_progress("waiting_lock", "waiting for another installer, if any")
            logger.info("softether install: waiting for build lock %s", lock_path)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            self._set_progress("resolving", "checking existing binary and official stable release")
            logger.info("softether install: build lock acquired")
            existing = self.server_binary()
            client = self.client_binary()
            if existing and client:
                self._set_progress("complete", "server and client already installed")
                return (f"SoftEther server+client already installed "
                        f"({existing}, {client}); no build needed")

            errors: list[str] = []
            try:
                result = self._install_from_github()
                self._set_progress("complete", "official stable bundle installed")
                return result
            except Exception as exc:  # noqa: BLE001 — report every attempt
                errors.append(f"stable-bundle: {exc}")
            for manager, argv, refresh in self._PKG_MANAGERS:
                if shutil.which(manager) is None:
                    continue
                try:
                    if refresh:
                        self._run(refresh, timeout=600)
                    self._run(argv, timeout=900)
                    if self.server_binary() and self.client_binary():
                        self._set_progress("complete", f"server+client installed through {manager}")
                        return f"installed SoftEther server+client via {manager}"
                    errors.append(
                        f"{manager}: install completed but vpnserver/vpnclient pair not found")
                except CoreError as exc:
                    errors.append(f"{manager}: {exc}")
            try:
                self._set_progress("source_fallback", "stable/package unavailable; controlled source build")
                result = self._install_from_source()
                self._set_progress("complete", "controlled source build installed")
                return result
            except Exception as exc:  # noqa: BLE001 — report every attempt
                errors.append(f"source-build: {exc}")
            self._set_progress("failed", "all installation strategies failed; see error detail")
            raise CoreError(
                "could not self-install SoftEther VPN Server — attempts: "
                + " | ".join(errors or ["no strategy applicable on this host"])
            )

    def _link_on_path(self, root: str) -> None:
        # WRAPPER scripts, not symlinks (field failure): SoftEther
        # locates hamcore.se2/lang.config relative to its own argv[0] path —
        # started through a symlink in /usr/local/bin it dies with
        # 'hamcore.se2 is missing or broken'. A wrapper exec's the REAL path,
        # so the resource lookup stays anchored at the install root.
        for name in ("vpnserver", "vpnclient", "vpncmd"):
            real = os.path.join(root, name)
            link = os.path.join("/usr/local/bin", name)
            try:
                part = link + ".part"
                with open(part, "w", encoding="utf-8") as fh:
                    fh.write(f"#!/bin/sh\nexec \"{real}\" \"$@\"\n")
                os.chmod(part, 0o755)
                os.replace(part, link)
            except OSError as exc:
                logger.warning("softether PATH wrapper %s failed: %s", link, exc)

    def _ensure_bundle_deps(self) -> None:
        """Stable Linux bundles carry precompiled .a files; only the final
        linker toolchain is needed (no cmake, libsodium, or full source deps)."""
        if all(shutil.which(tool) for tool in ("make", "gcc", "ranlib")):
            return
        packages = {
            "apt-get": (["apt-get", "update"],
                        ["apt-get", "install", "-y", "build-essential", "binutils"]),
            "dnf": (None, ["dnf", "install", "-y", "gcc", "make", "binutils"]),
            "yum": (None, ["yum", "install", "-y", "gcc", "make", "binutils"]),
            "pacman": (None, ["pacman", "-S", "--noconfirm", "gcc", "make", "binutils"]),
            "apk": (None, ["apk", "add", "gcc", "musl-dev", "make", "binutils"]),
        }
        for manager, (refresh, install) in packages.items():
            if not shutil.which(manager):
                continue
            if refresh:
                self._run(refresh, timeout=600)
            self._run(install, timeout=1200)
            if all(shutil.which(tool) for tool in ("make", "gcc", "ranlib")):
                return
            break
        raise CoreError("stable bundle needs make, gcc and ranlib for its two final links")

    def _install_from_github(self) -> str:
        """Install matching official Stable vpnserver **and vpnclient** bundles.

        SoftEther publishes server and client as separate architecture assets.
        ``vpncmd`` alone is only a management utility; native outbound support
        requires the real ``vpnclient`` engine.  Both precompiled-object
        bundles are resolved from one exact RTM release, final-linked in their
        private caches, verified, and atomically published together.
        """
        import re
        import tarfile
        import tempfile

        from app.cores.github_install import fetch_release_list, host_arch, host_os

        system, arch = host_os(), host_arch()
        if system != "linux" or arch not in ("amd64", "arm64"):
            raise CoreError(f"no supported stable bundle for {system}/{arch}")
        arch_name = "x64-64bit" if arch == "amd64" else "arm64-64bit"
        self._set_progress("resolving", "selecting matching server/client RTM bundles")
        releases = fetch_release_list("SoftEtherVPN/SoftEtherVPN_Stable", limit=10)
        candidates = [r for r in releases
                      if not r.get("prerelease")
                      and re.match(r"^v\d+\.\d+-\d+-rtm$",
                                   str(r.get("tag_name") or ""), re.I)]
        if not candidates:
            raise CoreError("SoftEther stable repository published no RTM release")

        def version_key(release: dict) -> tuple[int, int, int]:
            nums = re.findall(r"\d+", str(release.get("tag_name") or ""))
            return tuple((list(map(int, nums)) + [0, 0, 0])[:3])  # type: ignore[return-value]

        release = max(candidates, key=version_key)
        tag = str(release["tag_name"])
        assets: dict[str, dict] = {}
        for kind in ("vpnserver", "vpnclient"):
            asset = next((a for a in release.get("assets", [])
                          if str(a.get("name", "")).startswith(f"softether-{kind}-")
                          and "-linux-" in str(a.get("name", "")).lower()
                          and arch_name in str(a.get("name", ""))
                          and str(a.get("name", "")).endswith(".tar.gz")), None)
            if not asset or not asset.get("browser_download_url"):
                raise CoreError(
                    f"{tag} has no Linux {arch_name} {kind} bundle")
            assets[kind] = asset

        cache_root = self._src_cache_root()
        ephemeral_root = None
        if cache_root:
            base = os.path.join(cache_root, "stable", tag, arch_name)
        else:
            ephemeral_root = tempfile.mkdtemp(prefix="zagros-softether-stable-")
            base = ephemeral_root
        os.makedirs(base, exist_ok=True)
        sources: dict[str, str] = {}
        try:
            for kind, asset in assets.items():
                work = os.path.join(base, kind)
                os.makedirs(work, exist_ok=True)
                package = os.path.join(work, "bundle.tar.gz")
                extracted = os.path.join(work, "extracted")
                complete = os.path.join(work, ".complete")
                if not os.path.exists(package):
                    self._set_progress("downloading", str(asset["name"]))
                    logger.info("softether stable bundle: downloading %s", asset["name"])
                    self._download(str(asset["browser_download_url"]), package)
                if not os.path.isdir(extracted):
                    self._set_progress("extracting", f"validating {kind} bundle")
                    part = f"{extracted}.part.{os.getpid()}"
                    shutil.rmtree(part, ignore_errors=True)
                    os.makedirs(part)
                    try:
                        with tarfile.open(package, "r:gz") as tar:
                            tar.extractall(part, filter="data")
                        source_part = os.path.join(part, kind)
                        expected = ("Makefile", f"code/{kind}.a", "code/vpncmd.a",
                                    "hamcore.se2")
                        if not all(os.path.exists(os.path.join(source_part, item))
                                   for item in expected):
                            raise CoreError(
                                f"stable {kind} bundle is missing its signed release layout")
                        os.replace(part, extracted)
                    except Exception:
                        shutil.rmtree(part, ignore_errors=True)
                        try:
                            os.remove(package)
                        except OSError:
                            pass
                        raise
                source = os.path.join(extracted, kind)
                if not all(os.path.isfile(os.path.join(source, name))
                           for name in (kind, "vpncmd")):
                    self._set_progress(
                        "linking", f"final-linking official {kind} objects (1 job)")
                    self._ensure_bundle_deps()
                    self._run_streamed(
                        ["make", "-C", source, "main", "-j", "1"], timeout=600)
                if not all(os.path.isfile(os.path.join(source, name))
                           for name in (kind, "vpncmd", "hamcore.se2")):
                    raise CoreError(
                        f"stable bundle final-link did not produce {kind}/vpncmd")
                with open(complete + ".part", "w", encoding="utf-8") as fh:
                    fh.write(tag)
                os.replace(complete + ".part", complete)
                sources[kind] = source

            self._set_progress("installing", "atomically publishing server+client runtime")
            root = self._INSTALL_ROOT
            stage = f"{root}.part.{os.getpid()}"
            backup = f"{root}.previous.{os.getpid()}"
            shutil.rmtree(stage, ignore_errors=True)
            os.makedirs(stage, mode=0o755)
            server_source = sources["vpnserver"]
            client_source = sources["vpnclient"]
            for name, source in (
                ("vpnserver", server_source),
                ("vpncmd", server_source),
                ("hamcore.se2", server_source),
                ("vpnclient", client_source),
            ):
                shutil.copy2(os.path.join(source, name), os.path.join(stage, name))
            for name in ("vpnserver", "vpncmd", "vpnclient"):
                os.chmod(os.path.join(stage, name), 0o755)
            # Preserve only server identity. Per-outbound vpnclient state lives
            # under its private policy runtime and is always derived/recreated.
            for name in ("vpn_server.config", "lang.config"):
                old = os.path.join(root, name)
                if os.path.isfile(old):
                    shutil.copy2(old, os.path.join(stage, name))
            shutil.rmtree(backup, ignore_errors=True)
            if os.path.isdir(root):
                os.replace(root, backup)
            try:
                os.replace(stage, root)
            except Exception:
                if os.path.isdir(backup) and not os.path.exists(root):
                    os.replace(backup, root)
                raise
            shutil.rmtree(backup, ignore_errors=True)
            self._link_on_path(root)
            logger.info("softether stable server+client runtime installed: %s", tag)
            return (
                f"installed SoftEther {tag} stable vpnserver+vpnclient bundles "
                "(precompiled objects; bounded final links)"
            )
        finally:
            if ephemeral_root:
                shutil.rmtree(ephemeral_root, ignore_errors=True)

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

    # the source build must be CONTROLLED, CACHED and
    # OBSERVABLE (field report: install pinned the host at 100% CPU with
    # zero visible progress and re-downloaded/re-compiled everything on
    # every retry):
    #: parallelism ceiling (env ZAGROS_SOFTETHER_BUILD_JOBS overrides) —
    #: a full-throttle --parallel <all cores> starves the panel and live
    #: VPN traffic on small VPS hosts
    _BUILD_JOBS_CAP = 4
    #: Build only the server, the real native client dataplane and vpncmd.
    #: vpnbridge/vpntest remain excluded.
    _BUILD_TARGETS = ("cedar", "mayaqua", "hamcore-archive-build",
                      "vpnserver", "vpnclient", "vpncmd")

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
                import threading

                probe = os.path.join(
                    root, f".probe.{os.getpid()}.{threading.get_ident()}")
                with open(probe, "w", encoding="utf-8") as fh:
                    fh.write("ok")
                os.remove(probe)
                return root
            except OSError:
                continue
        return None

    def _progress_file(self) -> str:
        root = self._src_cache_root() or "/tmp/zagros-softether-cache"
        os.makedirs(root, exist_ok=True)
        return os.path.join(root, "install-progress.json")

    def _set_progress(self, stage: str, detail: str = "") -> None:
        """Persist a secret-free installation stage for UI polling."""
        import json

        path = self._progress_file()
        part = path + ".part"
        payload = {"stage": stage, "detail": detail, "updated_at": int(time.time())}
        try:
            with open(part, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(part, path)
        except OSError:
            try:
                os.remove(part)
            except OSError:
                pass

    def install_progress(self) -> dict[str, object]:
        import json

        try:
            with open(self._progress_file(), encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {"stage": "unknown"}
        except (OSError, ValueError):
            return {"stage": "idle", "detail": ""}

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

         controls:
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
            # Build/copy into a sibling stage. A compile failure or SIGTERM
            # leaves the current install untouched; only a complete artifact
            # set is renamed into service.
            stage = f"{root}.part.{os.getpid()}"
            backup = f"{root}.previous.{os.getpid()}"
            shutil.rmtree(stage, ignore_errors=True)
            os.makedirs(stage, exist_ok=True)
            for name in ("vpnserver", "vpnclient", "vpncmd", "hamcore.se2"):
                built = os.path.join(build_dir, name)
                if not os.path.exists(built):
                    shutil.rmtree(stage, ignore_errors=True)
                    raise CoreError(f"cmake build did not produce '{name}'")
                shutil.copy2(built, os.path.join(stage, name))
            os.chmod(os.path.join(stage, "vpnserver"), 0o755)
            os.chmod(os.path.join(stage, "vpnclient"), 0o755)
            os.chmod(os.path.join(stage, "vpncmd"), 0o755)
            # cmake builds cedar/mayaqua as SHARED libs and bakes the temp
            # build dir into RUNPATH. Ship the libs next to the binaries.
            libs = sorted(
                name for name in os.listdir(build_dir)
                if name.startswith(("libcedar.so", "libmayaqua.so"))
                and os.path.isfile(os.path.join(build_dir, name))
            )
            for name in libs:
                shutil.copy2(os.path.join(build_dir, name), os.path.join(stage, name))
            for name in ("vpn_server.config", "lang.config"):
                old = os.path.join(root, name)
                if os.path.isfile(old):
                    shutil.copy2(old, os.path.join(stage, name))
            shutil.rmtree(backup, ignore_errors=True)
            if os.path.isdir(root):
                os.replace(root, backup)
            try:
                os.replace(stage, root)
            except Exception:
                if os.path.isdir(backup) and not os.path.exists(root):
                    os.replace(backup, root)
                raise
            shutil.rmtree(backup, ignore_errors=True)
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
        """Path of vpnserver, rejecting wrappers with vanished targets."""
        for candidate in (
            os.path.join(self._INSTALL_ROOT, "vpnserver"),
            shutil.which("vpnserver") or "",
            "/usr/local/softether/vpnserver",  # pre-fix direct-host compatibility
            "/usr/lib/softether/vpnserver",
            "/usr/libexec/softether/vpnserver",
        ):
            if candidate and self._usable_executable(candidate):
                return candidate
        return None

    def client_binary(self) -> str | None:
        """Resolve the real SoftEther VPN Client engine, never vpncmd."""
        for candidate in (
            os.path.join(self._INSTALL_ROOT, "vpnclient"),
            shutil.which("vpnclient") or "",
            "/usr/local/softether/vpnclient",
            "/usr/lib/softether/vpnclient",
            "/usr/libexec/softether/vpnclient",
        ):
            if candidate and self._usable_executable(candidate):
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
    def version(self) -> str | None:
        executable = self.vpncmd_binary()
        if executable is None:
            return None
        try:
            proc = subprocess.run(
                [executable, "/?"], capture_output=True, text=True,
                timeout=min(self.timeout, 10.0))
        except (OSError, subprocess.SubprocessError):
            return None
        output = (proc.stdout or "") + (proc.stderr or "")
        match = re.search(r"\bVersion\s+([0-9.]+)\s+Build\s+([0-9]+)", output)
        return f"{match.group(1)} build {match.group(2)}" if match else None

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

    def users_get(self, usernames: list[str]) -> dict[str, UserStatistics]:
        """Read many UserGet counters in one authenticated vpncmd session.

        SoftEther rate-limits rapid localhost management logins. Opening one
        process per account every recorder tick could pause an active SSTP
        data stream (TCP-over-TCP then collapsed). Keep the whole account
        sweep on one PTY/login; a failed or incomplete batch is discarded so
        cumulative counters are retried on the next tick without loss.
        """
        wanted = [self._validate_user_name(value) for value in usernames]
        if not wanted:
            return {}
        executable = self.vpncmd_binary()
        if executable is None:
            raise CoreError("vpncmd not found for SoftEther usage batch")
        selected_hub = self._validate_hub_name(self.hub)
        from app.cores.routing.softether_client import run_vpncmd_pty

        transcript = run_vpncmd_pty(
            [executable, self.server, "/SERVER", f"/HUB:{selected_hub}"],
            commands=[f"UserGet {username}" for username in wanted],
            administrator_password=self.password,
            prompt="VPN Server",
            timeout=max(self.timeout, 30.0),
        )
        # Every UserGet table starts with its stable English "User Name" row.
        # Split there so parse_user_get cannot overwrite an earlier table with
        # fields from the following command in the shared transcript.
        blocks: list[list[str]] = []
        current: list[str] | None = None
        for line in transcript.splitlines():
            label = line.split("|", 1)[0].strip(" -") if "|" in line else ""
            if label.lower() == "user name":
                if current:
                    blocks.append(current)
                current = [line]
            elif current is not None:
                current.append(line)
        if current:
            blocks.append(current)
        result: dict[str, UserStatistics] = {}
        for block in blocks:
            stats = parse_user_get("\n".join(block))
            if stats.username in wanted:
                result[stats.username] = stats
        missing = sorted(set(wanted) - set(result))
        if missing:
            raise CoreError(
                "SoftEther usage batch returned no UserGet table for: "
                + ", ".join(missing)
            )
        return result

    def user_list(self) -> list[str]:
        return [u.username for u in parse_user_list(self._cmd("UserList", csv=True))]

    def users_reconcile(
        self,
        accounts: list[tuple[str, str, str, bool]],
        delete: list[str],
    ) -> None:
        """Converge a desired account batch in one authenticated vpncmd PTY.

        The first command is the authoritative live UserList. Its transcript
        generates only necessary UserCreate calls, followed by password and
        enabled/expiry convergence. A partial failure is retry-safe because the
        next run re-reads the live list in the same session before deciding.
        No error code is suppressed and no sleep/retry loop is used.
        """
        executable = self.vpncmd_binary()
        if executable is None:
            raise CoreError("vpncmd not found for SoftEther account reconciliation")
        selected_hub = self._validate_hub_name(self.hub)
        if any(ch in self.password for ch in ("\r", "\n")):
            raise CoreError("SoftEther administrator password contains a newline.")

        desired: list[tuple[str, str, str, bool, str]] = []
        secret_values: list[str] = []
        for username, real_name, password, enabled in accounts:
            username = self._validate_user_name(username)
            real_name = self._validate_user_name(real_name)
            password_arg = self._validate_secret_arg(
                password, label=f"user password for {username}")
            desired.append((username, real_name, password, bool(enabled), password_arg))
            secret_values.append(password)
        stale = [self._validate_user_name(value) for value in delete]

        def followup(transcript: str) -> list[str]:
            current = {
                user.username
                for user in parse_user_list(self._csv_payload(transcript))
            }
            commands: list[str] = []
            for username in stale:
                if username in current:
                    commands.append(f"UserDelete {username}")
                    current.discard(username)
            for username, real_name, _password, enabled, password_arg in desired:
                if username not in current:
                    commands.append(
                        f'UserCreate {username} /GROUP: /REALNAME:"{real_name}" '
                        "/NOTE:panel"
                    )
                    current.add(username)
                commands.append(
                    f"UserPasswordSet {username} /PASSWORD:{password_arg}")
                expires = "none" if enabled else f'"{_SUSPENDED_EXPIRES}"'
                commands.append(f"UserExpiresSet {username} /EXPIRES:{expires}")
            return commands

        from app.cores.routing.softether_client import run_vpncmd_pty

        argv = [executable, self.server, "/SERVER", f"/HUB:{selected_hub}", "/CSV"]
        try:
            run_vpncmd_pty(
                argv,
                commands=["UserList"],
                administrator_password=self.password,
                prompt="VPN Server",
                secrets=secret_values,
                timeout=self.timeout,
                followup_factory=followup,
            )
        except CoreError as exc:
            raise CoreError(
                "vpncmd SoftEther account reconciliation failed: "
                f"{self._safe_command(str(exc))}") from exc

    def session_list(self) -> list[SESession]:
        return parse_session_list(self._cmd("SessionList", csv=True))

    def session_get(self, session_name: str) -> SessionStatistics:
        return parse_session_get(self._cmd(f"SessionGet {session_name}"))

    def session_disconnect(self, session_name: str) -> None:
        self._cmd(f"SessionDisconnect {session_name}")

    def sstp_sessions_active(self) -> bool:
        """Detect remote TCP/443 sessions without opening vpncmd.

        SoftEther's management RPC shares the server and rapid polling can
        collapse SSTP's nested TCP stream. During an active remote SSTP socket
        the recorder defers its cumulative read until disconnect. Loopback
        vpncmd sessions are ignored.
        """
        executable = shutil.which("ss")
        if executable is None:
            return False
        try:
            text = self._run(
                [executable, "-Hnt", "state", "established",
                 "sport", "=", ":443"],
                timeout=5,
            )
        except CoreError:
            return False
        for line in text.splitlines():
            columns = line.split()
            if len(columns) < 4:
                continue
            peer = columns[-1]
            host = peer.rsplit(":", 1)[0].strip("[]")
            if host not in {"127.0.0.1", "::1"}:
                return True
        return False

    def ipsec_psk(self) -> str | None:
        return None  # optional: IPsecEnable inspection (kept honest: unset)
