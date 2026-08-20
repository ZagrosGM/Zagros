"""Real PPP client profile materialization for policy-routing domains.

The module is intentionally pure: it renders private runtime files and
secret-free process argv; namespace/process ownership stays in
``PolicyRoutingManager``.  Keeping this boundary small makes it possible to
prove that credentials never enter argv, logs, process titles or public API
responses.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind, PPP_CLIENT_KINDS

_SSTP_PATH = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"


def _quoted_ppp(value: Any) -> str:
    text = str(value)
    if not text or any(ch in text for ch in "\x00\r\n"):
        raise CoreError("PPP option values must be non-empty and contain no NUL/newline")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _safe_dns_name(value: str) -> str:
    value = value.strip()
    if not value or any(ch.isspace() for ch in value) or not re.fullmatch(
        r"(?=.{1,253}\Z)[A-Za-z0-9:._-]+", value
    ):
        raise CoreError("invalid SSTP TLS server name")
    return value


@dataclass(frozen=True, slots=True)
class PPPClientPlan:
    kind: OutboundKind
    endpoint: str
    interface: str
    files: dict[str, str]
    file_modes: dict[str, int]
    primary_argv: list[str]
    auxiliary_argv: list[list[str]]
    health_protocol: str

    def assert_secret_free_argv(self, secrets: list[str]) -> None:
        serialized = "\x00".join(
            [*self.primary_argv, *(item for argv in self.auxiliary_argv for item in argv)]
        )
        leaked = [secret for secret in secrets if secret and secret in serialized]
        if leaked:
            raise CoreError("PPP provider refused credential-bearing process arguments")


def render_ppp_client_plan(
    outbound: Outbound,
    *,
    runtime_dir: str,
    endpoint: str,
    interface: str = "ppp0",
    pppd: str = "/usr/sbin/pppd",
    xl2tpd: str = "/usr/sbin/xl2tpd",
    sstpc: str = "/usr/sbin/sstpc",
    sstp_plugin: str = "/usr/lib/pppd/2.5.2/sstp-pppd-plugin.so",
    sstp_runtime_dir: str = "/var/run/sstpc",
    sstp_callback_id: str | None = None,
    pptp: str = "/usr/sbin/pptp",
    charon: str = "/usr/lib/ipsec/charon",
    swanctl: str = "/usr/sbin/swanctl",
) -> PPPClientPlan:
    if outbound.kind not in PPP_CLIENT_KINDS:
        raise CoreError(f"{outbound.kind.value} is not a PPP client provider")
    settings = outbound.settings
    runtime = Path(runtime_dir)
    options_path = runtime / "ppp.options"
    username = str(settings.get("username") or "")
    password = str(settings.get("password") or "")
    mtu = int(settings.get("mtu") or 1400)
    if not 1280 <= mtu <= 1500:
        raise CoreError("PPP MTU must be 1280-1500")

    options = [
        "noauth",
        "noipdefault",
        "ipcp-accept-local",
        "ipcp-accept-remote",
        "refuse-eap",
        "refuse-pap",
        "refuse-chap",
        "refuse-mschap",
        # Leaving MS-CHAPv2 enabled lets this client authenticate to the peer.
        # `require-mschap-v2` has the opposite direction: it requires the VPN
        # server to authenticate to pppd and breaks normal client sessions.
        "nobsdcomp",
        "nodeflate",
        "novj",
        "defaultroute",
        "replacedefaultroute",
        f"ifname {interface}",
        f"linkname zg-{outbound.name}",
        f"mtu {mtu}",
        f"mru {mtu}",
        f"name {_quoted_ppp(username)}",
        f"password {_quoted_ppp(password)}",
    ]
    files: dict[str, str] = {}
    file_modes: dict[str, int] = {}
    auxiliary: list[list[str]] = []
    primary: list[str]
    health = outbound.kind.value

    if outbound.kind is OutboundKind.PPTP:
        # Reference pptp-linux has no alternate control-port option.  The model
        # enforces 1723, and only the endpoint appears in the pty command.
        options.extend((
            "require-mppe",
            "require-mppe-128",
            f"pty {_quoted_ppp(f'{pptp} {endpoint} --nolaunchpppd --loglevel 0')}",
            "nodetach",
        ))
        primary = [pppd, "file", str(options_path)]
        health = "pptp-control+gre+ppp"
    elif outbound.kind is OutboundKind.SSTP:
        server_name = _safe_dns_name(
            str(settings.get("tls_server_name") or settings.get("server") or ""))
        port = int(settings.get("server_port") or 443)
        callback_id = str(
            sstp_callback_id
            or ("zg" + hashlib.sha256(outbound.name.encode()).hexdigest()[:6])
        )
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,10}", callback_id):
            raise CoreError("SSTP callback id must be 1-10 safe characters")
        callback_root = Path(sstp_runtime_dir)
        callback_socket = str(callback_root / f"sstpc-{callback_id}")
        ca_args: list[str]
        ca_pem = str(settings.get("ca_pem") or "").strip()
        if ca_pem:
            if "-----BEGIN CERTIFICATE-----" not in ca_pem:
                raise CoreError("SSTP ca_pem is not a PEM certificate")
            # sstpc uses its packaged unprivileged helper.  A mode-0600 file
            # below the mode-0700 credential directory is intentionally not
            # readable there, so materialize this *public CA certificate only*
            # in the package-owned /run/sstpc directory.  Passwords and PPP
            # options remain mode 0600 in the private profile directory.
            ca_path = callback_root / f"sstpc-{callback_id}-ca.pem"
            files[str(ca_path)] = ca_pem + ("\n" if not ca_pem.endswith("\n") else "")
            file_modes[str(ca_path)] = 0o644
            ca_args = ["--ca-cert", str(ca_path)]
        else:
            # sstp-client 1.0.20 sets its compiled-in SYSTEM_CA_PATH when no
            # CA option is supplied (the image's system bundle is therefore
            # used with normal hostname validation).  Do not emit --ca-dir:
            # this runtime rejects that legacy spelling.  A caller-supplied
            # CA is handled above with the supported --ca-cert file option.
            ca_args = []
        # sstp-client 1.0.20 requires its pppd plugin callback before it starts
        # SSTP link negotiation.  A profile-unique ipparam gives the helper and
        # plugin an exact, collision-free /run/sstpc socket without putting any
        # credential in argv.  --cert-warn is deliberately absent; --host plus
        # --tls-ext drives HTTP Host, TLS SNI, and OpenSSL hostname/IP-SAN
        # verification when the transport endpoint itself is an IP literal.
        command = [
            # This image intentionally has no syslog daemon/socket. sstpc's
            # default syslog sink stalls before its SSTP Connect-Request in
            # that environment; its credential-free protocol state goes to
            # the private per-domain client log instead.
            sstpc, "--log-level", "3", "--log-stderr", "--nolaunchpppd", *ca_args,
            "--host", server_name, "--tls-ext", "--ipparam", callback_id,
            f"https://{endpoint}:{port}{_SSTP_PATH}",
        ]
        options.extend((
            f"plugin {_quoted_ppp(sstp_plugin)}",
            f"sstp-sock {_quoted_ppp(callback_socket)}",
            f"ipparam {_quoted_ppp(callback_id)}",
            f"pty {_quoted_ppp(shlex.join(command))}",
            "nodetach",
        ))
        primary = [pppd, "file", str(options_path)]
        health = "tls-verified-sstp+plugin+ppp"
    else:
        xl2tp_config = runtime / "xl2tpd.conf"
        control = runtime / "xl2tpd.control"
        pid = runtime / "xl2tpd.pid"
        l2tp = "\n".join((
            "[global]",
            "port = 1701",
            "access control = no",
            "",
            "[lac zagros]",
            f"lns = {endpoint}",
            f"pppoptfile = {options_path}",
            "autodial = yes",
            "redial = no",
            "length bit = yes",
            "",
        ))
        files[str(xl2tp_config)] = l2tp
        primary = [
            xl2tpd, "-D", "-c", str(xl2tp_config),
            "-p", str(pid), "-C", str(control),
        ]
        if outbound.kind is OutboundKind.L2TP_IPSEC:
            strongswan_conf = runtime / "strongswan.conf"
            vici = runtime / "charon.vici"
            charon_run = runtime / "charon-run"
            swanctl_conf = runtime / "swanctl.conf"
            psk = str(settings.get("ipsec_psk") or "")
            # Runtime/vici paths are profile-specific. Debian's charon binary
            # still hard-codes its daemon PID under the compiled /var/run
            # piddir (the similarly named config key does not relocate that
            # startup lock), so each process also receives a private mount
            # namespace below. This permits concurrent isolated IPsec profiles
            # without touching another charon's global PID file.
            files[str(strongswan_conf)] = "\n".join((
                "include /etc/strongswan.d/*.conf",
                "charon {",
                "  load_modular = yes",
                "  install_routes = no",
                "  install_virtual_ip = no",
                "  plugins {",
                "    include /etc/strongswan.d/charon/*.conf",
                # The wrapper keeps this runtime as cwd before hiding /run;
                # the relative socket therefore lands in the shared domain
                # directory and remains reachable by swanctl via `vici`.
                "    vici { socket = unix://charon.vici }",
                "  }",
                "}",
                "",
            ))
            files[str(swanctl_conf)] = "\n".join((
                "connections {",
                "  zagros-l2tp {",
                "    version = 1",
                f"    remote_addrs = {endpoint}",
                "    local {",
                "      auth = psk",
                "      id = %any",
                "    }",
                "    remote {",
                "      auth = psk",
                "      id = %any",
                "    }",
                "    proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,3des-sha1-modp1024",
                "    children {",
                "      zagros-l2tp {",
                "        mode = transport",
                "        local_ts = dynamic[udp/1701]",
                f"        remote_ts = {endpoint}[udp/1701]",
                "        esp_proposals = aes256-sha256,aes256-sha1,aes128-sha1,3des-sha1",
                "        start_action = none",
                "      }",
                "    }",
                "  }",
                "}",
                "secrets {",
                "  ike-zagros {",
                "    id = %any",
                f"    secret = {_quoted_ppp(psk)}",
                "  }",
                "}",
                "",
            ))
            # Ensure the bind source exists before the process is launched.
            # The marker is non-secret and remains below the mode-0700 domain.
            files[str(charon_run / ".zagros-owned")] = "phase4-charon-piddir\n"
            auxiliary = [
                [
                    "/usr/bin/unshare", "--mount", "--propagation", "private",
                    "/bin/sh", "-ec",
                    'cd "$1"; mount --bind "$2" /var/run; shift 2; exec "$@"',
                    "zagros-charon-isolated", str(runtime), str(charon_run),
                    "/usr/bin/env", "STRONGSWAN_CONF=strongswan.conf",
                    charon, "--debug-dmn", "1", "--debug-ike", "1",
                    "--debug-knl", "1", "--debug-net", "1",
                ],
                [
                    swanctl, "--load-all", "--uri", f"unix://{vici}",
                    "--noprompt", "--file", str(swanctl_conf),
                ],
                [
                    swanctl, "--initiate", "--uri", f"unix://{vici}",
                    "--child", "zagros-l2tp",
                ],
            ]
            health = "ike-sa+child-sa+xfrm+l2tp+ppp"
        else:
            health = "raw-l2tp+ppp"

    files[str(options_path)] = "\n".join(options) + "\n"
    plan = PPPClientPlan(
        kind=outbound.kind,
        endpoint=endpoint,
        interface=interface,
        files=files,
        file_modes=file_modes,
        primary_argv=primary,
        auxiliary_argv=auxiliary,
        health_protocol=health,
    )
    plan.assert_secret_free_argv([
        password, str(settings.get("ipsec_psk") or ""),
    ])
    return plan


def write_private_plan_files(plan: PPPClientPlan) -> None:
    """Atomically write provider files with explicit least-privilege modes.

    Credential/config files default to mode 0600 below the caller's mode-0700
    domain directory.  The sole public exception is an administrator-supplied
    SSTP CA certificate (never a key), explicitly marked 0644 so sstpc's
    packaged unprivileged verifier can read it from package-owned /run/sstpc.
    ``O_NOFOLLOW`` on the final open is not portable through pathlib replace,
    so we create a sibling and atomically replace only after validating that
    the parent is not a symlink.
    """
    for raw_path, content in plan.files.items():
        path = Path(raw_path)
        mode = int(plan.file_modes.get(raw_path, 0o600))
        if mode not in (0o600, 0o644):
            raise CoreError("PPP runtime file mode is not allowed")
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if path.parent.is_symlink():
            raise CoreError("PPP runtime directory must not be a symlink")
        part = path.with_name(path.name + ".part")
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                part.unlink()
            except OSError:
                pass
            raise
        os.replace(part, path)
        os.chmod(path, mode)
