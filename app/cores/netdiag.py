"""Structured host network diagnosis — shared by the OS-level
cores (OpenVPN, WireGuard, …).

The field failures this replaces:
  * OpenVPN start died with a bare "management interface: Connection
    refused" — the REAL cause was three hops earlier (no /dev/net/tun in
    the container, no NET_ADMIN, module not loaded).
  * WireGuard `wg-quick up` failed with "Operation not permitted" and the
    panel repeated it verbatim — leaving the operator to guess between
    CAP_NET_ADMIN, a missing kernel module, docker device mapping, and an
    unprivileged LXC container.

Everything here is a small pure probe (read-only: /proc, /sys, device
nodes) plus a renderer. Drivers call the probes on their failure paths
and surface the structured result IN the CoreError, so the Cores page and
the core logs show *what* is wrong and *how to fix it on this specific
kind of host*.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# CAP_NET_ADMIN bit in /proc/*/status CapEff (capability(7): index 12)
_CAP_NET_ADMIN_BIT = 12


@dataclass
class CheckResult:
    """One probe outcome. ``fix`` is an actionable host-specific hint."""
    key: str
    ok: bool
    label: str
    detail: str
    fix: str = ""


# ---------------------------------------------------------------------- #
# pure probes (read-only; never raise)
# ---------------------------------------------------------------------- #
def _read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def net_admin_present(pid: int | None = None) -> bool | None:
    """True/False when decidable from /proc, None when it isn't."""
    status = _read_text(f"/proc/{pid or 'self'}/status")
    if status is None:
        return None
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            try:
                effective = int(line.split(":", 1)[1].strip(), 16)
            except ValueError:
                return None
            return bool(effective & (1 << _CAP_NET_ADMIN_BIT))
    return None


def in_container() -> str | None:
    """Best-effort container identification: 'docker', 'containerd',
    'kubernetes', 'lxc', or None when no marker is visible."""
    if os.path.exists("/.dockerenv"):
        return "docker"
    if os.path.exists("/run/.containerenv"):
        return "containerd"
    cgroup = _read_text("/proc/1/cgroup") or ""
    lowered = cgroup.lower()
    if "kubepods" in lowered:
        return "kubernetes"
    if "docker" in lowered:
        return "docker"
    if "containerd" in lowered:
        return "containerd"
    if "lxc" in lowered:
        return "lxc"
    return None


def tun_device_state() -> str:
    """'ok' | 'missing' | 'unreadable' | 'unknown' for /dev/net/tun."""
    if not os.path.exists("/dev/net/tun"):
        return "missing"
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    except PermissionError:
        return "unreadable"
    except OSError:
        return "unknown"  # exists but not openable here (busy/ENXIO …)
    else:
        os.close(fd)
        return "ok"


def kernel_module_present(name: str) -> bool | None:
    """Loaded (or builtin) kernel module? /sys/module is the ground truth;
    None when the host layout doesn't allow a decision."""
    if os.path.isdir(f"/sys/module/{name}"):
        return True
    modules = _read_text("/proc/modules")
    if modules is not None:
        return any(line.split(" ", 1)[0] == name for line in modules.splitlines())
    return None


# ---------------------------------------------------------------------- #
# composite diagnoses
# ---------------------------------------------------------------------- #
def _container_fix(container: str | None) -> str:
    if container in ("docker", "containerd", "kubernetes"):
        return (
            "the panel runs in a container — map the device and the "
            "capability: `devices: [/dev/net/tun:/dev/net/tun]` and "
            "`cap_add: [NET_ADMIN]` (docker run: `--device=/dev/net/tun "
            "--cap-add=NET_ADMIN`)"
        )
    if container == "lxc":
        return (
            "unprivileged LXC cannot create tunnel interfaces — enable "
            "TUN passthrough in the container config on the HOST "
            "(lxc.cgroup2.devices.allow + /dev/net/tun bind mount), or "
            "ask the provider"
        )
    return "enable the tun module on the host: `modprobe tun` (persist via /etc/modules)"


def diagnose_tun(feature: str = "OpenVPN") -> list[CheckResult]:
    """Everything a TUN-based data plane needs, in report order."""
    container = in_container()
    checks: list[CheckResult] = []

    state = tun_device_state()
    checks.append(CheckResult(
        key="tun_device",
        ok=state == "ok",
        label="TUN device",
        detail={
            "ok": "/dev/net/tun present and openable",
            "missing": "/dev/net/tun does not exist",
            "unreadable": "/dev/net/tun exists but opening it is denied",
            "unknown": "/dev/net/tun exists but could not be opened here",
        }[state],
        fix="" if state == "ok" else _container_fix(container),
    ))

    cap = net_admin_present()
    checks.append(CheckResult(
        key="net_admin",
        ok=cap is True,
        label="CAP_NET_ADMIN",
        detail={
            True: "effective capabilities include NET_ADMIN",
            False: "NET_ADMIN is NOT in the effective capability set",
            None: "could not read capabilities from /proc",
        }[cap],
        fix=None if cap is not False else (
            _container_fix(container) if container
            else "run the panel with the NET_ADMIN capability "
                 "(root normally has it)"),
    ))

    module = kernel_module_present("tun")
    # an openable device settles the data-plane question even when the
    # module table is unreadable (autoload on open, builtin hides)
    checks.append(CheckResult(
        key="tun_module",
        ok=module is True or state == "ok",
        label="tun kernel module",
        detail={
            True: "tun module loaded (or builtin)",
            False: "tun module not loaded",
            None: "module table unreadable on this host",
        }[module],
        fix=None if module is not False else
            "load it once: `modprobe tun`; persist it in /etc/modules "
            "(container hosts: load on the HOST kernel)",
    ))
    checks.append(CheckResult(
        key="container",
        ok=True,
        label="host context",
        detail=(f"running inside {container}" if container
                else "no container marker detected (bare metal / VM?)"),
    ))
    return checks


def diagnose_net_admin_kernel(module: str | None, feature: str) -> list[CheckResult]:
    """What WireGuard-style netdevs need: NET_ADMIN (+ kernel support)."""
    container = in_container()
    checks: list[CheckResult] = []
    cap = net_admin_present()
    cap_fix = (
        "the panel runs in a container — add the capability: "
        "`cap_add: [NET_ADMIN]` and `devices: [/dev/net/tun:/dev/net/tun]`; "
        "privileged LXC needs NET_ADMIN allowed by the HOST"
        if container else
        "run the panel with the NET_ADMIN capability (root normally has it)"
    )
    checks.append(CheckResult(
        key="net_admin",
        ok=cap is True,
        label="CAP_NET_ADMIN",
        detail={
            True: "effective capabilities include NET_ADMIN",
            False: "NET_ADMIN is NOT in the effective capability set — "
                   "every RTNETLINK call returns 'Operation not permitted'",
            None: "could not read capabilities from /proc",
        }[cap],
        fix=None if cap is not False else cap_fix,
    ))
    if module:
        present = kernel_module_present(module)
        checks.append(CheckResult(
            key=f"{module}_module",
            ok=present is True,
            label=f"{module} kernel module",
            detail={
                True: f"{module} module loaded (or builtin)",
                False: f"{module} module not present in this kernel",
                None: "module table unreadable on this host",
            }[present],
            fix=None if present is not False else (
                f"`modprobe {module}` on the host; kernels <5.6 need "
                f"wireguard-dkms; unprivileged LXC requires the provider "
                f"to load it on the HOST"
                if module == "wireguard" else f"`modprobe {module}` on the host"),
        ))
    checks.append(CheckResult(
        key="container",
        ok=True,
        label="host context",
        detail=(f"running inside {container}" if container
                else "no container marker detected (bare metal / VM?)"),
    ))
    return checks


def format_guidance(checks: list[CheckResult], header: str) -> str:
    """Render the checks as one operator-facing block (goes into CoreError
    text → Cores page + core logs)."""
    lines = [header, "host diagnosis:"]
    for check in checks:
        mark = "ok " if check.ok else "FAIL"
        line = f"  [{mark}] {check.label}: {check.detail}"
        if not check.ok and check.fix:
            line += f"\n       fix: {check.fix}"
        lines.append(line)
    return "\n".join(lines)
