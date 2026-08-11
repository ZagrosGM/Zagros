"""alpha.7.1 regression tests — OpenVPN / WireGuard / SSH root fixes.

Field reports pinned here:
* OpenVPN: "cannot reach openvpn management interface: Connection refused"
  (the process had died at boot — the bare socket error hid the real cause;
  and the container never had /dev/net/tun or the binary installed).
* WireGuard: "wg-quick up … ip: command not found" (iproute2/iptables were
  never declared dependencies).
* SSH: "sshd is not running — enable the system ssh service" (the driver
  only complained instead of bringing the service to READY).
"""
from __future__ import annotations

import pytest

from app.cores.exceptions import CoreError


# --------------------------------------------------------------------- #
# OpenVPN
# --------------------------------------------------------------------- #

def _ovpn_backend(tmp_path, monkeypatch):
    from app.cores.drivers.openvpn.backend import LocalOpenVPNBackend

    backend = LocalOpenVPNBackend({
        "executable_path": "openvpn",
        "work_dir": str(tmp_path),
        "management_port": 17599,
    })
    monkeypatch.setattr(backend, "install_packages",
                        lambda: "apt-get install -y openvpn openssl")
    return backend


def test_openvpn_preflight_self_heals_missing_binary(tmp_path, monkeypatch):
    backend = _ovpn_backend(tmp_path, monkeypatch)
    state = {"installed": False}

    def fake_install():
        state["installed"] = True
        return "apt-get install -y openvpn openssl"

    monkeypatch.setattr(backend, "install_packages", fake_install)
    monkeypatch.setattr("shutil.which",
                        lambda t: "/usr/bin/apt-get" if t == "apt-get" else None)
    monkeypatch.setattr(
        "os.path.exists",
        lambda p: (p != "/dev/net/tun")
        and (state["installed"] if p.endswith("openvpn") else True),
    )
    with pytest.raises(CoreError, match="/dev/net/tun is missing"):
        backend.preflight_start()
    assert state["installed"], "missing binary must trigger the install step"


def test_openvpn_preflight_reports_missing_tun_with_remedy(tmp_path, monkeypatch):
    backend = _ovpn_backend(tmp_path, monkeypatch)
    monkeypatch.setattr("shutil.which", lambda t: "/usr/sbin/openvpn")
    monkeypatch.setattr("os.path.exists", lambda p: p != "/dev/net/tun")
    with pytest.raises(CoreError) as ei:
        backend.preflight_start()
    msg = str(ei.value)
    assert "/dev/net/tun is missing" in msg
    assert "NET_ADMIN" in msg and "devices" in msg  # actionable, not hidden


def test_openvpn_preflight_structured_host_diagnosis(tmp_path, monkeypatch):
    """Item (alpha.7.2): preflight diagnoses TUN device, NET_ADMIN, kernel
    module AND container context — each failure with its own fix hint."""
    import app.cores.netdiag as nd

    backend = _ovpn_backend(tmp_path, monkeypatch)
    monkeypatch.setattr("shutil.which", lambda t: "/usr/sbin/openvpn")
    monkeypatch.setattr(nd, "tun_device_state", lambda: "missing")
    monkeypatch.setattr(nd, "net_admin_present", lambda: False)
    monkeypatch.setattr(nd, "kernel_module_present", lambda name: False)
    monkeypatch.setattr(nd, "in_container", lambda: "docker")
    with pytest.raises(CoreError) as ei:
        backend.preflight_start()
    msg = str(ei.value)
    assert "host diagnosis:" in msg                       # structured block
    assert "[FAIL] TUN device: /dev/net/tun does not exist" in msg
    assert "[FAIL] CAP_NET_ADMIN" in msg
    assert "[FAIL] tun kernel module" in msg
    assert "host context" in msg and "docker" in msg
    assert "devices: [/dev/net/tun:/dev/net/tun]" in msg   # per-host fix
    assert "cap_add: [NET_ADMIN]" in msg
    assert "modprobe tun" in msg

    # unreadable device gets its own header wording
    monkeypatch.setattr(nd, "tun_device_state", lambda: "unreadable")
    with pytest.raises(CoreError) as ei2:
        backend.preflight_start()
    assert "exists but cannot be opened" in str(ei2.value)

    # everything healthy → preflight silent
    monkeypatch.setattr(nd, "tun_device_state", lambda: "ok")
    monkeypatch.setattr(nd, "net_admin_present", lambda: True)
    monkeypatch.setattr(nd, "kernel_module_present", lambda name: True)
    backend.preflight_start()


def test_openvpn_mgmt_wait_surfaces_process_death_not_socket_error(tmp_path, monkeypatch):
    """Alpha.7.2 shape: one _Listener per tag; the same honesty contract —
    a dead process surfaces its OWN log tail, never a bare socket error,
    and the failure names the listener."""
    backend = _ovpn_backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "preflight_start", lambda: None)
    backend.configure([{
        "tag": "openvpn", "mgmt_port": 17599,
        "server_conf": "port 1194\n", "hook_script": "#!/bin/sh\nexit 0\n",
    }])

    class DeadProc:
        is_running = False

        def start(self): pass

        def stop(self): pass

        def logs(self, tail=15):
            return ["Options error: --ca fails with 'ca.crt': No such file or directory"]

    listener = backend._listeners["openvpn"]
    listener.proc = DeadProc()
    with pytest.raises(CoreError) as ei:
        backend._connect_management(listener, timeout=0.1)
    msg = str(ei.value)
    assert "openvpn exited during startup" in msg
    assert "Options error" in msg                     # the REAL cause, verbatim
    assert "Connection refused" not in msg

    # surfaced with the listener name when driven through start()
    listener.proc = DeadProc()
    with pytest.raises(CoreError) as ei2:
        backend.start()
    assert "listener 'openvpn'" in str(ei2.value)
    assert "Options error" in str(ei2.value)


def test_openvpn_mgmt_timeout_includes_recent_output(tmp_path, monkeypatch):
    backend = _ovpn_backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "preflight_start", lambda: None)
    backend.configure([{
        "tag": "openvpn", "mgmt_port": 17599,
        "server_conf": "port 1194\n", "hook_script": "#!/bin/sh\nexit 0\n",
    }])

    class AliveProc:
        is_running = True

        def start(self): pass

        def logs(self, tail=15):
            return ["NOTE: your local LAN uses ..."]

    listener = backend._listeners["openvpn"]
    listener.proc = AliveProc()
    with pytest.raises(CoreError) as ei:
        backend._connect_management(listener, timeout=0.05)
    assert "NOTE: your local LAN" in str(ei.value)


# --------------------------------------------------------------------- #
# WireGuard
# --------------------------------------------------------------------- #

def _wg_backend(tmp_path, monkeypatch):
    from app.cores.drivers.wireguard.backend import LocalWireGuardBackend

    return LocalWireGuardBackend({
        "work_dir": str(tmp_path),
        "interface": "wgtest0",
    })


def test_wireguard_install_covers_iproute2_and_iptables(tmp_path, monkeypatch):
    backend = _wg_backend(tmp_path, monkeypatch)
    calls: list[list[str]] = []

    monkeypatch.setattr(backend, "_run", lambda argv, **kw: calls.append(list(argv)) or "ok")
    monkeypatch.setattr("shutil.which", lambda exe: exe == "apt-get" and "/usr/bin/apt-get" or None)
    backend.install_packages()
    flat = [" ".join(c) for c in calls]
    assert flat[0] == "apt-get update"
    assert "wireguard-tools" in flat[1] and "iproute2" in flat[1] and "iptables" in flat[1]
    # exactly update + one install line: no speculative extras (DNS helpers
    # are client-side material; server interfaces render no `DNS =` lines)
    assert len(flat) == 2


def test_wireguard_up_self_heals_then_proceeds(tmp_path, monkeypatch):
    backend = _wg_backend(tmp_path, monkeypatch)
    apt_called: list[bool] = []
    monkeypatch.setattr(backend, "install_packages", lambda: apt_called.append(True) or "ok")
    states = iter([{"ip": "iproute2"}, {}])  # missing → healed

    monkeypatch.setattr(backend, "missing_dependencies", lambda: next(states))
    quick: list[list[str]] = []
    monkeypatch.setattr(backend, "_run", lambda argv, **kw: quick.append(list(argv)) or "ok")
    monkeypatch.setattr(backend, "is_running", lambda: False)
    backend.up("[Interface]\nPrivateKey = x\n")
    assert apt_called, "missing tools must trigger the install step"
    assert quick[0][1:2] == ["up"]
    # second call chain: _run list includes wg-quick up
    assert any("wg-quick" in " ".join(c) for c in quick)


def test_wireguard_preflight_names_missing_packages(tmp_path, monkeypatch):
    backend = _wg_backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "missing_dependencies",
                        lambda: {"ip": "iproute2", "iptables": "iptables"})
    monkeypatch.setattr(backend, "install_packages",
                        lambda: (_ for _ in ()).throw(CoreError("no pm")))
    with pytest.raises(CoreError, match="no pm"):
        backend._ensure_host_tools()

    monkeypatch.setattr(backend, "install_packages", lambda: "ok")
    with pytest.raises(CoreError) as ei:
        backend._ensure_host_tools()
    assert "iproute2" in str(ei.value) and "iptables" in str(ei.value)


def test_wireguard_missing_dependencies_map_tools_to_packages(tmp_path):
    backend = _wg_backend(tmp_path, None)
    import shutil
    orig_which = shutil.which
    try:
        # simulate a host without ip/iptables
        import app.cores.drivers.wireguard.backend as wb
        wb.shutil.which = lambda exe: ("/usr/bin/void" if exe in ("wg", "wg-quick") else None)
        got = backend.missing_dependencies()
    finally:
        wb.shutil.which = orig_which
    assert got["ip"] == "iproute2" and got["iptables"] == "iptables"
    assert "wg-quick" not in got


def test_wireguard_up_operation_not_permitted_gets_full_diagnosis(tmp_path, monkeypatch):
    """Item (alpha.7.2): 'Operation not permitted' is expanded into the
    structured host diagnosis — capability, kernel module, host context,
    each with its fix — while the original error stays verbatim."""
    import app.cores.netdiag as nd

    backend = _wg_backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "_ensure_host_tools", lambda: None)
    monkeypatch.setattr(backend, "is_running", lambda: False)

    def eperm(argv, *, input_text=None, timeout=30.0):
        raise CoreError("[#] ip link add wgtest0 type wireguard\n"
                        "RTNETLINK answers: Operation not permitted")
    monkeypatch.setattr(backend, "_run", eperm)
    monkeypatch.setattr(nd, "net_admin_present", lambda: False)
    monkeypatch.setattr(nd, "kernel_module_present", lambda name: True)
    monkeypatch.setattr(nd, "in_container", lambda: "docker")
    with pytest.raises(CoreError) as ei:
        backend.up("### wgtest0 ###\n")
    msg = str(ei.value)
    assert "could not be created" in msg
    assert "Operation not permitted" in msg       # original error preserved
    assert "host diagnosis:" in msg
    assert "[FAIL] CAP_NET_ADMIN" in msg
    assert "cap_add: [NET_ADMIN]" in msg
    assert "wireguard kernel module" in msg        # module line present (ok)

    # non-permission failures pass through untouched — no fake diagnosis
    def other(argv, *, input_text=None, timeout=30.0):
        raise CoreError("wg-quick: `wgtest0' already exists")
    monkeypatch.setattr(backend, "_run", other)
    with pytest.raises(CoreError) as ei2:
        backend.up("### wgtest0 ###\n")
    assert "already exists" in str(ei2.value)
    assert "host diagnosis:" not in str(ei2.value)

    # missing kernel module gets the dkms/provider hint instead
    def eperm2(argv, *, input_text=None, timeout=30.0):
        raise CoreError("RTNETLINK answers: Operation not supported")
    monkeypatch.setattr(backend, "_run", eperm2)
    monkeypatch.setattr(nd, "net_admin_present", lambda: True)
    monkeypatch.setattr(nd, "kernel_module_present", lambda name: False)
    monkeypatch.setattr(nd, "in_container", lambda: None)
    # "operation not supported" is NOT a permission pattern → no diagnosis
    with pytest.raises(CoreError) as ei3:
        backend.up("### wgtest0 ###\n")
    assert "host diagnosis:" not in str(ei3.value)


# --------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------- #

def _ssh_backend(settings_extra=None):
    from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

    settings = {"port": 2022, "dropin_path": None}
    settings.update(settings_extra or {})
    return LocalSystemSSHBackend(settings) if settings["dropin_path"] else \
        LocalSystemSSHBackend({k: v for k, v in settings.items() if v is not None})


def test_ssh_dropin_keeps_port_22_and_panel_port(tmp_path):
    backend = _ssh_backend({"dropin_path": str(tmp_path / "sshd_config.d" / "zagros.conf"),
                            "max_sessions": 10, "sftp": True})
    content = backend.render_dropin()
    assert "Port 22" in content          # operator lockout guard — contractual
    assert "Port 2022" in content        # panel tunnel port
    assert "MaxSessions 10" in content
    assert "Subsystem sftp" not in content  # main sshd_config owns it once
    assert "Match User zg-*" in content and "sftp_accounting.py" in content


def test_ssh_dropin_idempotent_write(tmp_path):
    dropin = tmp_path / "sshd_config.d" / "zagros.conf"
    backend = _ssh_backend({"dropin_path": str(dropin)})
    assert backend._write_dropin_if_changed() is True
    first = dropin.read_text()
    assert backend._write_dropin_if_changed() is False  # no rewrite, no reload ripple
    assert dropin.read_text() == first


def test_ssh_ensure_service_full_chain(tmp_path, monkeypatch):
    """install → host keys → drop-in → sshd -t → enable --now → verify."""
    from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

    dropin = tmp_path / "sshd_config.d" / "zagros.conf"
    backend = _ssh_backend({"dropin_path": str(dropin)})

    calls: list[list[str]] = []
    state = {"installed": False, "running": False}

    monkeypatch.setattr("shutil.which", lambda t: {
        "apt-get": "/usr/bin/apt-get",
        "sshd": "/usr/sbin/sshd" if state["installed"] else None,
        "ssh-keygen": "/usr/bin/ssh-keygen",
        "systemctl": "/usr/bin/systemctl",
    }.get(t))
    # /usr/sbin/sshd exists on real machines; simulate a bare container.
    monkeypatch.setattr(LocalSystemSSHBackend, "SSHD_FALLBACK_PATHS", ())

    def fake_run(argv, **kw):
        calls.append(list(argv))
        if argv[:2] == ["apt-get", "install"]:
            state["installed"] = True
        if argv[:2] == ["systemctl", "enable"]:
            state["running"] = True
        return "ok"

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr("glob.glob", lambda p: [] if "ssh_host" in p else [])  # no host keys
    monkeypatch.setattr(backend, "_systemd_alive", lambda: True)
    monkeypatch.setattr(backend, "_ssh_unit", lambda: "ssh.service")
    monkeypatch.setattr(backend, "sshd_running", lambda: state["running"])

    how = backend.ensure_service()
    assert how == "systemctl (ssh.service)"
    flat = [" ".join(c) for c in calls]
    assert flat[0].startswith("apt-get update")
    assert any(c.startswith("apt-get install -y openssh-server") for c in flat)
    assert any(c.endswith("ssh-keygen -A") for c in flat)             # containers have no host keys
    assert any(c.startswith("/usr/sbin/sshd -t") for c in flat)       # validate before start
    assert any(c.startswith("systemctl enable --now ssh.service") for c in flat)
    assert (dropin.read_text()).find("Port 22") >= 0


def test_ssh_ensure_service_validation_failure_is_loud(tmp_path, monkeypatch):
    dropin = tmp_path / "sshd_config.d" / "zagros.conf"
    backend = _ssh_backend({"dropin_path": str(dropin)})
    monkeypatch.setattr("shutil.which", lambda t: "/usr/sbin/sshd")
    monkeypatch.setattr(backend, "_ensure_host_keys", lambda: None)
    monkeypatch.setattr(backend, "sshd_running", lambda: False)

    def boom(argv, **kw):
        if argv[1] == "-t":
            raise CoreError("'/etc/ssh/sshd_config.d/zagros.conf' line 3: Bad configuration option")
        return "ok"

    monkeypatch.setattr(backend, "_run", boom)
    with pytest.raises(CoreError) as ei:
        backend.ensure_service()
    assert "failed validation" in str(ei.value) and "Bad configuration option" in str(ei.value)
