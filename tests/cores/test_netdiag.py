"""netdiag unit tests (alpha.7.2) — structured host diagnosis for the
OS-level cores. Pure probes are driven through monkeypatched /proc, /sys
and device-node reads; the drivers' failure paths are covered in their own
test modules (openvpn preflight, wireguard wg-quick up)."""
from __future__ import annotations

import os
import sys
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

import app.cores.netdiag as nd  # noqa: E402


def test_net_admin_cap_eff_parsing() -> None:
    with_cap = "Name:\tpanel\nCapEff:\t0000000000201000\n"
    without_cap = "Name:\tpanel\nCapEff:\t0000000000000000\n"
    reads = {"with": with_cap, "without": without_cap}

    orig = nd._read_text
    try:
        nd._read_text = lambda p: reads["with"]
        assert nd.net_admin_present(1) is True
        nd._read_text = lambda p: reads["without"]
        assert nd.net_admin_present(1) is False
        nd._read_text = lambda p: None
        assert nd.net_admin_present(1) is None
        nd._read_text = lambda p: "garbage"
        assert nd.net_admin_present(1) is None
    finally:
        nd._read_text = orig


def test_container_markers() -> None:
    orig_exists, orig_read = os.path.exists, nd._read_text
    try:
        os.path.exists = lambda p: p == "/.dockerenv"
        nd._read_text = lambda p: ""
        assert nd.in_container() == "docker"
        os.path.exists = lambda p: p == "/run/.containerenv"
        assert nd.in_container() == "containerd"
        os.path.exists = lambda p: False
        nd._read_text = lambda p: "12:pids:/kubepods/burstable/pod123" if "cgroup" in p else ""
        assert nd.in_container() == "kubernetes"
        nd._read_text = lambda p: "1:name=systemd:/lxc/panel" if "cgroup" in p else ""
        assert nd.in_container() == "lxc"
        nd._read_text = lambda p: "1:name=systemd:/"
        assert nd.in_container() is None
    finally:
        os.path.exists, nd._read_text = orig_exists, orig_read


def test_tun_device_states(tmp_path=None) -> None:
    orig_exists, orig_open = os.path.exists, os.open
    try:
        os.path.exists = lambda p: False
        assert nd.tun_device_state() == "missing"

        os.path.exists = lambda p: True

        def denied(path, flags):
            raise PermissionError(13, "Permission denied")
        os.open = denied
        assert nd.tun_device_state() == "unreadable"

        def weird(path, flags):
            raise OSError(6, "No such device or address")
        os.open = weird
        assert nd.tun_device_state() == "unknown"

        calls = []

        def ok(path, flags):
            calls.append(path)
            return 99
        os.open = ok
        orig_close = os.close
        os.close = lambda fd: None
        try:
            assert nd.tun_device_state() == "ok"
        finally:
            os.close = orig_close
    finally:
        os.path.exists, os.open = orig_exists, orig_open


def test_kernel_module_probe() -> None:
    orig_isdir, orig_read = os.path.isdir, nd._read_text
    try:
        os.path.isdir = lambda p: p == "/sys/module/wireguard"
        assert nd.kernel_module_present("wireguard") is True
        os.path.isdir = lambda p: False
        nd._read_text = lambda p: "tun 28672 3 - Live 0xffffffffc0a00000\n"
        assert nd.kernel_module_present("tun") is True
        assert nd.kernel_module_present("wireguard") is False
        nd._read_text = lambda p: None
        assert nd.kernel_module_present("wireguard") is None
    finally:
        os.path.isdir, nd._read_text = orig_isdir, orig_read


def test_diagnose_tun_renders_host_specific_fixes() -> None:
    orig_state, orig_cap, orig_mod, orig_cont = (
        nd.tun_device_state, nd.net_admin_present,
        nd.kernel_module_present, nd.in_container)
    try:
        nd.tun_device_state = lambda: "missing"
        nd.net_admin_present = lambda: False
        nd.kernel_module_present = lambda name: False
        nd.in_container = lambda: "docker"
        checks = nd.diagnose_tun("OpenVPN")
        failed = [c for c in checks if not c.ok]
        assert {c.key for c in failed} == {"tun_device", "net_admin", "tun_module"}
        text = nd.format_guidance(checks, "header line")
        assert "header line" in text
        assert "[FAIL] TUN device: /dev/net/tun does not exist" in text
        assert "devices: [/dev/net/tun:/dev/net/tun]" in text   # docker fix
        assert "cap_add: [NET_ADMIN]" in text
        assert "modprobe tun" in text

        # device openable ⇒ module check passes even with unreadable table
        nd.tun_device_state = lambda: "ok"
        nd.kernel_module_present = lambda name: None
        nd.net_admin_present = lambda: True
        assert all(c.ok for c in nd.diagnose_tun("OpenVPN"))

        # LXC gets the LXC-specific hint, not the docker one
        nd.tun_device_state = lambda: "missing"
        nd.in_container = lambda: "lxc"
        lxc = {c.key: c for c in nd.diagnose_tun("OpenVPN")}["tun_device"].fix
        assert "LXC" in lxc and "HOST" in lxc
    finally:
        (nd.tun_device_state, nd.net_admin_present,
         nd.kernel_module_present, nd.in_container) = (
            orig_state, orig_cap, orig_mod, orig_cont)


def test_diagnose_wireguard_names_the_deadly_one() -> None:
    orig_cap, orig_mod, orig_cont = (
        nd.net_admin_present, nd.kernel_module_present, nd.in_container)
    try:
        nd.net_admin_present = lambda: False
        nd.kernel_module_present = lambda name: True
        nd.in_container = lambda: "kubernetes"
        checks = nd.diagnose_net_admin_kernel("wireguard", "WireGuard")
        dead = [c for c in checks if not c.ok]
        assert [c.key for c in dead] == ["net_admin"]
        assert "Operation not permitted" in dead[0].detail
        text = nd.format_guidance(checks, "hdr")
        assert "cap_add: [NET_ADMIN]" in text
        # module missing + unprivileged host context ⇒ provider hint
        nd.net_admin_present = lambda: True
        nd.kernel_module_present = lambda name: False
        nd.in_container = lambda: None
        checks2 = nd.diagnose_net_admin_kernel("wireguard", "WireGuard")
        mod = [c for c in checks2 if c.key == "wireguard_module"][0]
        assert not mod.ok and "dkms" in mod.fix
    finally:
        nd.net_admin_present, nd.kernel_module_present, nd.in_container = (
            orig_cap, orig_mod, orig_cont)


def _run_standalone() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(_run_standalone())
