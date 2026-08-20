import os
import stat
from types import SimpleNamespace

import pytest

from app.cores.drivers.pptp.backend import LocalPptpBackend
from app.cores.exceptions import CoreError


class Runner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, input_text=None, check=True, timeout=30):
        self.calls.append((argv, input_text))
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def settings(tmp_path):
    return {
        "work_dir": str(tmp_path), "executable_path": str(tmp_path / "accel-pppd"),
        "module_dir": str(tmp_path / "modules"), "management_port": 22001,
    }


def test_atomic_sensitive_files_have_required_modes(tmp_path):
    backend = LocalPptpBackend(settings(tmp_path), runner=Runner())
    backend.configure("config\n", "secrets\n", "#!/bin/sh\n")
    assert stat.S_IMODE(os.stat(tmp_path).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(backend.config_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(backend.chap_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(backend.hook_path).st_mode) == 0o700
    assert not list(tmp_path.glob("*.tmp.*"))


def test_management_secret_is_stable_and_mode_0600(tmp_path):
    backend = LocalPptpBackend(settings(tmp_path), runner=Runner())
    first = backend.ensure_management_secret()
    second = backend.ensure_management_secret()
    assert first == second and len(first) >= 36
    assert stat.S_IMODE(os.stat(backend.secret_path).st_mode) == 0o600


def test_parse_real_show_sessions_shape():
    output = """ ifname | username | calling-sid | ip | type | comp | state | uptime-raw | sid | rx-bytes-raw | tx-bytes-raw\n---------+----------+-------------+----+------+------+-------+------------+-----+--------------+-------------\n zgppp0 | 1.alice.pptp | 198.51.100.4 | 10.77.0.2 | pptp | mppe | active | 12 | ABC | 123 | 456\n"""
    rows = LocalPptpBackend.parse_sessions(output)
    assert len(rows) == 1
    assert rows[0].username == "1.alice.pptp"
    assert rows[0].compression == "mppe"
    assert (rows[0].rx_bytes, rows[0].tx_bytes) == (123, 456)


def test_preflight_aggregates_failures_without_launch(tmp_path, monkeypatch):
    backend = LocalPptpBackend(settings(tmp_path), runner=Runner())
    monkeypatch.setattr(backend, "verify_installation", lambda: None)
    monkeypatch.setattr(backend, "_ppp_device_ready", lambda: (False, "/dev/ppp missing"))
    monkeypatch.setattr(backend, "_effective_capability", lambda bit: False)
    monkeypatch.setattr(backend, "_module_loaded", lambda name: False)
    monkeypatch.setattr(backend, "_tcp_available", lambda address, port: True)
    monkeypatch.setattr(backend, "_gre_ready", lambda: (False, "GRE unavailable"))
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("pathlib.Path.read_text", lambda self, *a, **k: "0")
    with pytest.raises(CoreError) as error:
        backend.preflight()
    text = str(error.value)
    assert "/dev/ppp" in text and "CAP_NET_ADMIN" in text and "CAP_NET_RAW" in text
    assert "ppp_mppe" in text and "GRE" in text


def test_cleanup_refuses_unowned_table(tmp_path):
    backend = LocalPptpBackend(settings(tmp_path), runner=Runner())
    backend._atomic_write(backend.manifest_path, '{"nft_table":"unrelated"}\n', 0o600)
    with pytest.raises(CoreError, match="owned"):
        backend.cleanup_firewall()


def test_firewall_uses_exact_scoped_base_chain_rules(tmp_path):
    runner = Runner()
    backend = LocalPptpBackend(settings(tmp_path), runner=runner)
    backend.apply_firewall("pptp-test", "10.77.0.0/24")
    script = next(text for argv, text in runner.calls if argv == ["nft", "-f", "-"])
    assert "insert rule ip filter FORWARD ip saddr 10.77.0.0/24" in script
    assert "insert rule ip nat POSTROUTING ip saddr 10.77.0.0/24" in script
    assert "flush" not in script and "delete table" not in script
