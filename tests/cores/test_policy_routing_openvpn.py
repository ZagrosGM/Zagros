"""OpenVPN outbound policy-domain regressions."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.policy import PolicyRoutingManager
from tests.cores.policy_fakes import EmptyCoreManager, FakeRunner


def _profile(extra: str = "") -> str:
    return f"""client
proto tcp
remote 198.51.100.7 443
nobind
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
TEST
-----END CERTIFICATE-----
</ca>
{extra}
"""


def _outbound(extra: str = "") -> Outbound:
    return Outbound(
        name="office-openvpn", kind=OutboundKind.OPENVPN,
        settings={
            "ovpn_content": _profile(extra),
            "username": "runtime-user", "password": "runtime-password",
        },
    )


def test_openvpn_domain_is_private_marked_and_credential_free_on_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )

    domains = manager.prepare([_outbound()])
    domain = domains["office-openvpn"]
    assert domain.ready and domain.mode == "openvpn"
    assert domain.interface.startswith("zgo") and len(domain.interface) <= 15
    assert domain.tunnel_interface == domain.interface
    assert domain.vrf_interface and domain.vrf_interface.startswith("zgr")
    assert domain.table_id == domain.fwmark

    config = Path(domain.runtime_dir) / "client.ovpn"
    auth = Path(domain.runtime_dir) / "auth.txt"
    assert config.stat().st_mode & 0o777 == 0o600
    assert auth.stat().st_mode & 0o777 == 0o600
    assert "route-noexec" in config.read_text()
    assert "pull-filter ignore \"redirect-gateway\"" in config.read_text()
    assert auth.read_text() == "runtime-user\nruntime-password\n"

    argv_text = "\n".join(" ".join(argv) for argv, _ in runner.calls)
    assert "runtime-password" not in argv_text
    assert "runtime-user" not in argv_text
    assert ["ip", "route", "replace", "table", str(domain.table_id),
            "default", "dev", domain.interface] in [call for call, _ in runner.calls]
    assert ["ip", "link", "set", "dev", domain.interface,
            "master", domain.vrf_interface] in [call for call, _ in runner.calls]


def test_openvpn_import_rejects_root_script_and_management_directives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    for directive in ("up /tmp/owned", "plugin /tmp/evil.so", "management 0.0.0.0 1"):
        with pytest.raises(CoreError, match="forbidden directive"):
            manager.prepare([_outbound(directive)])
        assert not manager.domain_views()


def test_openvpn_domain_repeat_is_idempotent_and_stop_is_symmetric(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(os, "killpg", lambda *_: None)
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    first = manager.prepare([_outbound()])["office-openvpn"]
    second = manager.prepare([_outbound()])["office-openvpn"]
    assert second is first
    starts = [argv for argv, _ in runner.calls
              if any(item.endswith("openvpn") for item in argv)]
    assert len(starts) == 1
    manager.stop()
    assert not manager.domain_views()
    assert first.interface not in runner.interfaces
