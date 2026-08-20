from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from app.cores.capabilities import (
    OutboundDataplane,
    SupportState,
    outbound_product_capability,
    routing_compatibility,
)
from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.outbounds.profile_schema import outbound_schemas
from app.cores.outbounds.repository import (
    OutboundSecretCodec,
    OutboundWrite,
    split_settings,
)
from app.cores.routing.policy import PolicyDomain, PolicyRoutingManager
from app.cores.routing.ppp_client import (
    render_ppp_client_plan,
    write_private_plan_files,
)
from app.persistence.cipher import SecretsCipher
from tests.cores.policy_fakes import EmptyCoreManager, FakeRunner


def _settings(kind: OutboundKind) -> dict:
    common = {
        "server": "vpn.example.test", "username": "alice",
        "password": "Never-In-Argv-42!", "ipv6": False,
    }
    if kind is OutboundKind.L2TP_IPSEC:
        return {**common, "server_port": 1701, "ipsec_psk": "IKE-Secret-77"}
    if kind is OutboundKind.L2TP_RAW:
        return {**common, "server_port": 1701, "legacy_risk_ack": True}
    if kind is OutboundKind.SSTP:
        return {**common, "server_port": 443,
                "tls_server_name": "vpn.example.test",
                "ca_pem": "-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----"}
    if kind is OutboundKind.PPTP:
        return {**common, "server_port": 1723, "legacy_risk_ack": True}
    raise AssertionError(kind)


@pytest.mark.parametrize("kind", [
    OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW,
    OutboundKind.SSTP, OutboundKind.PPTP,
])
def test_canonical_ppp_provider_contract(kind: OutboundKind) -> None:
    outbound = Outbound(name=f"peer-{kind.value}", kind=kind, settings=_settings(kind))
    capability = outbound_product_capability(kind)
    assert outbound.kind is kind
    assert capability.state is SupportState.SUPPORTED
    assert capability.dataplane is OutboundDataplane.POLICY_TUN
    assert capability.tun and capability.kernel_routing and capability.accounting
    assert capability.ip_versions == {"ipv4"}
    assert capability.routing_source_cores == {
        "xray", "sing-box", "openvpn", "wireguard", "softether", "ssh", "pptp",
    }
    state, reason = routing_compatibility(
        capability, source_cores={"pptp"}, networks={"tcp", "udp"})
    assert state is SupportState.SUPPORTED and reason is None


def test_phase4_product_routing_matrix_is_70_supported() -> None:
    sources = ["xray", "wireguard", "openvpn", "softether", "ssh", "pptp", "sing-box"]
    targets = {
        "xray": OutboundKind.VLESS,
        "wireguard": OutboundKind.WIREGUARD,
        "sing-box": OutboundKind.HYSTERIA2,
        "openvpn": OutboundKind.OPENVPN,
        "softether_native": OutboundKind.SOFTETHER_NATIVE,
        "l2tp_ipsec": OutboundKind.L2TP_IPSEC,
        "l2tp_raw": OutboundKind.L2TP_RAW,
        "sstp": OutboundKind.SSTP,
        "pptp": OutboundKind.PPTP,
        "ssh": OutboundKind.SSH,
    }
    cells = {}
    for source in sources:
        for target, kind in targets.items():
            networks = {"tcp"} if target == "ssh" else {"tcp", "udp"}
            cells[(source, target)] = routing_compatibility(
                outbound_product_capability(kind),
                source_cores={source}, networks=networks,
            )[0]
    assert len(cells) == 70
    assert all(state is SupportState.SUPPORTED for state in cells.values())


def test_legacy_insecure_and_fixed_port_rejections() -> None:
    with pytest.raises(ValueError, match="acknowledgement"):
        Outbound(name="raw-no-ack", kind="l2tp_raw", settings={
            "server": "vpn.test", "server_port": 1701,
            "username": "u", "password": "p",
        })
    with pytest.raises(ValueError, match="TCP/1723"):
        Outbound(name="pptp-wrong-port", kind="pptp", settings={
            "server": "vpn.test", "server_port": 11723,
            "username": "u", "password": "p", "legacy_risk_ack": True,
        })
    with pytest.raises(ValueError, match="verification cannot be bypassed"):
        Outbound(name="sstp-insecure", kind="sstp", settings={
            "server": "vpn.test", "server_port": 443,
            "username": "u", "password": "p", "allow_insecure": True,
        })


def test_schemas_expose_canonical_providers_and_omit_softether_aliases() -> None:
    schemas = outbound_schemas()
    for kind in ("l2tp_ipsec", "l2tp_raw", "sstp", "pptp"):
        assert schemas[kind]["x-availability"] in {"supported", "not_installed"}
        assert schemas[kind]["x-supported"] is True
        assert "password" in schemas[kind]["properties"]
    assert schemas["l2tp_raw"]["x-security-class"] == "legacy_insecure"
    assert schemas["pptp"]["x-security-class"] == "legacy_insecure"
    for alias in ("softether_l2tp", "softether_l2tp_raw",
                  "softether_sstp", "softether_pptp"):
        assert alias not in schemas


@pytest.mark.parametrize("value", [0, 19, 31, "many"])
def test_ppp_diagnostic_sample_count_is_strict(value) -> None:
    settings = _settings(OutboundKind.PPTP)
    settings["test_samples"] = value
    with pytest.raises(ValueError, match="test_samples must be 20-30"):
        Outbound(name="bad-samples", kind="pptp", settings=settings)


def test_ppp_diagnostic_url_and_public_probe_ca_are_strict() -> None:
    settings = _settings(OutboundKind.SSTP)
    settings["test_url"] = "http://probe.example.test/"
    with pytest.raises(ValueError, match="test_url must be an HTTPS URL"):
        Outbound(name="bad-probe-url", kind="sstp", settings=settings)
    settings = _settings(OutboundKind.SSTP)
    settings["probe_ca_pem"] = "not a certificate"
    with pytest.raises(ValueError, match="probe_ca_pem is not a PEM"):
        Outbound(name="bad-probe-ca", kind="sstp", settings=settings)


def test_ppp_network_diagnostics_separate_first_packet_and_verify_counters(
    tmp_path: Path, monkeypatch,
) -> None:
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=FakeRunner(),
        sleep=lambda _seconds: None,
    )
    domain = PolicyDomain(
        name="probe-pptp", kind=OutboundKind.PPTP,
        table_id=12010, fwmark=12010, bypass_mark=1, return_mark=2,
        interface="zglprobe", tunnel_interface="ppp0", mode="ppp",
        fingerprint="f", runtime_dir=str(tmp_path / "probe"),
        namespace="zgnprobe", client_adapter="ppp0",
    )
    Path(domain.runtime_dir).mkdir(mode=0o700)
    settings = _settings(OutboundKind.PPTP)
    settings.update({
        "test_url": "https://probe.example.test/nonce", "test_samples": 20,
    })
    outbound = Outbound(name="probe-pptp", kind="pptp", settings=settings)
    monkeypatch.setattr(
        "app.cores.routing.policy.shutil.which",
        lambda name: "/bin/busybox" if name == "busybox" else None,
    )
    monkeypatch.setattr(
        "app.cores.routing.policy.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("1.1.1.1", 443)),
        ],
    )
    statuses = iter([
        {"connected": True, "uplink_bytes": 100, "downlink_bytes": 200},
        {"connected": True, "uplink_bytes": 900, "downlink_bytes": 1200},
    ])
    monkeypatch.setattr(manager, "_ppp_status", lambda _domain: next(statuses))
    calls: list[list[str]] = []

    def run(*argv, check=True, timeout=30, input_text=None):
        values = [str(value) for value in argv]
        calls.append(values)
        if "ping" in values:
            replies = "\n".join(
                f"64 bytes from 1.1.1.1: seq={index} ttl=55 time={10 + index}.0 ms"
                for index in range(23)
            )
            return subprocess.CompletedProcess(values, 0, replies, "")
        if str(sys.executable) in values:
            suffix = "tunnel" if values[:3] == ["ip", "netns", "exec"] else "direct"
            payload = {
                "status": 200, "elapsed_ms": 25.0, "bytes": 80,
                "sha256": "a" * 64,
            }
            return subprocess.CompletedProcess(values, 0, json.dumps(payload), "")
        if values[:5] == ["ip", "-n", "zgnprobe", "route", "get"]:
            return subprocess.CompletedProcess(
                values, 0, "1.1.1.1 dev ppp0 src 10.0.0.2\n", "")
        raise AssertionError(values)

    monkeypatch.setattr(manager, "_run", run)
    measured = manager.measure_ppp(domain, outbound)
    assert measured["direct_rtt"]["samples"] == 20
    assert measured["direct_rtt"]["warmup_samples"] == 3
    assert measured["direct_rtt"]["warmup_ms"] == [10.0, 11.0, 12.0]
    assert measured["direct_rtt"]["median_ms"] == 22.5
    assert measured["tunnel_rtt"]["p95_ms"] == 31.0
    assert measured["selected_rtt_ms"] == 22.5
    assert measured["measurement_window_samples"] == [float(v) for v in range(13, 33)]
    assert measured["direct_https"]["nonce"] != measured["tunnel_https"]["nonce"]
    assert measured["counter_delta"] == {
        "uplink_bytes": 800, "downlink_bytes": 1000,
    }
    ping_calls = [values for values in calls if "ping" in values]
    assert len(ping_calls) == 2
    assert all(values[values.index("-c") + 1] == "23" for values in ping_calls)
    script = (Path(domain.runtime_dir) / "https-probe.py").read_text()
    assert "ssl.create_default_context" in script
    assert "_create_unverified_context" not in script


@pytest.mark.parametrize("kind", [
    OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW,
    OutboundKind.SSTP, OutboundKind.PPTP,
])
def test_ppp_materialization_keeps_secrets_out_of_argv_and_files_private(
    tmp_path: Path, kind: OutboundKind,
) -> None:
    outbound = Outbound(name=f"provider-{kind.value}", kind=kind,
                        settings=_settings(kind))
    plan = render_ppp_client_plan(
        outbound, runtime_dir=str(tmp_path), endpoint="192.0.2.10",
        pppd="/usr/sbin/pppd", xl2tpd="/usr/sbin/xl2tpd",
        sstpc="/usr/sbin/sstpc", sstp_runtime_dir=str(tmp_path / "sstpc"),
        sstp_callback_id="zg12345", pptp="/usr/sbin/pptp",
        charon="/usr/lib/ipsec/charon", swanctl="/usr/sbin/swanctl",
    )
    argv = json.dumps([plan.primary_argv, plan.auxiliary_argv])
    assert _settings(kind)["password"] not in argv
    assert _settings(kind).get("ipsec_psk", "not-present") not in argv
    write_private_plan_files(plan)
    for path in plan.files:
        expected = 0o644 if plan.file_modes.get(path) == 0o644 else 0o600
        assert os.stat(path).st_mode & 0o777 == expected
    options = (tmp_path / "ppp.options").read_text()
    assert _settings(kind)["password"] in options
    # This is a client: MS-CHAPv2 stays allowed for authenticating to the
    # server. `require-mschap-v2` would incorrectly demand reciprocal server
    # authentication and prevents real client sessions from negotiating.
    assert "require-mschap-v2" not in options
    if kind is OutboundKind.SSTP:
        assert "--cert-warn" not in options
        assert "--ca-dir" not in options
        assert "--ca-cert" in options
        assert "--log-level 3 --log-stderr --nolaunchpppd" in options
        assert "--host vpn.example.test --tls-ext --ipparam zg12345" in options
        assert 'plugin "/usr/lib/pppd/2.5.2/sstp-pppd-plugin.so"' in options
        assert f'sstp-sock "{tmp_path}/sstpc/sstpc-zg12345"' in options
        assert 'ipparam "zg12345"' in options
        public_ca = next(path for path, mode in plan.file_modes.items() if mode == 0o644)
        assert public_ca.startswith(str(tmp_path / "sstpc"))
        assert "--password" not in options and "--user" not in options
    if kind is OutboundKind.PPTP:
        assert "--nolaunchpppd" in options
        assert "require-mppe-128" in options
        assert "1723" not in options  # reference client uses its fixed port
    if kind is OutboundKind.L2TP_IPSEC:
        assert _settings(kind)["ipsec_psk"] in (tmp_path / "swanctl.conf").read_text()
        assert "mode = transport" in (tmp_path / "swanctl.conf").read_text()
        strongswan = (tmp_path / "strongswan.conf").read_text()
        assert "pid_file" not in strongswan
        assert "vici { socket = unix://charon.vici }" in strongswan
        assert strongswan.index("include /etc/strongswan.d/*.conf") < strongswan.index("charon {")
        assert plan.auxiliary_argv[0][:4] == [
            "/usr/bin/unshare", "--mount", "--propagation", "private",
        ]
        assert any("mount --bind" in value for value in plan.auxiliary_argv[0])
        assert str(tmp_path / "charon-run") in plan.auxiliary_argv[0]
        assert (tmp_path / "charon-run" / ".zagros-owned").read_text() == (
            "phase4-charon-piddir\n")
        assert plan.auxiliary_argv[1][1] == "--load-all"
        assert "--uri" in plan.auxiliary_argv[1]
        assert plan.auxiliary_argv[2][1] == "--initiate"


def test_sstp_default_trust_uses_client_system_bundle_without_legacy_ca_dir(
    tmp_path: Path,
) -> None:
    settings = _settings(OutboundKind.SSTP)
    settings.pop("ca_pem")
    outbound = Outbound(name="system-ca-sstp", kind="sstp", settings=settings)
    plan = render_ppp_client_plan(
        outbound, runtime_dir=str(tmp_path), endpoint="192.0.2.10",
        sstpc="/usr/sbin/sstpc", sstp_runtime_dir=str(tmp_path / "sstpc"),
        sstp_callback_id="zg12345",
    )
    options = plan.files[str(tmp_path / "ppp.options")]
    assert "--ca-dir" not in options
    assert "--ca-path" not in options
    assert "--ca-cert" not in options
    assert "--tls-ext" in options
    assert not any(mode == 0o644 for mode in plan.file_modes.values())


def test_default_policy_runtime_keeps_credentials_ephemeral_and_counters_persistent() -> None:
    manager = PolicyRoutingManager(EmptyCoreManager())
    assert manager._root == Path("/run/zagros/routing")  # noqa: SLF001
    assert manager._counter_path == Path(  # noqa: SLF001
        "/var/lib/zagros/routing/outbound-accounting.json"
    )


def test_sstp_rejects_callback_identity_too_long_for_runtime(tmp_path: Path) -> None:
    outbound = Outbound(
        name="provider-sstp", kind=OutboundKind.SSTP,
        settings=_settings(OutboundKind.SSTP),
    )
    with pytest.raises(CoreError, match="callback id"):
        render_ppp_client_plan(
            outbound, runtime_dir=str(tmp_path), endpoint="192.0.2.10",
            sstp_callback_id="zg0123456789",
        )


def test_stop_process_kills_owned_group_when_pppd_leader_already_exited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExitedLeader:
        pid = 4242

        @staticmethod
        def poll() -> int:
            return 1

        @staticmethod
        def wait(*, timeout: int) -> int:
            assert timeout == 8
            return 1

    calls: list[tuple[int, int]] = []
    probes = 0

    def killpg(pid: int, sig: int) -> None:
        nonlocal probes
        calls.append((pid, sig))
        if sig == 0:
            probes += 1
            if probes > 1:
                raise ProcessLookupError

    monkeypatch.setattr(os, "killpg", killpg)
    manager = PolicyRoutingManager(EmptyCoreManager())
    manager._stop_process(ExitedLeader())  # type: ignore[arg-type]  # noqa: SLF001
    assert calls == [
        (4242, signal.SIGTERM),
        (4242, 0),
        (4242, signal.SIGKILL),
    ]


def test_outbound_codec_encrypts_at_rest_redacts_api_and_preserves_omitted_secret() -> None:
    cipher = SecretsCipher(b"x" * 32)
    codec = OutboundSecretCodec(cipher)
    original = Outbound(
        name="secure-pptp", kind="pptp", settings=_settings(OutboundKind.PPTP))
    encoded = codec.encode([original])
    serialized = json.dumps(encoded)
    assert "Never-In-Argv-42!" not in serialized
    assert encoded["version"] == 2
    assert encoded["profiles"][0]["credentials_enc"].startswith("v1:")
    public = codec.public_view(original)
    assert "password" not in public["settings"]
    assert public["secret_state"] == {"password": True}
    decoded = codec.decode(encoded)
    assert decoded[0].settings["password"] == "Never-In-Argv-42!"

    sealed = codec.seal_import_credentials(
        OutboundKind.PPTP, {"password": "Imported-Sealed-99"})
    imported = codec.merge_writes([
        OutboundWrite(name="imported-pptp", kind="pptp", settings={
            "server": "vpn.example.test", "server_port": 1723,
            "username": "alice", "legacy_risk_ack": True,
        }, sealed_credentials=sealed)
    ], [])
    assert imported[0].settings["password"] == "Imported-Sealed-99"

    merged = codec.merge_writes([
        OutboundWrite(name="secure-pptp", kind="pptp", settings={
            "server": "vpn2.example.test", "server_port": 1723,
            "username": "alice", "legacy_risk_ack": True,
        })
    ], decoded)
    assert merged[0].settings["server"] == "vpn2.example.test"
    assert merged[0].settings["password"] == "Never-In-Argv-42!"

    with pytest.raises(ValueError, match="requires password"):
        codec.merge_writes([
            OutboundWrite(
                name="secure-pptp", kind="pptp",
                settings={
                    "server": "vpn2.example.test", "server_port": 1723,
                    "username": "alice", "legacy_risk_ack": True,
                },
                clear_secret_keys=["password"],
            )
        ], decoded)


def test_legacy_plaintext_profiles_migrate_only_on_successful_encode() -> None:
    codec = OutboundSecretCodec(SecretsCipher(b"m" * 32))
    legacy = [{
        "name": "legacy-sstp", "kind": "sstp", "enabled": True,
        "settings": _settings(OutboundKind.SSTP),
    }]
    decoded = codec.decode(legacy)
    assert decoded[0].settings["password"] == "Never-In-Argv-42!"
    migrated = codec.encode(decoded)
    assert migrated["version"] == 2
    assert "Never-In-Argv-42!" not in json.dumps(migrated)


def test_ciphertext_is_bound_to_name_and_kind() -> None:
    codec = OutboundSecretCodec(SecretsCipher(b"y" * 32))
    encoded = codec.encode([Outbound(
        name="bound-name", kind="sstp", settings=_settings(OutboundKind.SSTP))])
    encoded["profiles"][0]["name"] = "swapped-name"
    with pytest.raises(ValueError, match="failed authentication"):
        codec.decode(encoded)


def test_secret_classifier_keeps_public_key_and_cert_material_public() -> None:
    public, secret = split_settings({
        "peer_public_key": "pub", "ca_pem": "ca", "server_cert": "cert",
        "private_key": "private", "password": "pw", "ipsec_psk": "psk",
    })
    assert public == {"peer_public_key": "pub", "ca_pem": "ca", "server_cert": "cert"}
    assert secret == {"private_key": "private", "password": "pw", "ipsec_psk": "psk"}


def test_pptp_namespace_lifecycle_owns_only_deterministic_resources(
    tmp_path: Path, monkeypatch,
) -> None:
    runner = FakeRunner()
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _seconds: None,
    )
    domain = PolicyDomain(
        name="phase3-pptp", kind=OutboundKind.PPTP,
        table_id=12001, fwmark=12001, bypass_mark=1, return_mark=2,
        interface=manager._interface_for("phase3-pptp", "ppp"),  # noqa: SLF001
        mode="ppp", fingerprint="f",
        runtime_dir=str(tmp_path / "domain"),
        namespace=manager._softether_names("phase3-pptp")["namespace"],  # noqa: SLF001
        control_interface=manager._softether_names("phase3-pptp")["control"],  # noqa: SLF001
        client_adapter="ppp0",
    )
    Path(domain.runtime_dir).mkdir(mode=0o700)
    monkeypatch.setattr(manager, "_resolve_ipv4", lambda _host: "192.0.2.10")
    monkeypatch.setattr(manager, "_ppp_binary", lambda name, *fallbacks: f"/usr/sbin/{name}")
    monkeypatch.setattr(manager, "_ppp_status", lambda _domain: {
        "connected": True, "state": "connected", "address": "10.90.0.2",
        "uplink_bytes": 0, "downlink_bytes": 0,
    })
    outbound = Outbound(
        name="phase3-pptp", kind="pptp", settings=_settings(OutboundKind.PPTP))
    manager._start_ppp(domain, outbound)  # noqa: SLF001
    flattened = [argv for argv, _stdin in runner.calls]
    assert ["ip", "netns", "add", domain.namespace] in flattened
    assert any(argv[:5] == ["ip", "link", "add", "dev", domain.control_interface]
               for argv in flattened)
    assert any(argv[:5] == ["ip", "link", "add", "dev", domain.interface]
               for argv in flattened)
    process = next(argv for argv in flattened if "/usr/sbin/pppd" in argv)
    assert _settings(OutboundKind.PPTP)["password"] not in " ".join(process)
    assert any(argv[-5:] == ["POSTROUTING", "-o", "ppp0", "-j", "MASQUERADE"]
               for argv in flattened)
    assert any(
        argv[:5] in (
            ["iptables", "-t", "raw", "-C", "PREROUTING"],
            ["iptables", "-t", "raw", "-I", "PREROUTING"],
        ) and argv[-4:] == ["-j", "CT", "--helper", "pptp"]
        for argv in flattened
    )
    assert domain.client_address == "10.90.0.2"

    manager._cleanup_ppp(domain)  # noqa: SLF001
    flattened = [argv for argv, _stdin in runner.calls]
    assert ["ip", "netns", "del", domain.namespace] in flattened
    assert any(
        argv[:5] == ["iptables", "-t", "raw", "-D", "PREROUTING"]
        and argv[-4:] == ["-j", "CT", "--helper", "pptp"]
        for argv in flattened
    )
    # No global flush/default-route deletion is part of provider cleanup.
    assert not any(argv[:3] in (["nft", "flush", "ruleset"],
                                ["ip", "route", "flush"])
                   and "table" not in argv for argv in flattened)


def test_ppp_domain_starts_native_core_socks_gateway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=FakeRunner(),
        sleep=lambda _seconds: None,
    )
    domain = PolicyDomain(
        name="native-to-pptp", kind=OutboundKind.PPTP,
        table_id=12003, fwmark=12003, bypass_mark=1, return_mark=2,
        interface="zglgateway", mode="ppp", fingerprint="f",
        runtime_dir=str(tmp_path / "native-to-pptp"),
        namespace="zgngateway", control_interface="zgcgateway",
        client_adapter="ppp0", vrf_interface="zgrgateway",
    )
    outbound = Outbound(
        name=domain.name, kind=OutboundKind.PPTP,
        settings=_settings(OutboundKind.PPTP),
    )
    calls: list[str] = []
    monkeypatch.setattr(manager, "_start_ppp", lambda *_: calls.append("ppp"))
    monkeypatch.setattr(manager, "_wait_interface", lambda *_: calls.append("wait"))
    monkeypatch.setattr(manager, "_attach_vrf", lambda *_: calls.append("vrf"))
    monkeypatch.setattr(manager, "_start_gateway", lambda *_: calls.append("gateway"))
    manager._start_domain(domain, outbound)  # noqa: SLF001
    assert calls == ["ppp", "wait", "vrf", "gateway"]


def test_ppp_start_failure_rolls_back_namespace_files_and_links(
    tmp_path: Path, monkeypatch,
) -> None:
    runner = FakeRunner()
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _seconds: None,
    )
    names = manager._softether_names("dead-pptp")  # noqa: SLF001
    links = manager._softether_links(12002)  # noqa: SLF001
    domain = PolicyDomain(
        name="dead-pptp", kind=OutboundKind.PPTP,
        table_id=12002, fwmark=12002, bypass_mark=1, return_mark=2,
        interface=manager._interface_for("dead-pptp", "ppp"),  # noqa: SLF001
        mode="ppp", fingerprint="f",
        runtime_dir=str(tmp_path / "dead-domain"), namespace=names["namespace"],
        control_interface=names["control"], control_peer=links["control_peer"],
        data_peer=links["data_peer"], route_gateway=links["data_peer"],
        client_adapter="ppp0",
    )
    monkeypatch.setattr(manager, "_resolve_ipv4", lambda _host: "192.0.2.10")
    monkeypatch.setattr(manager, "_ppp_binary", lambda name, *fallbacks: f"/usr/sbin/{name}")
    monkeypatch.setattr(manager, "_ppp_status", lambda _domain: {
        "connected": False, "state": "not connected",
    })

    class DeadProcess:
        pid = 77777
        def poll(self): return 1
        def wait(self, timeout=None): return 1

    def dead_popen(argv, *, stdout):
        runner.calls.append(([str(item) for item in argv], None))
        return DeadProcess()

    monkeypatch.setattr(runner, "popen", dead_popen)
    outbound = Outbound(
        name="dead-pptp", kind="pptp", settings=_settings(OutboundKind.PPTP))
    with pytest.raises(CoreError, match="exited before PPP connected"):
        manager._start_domain(domain, outbound)  # noqa: SLF001
    assert not Path(domain.runtime_dir).exists()
    calls = [argv for argv, _stdin in runner.calls]
    assert ["ip", "netns", "del", domain.namespace] in calls
    assert any(argv[:5] == ["ip", "link", "del", "dev", domain.interface]
               for argv in calls)


def test_outbound_counter_ledger_is_monotonic_across_reconnects(tmp_path: Path) -> None:
    manager = PolicyRoutingManager(_Cores(), runtime_root=str(tmp_path))
    domain = PolicyDomain(
        name="accounted-pptp", kind=OutboundKind.PPTP,
        table_id=12000, fwmark=12000, bypass_mark=1, return_mark=2,
        interface="zgltest", mode="ppp", fingerprint="f",
    )
    assert manager._fold_outbound_counters(  # noqa: SLF001
        domain, uplink=100, downlink=50, generation="ns:8") == (100, 50)
    assert manager._fold_outbound_counters(  # noqa: SLF001
        domain, uplink=140, downlink=70, generation="ns:8") == (140, 70)
    # Same ifindex but lower live counters means pppd reconnected/reset.
    assert manager._fold_outbound_counters(  # noqa: SLF001
        domain, uplink=5, downlink=9, generation="ns:8") == (145, 79)
    assert manager._fold_outbound_counters(  # noqa: SLF001
        domain, uplink=3, downlink=4, generation="ns:22") == (148, 83)
    restored = PolicyRoutingManager(_Cores(), runtime_root=str(tmp_path))
    assert restored._load_counter_ledger()["accounted-pptp"]["total_up"] == 148  # noqa: SLF001
    assert os.stat(tmp_path / "outbound-accounting.json").st_mode & 0o777 == 0o600


class _PptpDriver:
    settings = {"inbounds": [{
        "tag": "pptp-browser", "protocol": "pptp", "subnet": "10.77.0.0/24",
    }]}


class _Cores:
    def list_cores(self):
        return ["pptp"]

    def get(self, core_id):
        assert core_id == "pptp"
        return _PptpDriver()


def test_independent_pptp_inbound_is_a_classifiable_policy_source(tmp_path: Path) -> None:
    manager = PolicyRoutingManager(_Cores(), runtime_root=str(tmp_path))
    sources = manager.traffic_sources()
    assert len(sources) == 1
    source = sources[0]
    assert source.core_id == "pptp"
    assert source.inbound_tag == "pptp-browser"
    assert source.source_subnet == "10.77.0.0/24"
