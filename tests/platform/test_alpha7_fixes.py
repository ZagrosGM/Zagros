"""Regression tests for the alpha.7 field-feedback batch (real VPS report).

Each test pins ONE reported bug to its fix:
1. apt-based installers must run `apt-get update` before `install`
   ("Unable to locate package" on containers with empty apt lists).
2. LocalHysteria2Backend must keep `.settings` (AttributeError on install).
3. sing-box must not render experimental.v2ray_api on builds lacking it
   ("v2ray api is not included in this build" FATAL at start).
4. sing-box studio wizard entries must translate natively (strictly).
5. TUIC must expose a studio inbound (single-listener cardinality enforced).
6. xray start must self-install the binary when missing (ENOENT on Start).
7. wizard blueprint endpoint shape (dynamic Core→Protocol→Transport→Security).
"""
from __future__ import annotations

import asyncio

import pytest

from app.cores.exceptions import CoreError


# --------------------------------------------------------------------- #
# 1. apt-get update ordering (wireguard / ssh / openvpn)
# --------------------------------------------------------------------- #

class _AptRecorder:
    def __init__(self, backend, monkeypatch):
        self.calls: list[list[str]] = []

        def fake_run(argv, **kw):
            self.calls.append(list(argv))
            return "ok"

        monkeypatch.setattr(backend, "_run", fake_run)
        monkeypatch.setattr("shutil.which", lambda exe: exe == "apt-get" and "/usr/bin/apt-get" or None)


def _assert_update_before_install(backend_cls, settings, settings_kw, monkeypatch, tmp_path):
    backend = backend_cls(**settings_kw)
    rec = _AptRecorder(backend, monkeypatch)
    backend.install_packages()
    flat = [" ".join(c) for c in rec.calls]
    assert flat[0] == "apt-get update", f"update must precede install: {flat}"
    assert flat[1].startswith("apt-get install -y"), flat
    assert len(rec.calls) == 2


@pytest.mark.parametrize("pkg", ["wireguard-tools", "openssh-server", "openvpn"])
def test_apt_update_precedes_install(pkg, monkeypatch, tmp_path):
    if pkg == "wireguard-tools":
        from app.cores.drivers.wireguard.backend import LocalWireGuardBackend as B
        backend = B.__new__(B)
        backend.config_path = str(tmp_path / "wg.conf")
        backend.executable = "wg"
    elif pkg == "openssh-server":
        from app.cores.drivers.ssh.backend import LocalSystemSSHBackend as B
        backend = B.__new__(B)
    else:
        from app.cores.drivers.openvpn.backend import LocalOpenVPNBackend as B
        backend = B.__new__(B)
        backend.config_path = str(tmp_path / "ovpn.conf")
    rec = _AptRecorder(backend, monkeypatch)
    backend.install_packages()
    flat = [" ".join(c) for c in rec.calls]
    assert flat[0] == "apt-get update", f"{pkg}: update must precede install: {flat}"
    assert pkg in flat[1] or (pkg == "openssh-server" and "openssh" in flat[1]), flat
    assert len(rec.calls) == 2, flat


# --------------------------------------------------------------------- #
# 2. hysteria2 backend keeps settings
# --------------------------------------------------------------------- #

def test_hysteria2_backend_keeps_settings(tmp_path):
    from app.cores.drivers.hysteria2.backend import LocalHysteria2Backend

    backend = LocalHysteria2Backend({"release_version": "2.6.0",
                                     "work_dir": str(tmp_path)})
    assert backend.settings["release_version"] == "2.6.0"
    # the reported crash was inside install_binary's pin resolution — the
    # code path itself must also read settings without AttributeError
    assert str(backend.settings.get("release_version") or "") == "2.6.0"


# --------------------------------------------------------------------- #
# 3. sing-box v2ray_api probe gates the experimental block
# --------------------------------------------------------------------- #

def _singbox(supported: bool):
    from app.cores.drivers.singbox.driver import SingBoxDriver

    class FakeBackend:
        def probe_v2ray_support(self):
            return supported

    driver = SingBoxDriver(
        {"listen": "0.0.0.0", "ports": {"vless": 443},
         "stats_enabled": True, "stats_api": "127.0.0.1:19091"},
        backend=FakeBackend(), stats=object(),
    )
    return driver


def test_singbox_renders_v2ray_api_only_when_supported():
    driver = _singbox(True)
    driver._accounts["u"] = type("A", (), {
        "protocol": "vless", "account_id": "u", "enabled": True,
        "settings": {"id": "11111111-2222-3333-4444-555555555555"}})()
    config = driver.render_config()
    assert "v2ray_api" in config["experimental"]


def test_singbox_omits_v2ray_api_and_degrades_honestly_when_unsupported():
    driver = _singbox(False)
    driver._accounts["u"] = type("A", (), {
        "protocol": "vless", "account_id": "u", "enabled": True,
        "settings": {"id": "11111111-2222-3333-4444-555555555555"}})()
    config = driver.render_config()
    assert "experimental" not in config, "build without v2ray_api FATALs on this block"
    assert driver._stats_error and "v2ray_api" in driver._stats_error


# --------------------------------------------------------------------- #
# 4. sing-box studio entry translation (strict)
# --------------------------------------------------------------------- #

def _studio_driver():
    from app.cores.drivers.singbox.driver import SingBoxDriver

    return SingBoxDriver({"listen": "0.0.0.0", "ports": {"vless": 443},
                          "stats_enabled": False}, backend=object(), stats=object())


def test_singbox_studio_ws_translation():
    ib = _studio_driver()._studio_entry_to_native(
        {"tag": "w", "protocol": "vless", "port": 8443, "transport": "ws",
         "path": "/ws", "host": "cdn.example.com", "security": "none"})
    assert ib["type"] == "vless" and ib["listen_port"] == 8443
    assert ib["transport"] == {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}}
    assert "tls" not in ib


def test_singbox_studio_reality_generates_keypair():
    ib = _studio_driver()._studio_entry_to_native(
        {"tag": "r", "protocol": "vless", "port": 443,
         "transport": "tcp", "security": "reality", "sni": "www.microsoft.com"})
    reality = ib["tls"]["reality"]
    assert reality["enabled"] and reality["private_key"]
    assert len(reality["short_id"][0]) == 16
    assert ib["_reality_public_key"]


def test_singbox_studio_grpc_requires_service_name():
    with pytest.raises(CoreError):
        _studio_driver()._studio_entry_to_native(
            {"tag": "g", "protocol": "vless", "port": 2050, "transport": "grpc"})


def test_singbox_studio_xhttp_rejected_honestly():
    with pytest.raises(CoreError, match="Xray-only|xhttp"):
        _studio_driver()._studio_entry_to_native(
            {"tag": "x", "protocol": "vless", "port": 1, "transport": "xhttp"})


def test_singbox_studio_unknown_fields_never_dropped_silently():
    with pytest.raises(CoreError, match="bogus"):
        _studio_driver()._studio_entry_to_native(
            {"tag": "x", "protocol": "vless", "port": 1, "bogus": 1})


def test_singbox_studio_users_stay_platform_driven_on_merge():
    driver = _studio_driver()
    driver._accounts["u1"] = type("A", (), {
        "protocol": "vless", "account_id": "u1", "enabled": True,
        "settings": {"id": "11111111-2222-3333-4444-555555555555"}})()
    driver._studio_doc = {"inbounds": [
        {"tag": "w", "protocol": "vless", "port": 8443,
         "transport": "ws", "path": "/ws", "security": "none"},
    ]}
    merged = driver._merge_studio_inbounds()
    assert merged[0]["tag"] == "w"
    assert merged[0]["users"][0]["name"] == "u1"


# --------------------------------------------------------------------- #
# 5. TUIC studio exposure
# --------------------------------------------------------------------- #

def test_tuic_declares_studio_path_and_exports_single_inbound():
    from app.cores.drivers.tuic.driver import TUICDriver

    assert TUICDriver.metadata.studio_inbounds_path == "/inbounds"

    class FB:
        def apply_config(self, c): pass
        def is_running(self): return False

    driver = TUICDriver({"work_dir": "/tmp/zagros-test-tuic"}, backend=FB())
    doc = driver.export_config_document()
    assert doc["inbounds"][0]["protocol"] == "tuic"
    assert doc["inbounds"][0]["port"] == 8443


def test_tuic_studio_apply_adopts_settings_and_enforces_cardinality():
    from app.cores.drivers.tuic.driver import TUICDriver

    applied = {}

    class FB:
        def apply_config(self, c): applied.update(c)
        def is_running(self): return False

    driver = TUICDriver({"work_dir": "/tmp/zagros-test-tuic"}, backend=FB())
    asyncio.run(driver.apply_studio_document(
        {"inbounds": [{"tag": "tuic", "port": 9443, "congestion_control": "cubic"}]}))
    assert driver.settings["port"] == 9443
    assert applied["congestion_control"] == "cubic"
    with pytest.raises(CoreError, match="exactly ONE listener"):
        asyncio.run(driver.apply_studio_document({"inbounds": [{"port": 1}, {"port": 2}]}))


# --------------------------------------------------------------------- #
# 6. xray start self-heals a missing binary
# --------------------------------------------------------------------- #

def test_xray_start_self_installs_missing_binary(monkeypatch, tmp_path):
    import app.cores.drivers.xray.driver as xray_mod

    exe = tmp_path / "xray"

    class FakeBackend:
        started = False

        def executable_path(self):
            return str(exe)

        def start(self):
            FakeBackend.started = True

    installed = []

    monkeypatch.setattr(
        xray_mod, "_install_xray",
        lambda settings: installed.append(settings["executable_path"]) or "v1.2.3",
    )
    driver = xray_mod.XrayDriver(backend=FakeBackend())
    asyncio.run(driver.start())
    assert installed == [str(exe)], "missing binary must trigger self-install first"
    assert FakeBackend.started


def test_xray_export_reads_real_config_document():
    from app.cores.drivers.xray.driver import XrayDriver

    driver = XrayDriver.__new__(XrayDriver)
    doc = XrayDriver.export_config_document(driver)
    assert "inbounds" in doc  # repo's real xray_config.json
    assert doc["inbounds"], "export must not be empty on the shipped config"


# --------------------------------------------------------------------- #
# 7. wizard blueprint (dynamic Core → Protocol → Transport → Security)
# --------------------------------------------------------------------- #

def test_wizard_blueprint_changes_with_core():
    from app.studio.wizard import blueprint_for

    sing = blueprint_for("singbox")
    xray = blueprint_for("xray")
    assert [p["id"] for p in sing["protocols"]] != [p["id"] for p in xray["protocols"]]
    sing_ids = {p["id"] for p in sing["protocols"]}
    assert {"hysteria2", "tuic"} <= sing_ids, "sing-box hosts both QUIC protocols"
    assert "hysteria2" not in {p["id"] for p in xray["protocols"]}


def test_wizard_blueprint_security_fields_follow_selection():
    from app.studio.wizard import blueprint_for

    bp = blueprint_for("singbox")
    vless = next(p for p in bp["protocols"] if p["id"] == "vless")
    tcp = next(t for t in vless["transports"] if t["id"] == "tcp")
    sec_ids = [s["id"] for s in tcp["securities"]]
    assert sec_ids == ["reality", "tls", "none"]
    reality = tcp["securities"][0]
    keys = [f["key"] for f in reality["fields"]]
    assert "sni" in keys and "fingerprint" in keys
    ws = next(t for t in vless["transports"] if t["id"] == "ws")
    ws_tls = next(s for s in ws["securities"] if s["id"] == "tls")
    keys = [f["key"] for f in ws_tls["fields"]]
    assert keys[:2] == ["path", "host"], "transport fields lead for ws"


def test_wizard_blueprint_rejects_unknown_core():
    from app.studio.wizard import blueprint_for

    with pytest.raises(KeyError):
        blueprint_for("nonsense")


# --------------------------------------------------------------------- #
# 8. studio service: wizard on an empty document no longer 422s
# --------------------------------------------------------------------- #

def test_studio_wizard_creates_missing_parent_list(tmp_path):
    from app.studio.service import ConfigStudioService, InboundSpec

    class MemStore:
        def __init__(self): self.doc = None
        async def get_document(self, core_id): return self.doc
        async def save_document(self, core_id, document): self.doc = document

    class FakeDriver:
        class M:
            id = "singbox"
            studio_inbounds_path = "/inbounds"
            config_schema = None
        metadata = M()

        def render_config(self):
            return {}

    svc = ConfigStudioService(MemStore())
    spec = InboundSpec(tag="w", protocol="vless", port=8443,
                       settings={"transport": "ws", "path": "/ws"})
    result = asyncio.run(svc.wizard_add_inbound(FakeDriver(), spec))
    assert result.valid, result.errors
    doc = svc._store.doc
    assert doc["inbounds"][0]["tag"] == "w"
