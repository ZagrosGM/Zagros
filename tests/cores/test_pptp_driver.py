import os
from types import SimpleNamespace

import pytest

from app.cores.drivers.pptp.accounting import PptpAccountingLedger, PptpSession
from app.cores.drivers.pptp.driver import PptpDriver
from app.cores.exceptions import CoreError
from app.cores.types import CoreMetrics, UserAccount


class Backend:
    def __init__(self, tmp_path):
        self.work_dir = str(tmp_path)
        self.accounting_path = str(tmp_path / "accounting.sqlite3")
        self.generation_path = str(tmp_path / "generation")
        self.chap_path = str(tmp_path / "chap-secrets")
        self.hook_path = str(tmp_path / "hook.py")
        self.running = False
        self.configured = None
        self.reloads = 0
        self.killed = []

    def validate_subnet(self, subnet): return []
    def verify_installation(self): return None
    def ensure_management_secret(self): return "management-secret-not-exposed"
    def configure(self, config, chap, hook): self.configured = (config, chap, hook)
    def reload(self): self.reloads += 1
    def is_running(self): return self.running
    def start(self, **kwargs): self.running = True
    def stop(self): self.running = False
    def purge(self): self.running = False
    def version(self): return "1.14.0"
    def sessions(self): return []
    def metrics(self): return CoreMetrics()
    def logs(self, tail=200): return []
    def terminate_account(self, account): self.killed.append(account)


def make_driver(tmp_path, **overrides):
    backend = Backend(tmp_path)
    settings = {
        "legacy_risk_ack": True, "internet_exposure_ack": True,
        "work_dir": str(tmp_path), "module_dir": "/runtime/modules",
        "management_port": 22001, "advertise_host": "vpn.example.test",
        "inbounds": [], **overrides,
    }
    driver = PptpDriver(settings, backend=backend,
                        ledger=PptpAccountingLedger(backend.accounting_path))
    return driver, backend


def inbound(**overrides):
    return {
        "tag": "pptp-legacy", "protocol": "pptp", "listen": "0.0.0.0",
        "port": 1723, "subnet": "10.77.0.0/24", "dns": "1.1.1.1,8.8.8.8",
        "legacy_risk_ack": True, "internet_exposure_ack": True,
        "authentication": "MS-CHAPv2", "encryption": "MPPE128",
        "network": "IPv4", "ipv6": False, "security_class": "legacy_insecure",
        **overrides,
    }


def account(password="safe-password"):
    return UserAccount(user_id=1, username="alice", account_id="1.alice.pptp",
                       protocol="pptp", settings={"password": password,
                                                  "inbound_tags": ["pptp-legacy"]})


def test_provider_identity_and_softether_independence():
    meta = PptpDriver.metadata
    assert meta.id == "pptp" and meta.security_class == "legacy_insecure"
    assert meta.studio_max_inbounds == 1 and meta.stop_when_no_inbounds
    assert "softether" not in PptpDriver.__module__


@pytest.mark.parametrize("change,reason", [
    ({"port": 1724}, "1723"),
    ({"legacy_risk_ack": False}, "Legacy/Insecure"),
    ({"internet_exposure_ack": False}, "Internet exposure"),
    ({"authentication": "PAP"}, "MS-CHAPv2"),
    ({"authentication": "CHAP-MD5"}, "MS-CHAPv2"),
    ({"authentication": "MS-CHAPv1"}, "MS-CHAPv2"),
    ({"encryption": "none"}, "MPPE128"),
    ({"encryption": "MPPE40"}, "MPPE128"),
    ({"network": "IPv6", "ipv6": True}, "IPv4-only"),
    ({"subnet": "not-a-network"}, "invalid PPTP"),
])
def test_strict_negative_validation(tmp_path, change, reason):
    driver, _ = make_driver(tmp_path)
    errors = driver.validate_studio_document({"inbounds": [inbound(**change)]})
    assert errors and reason in errors[0]


def test_deterministic_config_loads_only_allowed_modules(tmp_path):
    driver, backend = make_driver(tmp_path)
    listener = driver._normalize_inbound(inbound())
    config = driver.render_config(listener, "redacted-management-value")
    module_block = config.split("[core]", 1)[0]
    for required in ("pptp", "auth_mschap_v2", "chap-secrets", "ippool",
                     "sigchld", "pppd_compat", "log_file"):
        assert required in module_block
    for forbidden in ("auth_pap", "auth_chap_md5", "auth_mschap_v1", "ipv6pool"):
        assert forbidden not in module_block
    assert "mppe=require" in config and "ipv4=require" in config and "ipv6=deny" in config
    assert "single-session=replace" in config
    assert "127.0.0.1:22001" in config
    assert config == driver.render_config(listener, "redacted-management-value")


@pytest.mark.asyncio
async def test_install_requires_both_backend_confirmations(tmp_path):
    driver, _ = make_driver(tmp_path, legacy_risk_ack=False)
    with pytest.raises(CoreError, match="Legacy/Insecure"):
        await driver.install()
    driver, _ = make_driver(tmp_path, internet_exposure_ack=False)
    with pytest.raises(CoreError, match="Internet exposure"):
        await driver.install()


@pytest.mark.asyncio
async def test_account_lifecycle_generates_secret_and_terminates(tmp_path):
    driver, backend = make_driver(tmp_path, inbounds=[inbound()])
    item = account(password="")
    await driver.create_account(item)
    assert item.settings["password"]
    assert "1.alice.pptp" in backend.configured[1]
    await driver.suspend_account(item.account_id)
    assert item.account_id in backend.killed
    assert "1.alice.pptp" not in backend.configured[1]
    await driver.delete_account(item.account_id)
    assert item.account_id not in driver._accounts


@pytest.mark.asyncio
async def test_studio_apply_and_empty_delete_stop_runtime(tmp_path):
    driver, backend = make_driver(tmp_path)
    await driver.apply_studio_document({"inbounds": [inbound()]})
    assert driver.export_config_document()["inbounds"][0]["port"] == 1723
    backend.running = True
    await driver.apply_studio_document({"inbounds": []})
    assert not backend.running and driver.export_config_document() == {"inbounds": []}


@pytest.mark.asyncio
async def test_client_config_is_marked_legacy_and_secret_repr_redacted(tmp_path):
    driver, _ = make_driver(tmp_path, inbounds=[inbound()])
    cfg = await driver.build_client_config(account())
    assert cfg.payload["authentication"] == "MS-CHAPv2"
    assert cfg.payload["encryption"] == "MPPE128"
    assert cfg.payload["security_class"] == "legacy_insecure"
    assert "safe-password" not in repr(cfg)
    assert "Legacy / Insecure" in cfg.display_name
