from types import SimpleNamespace

import pytest

from app.cores.drivers.pptp.capabilities import provider_capability
from app.cores.drivers.pptp.driver import PptpDriver
from app.cores.matrix import capability_matrix
from app.studio.service import ConfigStudioService, InMemoryStudioStore, InboundSpec
from app.studio.wizard import blueprint_for


from app.cores.types import CoreMetrics


def test_independent_server_and_outbound_capabilities_stay_separate():
    provider = provider_capability(installed=True)
    assert provider["provider"] == "pptp" and provider["engine"] == "accel-ppp"
    assert provider["dataplane"] == "pptp_server"
    assert provider["security_class"] == "legacy_insecure"
    cells = capability_matrix(installed={"pptp"})["pptp"]
    assert cells["inbound"]["state"] == "supported"
    # The core is still the ACCEL-PPP inbound provider; Phase 3 adds a
    # separate pptp-linux/pppd outbound and subnet-based source classifier.
    assert cells["outbound"]["state"] == "supported"
    assert "pptp-linux" in cells["outbound"]["detail"]
    assert cells["routing_source"]["state"] == "supported"


def test_wizard_is_independent_fixed_and_has_no_weak_choices():
    pptp = blueprint_for("pptp")
    assert pptp["core_id"] == "pptp"
    protocol = pptp["protocols"][0]
    assert protocol["fixed_port"] and protocol["default_port"] == 1723
    assert protocol["security_class"] == "legacy_insecure"
    fields = {f["key"]: f for f in protocol["transports"][0]["securities"][0]["fields"]}
    assert fields["authentication"]["options"] == ["MS-CHAPv2"]
    assert fields["encryption"]["options"] == ["MPPE128"]
    assert fields["ipv6"]["default"] is False
    softether_ids = {item["id"] for item in blueprint_for("softether")["protocols"]}
    assert "pptp" not in softether_ids


@pytest.mark.asyncio
async def test_studio_preview_invokes_backend_semantic_validation(tmp_path):
    class Backend:
        accounting_path = str(tmp_path / "acct.sqlite3")
        generation_path = str(tmp_path / "generation")
        chap_path = str(tmp_path / "chap")
        hook_path = str(tmp_path / "hook")
        def validate_subnet(self, subnet): return []
        def is_running(self): return False

    driver = PptpDriver({
        "legacy_risk_ack": True, "internet_exposure_ack": True,
        "work_dir": str(tmp_path), "module_dir": "/modules", "inbounds": [],
    }, backend=Backend())
    studio = ConfigStudioService(InMemoryStudioStore())
    bad = InboundSpec(tag="legacy", protocol="pptp", listen="0.0.0.0", port=1724,
                      settings={
                          "subnet": "10.77.0.0/24", "legacy_risk_ack": True,
                          "internet_exposure_ack": True,
                          "authentication": "MS-CHAPv2", "encryption": "MPPE128",
                          "network": "IPv4", "ipv6": False,
                          "security_class": "legacy_insecure",
                      })
    result = await studio.wizard_preview_inbound(driver, bad)
    assert not result.valid and any("1723" in error for error in result.errors)


@pytest.mark.asyncio
async def test_pptp_fresh_install_auto_provisions_inbound_enables_starts(tmp_path):
    from app.platform.runtime import PlatformRuntime
    from app.platform.admin_api import cores_install, CoreInstallBody

    class FakeBackend:
        accounting_path = str(tmp_path / "acct.sqlite3")
        generation_path = str(tmp_path / "gen")
        chap_path = str(tmp_path / "chap")
        hook_path = str(tmp_path / "hook")
        def __init__(self, settings):
            self.settings = settings
            self.running = False
            self.configured = False
        def verify_installation(self): pass
        def ensure_management_secret(self): return "secret"
        def configure(self, cfg, chap, hook): self.configured = True
        def reload(self): pass
        def is_running(self): return self.running
        def start(self, tag, subnet, listen): self.running = True
        def stop(self): self.running = False
        def sessions(self): return []
        def metrics(self): return CoreMetrics(active_sessions=0, active_accounts=0)

    db_path = tmp_path / "test.db"
    runtime = PlatformRuntime(database_url=f"sqlite:///{db_path}", master_secret="0123456789abcdef0123456789abcdef")
    from app.persistence.base import Base
    Base.metadata.create_all(bind=runtime.session_factory.kw["bind"])
    runtime.verify_schema = lambda: None

    # Patch PPTpDriver to use FakeBackend
    from app.cores.drivers.pptp.driver import PptpDriver
    original_init = PptpDriver.__init__

    def patched_init(self, settings=None, *, backend=None, ledger=None):
        original_init(self, settings, backend=FakeBackend(settings or {}), ledger=ledger)

    PptpDriver.__init__ = patched_init
    try:
        # 1. Fresh install PPTP
        res = await cores_install("pptp", CoreInstallBody(), runtime=runtime)
        assert res["ok"] is True
        assert res["core"] == "pptp"
        assert res["enabled"] is True
        assert res["state"] == "running"

        # Check that default inbound exists in studio doc and driver
        doc = await runtime.studio_store.get_document("pptp")
        assert len(doc["inbounds"]) == 1
        assert doc["inbounds"][0]["tag"] == "pptp-default"
        assert doc["inbounds"][0]["port"] == 1723

        # Check driver state and backend running state
        driver = runtime.core_manager.get("pptp")
        assert runtime.core_manager.is_enabled("pptp") is True
        assert driver._backend.is_running() is True

        # 2. Idempotency test: Re-install when inbound already exists
        res2 = await cores_install("pptp", CoreInstallBody(), runtime=runtime)
        doc2 = await runtime.studio_store.get_document("pptp")
        assert len(doc2["inbounds"]) == 1
        assert doc2["inbounds"][0]["tag"] == "pptp-default"
    finally:
        PptpDriver.__init__ = original_init
