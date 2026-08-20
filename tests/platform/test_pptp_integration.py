from types import SimpleNamespace

import pytest

from app.cores.drivers.pptp.capabilities import provider_capability
from app.cores.drivers.pptp.driver import PptpDriver
from app.cores.matrix import capability_matrix
from app.studio.service import ConfigStudioService, InMemoryStudioStore, InboundSpec
from app.studio.wizard import blueprint_for


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
