"""f-l2tplink-1 — Host Settings must rewrite l2tp/l2tp+ipsec share links.

Installer report: setting an address on the SoftEther L2TP inbound left
every subscriber link on the panel's request domain, because the host
engine parsed LINK artifacts with parse_share_url — which (rightly) has no
OutboundKind for dial links — and kept the original on parse failure.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("pydantic",)
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")


def _engine():
    from app.portal.hostengine import HostSettingsEngine

    return HostSettingsEngine()


def _entry(**kw):
    from app.portal.hostengine import HostEntry

    return HostEntry(**{"remark": "relay-1", "address": "203.0.113.9", **kw})


def _artifact(content: str):
    from app.cores.delivery import ArtifactKind, DeliveryArtifact

    return DeliveryArtifact(kind=ArtifactKind.LINK, label="VPN (L2TP/IPsec)",
                            content=content)


L2TP = ("l2tp+ipsec://vpnuser:s3cret@panel.example.com:1701"
        "?hub=DEFAULT&psk=PSKVALUE#VPN%20%28L2TP%2FIPsec%29")


def test_address_and_port_override_replaces_panel_domain():
    engine = _engine()
    out = engine._expand_l2tp_link(_artifact(L2TP), [_entry(port=1701)],
                                   {}, [])
    assert len(out) == 1
    link = out[0].content
    assert link.startswith("l2tp+ipsec://vpnuser:s3cret@203.0.113.9:1701?")
    assert "panel.example.com" not in link
    # query and fragment survive byte-for-byte (fragment re-remarked)
    assert "hub=DEFAULT&psk=PSKVALUE" in link
    assert "#relay-1" in link
    assert out[0].qr == _artifact(L2TP).qr


def test_no_entries_means_no_leak_path_is_untouched():
    engine = _engine()
    out = engine._expand_l2tp_link(_artifact(L2TP), [], {}, [])
    assert out == []


def test_templated_address_renders_variables():
    engine = _engine()
    # SERVER_IP means "the link's current host" (parity with the generic
    # path); a custom variable renders the admin's value.
    out = engine._expand_l2tp_link(
        _artifact(L2TP), [_entry(address="{RELAY}")],
        {"RELAY": "198.51.100.4"}, [])
    assert "@198.51.100.4:" in out[0].content
    assert "panel.example.com" not in out[0].content
    out2 = engine._expand_l2tp_link(
        _artifact(L2TP), [_entry(address="{SERVER_IP}")], {}, [])
    assert "@panel.example.com:" in out2[0].content  # parity: current host


def test_meaningless_overrides_are_reported_not_dropped():
    engine = _engine()
    notes: list[str] = []
    out = engine._expand_l2tp_link(
        _artifact(L2TP), [_entry(sni="x.example.com", port=1701)], {}, notes)
    assert len(out) == 1
    assert any("SNI has no meaning" in n for n in notes), notes


def test_missing_address_and_port_reports_honestly():
    engine = _engine()
    notes: list[str] = []
    out = engine._expand_l2tp_link(
        _artifact("l2tp://@:1701?hub=X#n"), [_entry()], {}, notes)
    assert len(out) == 1 and out[0].content.startswith("l2tp://@:1701")
    assert notes  # honest: original kept


def test_plain_l2tp_scheme_supported_too():
    engine = _engine()
    out = engine._expand_l2tp_link(
        _artifact("l2tp://u:p@old.example.com:1701?hub=D#L2TP"),
        [_entry(address="198.51.100.8")], {}, [])
    assert out[0].content.startswith("l2tp://u:p@198.51.100.8:1701?hub=D#")


def test_generic_expand_link_routes_l2tp():
    """The dispatcher itself must route dial links away from _parse."""
    from app.cores.delivery import ArtifactKind, DeliverySection
    from app.portal.hostengine import HostEntry

    engine = _engine()
    section = DeliverySection(
        core_id="softether", inbound_tag="l2tp-de", protocol="l2tp",
        title="L2TP/IPsec", engine="native",
        artifacts=[_artifact(L2TP)])
    expanded = engine.expand(
        __import__("app.cores.delivery", fromlist=["DeliveryProfile"])
        .DeliveryProfile(core_id="softether", sections=[section]),
        {"l2tp-de": [HostEntry(remark="relay", address="203.0.113.9", port=1701)]},
        {"USERNAME": "u1"})
    link = expanded.sections[0].artifacts[0].content
    assert "@203.0.113.9:1701" in link
    assert "panel.example.com" not in link


# --------------------------------------------------------------------- #
# f-diallink-1 — PPTP and SSH links are dial links too
# --------------------------------------------------------------------- #

PPTP = ("pptp://2.testuser.pptp:PPTPPASS@panel.example.com:1723"
        "#PPTP%20%E2%80%94%20Legacy%20%2F%20Insecure")
SSH = "ssh://zg-2-test-user-ssh:SSHPASS@panel.example.com:2022#ssh%20%C2%B7%20SSH"


@pytest.mark.parametrize(
    ("content", "scheme", "port"),
    [(PPTP, "pptp", 1723), (SSH, "ssh", 2022)],
)
def test_dial_links_are_expanded_instead_of_warned_about(content, scheme, port):
    """A correct subscription must not carry a bogus parse warning.

    The generic path called parse_share_url, which supports only proxy
    protocols; PPTP and SSH links therefore survived with the panel's
    request domain AND emitted "could not be parsed for host overrides"
    next to a link that was perfectly fine.
    """
    engine = _engine()
    inapplicable: list[str] = []
    out = engine._expand_link(
        _artifact(content), [_entry(port=port)], {}, inapplicable,
        section_proto=scheme,
    )
    assert inapplicable == [], inapplicable
    assert len(out) == 1
    link = out[0].content
    assert link.startswith(f"{scheme}://")
    assert "panel.example.com" not in link
    assert "203.0.113.9" in link
    assert f":{port}" in link
    # credentials are preserved verbatim
    assert "@203.0.113.9" in link
    assert "#relay-1" in link


def test_ssh_link_keeps_userinfo_and_reports_tls_overrides():
    engine = _engine()
    inapplicable: list[str] = []
    out = engine._expand_link(
        _artifact(SSH), [_entry(port=2022, sni="example.org")], {},
        inapplicable, section_proto="ssh",
    )
    assert out[0].content.startswith("ssh://zg-2-test-user-ssh:SSHPASS@203.0.113.9:2022")
    assert any("SNI" in item and "ssh dial link" in item for item in inapplicable), \
        inapplicable
