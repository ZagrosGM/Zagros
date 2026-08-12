"""Host Settings engine (alpha.7.2, item 13) — expansion semantics.

Pins: template chain (multi-pick / wildcard salt / variables / SERVER_IP),
parse→override→emit round-trips per scheme, capability honesty notes, the
full Marzban field set (fragment / noise / mux / allowinsecure / alpn /
fingerprint / use_sni_as_host), priority ordering, and comma-safety of
non-pick fields.  Every test uses public surfaces only.
"""
from __future__ import annotations

import base64
import json
import urllib.parse as up

import pytest

from app.cores.delivery import (
    ArtifactKind,
    DeliveryArtifact,
    DeliveryField,
    DeliveryProfile,
    DeliverySection,
)
from app.portal.hostengine import (
    DEFAULT_REMARK,
    HostEntry,
    HostSettingsEngine,
    render_host_remark,
    render_host_single,
    render_host_value,
)


@pytest.fixture()
def engine() -> HostSettingsEngine:
    return HostSettingsEngine()


def _vars() -> dict[str, str]:
    return {"USERNAME": "alice", "SERVER_IP": "10.0.0.9",
            "DATA_USAGE": "1.5GB", "DAYS_LEFT": "12"}


def _link_profile(link: str, *, tag: str | None = "in-a",
                  protocol: str = "vless") -> DeliveryProfile:
    return DeliveryProfile(core_id="sing-box", sections=[
        DeliverySection(protocol=protocol, title="T", engine="sing-box",
                        inbound_tag=tag,
                        artifacts=[DeliveryArtifact(
                            kind=ArtifactKind.LINK, label="base",
                            content=link, qr=True)])])


def _q(link: str) -> dict[str, str]:
    return dict(up.parse_qsl(up.urlparse(link).query))


# --------------------------------------------------------------------- #
# template chain
# --------------------------------------------------------------------- #

class TestTemplateChain:
    def test_comma_list_picks_one_member(self):
        seen = {render_host_value("a.example.com,b.example.com", {})}
        for _ in range(40):
            seen.add(render_host_value("a.example.com,b.example.com", {}))
        assert seen == {"a.example.com", "b.example.com"}

    def test_star_salts_to_random_hex(self):
        a, b = (render_host_value("*.example.com", {}) for _ in range(2))
        assert a != b
        assert a.endswith(".example.com") and len(a.split(".")[0]) == 16

    def test_variables_resolve_and_missing_is_honest(self):
        out = render_host_value("{USERNAME}.cdn.com/{MISSING}", _vars())
        assert out == "alice.cdn.com/<missing>"

    def test_single_keeps_commas(self):
        # fragment spec literally contains commas — must survive intact
        fs = "10-20,10-20,tlshello"
        assert render_host_single(fs, {}) == fs
        assert render_host_single("{USERNAME}_ua", _vars()) == "alice_ua"

    def test_remark_never_splits_and_never_salts(self):
        assert render_host_remark("DC1, Europe {USERNAME}", _vars()) == \
            "DC1, Europe alice"
        assert render_host_remark("edge * node", _vars()) == "edge * node"

    def test_delivery_variables_minimal_fallback(self):
        import datetime as dt

        from app.portal.hostengine import delivery_variables
        from app.portal.models import PortalUserView
        user = PortalUserView(user_id=1, username="bob", status="active",
                              used_bytes=0, data_limit_bytes=None,
                              expire_at=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
        v = delivery_variables(user)
        assert str(v["USERNAME"]) == "bob"


# --------------------------------------------------------------------- #
# link expansion per scheme
# --------------------------------------------------------------------- #

VLESS = ("vless://11111111-2222-3333-4444-555555555555@old.example.com:443"
         "?type=ws&security=tls&sni=old.example.com&path=%2Fw&host=cdn.old.com#_base")
TROJAN_REALITY = ("trojan://pw@tj.example.com:443?type=tcp&security=reality"
                  "&sni=www.microsoft.com&pbk=PK&sid=AB&fp=chrome#_base")


class TestLinkExpansion:
    def test_vless_full_override_roundtrip(self, engine):
        entries = [HostEntry(remark="DC1 {USERNAME}", address="dc1.example.com",
                             port=8443, sni="cdn.example.com",
                             host="h1.example.com", path="/v2")]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        art = out.sections[0].artifacts[0]
        assert art.kind is ArtifactKind.LINK
        parsed = up.urlparse(art.content)
        assert parsed.hostname == "dc1.example.com" and parsed.port == 8443
        q = _q(art.content)
        assert q["sni"] == "cdn.example.com" and q["host"] == "h1.example.com"
        assert q["path"] == "/v2"
        assert up.unquote(parsed.fragment) == "DC1 alice"

    def test_disabled_entries_are_skipped(self, engine):
        entries = [HostEntry(address="x.example.com", is_disabled=True)]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        arts = [a for a in out.sections[0].artifacts if a.kind is ArtifactKind.LINK]
        assert arts[0].content == VLESS  # untouched base only

    def test_multiple_entries_emit_in_priority_order(self, engine):
        entries = [HostEntry(remark="a-first", address="a.example.com"),
                   HostEntry(remark="b-second", address="b.example.com")]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        names = [up.unquote(up.urlparse(a.content).fragment)
                 for a in out.sections[0].artifacts if a.kind is ArtifactKind.LINK]
        assert names == ["a-first", "b-second"]

    def test_trojan_reality_preserved_on_emit(self, engine):
        entries = [HostEntry(address="tj2.example.com")]
        out = engine.expand(_link_profile(TROJAN_REALITY, protocol="trojan"),
                            {"in-a": entries}, _vars())
        q = _q(out.sections[0].artifacts[0].content)
        assert q["security"] == "reality" and q["pbk"] == "PK" and q["sid"] == "AB"
        assert up.urlparse(out.sections[0].artifacts[0].content).hostname == \
            "tj2.example.com"

    def test_vmess_b64_roundtrip(self, engine):
        doc = {"v": "2", "ps": "base", "add": "vm.example.com", "port": "443",
               "id": "u-u-i-d", "aid": "0", "scy": "auto", "net": "ws",
               "type": "none", "host": "cdn.example.com", "path": "/w",
               "tls": "tls", "sni": "vm.example.com", "alpn": "", "fp": ""}
        link = "vmess://" + base64.b64encode(json.dumps(doc).encode()).decode()
        entries = [HostEntry(remark="VM DC", address="vm2.example.com",
                             sni="sni2.example.com")]
        out = engine.expand(_link_profile(link, protocol="vmess"),
                            {"in-a": entries}, _vars())
        payload = json.loads(base64.b64decode(
            out.sections[0].artifacts[0].content.split("vmess://", 1)[1]).decode())
        assert payload["add"] == "vm2.example.com"
        assert payload["sni"] == "sni2.example.com"
        assert payload["ps"] == "VM DC"

    def test_ss_roundtrip(self, engine):
        cred = base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
        link = f"ss://{cred}@ss.example.com:8388#_base"
        entries = [HostEntry(remark="SS DC", address="ss2.example.com", port=8389)]
        out = engine.expand(_link_profile(link, protocol="shadowsocks"),
                            {"in-a": entries}, _vars())
        url = up.urlparse(out.sections[0].artifacts[0].content)
        assert url.hostname == "ss2.example.com" and url.port == 8389
        assert up.unquote(url.fragment) == "SS DC"

    def test_hysteria2_inapplicable_fields_get_note(self, engine):
        link = "hy2://pw@h2.example.com:443?sni=h2.example.com#_base"
        entries = [HostEntry(remark="H2", address="h2b.example.com",
                             security="none", host="nope.example.com")]
        out = engine.expand(_link_profile(link, protocol="hysteria2"),
                            {"in-a": entries}, _vars())
        notes = [a for a in out.sections[0].artifacts if a.kind is ArtifactKind.NOTE]
        assert notes, "expected an honesty note"
        text = notes[0].note or ""
        assert "security=none" in text and "host header" in text
        links = [a for a in out.sections[0].artifacts if a.kind is ArtifactKind.LINK]
        assert up.urlparse(links[0].content).hostname == "h2b.example.com"

    def test_tuic_roundtrip(self, engine):
        link = ("tuic://uuid:pw@t.example.com:443?congestion_control=bbr"
                "&alpn=h3&sni=t.example.com#_base")
        entries = [HostEntry(remark="TUIC DC", address="t2.example.com",
                             sni="sni2.example.com")]
        out = engine.expand(_link_profile(link, protocol="tuic"),
                            {"in-a": entries}, _vars())
        q = _q(out.sections[0].artifacts[0].content)
        assert q["congestion_control"] == "bbr" and q["sni"] == "sni2.example.com"

    def test_unparseable_link_kept_with_note(self, engine):
        profile = _link_profile("vless://broken-no-port")
        out = engine.expand(profile, {"in-a": [HostEntry(address="a.b")]}, _vars())
        kinds = [a.kind for a in out.sections[0].artifacts]
        assert ArtifactKind.NOTE in kinds and ArtifactKind.LINK in kinds

    def test_no_entries_passes_profile_through(self, engine):
        profile = _link_profile(VLESS)
        assert engine.expand(profile, {}, _vars()) is profile
        assert engine.expand(profile, {"other-tag": [HostEntry(address="a.b")]},
                             _vars()).sections[0].artifacts[0].content == VLESS

    def test_reality_only_on_vless(self, engine):
        entries = [HostEntry(address="a.example.com", security="reality")]
        out = engine.expand(_link_profile(TROJAN_REALITY, protocol="trojan"),
                            {"in-a": entries}, _vars())
        notes = [a for a in out.sections[0].artifacts if a.kind is ArtifactKind.NOTE]
        assert any("REALITY" in (n.note or "") for n in notes)


# --------------------------------------------------------------------- #
# item-13 field set: fragment / noise / mux / alpn / use_sni_as_host
# --------------------------------------------------------------------- #

class TestItem13FieldSet:
    def test_fragment_and_noise_emitted_on_tls(self, engine):
        entries = [HostEntry(remark="F", address="f.example.com",
                             fragment_setting="10-20,10-20,tlshello",
                             noise_setting="quic:80-90")]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        q = _q(out.sections[0].artifacts[0].content)
        assert q["fragment"] == "10-20,10-20,tlshello"
        assert q["noise"] == "quic:80-90"

    def test_fragment_dropped_with_honest_note_on_none_security(self, engine):
        link = ("vless://u@plain.example.com:80?type=tcp&security=none#_base")
        entries = [HostEntry(address="f.example.com",
                             fragment_setting="10-20,10-20,tlshello")]
        out = engine.expand(_link_profile(link), {"in-a": entries}, _vars())
        q = _q(out.sections[0].artifacts[0].content)
        assert "fragment" not in q
        notes = [a for a in out.sections[0].artifacts if a.kind is ArtifactKind.NOTE]
        assert any("fragment" in (n.note or "") for n in notes)

    def test_fragment_roundtrip_parse_preserves_hint(self):
        from app.utils.shareurl import parse_share_url
        link = ("vless://u@a.example.com:443?type=tcp&security=tls&sni=a"
                "&fragment=1-3%2C1-3%2Ctlshello#_x")
        parsed = parse_share_url(link)
        assert parsed.settings.get("fragment") == "1-3,1-3,tlshello"

    def test_mux_emitted_on_vless_only(self, engine):
        entries = [HostEntry(address="m.example.com", mux_enable=True)]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        q = _q(out.sections[0].artifacts[0].content)
        assert json.loads(q["xmux"])["enabled"] is True
        # ss: mux note instead
        cred = base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
        ss = f"ss://{cred}@ss.example.com:8388#_b"
        out2 = engine.expand(
            _link_profile(ss, protocol="shadowsocks"),
            {"in-a": [HostEntry(address="m.example.com", mux_enable=True)]}, _vars())
        assert any(a.kind is ArtifactKind.NOTE and "mux" in (a.note or "")
                   for a in out2.sections[0].artifacts)

    def test_use_sni_as_host_reuses_effective_sni(self, engine):
        entries = [HostEntry(address="u.example.com", sni="sni-new.example.com",
                             use_sni_as_host=True)]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        q = _q(out.sections[0].artifacts[0].content)
        assert q["host"] == "sni-new.example.com"

    def test_alpn_comma_list_is_not_random_picked(self, engine):
        entries = [HostEntry(address="a.example.com", alpn="h2,http/1.1")]
        for _ in range(10):
            out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
            assert _q(out.sections[0].artifacts[0].content)["alpn"] == "h2,http/1.1"

    def test_random_user_agent_is_honestly_noted(self, engine):
        entries = [HostEntry(address="a.example.com", random_user_agent=True)]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        assert any(a.kind is ArtifactKind.NOTE and "user-agent" in (a.note or "")
                   for a in out.sections[0].artifacts)

    def test_security_none_purges_tls_hygiene_params(self, engine):
        entries = [HostEntry(address="n.example.com", security="none")]
        out = engine.expand(_link_profile(VLESS), {"in-a": entries}, _vars())
        q = _q(out.sections[0].artifacts[0].content)
        assert q["security"] == "none" and "sni" not in q and "fragment" not in q


# --------------------------------------------------------------------- #
# tag matching + file/fields artifacts
# --------------------------------------------------------------------- #

class TestTagMatching:
    def test_single_tag_map_expands_tagless_section(self, engine):
        profile = _link_profile(VLESS, tag=None)
        out = engine.expand(profile, {"in-a": [HostEntry(address="dc.example.com")]},
                            _vars())
        assert up.urlparse(out.sections[0].artifacts[0].content).hostname == \
            "dc.example.com"

    def test_multi_tag_map_does_not_guess(self, engine):
        profile = _link_profile(VLESS, tag=None)
        out = engine.expand(profile, {
            "in-a": [HostEntry(address="a.example.com")],
            "in-b": [HostEntry(address="b.example.com")]}, _vars())
        assert out.sections[0].artifacts[0].content == VLESS

    def test_wireguard_endpoint_cloned_per_entry(self, engine):
        wg_file = ("[Interface]\nPrivateKey = K\nAddress = 10.0.0.2/32\n\n"
                   "[Peer]\nPublicKey = P\nEndpoint = wg.example.com:51820\n")
        profile = DeliveryProfile(core_id="wireguard", sections=[
            DeliverySection(protocol="wireguard", title="WG", engine="wireguard",
                            inbound_tag="wireguard",
                            artifacts=[DeliveryArtifact(
                                kind=ArtifactKind.FILE, label="wireguard.conf",
                                content=wg_file, filename="wireguard.conf")])])
        entries = [HostEntry(remark="DC1", address="wg1.example.com"),
                   HostEntry(remark="DC2", address="wg2.example.com", port=51830)]
        out = engine.expand(profile, {"wireguard": entries}, _vars())
        files = [a for a in out.sections[0].artifacts if a.kind is ArtifactKind.FILE]
        assert len(files) == 2
        assert "Endpoint = wg1.example.com:51820" in files[0].content
        assert "Endpoint = wg2.example.com:51830" in files[1].content
        assert files[0].filename.endswith(".conf") and "DC1" in files[0].filename

    def test_multi_wireguard_inbounds_keep_unique_download_filenames(self, engine):
        def section(tag: str, port: int) -> DeliverySection:
            content = (
                "[Interface]\nPrivateKey = K\nAddress = 10.0.0.2/32\n\n"
                f"[Peer]\nPublicKey = P\nEndpoint = wg.example.com:{port}\n"
            )
            return DeliverySection(
                protocol="wireguard", title=tag, engine="wireguard",
                inbound_tag=tag, artifacts=[DeliveryArtifact(
                    kind=ArtifactKind.FILE, label="WireGuard configuration",
                    content=content, filename=f"alice-{tag}.conf")])

        profile = DeliveryProfile(core_id="wireguard", sections=[
            section("wg-a", 51820), section("wg-b", 51821)])
        entries = {
            "wg-a": [HostEntry(remark=DEFAULT_REMARK, address="a.example.com")],
            "wg-b": [HostEntry(remark=DEFAULT_REMARK, address="b.example.com")],
        }
        out = engine.expand(profile, entries, _vars())
        files = [next(a for a in section.artifacts if a.kind is ArtifactKind.FILE)
                 for section in out.sections]
        assert len({artifact.filename for artifact in files}) == 2
        assert "wg-a" in files[0].filename and "wg-b" in files[1].filename
        assert "Endpoint = a.example.com:51820" in files[0].content
        assert "Endpoint = b.example.com:51821" in files[1].content

    def test_file_entry_without_address_or_port_produces_nothing(self, engine):
        profile = DeliveryProfile(core_id="wireguard", sections=[
            DeliverySection(protocol="wireguard", title="WG", engine="wg",
                            inbound_tag="wireguard",
                            artifacts=[DeliveryArtifact(
                                kind=ArtifactKind.FILE, label="c",
                                content="Endpoint = a.b:1\n", filename="w.conf")])])
        out = engine.expand(profile,
                            {"wireguard": [HostEntry(remark="meta-only",
                                                     sni="x.example.com")]},
                            _vars())
        assert [a for a in out.sections[0].artifacts
                if a.kind is ArtifactKind.FILE] == []

    def test_openvpn_remote_line(self, engine):
        ovpn = "client\ndev tun\nremote ovpn.example.com 1194 udp\n<ca>\nX\n</ca>\n"
        profile = DeliveryProfile(core_id="openvpn", sections=[
            DeliverySection(protocol="openvpn", title="OV", engine="openvpn",
                            inbound_tag="openvpn-tcp",
                            artifacts=[DeliveryArtifact(
                                kind=ArtifactKind.FILE, label="c.ovpn",
                                content=ovpn, filename="c.ovpn",
                                mime="application/x-openvpn-profile")])])
        out = engine.expand(profile,
                            {"openvpn-tcp": [HostEntry(remark="DC9",
                                                       address="ovpn2.example.com",
                                                       port=1294)]}, _vars())
        files = [a for a in out.sections[0].artifacts if a.kind is ArtifactKind.FILE]
        assert "remote ovpn2.example.com 1294 udp" in files[0].content

    def test_fields_clone_overrides_host_and_port(self, engine):
        fields = [DeliveryField(key="host", label="Server", value="ssh.example.com"),
                  DeliveryField(key="port", label="Port", value="22"),
                  DeliveryField(key="username", label="User", value="zg")]
        profile = DeliveryProfile(core_id="ssh", sections=[
            DeliverySection(protocol="ssh", title="SSH", engine="ssh",
                            inbound_tag="ssh",
                            artifacts=[DeliveryArtifact(
                                kind=ArtifactKind.FIELDS, label="SSH", fields=fields)])])
        out = engine.expand(profile,
                            {"ssh": [HostEntry(remark="DC-SSH",
                                               address="ssh2.example.com",
                                               port=2222)]}, _vars())
        clones = [a for a in out.sections[0].artifacts
                  if a.kind is ArtifactKind.FIELDS and a.label == "DC-SSH"]
        assert len(clones) == 1
        values = {f.key: f.value for f in clones[0].fields}
        assert values == {"host": "ssh2.example.com", "port": "2222",
                          "username": "zg"}
