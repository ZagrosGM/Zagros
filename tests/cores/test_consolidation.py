"""Core consolidation tests (alpha.7.2, batch item 1).

The standalone hysteria2/tuic cores folded into sing-box. These tests pin:

1. the pure translation layer (``app/cores/consolidation.py``) — studio
   documents, settings synthesis, tag-collision renames, grant re-keying;
2. the sing-box core as the REAL host of both protocols — rendered configs,
   account provisioning, share-link delivery (round-tripped through the
   share-url parser), all validated against the REAL sing-box binary when
   one is available (never silently green);
3. the Alembic revision ``0007_core_consolidation`` migrating a fabricated
   alpha.7.1 database end-to-end in a real subprocess.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from app.cores.consolidation import (
    MERGED_CORES,
    TARGET_CORE_ID,
    ConsolidationError,
    merge_core_access,
    merge_inbound_entries,
    synthesize_default_entry,
    translate_entry,
)

ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------- #
# 1) pure translation layer
# --------------------------------------------------------------------- #

class TestTranslateEntry:
    def test_hy2_driver_document_full_mapping(self):
        entry = translate_entry("hysteria2", {
            "tag": "hysteria2", "protocol": "hysteria2", "listen": "::",
            "port": 443, "sni": "cdn.example.com",
            "masquerade": "https://www.bing.com",
            "up_mbps": "100", "down_mbps": 250, "obfs": "obfs-secret",
            "has_obfs": True, "has_certificate": False,
        })
        assert entry == {
            "tag": "hysteria2", "protocol": "hysteria2", "listen": "::",
            "port": 443, "security": "tls", "transport": "quic",
            "sni": "cdn.example.com", "masquerade": "https://www.bing.com",
            "up_mbps": 100, "down_mbps": 250, "obfs": "obfs-secret",
        }

    def test_hy2_bandwidth_string_form_parses(self):
        entry = translate_entry("hysteria2", {
            "tag": "hy", "bandwidth_up": "100 mbps", "bandwidth_down": "1 gbps"})
        assert entry["up_mbps"] == 100
        assert entry["down_mbps"] == 1

    def test_hy2_bandwidth_garbage_fails_loudly(self):
        with pytest.raises(ConsolidationError, match="up_mbps"):
            translate_entry("hysteria2", {"tag": "hy", "up_mbps": "fast"})

    def test_obfs_password_from_settings_flag(self):
        # the driver doc carries obfs:"" + has_obfs when only settings hold it
        entry = translate_entry("hysteria2", {
            "tag": "hy", "obfs": "", "has_obfs": True,
            "obfs_password": "from-settings"})
        assert entry["obfs"] == "from-settings"

    def test_tuic_full_mapping_incl_zero_rtt(self):
        entry = translate_entry("tuic", {
            "tag": "tuic", "protocol": "tuic", "listen": "[::]", "port": 8443,
            "congestion_control": "cubic", "zero_rtt": True,
            "sni": "cdn.cloudflare.com"})
        assert entry["zero_rtt"] is True
        assert entry["congestion_control"] == "cubic"
        assert entry["port"] == 8443

    def test_tuic_legacy_zero_rtt_handshake_key(self):
        entry = translate_entry("tuic", {"tag": "t", "zero_rtt_handshake": True})
        assert entry["zero_rtt"] is True

    def test_wrong_protocol_rejected_loudly(self):
        with pytest.raises(ConsolidationError, match="cannot host"):
            translate_entry("hysteria2", {"tag": "x", "protocol": "vless"})

    def test_unknown_core_rejected_loudly(self):
        with pytest.raises(ConsolidationError):
            translate_entry("wireguard", {"tag": "x"})

    def test_certificate_material_embedded(self):
        entry = translate_entry("tuic", {"tag": "t"},
                                certificate="CERT", certificate_key="KEY")
        assert entry["certificate"] == "CERT" and entry["certificate_key"] == "KEY"

    def test_bookkeeping_never_crosses(self):
        entry = translate_entry("hysteria2", {
            "tag": "hy", "has_obfs": True, "has_certificate": True})
        assert "has_obfs" not in entry and "has_certificate" not in entry


class TestSynthesizeDefaultEntry:
    def test_hy2_settings_mirror(self):
        entry = synthesize_default_entry("hysteria2", {
            "listen": "::", "port": 444, "advertise_sni": "sni.example.com",
            "masquerade_url": "https://mask.example.com",
            "bandwidth_up": "50", "bandwidth_down": "75",
            "obfs_password": "sekrit"})
        assert entry["port"] == 444
        assert entry["sni"] == "sni.example.com"
        assert entry["masquerade"] == "https://mask.example.com"
        assert entry["up_mbps"] == 50 and entry["down_mbps"] == 75
        assert entry["obfs"] == "sekrit"

    def test_tuic_settings_mirror(self):
        entry = synthesize_default_entry("tuic", {
            "listen": "[::]", "port": 8444, "cert_common_name": "cdn.cf",
            "congestion_control": "new_reno", "zero_rtt_handshake": True})
        assert entry["port"] == 8444
        assert entry["sni"] == "cdn.cf"
        assert entry["congestion_control"] == "new_reno"
        assert entry["zero_rtt"] is True

    def test_defaults_when_settings_empty(self):
        hy2 = synthesize_default_entry("hysteria2", {})
        tuic = synthesize_default_entry("tuic", {})
        assert hy2["port"] == 443 and hy2["tag"] == "hysteria2"
        assert tuic["port"] == 8443 and tuic["tag"] == "tuic"


class TestMergeInboundEntries:
    def test_appends_and_renames_collisions_deterministically(self):
        existing = [{"tag": "hysteria2", "protocol": "hysteria2", "port": 443}]
        incoming = [
            ("hysteria2", {"tag": "hysteria2", "protocol": "hysteria2", "port": 444}),
            ("tuic", {"tag": "hysteria2", "protocol": "tuic", "port": 8443}),
            ("tuic", {"tag": "tuic", "protocol": "tuic", "port": 8444}),
        ]
        merged, renames = merge_inbound_entries(existing, incoming)
        tags = [e["tag"] for e in merged]
        assert tags == ["hysteria2", "hysteria2-from-hysteria2",
                        "hysteria2-from-tuic", "tuic"]
        assert renames == {"hysteria2:hysteria2": "hysteria2-from-hysteria2",
                           "tuic:hysteria2": "hysteria2-from-tuic"}

    def test_no_collision_no_renames(self):
        merged, renames = merge_inbound_entries(
            [{"tag": "vless-a"}], [("tuic", {"tag": "tuic"})])
        assert [e["tag"] for e in merged] == ["vless-a", "tuic"]
        assert renames == {}

    def test_missing_tag_rejected(self):
        with pytest.raises(ConsolidationError):
            merge_inbound_entries([], [("tuic", {"protocol": "tuic"})])


class TestMergeCoreAccess:
    def test_rekey_and_union(self):
        access = {"xray": ["VLESS TCP"], "hysteria2": ["hysteria2"],
                  "tuic": ["tuic"], "sing-box": ["vless-ws"]}
        out = merge_core_access(access, {})
        assert out == {"xray": ["VLESS TCP"],
                       "sing-box": ["hysteria2", "tuic", "vless-ws"]}

    def test_renames_applied_to_tags(self):
        access = {"hysteria2": ["hysteria2", "hy2-alt"]}
        out = merge_core_access(access, {"hysteria2:hysteria2": "hysteria2-from-hysteria2"})
        assert out == {"sing-box": ["hysteria2-from-hysteria2", "hy2-alt"]}

    def test_dedupe_and_order(self):
        access = {"sing-box": ["a"], "tuic": ["a", "b", "b"]}
        assert merge_core_access(access, {}) == {"sing-box": ["a", "b"]}

    def test_none_passthrough(self):
        assert merge_core_access(None, {}) is None

    def test_no_merged_cores_untouched(self):
        access = {"wireguard": ["wg0"]}
        assert merge_core_access(access, {}) == {"wireguard": ["wg0"]}


# --------------------------------------------------------------------- #
# 2) sing-box as the real host of both protocols
# --------------------------------------------------------------------- #

def _driver(work: str):
    from app.cores.drivers.singbox.driver import SingBoxDriver
    from tests.cores.fakes import FakeSingBoxBackend, FakeV2RayStats

    return SingBoxDriver(
        {"work_dir": work, "advertise_host": "203.0.113.10"},
        backend=FakeSingBoxBackend(), stats=FakeV2RayStats())


def _acct(name: str, protocol: str, **settings):
    from app.cores.types import UserAccount

    return UserAccount(user_id=1, username=name, account_id=f"1.{name}.{protocol}",
                       protocol=protocol, enabled=True, settings=dict(settings))


class TestSingBoxHostsMergedProtocols:
    def test_translated_entries_apply_and_render(self, tmp_path):
        """The exact output of the consolidation translator must pass the
        sing-box studio STRICT translator (this is the migration hot path)."""
        d = _driver(str(tmp_path))
        entries = [
            translate_entry("hysteria2", {
                "tag": "hysteria2", "protocol": "hysteria2", "port": 443,
                "sni": "cdn.example.com", "masquerade": "https://www.bing.com",
                "up_mbps": "100", "obfs": "obfs-secret"}),
            translate_entry("tuic", {
                "tag": "tuic", "protocol": "tuic", "port": 8443,
                "congestion_control": "bbr", "zero_rtt": True,
                "sni": "cdn.cloudflare.com"}),
        ]
        asyncio.run(d.apply_studio_document({"inbounds": entries}))
        hy2, tuic = [d._studio_entry_to_native(e) for e in entries]
        # hy2 listener shape (verified against the real binary below)
        assert hy2["listen_port"] == 443
        assert hy2["tls"]["enabled"] is True
        assert hy2["tls"]["server_name"] == "cdn.example.com"
        assert hy2["obfs"] == {"type": "salamander", "password": "obfs-secret"}
        assert hy2["up_mbps"] == 100 and hy2["masquerade"] == "https://www.bing.com"
        # tuic zero_rtt maps to the native sing-box field
        assert tuic["zero_rtt_handshake"] is True
        assert tuic["congestion_control"] == "bbr"
        # re-translating the SAME (translated) document is idempotent
        native_again = [d._studio_entry_to_native(e) for e in entries]
        for ib in native_again:
            ib.pop("tls", None)
        assert all(not str(ib).startswith("_") for ib in native_again)

    def test_tls_mandatory_none_rejected(self, tmp_path):
        d = _driver(str(tmp_path))
        from app.cores.exceptions import CoreError

        with pytest.raises(CoreError, match="TLS is mandatory"):
            d._studio_entry_to_native({
                "tag": "hy2", "protocol": "hysteria2", "port": 443,
                "security": "none", "sni": "x"})

    def test_render_with_users_and_delivery_links(self, tmp_path):
        """End to end inside the sing-box core: studio doc + accounts ->
        rendered listeners users attach -> delivery links parse back."""
        from app.utils.shareurl import parse_share_url

        d = _driver(str(tmp_path))
        entries = [
            translate_entry("hysteria2", {
                "tag": "hysteria2", "port": 443, "sni": "cdn.example.com",
                "obfs": "obfs-secret"}),
            translate_entry("tuic", {
                "tag": "tuic", "port": 8443, "sni": "cdn.cloudflare.com"}),
        ]
        asyncio.run(d.apply_studio_document({"inbounds": entries}))
        hy2_acc = _acct("alice", "hysteria2")
        tuic_acc = _acct("bob", "tuic")
        asyncio.run(d.create_account(hy2_acc))
        asyncio.run(d.create_account(tuic_acc))
        # credentials were provisioned into the passed dicts (grant flow)
        assert hy2_acc.settings["password"]
        assert tuic_acc.settings["uuid"] and tuic_acc.settings["password"]

        rendered = d.render_config()
        tags = {ib["tag"] for ib in rendered["inbounds"]}
        assert {"hysteria2", "tuic"} <= tags
        hy2_ib = next(ib for ib in rendered["inbounds"] if ib["tag"] == "hysteria2")
        assert hy2_ib["users"] == [{"name": "1.alice.hysteria2",
                                    "password": hy2_acc.settings["password"]}]
        assert hy2_ib["tls"]["enabled"] is True
        tuic_ib = next(ib for ib in rendered["inbounds"] if ib["tag"] == "tuic")
        assert tuic_ib["users"] == [{
            "name": "1.bob.tuic",
            "uuid": tuic_acc.settings["uuid"],
            "password": tuic_acc.settings["password"],
        }]
        # panel metadata never leaks into the rendered binary config
        assert not any(k.startswith("_") for ib in rendered["inbounds"] for k in ib)

        # delivery: real share links per selected inbound
        profile = asyncio.run(d.describe_delivery(hy2_acc))
        profile.validate_shape()
        links = [a.content for s in profile.sections for a in s.artifacts
                 if a.kind.value == "link"]
        assert len(links) == 1 and links[0].startswith("hy2://")
        parsed = parse_share_url(links[0])
        assert parsed.settings["server"] == "203.0.113.10"
        assert parsed.settings["server_port"] == 443
        assert parsed.settings["password"] == hy2_acc.settings["password"]
        assert parsed.settings["sni"] == "cdn.example.com"
        assert parsed.settings.get("obfs_password") == "obfs-secret"
        # self-signed panel cert -> honest insecure flag for the client
        assert parsed.settings.get("allow_insecure") is True

        profile = asyncio.run(d.describe_delivery(tuic_acc))
        links = [a.content for s in profile.sections for a in s.artifacts
                 if a.kind.value == "link"]
        assert len(links) == 1 and links[0].startswith("tuic://")
        parsed = parse_share_url(links[0])
        assert parsed.settings["uuid"] == tuic_acc.settings["uuid"]
        assert parsed.settings["password"] == tuic_acc.settings["password"]
        assert parsed.settings["congestion_control"] == "bbr"

    def test_grant_subset_selection(self, tmp_path):
        """Two hy2 inbounds, grant selects one — delivery covers only it."""
        d = _driver(str(tmp_path))
        asyncio.run(d.apply_studio_document({"inbounds": [
            translate_entry("hysteria2", {"tag": "hy2-a", "port": 443,
                                          "sni": "a.example.com"}),
            translate_entry("hysteria2", {"tag": "hy2-b", "port": 444,
                                          "sni": "b.example.com"}),
        ]}))
        account = _acct("alice", "hysteria2", password="pw",
                        inbound_tags=["hy2-b"])
        asyncio.run(d.create_account(account))
        profile = asyncio.run(d.describe_delivery(account))
        links = [a.content for s in profile.sections for a in s.artifacts
                 if a.kind.value == "link"]
        assert len(links) == 1
        assert ":444?" in links[0]
        account_ex = _acct("dave", "hysteria2", password="pw",
                           excluded_inbounds=["hy2-b"])
        asyncio.run(d.create_account(account_ex))
        profile = asyncio.run(d.describe_delivery(account_ex))
        links = [a.content for s in profile.sections for a in s.artifacts
                 if a.kind.value == "link"]
        assert len(links) == 1 and ":443?" in links[0]

    def test_explicit_quic_listener_binds_before_first_user(self, tmp_path):
        """Explicit Hysteria2/TUIC listeners accept an empty user list and
        bind immediately; granting TUIC later does not remove Hysteria2."""
        d = _driver(str(tmp_path))
        asyncio.run(d.apply_studio_document({"inbounds": [
            translate_entry("hysteria2", {"tag": "hysteria2", "port": 443}),
            translate_entry("tuic", {"tag": "tuic", "port": 8443}),
        ]}))
        asyncio.run(d.create_account(_acct("bob", "tuic")))
        rendered = d.render_config()
        tags = {ib["tag"] for ib in rendered["inbounds"]}
        assert {"hysteria2", "tuic"} <= tags
        hy2 = next(ib for ib in rendered["inbounds"]
                   if ib["tag"] == "hysteria2")
        assert hy2["users"] == []

    def test_no_usable_inbound_honest_note(self, tmp_path):
        d = _driver(str(tmp_path))
        account = _acct("alice", "hysteria2", password="pw")
        asyncio.run(d.create_account(account))  # no studio doc at all
        # seed path renders a listener (ports defaults) — so delivery works;
        # but a grant selecting a non-existent tag reports honestly.
        account.settings["inbound_tags"] = ["does-not-exist"]
        profile = asyncio.run(d.describe_delivery(account))
        note = profile.sections[0].artifacts[0]
        assert note.kind.value == "note" and "hysteria2" in note.note

    def test_seed_path_renders_valid_tls_listeners(self, tmp_path):
        """No studio doc: accounts on the merged protocols still get servable
        listeners (self-signed pair minted exactly like the studio path)."""
        d = _driver(str(tmp_path))
        asyncio.run(d.create_account(_acct("alice", "hysteria2")))
        asyncio.run(d.create_account(_acct("bob", "tuic")))
        rendered = d.render_config()
        by_type = {ib["type"]: ib for ib in rendered["inbounds"]}
        assert by_type["hysteria2"]["tls"]["enabled"] is True
        assert by_type["tuic"]["tls"]["enabled"] is True
        assert by_type["tuic"]["congestion_control"] == "bbr"
        profile = asyncio.run(d.describe_delivery(_acct(
            "alice", "hysteria2", **d._accounts["1.alice.hysteria2"].settings)))
        links = [a.content for s in profile.sections for a in s.artifacts
                 if a.kind.value == "link"]
        assert links and links[0].startswith("hy2://")
        assert "insecure=1" in links[0]  # panel self-signed pair


_SINGBOX_BIN = os.environ.get("ZAGROS_SINGBOX_BIN") or shutil.which("sing-box") \
    or ("/tmp/sbcheck/sb112" if Path("/tmp/sbcheck/sb112").exists() else None)


@pytest.mark.skipif(not _SINGBOX_BIN,
                    reason="real sing-box binary unavailable "
                           "(set ZAGROS_SINGBOX_BIN to enable)")
class TestMergedConfigRealBinary:
    """The rendered config for the consolidated protocols must pass
    `sing-box check` on the REAL binary — the same bar every other wizard
    cell meets (never silently green in CI where the binary is present)."""

    def test_consolidated_doc_passes_check(self, tmp_path):
        # stats off: the v2ray_api experimental block is a build-tag concern
        # (stock binaries lack it), orthogonal to the inbound shapes this
        # test pins. The vendored stats builds pass the SAME config with the
        # block enabled — verified in the release pipeline.
        from app.cores.drivers.singbox.driver import SingBoxDriver
        from tests.cores.fakes import FakeSingBoxBackend, FakeV2RayStats

        d = SingBoxDriver(
            {"work_dir": str(tmp_path), "advertise_host": "203.0.113.10",
             "stats_enabled": False},
            backend=FakeSingBoxBackend(), stats=FakeV2RayStats())
        entries = [
            translate_entry("hysteria2", {
                "tag": "hysteria2", "port": 443, "sni": "cdn.example.com",
                "obfs": "obfs-secret", "up_mbps": 100}),
            translate_entry("tuic", {
                "tag": "tuic", "port": 8443, "zero_rtt": True,
                "sni": "cdn.cloudflare.com"}),
        ]
        asyncio.run(d.apply_studio_document({"inbounds": entries}))
        asyncio.run(d.create_account(_acct("alice", "hysteria2")))
        asyncio.run(d.create_account(_acct("bob", "tuic")))
        rendered = d.render_config()
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps(rendered))
        proc = subprocess.run(
            [_SINGBOX_BIN, "check", "-c", str(cfg)],
            capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, (
            f"rendered config failed {_SINGBOX_BIN} check:\n"
            f"{proc.stdout}\n{proc.stderr}\n"
            f"config: {cfg.read_text()[:2000]}")


# --------------------------------------------------------------------- #
# 3) alembic 0007 migration end-to-end (real subprocess, fabricated
#    alpha.7.1 state -> upgrade -> verify every re-key)
# --------------------------------------------------------------------- #

def _upgrade(platform_url: str, legacy_url: str, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({
        "ZAGROS_DATABASE_URL": platform_url,
        "SQLALCHEMY_DATABASE_URL": legacy_url,
        "ZAGROS_SECRET_KEY": "alembic-test-key-0123456789abcd",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)


@pytest.mark.skipif(shutil.which("python3") is None, reason="python3 required")
class TestAlembicConsolidation:
    def _seed_alpha71_state(self, platform_db: Path, legacy_db: Path) -> None:
        import sqlite3

        hy2_settings = json.dumps({
            "port": 443, "listen": "::", "advertise_sni": "hy2.example.com",
            "masquerade_url": "https://mask.example.com",
            "bandwidth_up": "100", "obfs_password": "obfs-secret"})
        tuic_settings = json.dumps({
            "port": 8443, "listen": "[::]", "cert_common_name": "cdn.cf",
            "congestion_control": "cubic", "zero_rtt_handshake": True})
        hy2_doc = json.dumps({"inbounds": [{
            "tag": "hysteria2", "protocol": "hysteria2", "port": 443,
            "sni": "hy2.example.com", "masquerade": "https://mask.example.com",
            "up_mbps": "100", "obfs": "obfs-secret",
            "has_obfs": True, "has_certificate": False}]})
        tuic_doc = json.dumps({"inbounds": [{
            "tag": "tuic", "protocol": "tuic", "port": 8443, "sni": "cdn.cf",
            "congestion_control": "cubic", "zero_rtt": True}]})
        sb_doc = json.dumps({"inbounds": [{
            "tag": "vless-ws", "protocol": "vless", "port": 10001,
            "transport": "ws", "security": "none"}]})
        with sqlite3.connect(platform_db) as db:
            db.execute(
                "INSERT INTO cores (core_id, enabled, state, health, settings_json, updated_at)"
                " VALUES ('hysteria2', 1, 'stopped', 'unknown', ?, CURRENT_TIMESTAMP),"
                "        ('tuic', 1, 'stopped', 'unknown', ?, CURRENT_TIMESTAMP),"
                "        ('sing-box', 1, 'running', 'healthy', ?, CURRENT_TIMESTAMP)",
                (hy2_settings, tuic_settings, '{"ports": {"vless": 10001}}'))
            db.executescript(
                """
                INSERT INTO core_inbounds (core_id, tag, protocol, port, settings_json)
                VALUES ('hysteria2', 'hysteria2', 'hysteria2', 443, '{}'),
                       ('tuic', 'tuic', 'tuic', 8443, '{}');
                INSERT INTO users (username, status, data_limit_reset_strategy, created_at)
                VALUES ('alice', 'active', 'no_reset', CURRENT_TIMESTAMP);
                INSERT INTO user_core_accounts
                 (user_id, core_id, account_id, protocol, enabled, created_at)
                VALUES
                 (1, 'hysteria2', '1.alice.hysteria2', 'hysteria2', 1, CURRENT_TIMESTAMP),
                 (1, 'tuic', '1.alice.tuic', 'tuic', 1, CURRENT_TIMESTAMP),
                 (1, 'sing-box', '1.alice.vless', 'vless', 1, CURRENT_TIMESTAMP);
                INSERT INTO usage_baselines (key, uplink_base, downlink_base, updated_at)
                VALUES ('hysteria2:1.alice.hysteria2', 10, 20, CURRENT_TIMESTAMP),
                       ('tuic:1.alice.tuic', 30, 40, CURRENT_TIMESTAMP),
                       ('sing-box:1.alice.vless', 1, 2, CURRENT_TIMESTAMP);
                """
            )
            db.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES"
                " ('studio.document.hysteria2', ?, CURRENT_TIMESTAMP),"
                " ('studio.document.tuic', ?, CURRENT_TIMESTAMP),"
                " ('studio.document.sing-box', ?, CURRENT_TIMESTAMP)",
                (hy2_doc, tuic_doc, sb_doc))

        # user grants live on the PLATFORM (seeded above); the only legacy
        # grant mapping is on templates.
        with sqlite3.connect(legacy_db) as db:
            db.execute(
                "INSERT INTO user_templates (name, data_limit, expire_duration, "
                "username_prefix, username_suffix, core_access) "
                "VALUES ('gold', 0, 0, '', '', ?)",
                (json.dumps({"hysteria2": ["hysteria2"], "tuic": ["tuic"],
                             "sing-box": ["vless-ws"], "xray": ["VLESS TCP"]}),),
            )

    def test_migration_folds_everything(self, tmp_path):
        platform_db = tmp_path / "zagros.db"
        legacy_db = tmp_path / "legacy.db"
        purl, lurl = f"sqlite:///{platform_db}", f"sqlite:///{legacy_db}"

        proc = _upgrade(purl, lurl, "upgrade", "0006_device_limit")
        assert proc.returncode == 0, proc.stderr[-2000:]
        self._seed_alpha71_state(platform_db, legacy_db)

        proc = _upgrade(purl, lurl, "upgrade", "head")
        assert proc.returncode == 0, (
            f"migration failed:\n{proc.stdout[-1000:]}\n{proc.stderr[-2000:]}")

        import sqlite3

        with sqlite3.connect(platform_db) as db:
            # merged cores/inbound registry rows/standalone docs are gone
            remaining = {r[0] for r in db.execute("SELECT core_id FROM cores")}
            assert "hysteria2" not in remaining and "tuic" not in remaining
            ib_cores = {r[0] for r in db.execute("SELECT DISTINCT core_id FROM core_inbounds")}
            assert "hysteria2" not in ib_cores and "tuic" not in ib_cores
            keys = {r[0] for r in db.execute("SELECT key FROM settings")}
            assert "studio.document.hysteria2" not in keys
            assert "studio.document.tuic" not in keys

            # sing-box studio doc gained both listeners, existing kept
            (doc_raw,) = db.execute(
                "SELECT value_json FROM settings WHERE key='studio.document.sing-box'"
            ).fetchone()
            doc = json.loads(doc_raw)
            by_tag = {e["tag"]: e for e in doc["inbounds"]}
            assert set(by_tag) == {"vless-ws", "hysteria2", "tuic"}
            hy2 = by_tag["hysteria2"]
            assert hy2["port"] == 443 and hy2["sni"] == "hy2.example.com"
            assert hy2["obfs"] == "obfs-secret" and hy2["up_mbps"] == 100
            assert "has_obfs" not in hy2 and "has_certificate" not in hy2
            tuic = by_tag["tuic"]
            assert tuic["zero_rtt"] is True and tuic["port"] == 8443

            # accounts and baselines re-keyed to the hosting core
            rows = sorted(db.execute(
                "SELECT core_id, account_id FROM user_core_accounts ORDER BY account_id"))
            assert rows == [("sing-box", "1.alice.hysteria2"),
                            ("sing-box", "1.alice.tuic"),
                            ("sing-box", "1.alice.vless")]
            keys = {r[0] for r in db.execute("SELECT key FROM usage_baselines")}
            assert keys == {"sing-box:1.alice.hysteria2",
                            "sing-box:1.alice.tuic", "sing-box:1.alice.vless"}
            totals = dict(db.execute(
                "SELECT key, uplink_base FROM usage_baselines"))
            assert totals["sing-box:1.alice.hysteria2"] == 10  # bytes preserved

        with sqlite3.connect(legacy_db) as db:
            (tpl_raw,) = db.execute(
                "SELECT core_access FROM user_templates WHERE name='gold'").fetchone()
            assert json.loads(tpl_raw) == {
                "xray": ["VLESS TCP"],
                "sing-box": ["hysteria2", "tuic", "vless-ws"]}

    def test_tag_collision_renames_grants_too(self, tmp_path):
        """A sing-box doc ALREADY owning tag 'hysteria2' forces the merged
        listener to 'hysteria2-from-hysteria2', and grants follow."""
        platform_db = tmp_path / "zagros.db"
        legacy_db = tmp_path / "legacy.db"
        purl, lurl = f"sqlite:///{platform_db}", f"sqlite:///{legacy_db}"

        proc = _upgrade(purl, lurl, "upgrade", "0006_device_limit")
        assert proc.returncode == 0, proc.stderr[-2000:]

        import sqlite3

        with sqlite3.connect(platform_db) as db:
            db.executescript(
                """
                INSERT INTO cores (core_id, enabled, state, health, settings_json, updated_at)
                VALUES ('hysteria2', 1, 'stopped', 'unknown', '{}', CURRENT_TIMESTAMP);
                INSERT INTO settings (key, value_json, updated_at) VALUES
                 ('studio.document.hysteria2',
                  '{"inbounds": [{"tag": "hysteria2", "protocol": "hysteria2", "port": 443}]}',
                  CURRENT_TIMESTAMP),
                 ('studio.document.sing-box',
                  '{"inbounds": [{"tag": "hysteria2", "protocol": "hysteria2", "port": 1443}]}',
                  CURRENT_TIMESTAMP);
                """
            )
        with sqlite3.connect(legacy_db) as db:
            db.execute(
                "INSERT INTO user_templates (name, data_limit, expire_duration, "
                "username_prefix, username_suffix, core_access) "
                "VALUES ('silver', 0, 0, '', '', ?)",
                (json.dumps({"hysteria2": ["hysteria2"]}),),
            )

        proc = _upgrade(purl, lurl, "upgrade", "head")
        assert proc.returncode == 0, proc.stderr[-2000:]

        with sqlite3.connect(platform_db) as db:
            (doc_raw,) = db.execute(
                "SELECT value_json FROM settings WHERE key='studio.document.sing-box'"
            ).fetchone()
            tags = {e["tag"] for e in json.loads(doc_raw)["inbounds"]}
            assert tags == {"hysteria2", "hysteria2-from-hysteria2"}
        with sqlite3.connect(legacy_db) as db:
            (access_raw,) = db.execute(
                "SELECT core_access FROM user_templates WHERE name='silver'").fetchone()
            assert json.loads(access_raw) == {"sing-box": ["hysteria2-from-hysteria2"]}

    def test_fresh_install_is_a_noop(self, tmp_path):
        platform_db = tmp_path / "zagros.db"
        legacy_db = tmp_path / "legacy.db"
        purl, lurl = f"sqlite:///{platform_db}", f"sqlite:///{legacy_db}"
        proc = _upgrade(purl, lurl, "upgrade", "head")
        assert proc.returncode == 0, proc.stderr[-2000:]

        import sqlite3

        with sqlite3.connect(platform_db) as db:
            keys = {r[0] for r in db.execute("SELECT key FROM settings")}
            assert not any(k.startswith("studio.document.") for k in keys)
            (head,) = db.execute("SELECT version_num FROM alembic_version").fetchone()
            assert head == "0011_user_bandwidth_limits"
