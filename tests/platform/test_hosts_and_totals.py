"""Host Settings visibility (item 17), host field matrix (item 18),
default remark template (item 16) and per-core traffic totals (item 19).

Run: pytest tests/platform/test_hosts_and_totals.py -q
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.platform.inbounds import _service_inbounds, _studio_inbounds  # noqa: E402


# --------------------------------------------------------------------- #
# item 17 — sing-box must surface in Host Settings                        #
# --------------------------------------------------------------------- #

class _Store:
    def __init__(self, doc):
        self._doc = doc

    async def get_document(self, core_id):
        return self._doc


class _Manager:
    def __init__(self, driver):
        self._driver = driver

    def get(self, core_id):
        if self._driver is None:
            raise KeyError(core_id)
        return self._driver


NATIVE_SINGBOX_RENDER = {
    "inbounds": [
        {"type": "vless", "tag": "vless-reality-in", "listen": "0.0.0.0",
         "listen_port": 443, "users": [{"uuid": "u"}]},
        {"type": "hysteria2", "tag": "hysteria2-in", "listen_port": 8443,
         "users": [{"password": "p"}]},
    ]
}


def test_singbox_derives_catalog_from_live_render_without_studio_doc():
    """No persisted studio document → the catalog derives sing-box's
    EFFECTIVE inbounds from the driver render (native shape: type +
    listen_port). This is the item-17 regression path."""
    driver = SimpleNamespace(export_config_document=lambda: NATIVE_SINGBOX_RENDER)
    runtime = SimpleNamespace(studio_store=_Store(None),
                              core_manager=_Manager(driver))
    found = asyncio.run(_studio_inbounds(runtime, "sing-box"))
    assert [(i.tag, i.protocol, i.port) for i in found] == [
        ("vless-reality-in", "vless", 443),
        ("hysteria2-in", "hysteria2", 8443),
    ]


def test_persisted_studio_doc_wins_over_live_render():
    doc = {"inbounds": [{"tag": "sb-1", "protocol": "trojan", "port": 2053}]}
    driver = SimpleNamespace(export_config_document=lambda: NATIVE_SINGBOX_RENDER)
    runtime = SimpleNamespace(studio_store=_Store(doc),
                              core_manager=_Manager(driver))
    found = asyncio.run(_studio_inbounds(runtime, "sing-box"))
    assert [(i.tag, i.protocol) for i in found] == [("sb-1", "trojan")]


def test_service_cores_keep_their_static_fallback_unchanged():
    """Healthy-behavior guard: cores with static service entries (wireguard,
    ssh, openvpn, softether) must NOT switch to the export-render path —
    their established catalog surface stays."""
    driver = SimpleNamespace(export_config_document=lambda: NATIVE_SINGBOX_RENDER)
    runtime = SimpleNamespace(studio_store=_Store(None),
                              core_manager=_Manager(driver))
    assert asyncio.run(_studio_inbounds(runtime, "wireguard")) == []
    assert [(i.tag, i.protocol) for i in _service_inbounds("wireguard",
                                                           {"port": 51820})] == \
        [("wireguard", "wireguard")]


def test_fresh_singbox_without_accounts_is_honestly_empty():
    # the deliberate "clean start": zero users → zero rendered inbounds
    driver = SimpleNamespace(export_config_document=lambda: {"inbounds": []})
    runtime = SimpleNamespace(studio_store=_Store(None),
                              core_manager=_Manager(driver))
    assert asyncio.run(_studio_inbounds(runtime, "sing-box")) == []


def test_broken_driver_export_does_not_blank_the_catalog(monkeypatch):
    def _boom():
        raise RuntimeError("render exploded")
    driver = SimpleNamespace(export_config_document=_boom)
    runtime = SimpleNamespace(studio_store=_Store(None),
                              core_manager=_Manager(driver))
    assert asyncio.run(_studio_inbounds(runtime, "sing-box")) == []


# --------------------------------------------------------------------- #
# item 16 — default remark template carries NO server address             #
# --------------------------------------------------------------------- #

def test_default_remark_has_no_server_ip_suffix():
    from app.portal.hostengine import DEFAULT_REMARK

    assert "SERVER_IP" not in DEFAULT_REMARK
    assert "»" not in DEFAULT_REMARK
    assert "{USERNAME}" in DEFAULT_REMARK
    assert "{PROTOCOL}" in DEFAULT_REMARK and "{TRANSPORT}" in DEFAULT_REMARK


# --------------------------------------------------------------------- #
# item 18 — capability-shaped host field matrix                           #
# --------------------------------------------------------------------- #

def test_host_field_matrix_per_protocol():
    from app.portal.hostengine import host_field_matrix

    # non-link configs (files / fields blocks): endpoint semantics only —
    # a WireGuard row must never offer ALPN/Security/Fingerprint/TLS inputs
    for proto in ("wireguard", "openvpn", "ssh", "softether"):
        assert host_field_matrix(proto) == \
            ["remark", "address", "port", "is_disabled"], proto
    # TLS-capable links get the security surface, UDP QUIC links do NOT get
    # xray-style fragment/noise knobs
    hy2 = host_field_matrix("hysteria2", engine="sing-box")
    assert {"sni", "alpn", "fingerprint", "allowinsecure"} <= set(hy2)
    assert "fragment_setting" not in hy2 and "noise_setting" not in hy2
    assert "security" not in hy2  # hysteria2 is always-TLS, nothing to choose
    # shadowsocks links cannot express host/header/TLS overrides at all
    assert host_field_matrix("shadowsocks") == \
        ["remark", "address", "port", "is_disabled"]
    # the classic three keep the full TLS surface incl. fragment family
    vless = host_field_matrix("vless", engine="xray")
    assert {"security", "alpn", "fingerprint", "fragment_setting",
            "noise_setting", "mux_enable", "host", "path", "sni"} <= set(vless)


def test_engine_argument_is_accepted_for_all_catalog_protocols():
    from app.portal.hostengine import host_field_matrix

    for proto in ("vless", "trojan", "vmess", "shadowsocks", "hysteria2",
                  "tuic", "wireguard", "openvpn", "ssh", "l2tp", "sstp",
                  "pptp", "ovpn"):
        assert host_field_matrix(proto, engine="sing-box")
        assert host_field_matrix(proto, engine="singbox")
        assert host_field_matrix(proto, engine=None)


# --------------------------------------------------------------------- #
# item 19 — per-core totals: accounted traffic of THAT core only          #
# --------------------------------------------------------------------- #

class _OwnDB:
    """Minimal stand-in for app.db.GetDB (context-manager session)."""

    def __init__(self, session):
        self._session = session

    def __enter__(self):
        return self._session

    def __exit__(self, *exc):
        self._session.close()
        return False


def test_cores_traffic_totals_database_and_runtime(monkeypatch, tmp_path):
    """database+runtime pin for item 19:

    * xray total = sum of the ACTUAL accounted NodeUserUsage rows (its own
      stats pipeline), all users, all nodes, all hourly buckets;
    * every other core = exactly its usage-journal (up, down);
    * the user-quota path (users.used_traffic) is never mixed in.
    """
    from datetime import datetime

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models import NodeUserUsage, User
    from app.platform import admin_api

    engine = create_engine(f"sqlite:///{tmp_path}/legacy.db")
    NodeUserUsage.__table__.create(bind=engine)
    User.__table__.create(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        hour_a = datetime(2026, 8, 9, 10, 0, 0)
        hour_b = datetime(2026, 8, 9, 11, 0, 0)
        session.add_all([
            # master node (node_id NULL), spread across users + hours
            NodeUserUsage(created_at=hour_a, user_id=1, node_id=None,
                          used_traffic=500),
            NodeUserUsage(created_at=hour_b, user_id=1, node_id=None,
                          used_traffic=700),
            # a real ynode's own bucket (per-node attribution, counted once)
            NodeUserUsage(created_at=hour_a, user_id=2, node_id=5,
                          used_traffic=300),
        ])
        session.commit()
    finally:
        session.close()

    class _Journal:
        async def totals_by_core(self):
            return {"sing-box": (3 * 2**30, 2**30), "ssh": (0, 5 * 2**30)}

    runtime = SimpleNamespace(usage_journal=_Journal())
    monkeypatch.setattr("app.db.GetDB", lambda: _OwnDB(Session()))

    out = asyncio.run(admin_api.cores_traffic_totals(runtime))
    totals = out["totals"]
    # xray: exactly 500+700+300 from NodeUserUsage — nothing else
    assert totals["xray"] == {"uplink_bytes": 0, "downlink_bytes": 1500,
                              "total_bytes": 1500}
    # journal cores: exact (up, down) passthrough per core
    assert totals["sing-box"]["total_bytes"] == 3 * 2**30 + 2**30
    assert totals["ssh"] == {"uplink_bytes": 0, "downlink_bytes": 5 * 2**30,
                             "total_bytes": 5 * 2**30}
    # no cross-mixing: the user-quota table is untouched by the endpoint
    assert all(set(entry) == {"uplink_bytes", "downlink_bytes", "total_bytes"}
               for entry in totals.values())


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
