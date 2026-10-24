"""f-policyfirst-1 — an admin Routing rule must beat bandwidth accounting.

Both engines are first-match-wins. The per-user bandwidth identities
(``zg-bw-u<id>`` in sing-box, ``zg-bw-u<id>`` freedom+SO_MARK in xray) used to
be emitted BEFORE the panel-managed policy rules, so every authenticated user
was matched by their own accounting rule and the deployed inbound → outbound
routing was silently ignored for real traffic. This is the "routing only works
sometimes / only for some users" symptom: anonymous test probes obeyed the
policy, signed-in clients did not.

Verbatim VPS reproduction (before the fix, sing-box route.rules)::

    {"auth_user": ["2.zzroute_d73e.vmess"], "action": "route", "outbound": "zg-bw-u2"}
    ...
    {"inbound": ["vmess-22443"], "action": "route", "outbound": "sub-ss"}

The vmess inbound still reported the host's own exit IP (104.253.175.201)
instead of the outbound's (13.140.88.56).
"""
from __future__ import annotations

import json

from app.cores.drivers.singbox.driver import SingBoxDriver
from app.cores.types import UserAccount


class _Backend:
    def logs(self, tail=200): return []
    def clash_connections(self): return []
    def close_connections_from(self, ip): return 0
    def probe_v2ray_support(self): return False


class _Stats:
    def query_user_counters(self): return {}


def _driver() -> SingBoxDriver:
    driver = SingBoxDriver(backend=_Backend(), stats=_Stats())
    driver._accounts["2.alice.vmess"] = UserAccount(
        user_id=2, username="alice", account_id="2.alice.vmess",
        protocol="vmess", settings={"id": "3f1b0e1c-0000-4000-8000-000000000001"},
    )
    driver._native_rules = [
        {"inbound": ["vmess-22443"], "action": "route", "outbound": "sub-ss"},
    ]
    return driver


def test_policy_rules_precede_bandwidth_accounting_rules():
    config = _driver().render_config()
    rules = config["route"]["rules"]

    policy = next(r for r in rules if r.get("inbound") == ["vmess-22443"])
    accounting = next(r for r in rules if r.get("auth_user"))

    assert rules.index(policy) < rules.index(accounting), (
        "sing-box stops at the first matching rule: accounting rules ahead of "
        "the policy rules make every authenticated user bypass routing"
    )


def test_dns_hijack_still_comes_first_and_remote_dns_survives():
    config = _driver().render_config()
    rules = config["route"]["rules"]
    assert rules[0] == {"protocol": "dns", "action": "hijack-dns"}


def test_bandwidth_identity_survives_as_final_fallback():
    """Accounting is kept, just last: traffic no policy rule claims is still
    attributed to the right user by the shared kernel limiter."""
    config = _driver().render_config()
    rules = config["route"]["rules"]
    tags = {ob.get("tag") for ob in config["outbounds"]}
    assert "zg-bw-u2" in tags
    accounting = [r for r in rules if r.get("auth_user")]
    assert accounting and accounting[-1]["outbound"] == "zg-bw-u2"
    assert rules[-1] in accounting, "accounting rules must be the last tier"


class _Row:
    def __init__(self, user_id, username, type_, settings):
        self.id = user_id
        self.username = username
        self.type = type_
        self.settings = settings
        self.excluded_inbound_tags = None


class _Query:
    """Minimal stand-in for the SQLAlchemy chain include_db_users builds."""

    def __init__(self, rows):
        self._rows = rows

    def join(self, *a, **k): return self
    def outerjoin(self, *a, **k): return self
    def filter(self, *a, **k): return self
    def group_by(self, *a, **k): return self
    def all(self): return list(self._rows)


class _Session:
    def __init__(self, rows):
        self._rows = rows

    def get_bind(self): return None
    def query(self, *a, **k): return _Query(self._rows)
    def __enter__(self): return self
    def __exit__(self, *exc): return False


def test_xray_bandwidth_rules_trail_policy_rules(tmp_path, monkeypatch):
    """Same precedence contract on the xray side."""
    monkeypatch.setenv("ZAGROS_XRAY_MANAGED_STATE", str(tmp_path / "managed.json"))
    import sys

    from app.xray import managed
    from app.xray.config import XRayConfig

    # ``app.xray.config`` the *package attribute* is the live XRayConfig
    # singleton, not the module; grab the real module from sys.modules.
    xray_config = sys.modules["app.xray.config"]

    rows = [_Row(7, "alice", "vmess",
                 json.dumps({"id": "3f1b0e1c-0000-4000-8000-000000000001"}))]
    # Proxy.settings is a JSON column: the ORM hands back a dict.
    rows[0].settings = {"id": "3f1b0e1c-0000-4000-8000-000000000001"}
    monkeypatch.setattr(xray_config, "GetDB", lambda: _Session(rows))

    policy = {"type": "field", "inboundTag": ["vmess-21443"],
              "outboundTag": "sub-ss"}
    managed.save(rules=[policy])
    base = {
        "inbounds": [{"tag": "vmess-21443", "port": 21443,
                      "protocol": "vmess",
                      "settings": {"clients": []}}],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}],
        "routing": {"rules": []},
    }
    rebuilt = XRayConfig(base).include_db_users()
    rules = rebuilt["routing"]["rules"]

    policy_index = rules.index(policy)
    user_rules = [i for i, r in enumerate(rules) if r.get("user")]
    assert user_rules, "bandwidth identity rules disappeared"
    assert policy_index < min(user_rules), (
        "xray is first-match-wins: per-user bandwidth rules ahead of the "
        "policy rule send every real user to the freedom+SO_MARK outbound"
    )
    # the API control-plane rule still precedes everything the panel manages
    api = [i for i, r in enumerate(rules)
           if "API_INBOUND" in (r.get("inboundTag") or [])]
    assert not api or max(api) < policy_index
