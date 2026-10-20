"""Usage coefficients (f-usagecoeff-1, installer FR).

Three sources multiply a raw traffic delta before it lands anywhere money-
or quota-shaped:

  * master      — settings ``usage_coefficient_master`` (default 1.0).
                  Applies ONLY to traffic served by the MASTER's own cores
                  (f-usagecoeff-2 decision, v1.1.3). Node-served traffic
                  already carries its server factor: every node row has its
                  own ``usage_coefficient`` applied in collect_node_usage —
                  multiplying node deltas by the master factor too made the
                  commit message a lie and priced node traffic twice when an
                  operator raised both. Nodes: raise the node's own
                  coefficient on the Nodes page.
  * per inbound — settings ``usage_coefficient_inbounds`` ({tag: factor}).
                  Location/protocol pricing independent of the server.
                  An account that maps to exactly one inbound uses that
                  tag's factor; multi-tag accounts use the MAX (documented,
                  operator-friendly); unmapped accounts use 1.0.
  * target split— settings ``usage_coefficient_quota`` /
                  ``usage_coefficient_billing`` (final multipliers, 1.0).
                  Quota = user data-limit deduction + legacy used_traffic.
                  Billing = admins.users_usage (reseller invoices).

effective_quota   = server × inbound × quota_multiplier
effective_billing = server × inbound × billing_multiplier

The usage JOURNAL always keeps the RAW bytes (statistics stay physical);
the applied factors are recorded with each daily rollup instead. Every
factor change goes through the audit log because it changes money.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

K_MASTER = "usage_coefficient_master"
K_QUOTA = "usage_coefficient_quota"
K_BILLING = "usage_coefficient_billing"
K_INBOUNDS = "usage_coefficient_inbounds"


def _posf(value, default: float = 1.0) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if f > 0 else default


@dataclass
class Coeffs:
    master: float = 1.0
    quota_mult: float = 1.0
    billing_mult: float = 1.0
    inbounds: dict[str, float] = field(default_factory=dict)

    def factors_for_tags(self, tags: list[str] | None,
                         *, with_master: bool = True) -> tuple[float, float]:
        """(quota_factor, billing_factor) for one usage record.

        ``with_master=False`` is the NODE path (f-usagecoeff-2): node deltas
        were already scaled by the node's own ``usage_coefficient`` in
        collect_node_usage, so the master server factor must not compound
        on top of them.
        """
        inbound = 1.0
        if tags:
            known = [self.inbounds[t] for t in tags if t in self.inbounds]
            if known:
                inbound = max(known)
        effective = (self.master if with_master else 1.0) * inbound
        return effective * self.quota_mult, effective * self.billing_mult


def load(runtime) -> Coeffs:
    """Read all coefficient sources once (call once per recorder tick)."""
    from app.platform import settings_kv

    sf = getattr(runtime, "session_factory", None)
    if sf is None:
        return Coeffs()
    inbounds_raw = settings_kv.load(sf, K_INBOUNDS, {}) or {}
    inbounds: dict[str, float] = {}
    if isinstance(inbounds_raw, dict):
        for tag, value in inbounds_raw.items():
            factor = _posf(value, 0.0)
            if factor > 0 and isinstance(tag, str) and tag.strip():
                inbounds[tag.strip()] = factor
    return Coeffs(
        master=_posf(settings_kv.load(sf, K_MASTER, 1.0)),
        quota_mult=_posf(settings_kv.load(sf, K_QUOTA, 1.0)),
        billing_mult=_posf(settings_kv.load(sf, K_BILLING, 1.0)),
        inbounds=inbounds,
    )
