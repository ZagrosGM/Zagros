"""Defaults for users created through the *Marzban-compatible* API.

Bots and shops written for Marzban (Mirza, Hidify-style resellers, custom
scripts) call ``POST /api/user`` with ``proxies``/``inbounds`` only — they have
never heard of Zagros' ``core_access``. Such a user used to receive the xray
core alone even on a panel that also runs sing-box, WireGuard, OpenVPN, SSH or
SoftEther; the operator then had to open every bot-created user and tick the
other cores by hand.

This module holds the panel-wide policy applied when a create request carries
NO ``core_access`` key at all (``None``). An explicit mapping — even an empty
one — always wins, so the dashboard and Zagros-aware clients are untouched.

Policy (``settings`` row ``api.user_defaults``)::

    {"core_access": "all" | "none" | {"<core_id>": ["tag", ...]}}

* ``"all"``   — grant every inbound of every enabled non-xray core (mirrors
                what the dashboard pre-selects on *Create user*). Default.
* ``"none"``  — legacy behaviour: xray only.
* mapping     — a fixed selection; tags that no longer exist are dropped
                with a warning instead of failing the bot's request.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

SETTINGS_KEY = "api.user_defaults"
DEFAULT_POLICY: dict[str, Any] = {"core_access": "all"}
LEGACY_CORE_ID = "xray"


def load_policy(session_factory) -> dict[str, Any]:
    from app.platform.settings_kv import load

    raw = load(session_factory, SETTINGS_KEY, None)
    if not isinstance(raw, dict):
        return dict(DEFAULT_POLICY)
    policy = dict(DEFAULT_POLICY)
    policy.update(raw)
    return policy


def save_policy(session_factory, policy: dict[str, Any]) -> dict[str, Any]:
    from app.platform.settings_kv import save

    return save(session_factory, SETTINGS_KEY, normalize_policy(policy))


def normalize_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Validate the stored shape; raises ``ValueError`` with a plain reason."""
    value = (policy or {}).get("core_access", "all")
    if isinstance(value, str):
        mode = value.strip().lower()
        if mode not in ("all", "none"):
            raise ValueError("core_access must be 'all', 'none' or {core_id: [tags]}")
        return {"core_access": mode}
    if isinstance(value, dict):
        out: dict[str, list[str]] = {}
        for core_id, tags in value.items():
            if not isinstance(core_id, str) or not core_id:
                raise ValueError("core_access keys must be core ids")
            if not isinstance(tags, (list, tuple)):
                raise ValueError(f"core_access['{core_id}'] must be a list of inbound tags")
            out[core_id] = [str(t) for t in tags]
        return {"core_access": out}
    raise ValueError("core_access must be 'all', 'none' or {core_id: [tags]}")


async def default_core_access(runtime) -> dict[str, list[str]] | None:
    """The grants an API-created user gets when the caller sent none.

    Returns ``None`` when the policy is ``none`` (or nothing is grantable) so
    the caller keeps the exact legacy path (``_bridge_sync(grants=None)``).
    """
    if runtime is None:
        return None
    policy = load_policy(runtime.session_factory)
    mode = policy.get("core_access", "all")
    try:
        # the same read model apply_grants() validates against, so a default
        # grant can never name an inbound provisioning would refuse
        from app.platform import provisioning

        groups = await provisioning.build_inbound_catalog(runtime)
    except Exception as exc:  # noqa: BLE001 - a bot's create must not 500 here
        logger.warning("default core_access skipped — catalog unavailable: %s", exc)
        return None
    live = {g.core_id: [i.tag for i in g.inbounds] for g in groups
            if g.core_id != LEGACY_CORE_ID and g.enabled and g.inbounds}

    if mode == "none":
        return None
    if mode == "all":
        return {core_id: list(tags) for core_id, tags in live.items()} or None

    fixed: dict[str, list[str]] = {}
    for core_id, tags in (mode or {}).items():
        known = live.get(core_id)
        if not known:
            logger.warning("default core_access: core '%s' is not available — skipped", core_id)
            continue
        kept = [t for t in tags if t in known] if tags else list(known)
        dropped = sorted(set(tags) - set(kept))
        if dropped:
            logger.warning("default core_access: core '%s' has no inbound(s) %s — dropped",
                           core_id, dropped)
        if kept:
            fixed[core_id] = kept
    return fixed or None
