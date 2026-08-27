# ruff: noqa: B008 — FastAPI idiom: Depends() in argument defaults is the
# canonical router pattern used across this codebase.
"""Zagros unified-dashboard admin API — the panel's own management surface.

Rule #1 of the frontend refactor: EVERYTHING the dashboard does goes through
real admin APIs on the running panel — no CLI dependency for daily
operations, no mock data, no hidden capability. This module extends
``/api/zagros`` (sudo-admin-guarded, same auth stack as the rest of the
platform) with the surfaces the unified dashboard needs:

* **cores** — full lifecycle (install/remove/update/enable/disable/
  start/stop/restart) + live status, registry catalog and log tails
  (`hostctl` keeps working; these endpoints expose the same CoreManager
  in-process, so panel-side transitions apply immediately).
* **routing** — persistent rule set (panel DB, KV-backed), dry **preview**
  (per-core coverage matrix, zero core mutations) and **deploy**.
* **outbounds** — persistent registry (KV-backed, reconciled into the
  OutboundManager), connectivity **test** (real TCP dial + latency), clone.
* **sessions / client-sessions / devices** — honest inventory from the
  platform stores (refresh-session revocation included).
* **certificates** — inventory/import/self-signed/delete (real crypto);
  ACME automation is roadmap-only and labeled as such.
* **panel info** — version, identity URLs, auth mode, uptime.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import shlex
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr

from app.cores.capabilities import outbound_capability, validate_selectable
from app.cores.exceptions import CoreError, CoreNotFoundError
from app.cores.outbounds.manager import OutboundManager
from app.cores.outbounds.model import (
    LEGACY_SOFTETHER_OUTBOUND_KINDS,
    Outbound,
    OutboundKind,
    PPP_CLIENT_KINDS,
)
from app.cores.outbounds.repository import (
    OutboundSecretCodec,
    OutboundWrite,
    is_secret_setting,
    split_settings,
)
from app.cores.routing.model import RoutingRule
from app.platform import certificates
from app.platform.routers import get_runtime, zagros_admin_router, zagros_router

_STARTED_MONO = time.monotonic()
_TEST_LOG = logging.getLogger("zagros.admin.outbound_test")

_RULES_KEY = "admin.routing.rules.v1"
_OUTBOUNDS_KEY = "admin.outbounds.v1"
_PANEL_NETWORK_KEY = "admin.panel.network.v1"
_PANEL_NETWORK_APPLIED_KEY = "admin.panel.network.applied.v1"
_PANEL_NETWORK_PENDING_KEY = "admin.panel.network.pending.v1"


# --------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------- #

_SECRETISH = ("secret", "password", "token", "private_key", "privatekey")


def _mask_settings(settings: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in (settings or {}).items():
        lowered = key.lower()
        if any(marker in lowered for marker in _SECRETISH) and "public" not in lowered:
            text = str(value) if value is not None else ""
            out[key] = f"set ({len(text)} chars)" if text else ""
        else:
            out[key] = value
    return out


class CoreInstallBody(BaseModel):
    settings: dict[str, Any] | None = None
    enabled: bool = True


class CoreUpdateBody(BaseModel):
    version: str | None = None


class CoreUninstallBody(BaseModel):
    purge: bool = False
    force: bool = False


class SoftEtherPolicyHubBody(BaseModel):
    """Credential-safe request for one isolated SoftEther routing source."""

    hub: str = Field(min_length=1, max_length=31, pattern=r"^[A-Za-z0-9_-]+$")
    inbound_tag: str = Field(min_length=1, max_length=128,
                             pattern=r"^[A-Za-z0-9_.:@-]+$")
    tap_device: str = Field(min_length=1, max_length=10,
                            pattern=r"^[A-Za-z0-9_.-]+$")
    subnet: str = Field(min_length=9, max_length=32)
    gateway: str = Field(min_length=7, max_length=15)
    username: str = Field(min_length=1, max_length=64,
                          pattern=r"^[A-Za-z0-9_.@-]+$")
    user_password: SecretStr = Field(min_length=12, max_length=128)


def _err(exc: Exception, status: int = 400) -> HTTPException:
    return HTTPException(status, str(exc))


# --------------------------------------------------------------------- #
# cores — full lifecycle, in-process (no CLI needed)
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/cores/registry")
async def cores_registry(runtime=Depends(get_runtime)):
    from app.cores.registry import available_drivers, get_driver_class

    installed = set(runtime.core_manager.list_cores())
    catalog = []
    for core_id in sorted(available_drivers()):
        cls = get_driver_class(core_id)
        meta = cls.metadata
        catalog.append({
            "id": meta.id,
            "name": meta.name,
            "description": meta.description,
            "protocols": meta.protocols,
            "capabilities": sorted(c.value for c in meta.capabilities),
            "provides": sorted(meta.provides),
            "requires": sorted(meta.requires),
            "studio_inbounds_path": meta.studio_inbounds_path,
            "config_schema": meta.config_schema,
            "default_settings": _mask_settings(meta.default_settings),
            "driver_version": meta.driver_version,
            "homepage": meta.homepage,
            "security_class": meta.security_class,
            "installed": core_id in installed,
        })
    return {"registry": catalog}


async def _core_view(runtime, core_id: str, status_by_id: dict) -> dict:
    from app.cores.manager import BUILTIN_CORE_IDS
    from app.cores.types import CoreState, HealthStatus

    manager = runtime.core_manager
    driver = manager.get(core_id)
    meta = driver.metadata
    stored = await runtime.core_state.load()
    stored_entry = stored.get(core_id, {}) if isinstance(stored, dict) else {}
    status = status_by_id.get(core_id)

    binary_path = None
    for attr in ("binary_path", "executable_path"):
        candidate = getattr(driver, attr, None)
        if callable(candidate):
            try:
                candidate = candidate()
            except Exception:  # noqa: BLE001
                candidate = None
        if isinstance(candidate, str) and candidate:
            binary_path = candidate
            break
    if binary_path is None:
        binary_path = driver.settings.get("executable_path") or driver.settings.get("binary_path")

    state = stored_entry.get("state")
    state_value = state.value if isinstance(state, CoreState) else state
    if status is not None:
        # The live probe is the ground truth for liveness (alpha.7.2 item 3):
        # * a live RUNNING probe ALWAYS wins over the persisted record — a
        #   recorded "error" from a start that died after the process came
        #   up must not paint the healthy core as Error;
        # * a stopped probe contradicts only states that CLAIM the core is
        #   up-ish (running/error/starting) — a freshly INSTALLED core is
        #   genuinely installed-not-stopped, so its record stands.
        # (The health monitor additionally reconciles the record itself.)
        live = status.state.value if isinstance(status.state, CoreState) else str(status.state)
        if live == CoreState.RUNNING.value:
            state_value = live
        elif state_value in (CoreState.RUNNING.value, CoreState.ERROR.value,
                             CoreState.STARTING.value) and live:
            state_value = live
    enabled = stored_entry.get("enabled", manager.is_enabled(core_id))
    view = {
        "id": meta.id,
        "name": meta.name,
        "description": meta.description,
        "protocols": meta.protocols,
        "capabilities": sorted(c.value for c in meta.capabilities),
        "provides": sorted(meta.provides),
        "requires": sorted(meta.requires),
        "driver_version": meta.driver_version,
        "security_class": meta.security_class,
        "studio_inbounds_path": meta.studio_inbounds_path,
        "config_schema": meta.config_schema,
        "state": state_value or "installed",
        "enabled": bool(enabled),
        "builtin": core_id in BUILTIN_CORE_IDS,
        "settings": _mask_settings(driver.settings),
        "binary_path": binary_path,
        "health": None,
        "core_version": None,
        "version_reason": "status/version probe unavailable",
        "message": None,
        "pid": None,
        "uptime_seconds": None,
        "metrics": None,
    }
    if status is not None:
        view.update({
            "health": status.health.value if isinstance(status.health, HealthStatus) else str(status.health),
            "core_version": status.core_version,
            "version_reason": status.version_reason,
            "message": status.message,
            "pid": status.pid,
            "uptime_seconds": status.uptime_seconds,
            "metrics": status.metrics.model_dump() if status.metrics else None,
        })
    return view


@zagros_admin_router.get("/cores")
async def cores_list(runtime=Depends(get_runtime)):
    manager = runtime.core_manager
    try:
        statuses = await asyncio.wait_for(manager.status_all(), timeout=12)
        status_by_id = {s.core_id: s for s in statuses}
    except Exception:  # noqa: BLE001 - probing must not break the listing
        status_by_id = {}
    cores = [await _core_view(runtime, cid, status_by_id) for cid in manager.list_cores()]
    return {"cores": cores}


@zagros_admin_router.get("/cores/capability-matrix")
async def cores_capability_matrix(runtime=Depends(get_runtime)):
    from app.cores.drivers.softether.capabilities import (
        softether_transport_capabilities,
    )
    from app.cores.matrix import FEATURES, capability_matrix, routing_pair_matrix
    from app.cores.drivers.pptp.capabilities import provider_capability

    installed = set(runtime.core_manager.list_cores())
    softether = await asyncio.to_thread(softether_transport_capabilities, runtime)
    return {"features": list(FEATURES),
            "installed": sorted(installed),
            "cores": capability_matrix(installed=installed),
            "all": capability_matrix(),
            "routing": routing_pair_matrix(installed=installed),
            "provider_capabilities": {
                "pptp": provider_capability(installed="pptp" in installed),
            },
            "softether_transports": softether}


@zagros_admin_router.get("/cores/traffic/totals")
async def cores_traffic_totals(runtime=Depends(get_runtime)):
    """Item 17 — REAL per-core traffic totals (user usage, NOT host NIC bytes).

    * non-xray cores → usage journal sums (exactly-once deltas);
    * xray → legacy NodeUserUsage rollup (its own stats pipeline).
    """
    from app.cores.manager import BUILTIN_CORE_IDS

    totals: dict[str, dict[str, int]] = {}
    try:
        journal = await runtime.usage_journal.totals_by_core()
    except Exception as exc:  # noqa: BLE001 — never break the page
        logger.warning("usage journal totals failed: %s", exc)
        journal = {}
    for core_id, (up, down) in journal.items():
        totals[core_id] = {"uplink_bytes": up, "downlink_bytes": down,
                           "total_bytes": up + down}

    if BUILTIN_CORE_IDS:
        def _legacy_xray_total() -> tuple[int, int] | None:
            try:
                from sqlalchemy import func, select

                from app.db import GetDB
                from app.db.models import NodeUserUsage

                with GetDB() as db:
                    up_down = db.execute(
                        select(
                            func.coalesce(func.sum(NodeUserUsage.used_traffic), 0),
                        )
                    ).one()
                    return 0, int(up_down[0] or 0)
            except Exception:  # noqa: BLE001 — legacy store optional
                return None
        xray_tot = await asyncio.to_thread(_legacy_xray_total)
        if xray_tot is not None:
            _up, down = xray_tot
            for cid in BUILTIN_CORE_IDS:
                totals[cid] = {"uplink_bytes": 0, "downlink_bytes": down,
                               "total_bytes": down}
    return {"totals": totals}


@zagros_admin_router.get("/bandwidth/status")
async def bandwidth_status(runtime=Depends(get_runtime)):
    status = runtime.bandwidth.status()
    status["tc_police"] = await asyncio.to_thread(runtime.bandwidth.tc_stats)
    return status


@zagros_admin_router.post("/bandwidth/reconcile")
async def bandwidth_reconcile(runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(runtime.bandwidth.reconcile)
    except Exception as exc:
        raise HTTPException(503, f"bandwidth limiter reconciliation failed: {exc}") from exc


@zagros_admin_router.get("/cores/{core_id}")
async def cores_detail(core_id: str, runtime=Depends(get_runtime)):
    try:
        driver = runtime.core_manager.get(core_id)
    except CoreNotFoundError as exc:
        raise HTTPException(404, f"core '{core_id}' is not installed or not managed") from exc
    try:
        status = await asyncio.wait_for(driver.status(), timeout=10)
    except Exception:  # noqa: BLE001
        status = None
    return await _core_view(runtime, core_id,
                            {core_id: status} if status else {})


@zagros_admin_router.get("/cores/softether/policy-hubs")
async def softether_policy_hubs(runtime=Depends(get_runtime)):
    """List only Zagros-managed isolated hub metadata; never credentials."""
    try:
        driver = runtime.core_manager.get("softether")
        specs = [spec for spec in driver.routing_source_specs()
                 if spec.get("managed_by_zagros") is True]
        live = set(await asyncio.to_thread(driver._backend.hub_list))  # noqa: SLF001
        active = {item["id"] for item in driver.policy_sources()}
    except Exception as exc:
        raise _err(exc) from exc
    return {"hubs": [{
        "hub": spec["hub"], "inbound_tag": spec["tags"][0],
        "tap_device": spec["tap_device"], "subnet": spec["subnet"],
        "gateway": spec["gateway"], "username": spec["username"],
        "live": spec["hub"] in live, "routed": spec["id"] in active,
    } for spec in specs]}


@zagros_admin_router.post("/cores/softether/policy-hubs")
async def softether_policy_hub_create(
    body: SoftEtherPolicyHubBody, runtime=Depends(get_runtime),
):
    """Create an independent Virtual Hub/user; response never echoes secrets."""
    try:
        created = await runtime.core_manager.create_softether_policy_hub(
            hub=body.hub, inbound_tag=body.inbound_tag,
            tap_device=body.tap_device, subnet=body.subnet,
            gateway=body.gateway, username=body.username,
            user_password=body.user_password.get_secret_value(),
        )
    except Exception as exc:
        raise _err(exc, 422) from exc
    return {"ok": True, "hub": created["hub"],
            "inbound_tag": created["inbound_tag"], "credential_stored": False}


@zagros_admin_router.delete("/cores/softether/policy-hubs/{hub}")
async def softether_policy_hub_delete(hub: str, runtime=Depends(get_runtime)):
    """Delete only a tracked managed hub after all routing references vanish."""
    try:
        driver = runtime.core_manager.get("softether")
        spec = next((item for item in driver.routing_source_specs()
                     if item.get("managed_by_zagros") is True
                     and item.get("hub") == hub), None)
        if spec is None:
            raise HTTPException(404, f"SoftEther hub '{hub}' is not Zagros-managed")
        tag = str(spec["tags"][0])
        rules = await _load_rules(runtime)
        references = [rule.name for rule in rules if tag in rule.matcher.inbounds]
        if references:
            raise HTTPException(
                409, f"remove routing rules that reference '{tag}' first: {references}")
        # Converge current persisted rules so the managed bridge/TAP is removed
        # before HubDelete.  This also atomically rewrites nft without the tag.
        runtime.policy_router.apply_rules(rules)
        await runtime.core_manager.delete_softether_policy_hub(hub)
    except HTTPException:
        raise
    except Exception as exc:
        raise _err(exc, 422) from exc
    return {"ok": True, "hub": hub, "deleted": True}


async def _manager_call(runtime, core_id: str, method: str, *args, **kwargs):
    manager = runtime.core_manager
    if core_id not in manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    fn = getattr(manager, method)
    try:
        return await fn(core_id, *args, **kwargs)
    except Exception as exc:
        raise _err(exc) from exc


@zagros_admin_router.get("/cores/{core_id}/install-progress")
async def cores_install_progress(core_id: str, runtime=Depends(get_runtime)):
    """Observable long-install stage (currently SoftEther's stable/source
    pipeline). Returns idle for drivers without a progress provider."""
    try:
        driver = runtime.core_manager.get(core_id)
    except CoreNotFoundError:
        return {"stage": "idle", "detail": "installation has not started"}
    backend = getattr(driver, "_backend", None)
    provider = getattr(backend, "install_progress", None)
    if not callable(provider):
        return {"stage": "working", "detail": "driver installation in progress"}
    return await asyncio.to_thread(provider)


@zagros_admin_router.post("/cores/{core_id}/install")
async def cores_install(core_id: str, body: CoreInstallBody, runtime=Depends(get_runtime)):
    from app.cores.registry import available_drivers

    if core_id not in available_drivers():
        raise HTTPException(404, f"unknown core '{core_id}' — see /cores/registry")
    try:
        from app.cores.registry import get_driver_class

        # Legacy/insecure providers are always installed disabled. Enabling is
        # a separate explicit operation after both backend-validated safety
        # acknowledgements and an inbound exist.
        security_class = get_driver_class(core_id).metadata.security_class
        enabled = False if security_class == "legacy_insecure" else body.enabled
        state = await runtime.core_manager.install_core(
            core_id, body.settings, enabled=enabled)
        if core_id != "xray":
            # Service cores already have their initial listener at install
            # time. Give each real inbound its own default Host entry once;
            # later studio create/delete calls keep the same lifecycle.
            from app.platform.inbounds import catalog as _catalog
            from app.portal.hostengine import reconcile_default_hosts

            group = next((g for g in await _catalog(runtime)
                          if g.core_id == core_id), None)
            if group is not None:
                await reconcile_default_hosts(
                    runtime.core_hosts, core_id, [item.tag for item in group.inbounds])
    except Exception as exc:
        raise _err(exc) from exc
    return {"ok": True, "core": core_id, "state": state.value, "enabled": enabled}


@zagros_admin_router.post("/cores/{core_id}/uninstall")
async def cores_uninstall(core_id: str, body: CoreUninstallBody,
                          runtime=Depends(get_runtime)):
    manager = runtime.core_manager
    if core_id not in manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    dependents = manager.dependents(core_id)
    if dependents and not body.force:
        return {"ok": False, "code": "HAS_DEPENDENTS",
                "dependents": dependents,
                "error": f"cores {dependents} depend on '{core_id}'; pass force=true"}
    try:
        states = await runtime.core_state.load()
        if states.get(core_id, {}).get("state") == "running":
            await manager.stop_core(core_id)  # in-process: we CAN stop it first
        await manager.uninstall_core(core_id, purge=body.purge, force=True)
        if body.purge:
            # Purge only this provider's desired-state artifacts. Historical
            # unrelated users/cores/rules are never touched.
            rows = await asyncio.to_thread(
                runtime.users.accounts_of_core, core_id, decrypt=False)
            for row in rows:
                await asyncio.to_thread(
                    runtime.users.delete_account,
                    user_id=int(row["user_id"]), core_id=core_id,
                    account_id=str(row["account_id"]),
                )
            await runtime.studio_store.save_document(core_id, {})
            grouped = await runtime.core_hosts.list_grouped(core_id)
            if grouped:
                await runtime.core_hosts.replace_tags(
                    core_id, {tag: [] for tag in grouped})
    except Exception as exc:
        raise _err(exc) from exc
    return {"ok": True, "core": core_id, "purged": body.purge}


@zagros_admin_router.post("/cores/{core_id}/reinstall")
async def cores_reinstall(core_id: str, runtime=Depends(get_runtime)):
    """Reinstall preserving EVERYTHING server-side: settings snapshot (the
    full unmasked one — the UI can never round-trip secrets), data dir
    (purge=False) and the running state. Binary is re-fetched by the
    driver's own install()."""
    manager = runtime.core_manager
    if core_id not in manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    settings = dict(manager.get(core_id).settings)
    enabled = manager.is_enabled(core_id)
    states = await runtime.core_state.load()
    was_running = states.get(core_id, {}).get("state") == "running"
    try:
        await manager.uninstall_core(core_id, purge=False, force=True)
        state = await manager.install_core(core_id, settings, enabled=enabled)
        if was_running:
            await manager.start_core(core_id)
    except Exception as exc:
        raise _err(exc) from exc
    return {"ok": True, "core": core_id, "state": state.value,
            "restarted": was_running}


@zagros_admin_router.post("/cores/{core_id}/start")
async def cores_start(core_id: str, runtime=Depends(get_runtime)):
    status = await _manager_call(runtime, core_id, "start_core")
    return {"ok": True, "core": core_id, "state": status.state.value}


@zagros_admin_router.post("/cores/{core_id}/stop")
async def cores_stop(core_id: str, runtime=Depends(get_runtime)):
    status = await _manager_call(runtime, core_id, "stop_core")
    return {"ok": True, "core": core_id, "state": status.state.value}


@zagros_admin_router.post("/cores/{core_id}/restart")
async def cores_restart(core_id: str, runtime=Depends(get_runtime)):
    status = await _manager_call(runtime, core_id, "restart_core")
    return {"ok": True, "core": core_id, "state": status.state.value}


@zagros_admin_router.post("/cores/{core_id}/enable")
async def cores_enable(core_id: str, runtime=Depends(get_runtime)):
    await _manager_call(runtime, core_id, "enable_core")
    return {"ok": True, "core": core_id, "enabled": True}


@zagros_admin_router.post("/cores/{core_id}/disable")
async def cores_disable(core_id: str, runtime=Depends(get_runtime)):
    await _manager_call(runtime, core_id, "disable_core")
    return {"ok": True, "core": core_id, "enabled": False}


@zagros_admin_router.post("/cores/{core_id}/update")
async def cores_update(core_id: str, body: CoreUpdateBody, runtime=Depends(get_runtime)):
    version = await _manager_call(runtime, core_id, "update_core", body.version)
    states = await runtime.core_state.load()
    running = states.get(core_id, {}).get("state") == "running"
    return {"ok": True, "core": core_id, "version": version,
            "restart_required": running}


_VERSION_CACHE: dict[str, tuple[float, list[dict]]] = {}
_VERSION_CACHE_TTL = 600.0


@zagros_admin_router.get("/cores/{core_id}/versions")
async def cores_versions(core_id: str, limit: int = 10, runtime=Depends(get_runtime)):
    """Recent upstream release tags for a GitHub-managed core (drives the
    version picker in Simple install mode). Sourced from the DRIVER's own
    metadata (release_repo), never hardcoded. Cached 10 min in-process."""
    from app.cores.github_install import fetch_recent_releases
    from app.cores.registry import available_drivers, get_driver_class

    if core_id not in available_drivers():
        raise HTTPException(404, f"unknown core '{core_id}'")
    repo = get_driver_class(core_id).metadata.release_repo
    if not repo:
        raise HTTPException(
            404, f"core '{core_id}' is not GitHub-release managed — "
                 "no version list is available (install uses the OS package)")
    now = time.monotonic()
    cached = _VERSION_CACHE.get(core_id)
    if cached and now - cached[0] < _VERSION_CACHE_TTL:
        releases = cached[1]
    else:
        try:
            releases = await asyncio.to_thread(fetch_recent_releases, repo, limit=limit)
        except Exception as exc:
            raise HTTPException(502, str(exc)) from exc
        _VERSION_CACHE[core_id] = (now, releases)
    return {"core": core_id, "repo": repo, "releases": releases[: max(1, min(limit, 30))]}


@zagros_admin_router.get("/cores/{core_id}/logs")
async def cores_logs(core_id: str, lines: int = 200, runtime=Depends(get_runtime)):
    manager = runtime.core_manager
    if core_id not in manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    lines = max(10, min(lines, 2000))
    try:
        entries = await manager.get_logs(core_id, tail=lines)
    except Exception as exc:
        raise _err(exc) from exc
    return {"core": core_id, "lines": entries[-lines:], "count": len(entries[-lines:])}


# --------------------------------------------------------------------- #
# routing rules — persistent set + dry preview + deploy
# --------------------------------------------------------------------- #

async def _load_rules(runtime) -> list[RoutingRule]:
    raw = await runtime.kv.get_value(_RULES_KEY)
    if not raw:
        return []
    return [RoutingRule.model_validate(item) for item in raw]


async def _save_rules(runtime, rules: list[RoutingRule]) -> list[RoutingRule]:
    normalized = runtime.routing_engine.validate(rules)
    await runtime.kv.set_value(
        _RULES_KEY, [r.model_dump(mode="json") for r in normalized])
    return normalized


async def _load_outbounds(runtime) -> list[Outbound]:
    raw = await runtime.kv.get_value(_OUTBOUNDS_KEY)
    return OutboundSecretCodec(runtime.cipher).decode(raw)


async def _merge_outbound_writes(
    runtime, writes: list[OutboundWrite],
) -> list[Outbound]:
    """Restore omitted encrypted credentials before strict profile validation."""
    existing = await _load_outbounds(runtime)
    try:
        merged = OutboundSecretCodec(runtime.cipher).merge_writes(writes, existing)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    existing_by_name = {outbound.name: outbound for outbound in existing}
    for outbound in merged:
        if outbound.kind not in LEGACY_SOFTETHER_OUTBOUND_KINDS:
            continue
        previous = existing_by_name.get(outbound.name)
        if previous is None:
            raise HTTPException(
                422,
                f"deprecated outbound kind '{outbound.kind.value}' cannot be created; "
                "use its canonical independent provider",
            )
        if outbound != previous:
            raise HTTPException(
                422,
                f"deprecated outbound '{outbound.name}' is historical/read-only; "
                "it may be retained unchanged or deleted",
            )
    return merged


def _sync_manager(manager: OutboundManager, stored: list[Outbound]) -> None:
    """Reconcile the in-memory registry with the persisted set (idempotent)."""
    for existing in list(manager.list()):
        manager.unregister(existing.name)
    for outbound in stored:
        manager.register(outbound)


def _validate_outbound_capabilities(outbounds: list[Outbound], runtime=None) -> None:
    """Validate against the shared product/runtime matrix, never a deny-list."""
    try:
        validate_selectable(outbounds, runtime)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


async def _save_outbounds(runtime, outbounds: list[Outbound]) -> list[Outbound]:
    names = [o.name for o in outbounds]
    if len(names) != len(set(names)):
        raise HTTPException(422, "duplicate outbound names are not allowed")
    # Unchanged historical aliases may pass through solely so operators can
    # save other rows or delete aliases incrementally. `_merge_outbound_writes`
    # forbids creating or mutating them, and they remain absent from all public
    # schemas/capabilities. Canonical rows still receive full runtime checks.
    _validate_outbound_capabilities(
        [outbound for outbound in outbounds
         if outbound.kind not in LEGACY_SOFTETHER_OUTBOUND_KINDS],
        runtime,
    )
    await runtime.kv.set_value(
        _OUTBOUNDS_KEY, OutboundSecretCodec(runtime.cipher).encode(outbounds))
    _sync_manager(runtime.outbound_manager, outbounds)
    return outbounds


@zagros_admin_router.get("/inbounds")
async def unified_inbound_catalog(runtime=Depends(get_runtime)):
    """Every selectable inbound across ALL enabled cores (multi-core picker).

    Studio cores contribute their live config inbounds; service cores
    (openvpn/wireguard/ssh/softether) contribute entries derived from their
    real settings — the User dialog / Templates consume this as the grant
    source for ``core_access``.
    """
    from app.platform.inbounds import catalog as _catalog

    groups = await _catalog(runtime)
    return {"groups": [g.as_dict() for g in groups]}


@zagros_admin_router.get("/routing/sources")
async def routing_sources(runtime=Depends(get_runtime)):
    """Inbound inventory for rules, including routing-only managed hubs.

    Managed hub tags must be selectable in Routing but must not appear as user
    grant/subscription inbounds, so the general ``/inbounds`` catalog remains
    unchanged.
    """
    from app.platform.inbounds import catalog as _catalog

    groups = [group.as_dict() for group in await _catalog(runtime)]
    try:
        driver = runtime.core_manager.get("softether")
        managed = [spec for spec in driver.routing_source_specs()
                   if spec.get("managed_by_zagros") is True]
    except Exception:  # noqa: BLE001 - absent SoftEther means no extra group
        managed = []
    if managed:
        group = next((item for item in groups if item["core_id"] == "softether"), None)
        if group is None:
            group = {"core_id": "softether", "name": "SoftEther VPN",
                     "enabled": True, "inbounds": []}
            groups.append(group)
        native_port = int(driver.settings.get("native_port") or 5555)
        for spec in managed:
            group["inbounds"].append({
                "tag": spec["tags"][0], "protocol": "softether-managed-hub",
                "port": native_port, "routing_only": True,
            })
    owners: dict[str, set[str]] = {}
    for group in groups:
        for inbound in group.get("inbounds", []):
            tag = str(inbound.get("tag") or "")
            if tag:
                owners.setdefault(tag, set()).add(str(group["core_id"]))
    for group in groups:
        core_id = str(group["core_id"])
        for inbound in group.get("inbounds", []):
            tag = str(inbound.get("tag") or "")
            inbound["source_core"] = core_id
            inbound["source_id"] = f"{core_id}:{tag}"
            inbound["duplicate_tag"] = len(owners.get(tag, set())) > 1
    return {"groups": groups}


async def _routing_source_core_map(
    runtime, rules: list[RoutingRule] | None = None,
) -> dict[str, str]:
    """Resolve live tags and reject ambiguous references before mutation."""
    if rules:
        for rule in rules:
            tags = list(rule.matcher.inbounds)
            repeated = sorted({tag for tag in tags if tags.count(tag) > 1})
            if repeated:
                raise CoreError(
                    f"routing rule '{rule.name}' contains duplicate inbound "
                    f"tag(s) {repeated}; select each inbound once"
                )
    payload = await routing_sources(runtime)
    mapping: dict[str, str] = {}
    duplicates: set[str] = set()
    for group in payload["groups"]:
        core_id = str(group["core_id"])
        for inbound in group.get("inbounds", []):
            tag = str(inbound.get("tag") or "")
            if not tag:
                continue
            if tag in mapping and mapping[tag] != core_id:
                duplicates.add(tag)
            mapping[tag] = core_id
    for tag in duplicates:
        mapping.pop(tag, None)
    if rules:
        referenced = {
            tag for rule in rules for tag in rule.matcher.inbounds
            if tag in duplicates
        }
        if referenced:
            raise CoreError(
                "routing rule references duplicate inbound tag(s) "
                f"{sorted(referenced)} owned by multiple cores; rename the "
                "inbounds before saving/deploying"
            )
    return mapping


@zagros_admin_router.get("/routing/targets")
async def routing_targets(runtime=Depends(get_runtime)):
    """Capability-aware target inventory for the graphical rule builder.

    A single ``tun`` filter hid valid SSH application routing.  Return both
    implemented contexts so clients can select with the rule's source/network:
    service/kernel sources require ``policy_tun``; native Xray/sing-box rules
    explicitly limited to TCP may use ``native_application_tcp``.
    """
    targets = []
    for outbound in await _load_outbounds(runtime):
        capability = outbound_capability(outbound.kind, runtime)
        if not outbound.enabled or capability.state.value in {
            "unsupported", "not_applicable"
        }:
            continue
        contexts = sorted(context.value for context in capability.routing_contexts)
        if not contexts:
            continue
        targets.append({
            "name": outbound.name,
            "kind": outbound.kind.value,
            "state": capability.state.value,
            # NOT_INSTALLED profiles remain configurable; deployment reports
            # the missing runtime honestly. Only unsupported/not-applicable
            # provider identities are non-selectable.
            "selectable": capability.selectable,
            "direction": capability.direction,
            "dataplane": capability.dataplane.value,
            "contexts": contexts,
            # ``transports`` remains the outer carrier for compatibility;
            # payload compatibility comes from traffic_networks.
            "transports": sorted(capability.transports),
            "traffic_networks": sorted(capability.traffic_networks),
            "source_cores": sorted(capability.routing_source_cores),
            "application_level": capability.application_level,
            "tun": capability.tun,
            "reason": capability.reason,
        })
    return {"targets": targets}


@zagros_admin_router.get("/routing/rules")
async def routing_list(runtime=Depends(get_runtime)):
    rules = await _load_rules(runtime)
    return {"rules": [r.model_dump(mode="json") for r in rules]}


class RoutingSetBody(BaseModel):
    rules: list[RoutingRule] = Field(default_factory=list)


@zagros_admin_router.put("/routing/rules")
async def routing_save(body: RoutingSetBody, runtime=Depends(get_runtime)):
    try:
        normalized = runtime.routing_engine.validate(body.rules)
        policy_router = getattr(runtime, "policy_router", None)
        if policy_router is not None:
            policy_router.validate_rule_set(normalized)
        outbounds = {outbound.name: outbound
                     for outbound in await _load_outbounds(runtime)}
        if policy_router is not None:
            policy_router.validate_plan(
                normalized, outbounds.values(),
                source_core_map=await _routing_source_core_map(runtime, normalized),
            )
        for rule in normalized:
            if rule.action.value != "route_to":
                continue
            outbound = outbounds.get(str(rule.outbound))
            if outbound is None:
                raise ValueError(
                    f"rule '{rule.name}' references missing outbound '{rule.outbound}'")
            policy_router = getattr(runtime, "policy_router", None)
            mode = (policy_router._mode(outbound.kind, outbound.settings)  # noqa: SLF001
                    if policy_router is not None else None)
            policy_cores = {"xray", "sing-box", "openvpn", "wireguard", "softether", "ssh", "pptp"}
            policy_required = bool(
                policy_cores.intersection(runtime.core_manager.list_cores()))
            if mode and rule.enabled and policy_required:
                domain = next((item for item in policy_router.domain_views()
                               if item["outbound"] == outbound.name and item["ready"]), None)
                if domain is None:
                    raise ValueError(
                        f"rule '{rule.name}': outbound '{outbound.name}' is not running; "
                        "Deploy/Test the outbound before saving this enabled rule")
        await runtime.kv.set_value(
            _RULES_KEY, [r.model_dump(mode="json") for r in normalized])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ok": True, "count": len(normalized),
            "order": [r.name for r in normalized]}


class RoutingBody(BaseModel):
    rules: list[RoutingRule] = Field(default_factory=list)
    core_ids: list[str] | None = None


@zagros_admin_router.post("/routing/preview")
async def routing_preview(body: RoutingBody, runtime=Depends(get_runtime)):
    try:
        normalized = runtime.routing_engine.validate(body.rules)
        outbounds = await _load_outbounds(runtime)
        policy_router = getattr(runtime, "policy_router", None)
        if policy_router is not None:
            policy_router.validate_plan(
                normalized, outbounds, body.core_ids,
                source_core_map=await _routing_source_core_map(runtime, normalized),
            )
        report = await runtime.routing_engine.preview(
            normalized, core_ids=body.core_ids, outbounds=outbounds)
    except Exception as exc:
        raise _err(exc) from exc
    return report.model_dump(mode="json")


@zagros_admin_router.post("/routing/deploy")
async def routing_deploy(body: RoutingBody, runtime=Depends(get_runtime)):
    previous = await _load_rules(runtime)
    # Pure preflight is intentionally outside the mutation/rollback block.
    # Invalid SSH→TUN (and similar capability mismatches) therefore touches no
    # process, interface, classifier or persisted document and cannot produce a
    # misleading secondary rollback failure.
    try:
        normalized = runtime.routing_engine.validate(body.rules)
        outbounds = await _load_outbounds(runtime)
        policy_router = getattr(runtime, "policy_router", None)
        if policy_router is not None:
            policy_router.validate_plan(
                normalized, outbounds, body.core_ids,
                source_core_map=await _routing_source_core_map(runtime, normalized),
            )
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc

    mutated = False
    try:
        _sync_manager(runtime.outbound_manager, outbounds)
        # A routing transaction owns its dependencies: first prove every
        # outbound interface/table, then atomically replace classifiers and
        # native rules. No separate UI click is required.
        mutated = True
        await runtime.outbound_manager.deploy(core_ids=body.core_ids)
        report = await runtime.routing_engine.deploy(
            normalized, core_ids=body.core_ids, outbounds=outbounds)
        await runtime.kv.set_value(
            _RULES_KEY, [r.model_dump(mode="json") for r in normalized])
    except Exception as exc:
        if not mutated:  # defensive; currently every mutation follows the flag
            raise _err(exc) from exc
        try:
            stored_outbounds = await _load_outbounds(runtime)
            _sync_manager(runtime.outbound_manager, stored_outbounds)
            await runtime.outbound_manager.deploy(core_ids=body.core_ids)
            await runtime.routing_engine.deploy(
                previous, core_ids=body.core_ids, outbounds=stored_outbounds)
        except Exception as rollback_exc:  # noqa: BLE001
            raise HTTPException(
                500,
                f"routing deployment failed ({exc}); rollback also failed: {rollback_exc}",
            ) from exc
        raise _err(exc) from exc
    result = report.model_dump(mode="json")
    result["saved"] = True
    result["policy_domains"] = (policy_router.domain_views() if policy_router else [])
    return result


@zagros_admin_router.get("/routing/runtime")
async def routing_runtime(runtime=Depends(get_runtime)):
    """Secret-free kernel-domain health for validation/UI diagnostics."""
    policy_router = getattr(runtime, "policy_router", None)
    return {
        "domains": policy_router.domain_views() if policy_router else [],
        "rules": [rule.model_dump(mode="json")
                  for rule in await _load_rules(runtime)],
    }


# --------------------------------------------------------------------- #
# outbounds — persistent registry + live connectivity test
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/outbounds")
async def outbounds_list(runtime=Depends(get_runtime)):
    from app.cores.capabilities import outbound_capabilities

    outbounds = await _load_outbounds(runtime)
    codec = OutboundSecretCodec(runtime.cipher)
    return {
        "outbounds": [codec.public_view(o) for o in outbounds],
        "capabilities": {
            kind.value: capability.public()
            for kind, capability in outbound_capabilities(runtime).items()
            if kind not in LEGACY_SOFTETHER_OUTBOUND_KINDS
        },
    }


class OutboundsSetBody(BaseModel):
    outbounds: list[OutboundWrite] = Field(default_factory=list)


@zagros_admin_router.put("/outbounds")
async def outbounds_save(body: OutboundsSetBody, runtime=Depends(get_runtime)):
    try:
        candidates = await _merge_outbound_writes(runtime, body.outbounds)
        saved = await _save_outbounds(runtime, candidates)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ok": True, "count": len(saved)}


def _openvpn_endpoint(settings: dict[str, Any]) -> tuple[Any, Any, str]:
    """First remote + effective transport from an uploaded/manual profile."""
    server, port = settings.get("server"), settings.get("server_port")
    proto = str(settings.get("proto") or "udp").lower()
    content = str(settings.get("ovpn_content") or "")
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if parts and parts[0].lower() == "proto" and len(parts) > 1:
            proto = parts[1].lower()
        elif (parts and parts[0].lower() == "remote" and len(parts) > 1
              and (not server or not port)):
            server = server or parts[1]
            if len(parts) > 2 and not port:
                port = parts[2]
            if len(parts) > 3:
                proto = parts[3].lower()
    return server, port, proto


async def _udp_outbound_preflight(server: str, port: int) -> tuple[float, str]:
    """Resolve and route-connect a datagram endpoint without lying about auth.

    TCP dialing a UDP-only Hysteria2/TUIC/WireGuard/OpenVPN listener always
    returned ConnectionRefused even when the protocol worked. UDP itself has
    no connect handshake, so this test verifies DNS/address/route/socket
    readiness and says explicitly that authentication happens on deployment.
    """
    loop = asyncio.get_running_loop()
    started = time.monotonic()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(server, port, type=socket.SOCK_DGRAM), timeout=6)
    if not infos:
        raise OSError("endpoint did not resolve to a UDP address")
    family, socktype, proto, _canonname, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    try:
        sock.setblocking(False)
        await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout=6)
        local = sock.getsockname()
        if not local:
            raise OSError("kernel did not select a route/source address")
    finally:
        sock.close()
    return round((time.monotonic() - started) * 1000, 1), \
        f"udp {server}:{port} route ready; protocol authentication runs on deploy"


def _test_result(
    *, status: str, rtt_ms: float | None = None, error: str | None = None,
    availability: str | None = None,
) -> dict[str, Any]:
    """The public Test contract: status plus one optional real RTT only."""
    result: dict[str, Any] = {"status": status, "rtt_ms": rtt_ms}
    if error:
        result["error"] = error
    if availability:
        result["availability"] = availability
    return result


async def _test_outbound(runtime, outbound: Outbound) -> dict[str, Any]:
    """Protocol-aware endpoint test; never TCP-probe a UDP-only profile."""
    capability = outbound_capability(outbound.kind, runtime)
    if not capability.selectable:
        return _test_result(
            status="unhealthy", availability=capability.state.value,
            error=capability.reason or "outbound runtime is unavailable")
    if outbound.kind is OutboundKind.CORE:
        core_id = str(outbound.settings.get("core_id", ""))
        manager = runtime.core_manager
        if core_id not in manager.list_cores():
            return _test_result(
                status="unhealthy",
                error=f"target core '{core_id}' is not installed")
        states = await runtime.core_state.load()
        state = states.get(core_id, {}).get("state", "installed")
        running = state == "running"
        return _test_result(status="healthy" if running else "unhealthy")
    if outbound.kind in (OutboundKind.DIRECT, OutboundKind.BLOCK,
                         OutboundKind.BLACKHOLE, OutboundKind.DNS):
        return _test_result(status="healthy")
    if outbound.kind in PPP_CLIENT_KINDS:
        # A TCP/UDP port probe is not a VPN test.  Establish the real isolated
        # provider domain together with all currently stored domains, collect
        # tunnel/interface/session health, then restore the exact persisted set.
        policy = getattr(runtime, "policy_router", None)
        if policy is None:
            return _test_result(
                status="unhealthy", error="Linux policy router is unavailable")
        persisted = await _load_outbounds(runtime)
        candidates = {item.name: item for item in persisted if item.enabled}
        # Always establish a fresh disposable domain. Reusing an already-ready
        # persisted profile made Test measure two dictionary reconciliations,
        # not tunnel setup or network RTT.
        probe_outbound = outbound.model_copy(
            update={"name": f"zgtest-{secrets.token_hex(6)}"})
        candidates[probe_outbound.name] = probe_outbound
        error: Exception | None = None
        view: dict[str, Any] | None = None
        diagnostics: dict[str, Any] | None = None
        try:
            domains = await asyncio.to_thread(policy.prepare, candidates.values())
            domain = domains.get(probe_outbound.name)
            if domain is None or not domain.ready:
                raise CoreError("provider returned no ready policy domain")
            view = next((item for item in policy.domain_views()
                         if item["outbound"] == probe_outbound.name), None)
            if not view or not view.get("ready"):
                raise CoreError("provider tunnel health check did not stay ready")
            diagnostics = await asyncio.to_thread(
                policy.measure_ppp, domain, probe_outbound)
        except Exception as exc:  # noqa: BLE001 - result is returned after rollback
            error = exc
        rollback_error: Exception | None = None
        try:
            await asyncio.to_thread(
                policy.prepare, [item for item in persisted if item.enabled])
        except Exception as exc:  # noqa: BLE001 - report rollback loss explicitly
            rollback_error = exc
        if rollback_error is not None:
            primary = "provider test failed before rollback"
            if error is not None:
                primary = f"{type(error).__name__}: {str(error)[:400]}"
                for key, value in outbound.settings.items():
                    if is_secret_setting(key) and value not in (None, ""):
                        primary = primary.replace(str(value), "<redacted>")
            rollback = f"{type(rollback_error).__name__}: {str(rollback_error)[:400]}"
            for key, value in outbound.settings.items():
                if is_secret_setting(key) and value not in (None, ""):
                    rollback = rollback.replace(str(value), "<redacted>")
            return _test_result(
                status="unhealthy",
                error=(
                    f"{outbound.kind.value} test failed: {primary}; "
                    f"rollback failed: {rollback}"
                ),
            )
        if error is not None:
            message = str(error)
            for key, value in outbound.settings.items():
                if is_secret_setting(key) and value not in (None, ""):
                    message = message.replace(str(value), "<redacted>")
            return _test_result(
                status="unhealthy",
                error=f"{type(error).__name__}: {message[:400]}",
            )
        assert diagnostics is not None
        # Keep credential-free evidence in the server log for operators. The
        # public response deliberately has one measurement only: the
        # post-ready tunnel RTT window selected by policy.
        evidence = {
            "protocol": outbound.kind.value,
            "probe_target": diagnostics.get("probe_target"),
            "probe_url": diagnostics.get("probe_url"),
            "timestamp": diagnostics.get("measurement_timestamp"),
            "interface": diagnostics.get("interface"),
            "namespace": diagnostics.get("namespace"),
            "route_before": diagnostics.get("route_before"),
            "route": diagnostics.get("route"),
            "warmup_samples": diagnostics.get("warmup_samples"),
            "measurement_window_samples": diagnostics.get("measurement_window_samples"),
            "selected_rtt_ms": diagnostics.get("selected_rtt_ms"),
            "tunnel_https_status": (diagnostics.get("tunnel_https") or {}).get("status"),
            "counter_delta": diagnostics.get("counter_delta"),
        }
        # WARNING is intentional: the production image's default log level
        # suppresses INFO, while this evidence must remain available without
        # exposing the full internal diagnostics in the public API.
        _TEST_LOG.warning("outbound-test-evidence %s", json.dumps(evidence, sort_keys=True))
        return _test_result(
            status="healthy",
            rtt_ms=float(diagnostics["selected_rtt_ms"]),
        )

    settings = outbound.settings
    if outbound.kind is OutboundKind.OPENVPN:
        server, port, transport = _openvpn_endpoint(settings)
    else:
        server, port = settings.get("server"), settings.get("server_port")
        transport = str(settings.get("network") or "tcp").lower()
    try:
        server = str(server).strip()
        port = int(port)
    except (TypeError, ValueError):
        return _test_result(
            status="unhealthy",
            error=f"invalid server/server_port: {server!r}:{port!r}")
    if not server or not 1 <= port <= 65535:
        return _test_result(
            status="unhealthy",
            error=f"invalid server/server_port: {server!r}:{port!r}")

    udp = outbound.kind in {
        OutboundKind.HYSTERIA2, OutboundKind.TUIC, OutboundKind.WIREGUARD,
    } or (outbound.kind is OutboundKind.OPENVPN and transport.startswith("udp"))
    if udp:
        try:
            latency, _detail = await _udp_outbound_preflight(server, port)
        except Exception as exc:  # noqa: BLE001 - preflight failure is the answer
            message = str(exc).strip() or "UDP endpoint preflight failed"
            return _test_result(
                status="unhealthy",
                error=f"{type(exc).__name__}: {message}")
        return _test_result(status="healthy", rtt_ms=latency)

    started = time.monotonic()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=6)
    except Exception as exc:  # noqa: BLE001 - dial failure IS the answer
        message = str(exc).strip() or f"TCP connection to {server}:{port} failed"
        return _test_result(
            status="unhealthy",
            error=f"{type(exc).__name__}: {message}")
    latency = round((time.monotonic() - started) * 1000, 1)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001, S110 - close is best-effort cleanup
        pass
    return _test_result(status="healthy", rtt_ms=latency)


@zagros_admin_router.post("/outbounds/test")
async def outbounds_test(body: OutboundWrite, runtime=Depends(get_runtime)):
    outbound = (await _merge_outbound_writes(runtime, [body]))[0]
    return await _test_outbound(runtime, outbound)


# --------------------------------------------------------------------- #
# outbounds schema + share-url import + ovpn export (alpha.7)
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/outbounds/schema")
async def outbounds_schema(runtime=Depends(get_runtime)):
    """Per-kind field schemas — the SPA builds its forms from THIS, never
    from a hardcoded template (transports + security matrices included)."""
    from app.cores.outbounds.profile_schema import outbound_schemas

    return {"schemas": outbound_schemas(runtime)}


class ShareURLBody(BaseModel):
    url: str = Field(min_length=1)


@zagros_admin_router.post("/utils/parse-share-url")
async def parse_share_url_endpoint(body: ShareURLBody, runtime=Depends(get_runtime)):
    """"Import URL": paste vless://, vmess://, trojan://, ss://,
    hysteria2://, tuic:// → every form field filled automatically."""
    from app.utils.shareurl import SUPPORTED_SCHEMES, ShareURLError, parse_share_url

    try:
        parsed = parse_share_url(body.url)
    except ShareURLError as exc:
        raise HTTPException(422, str(exc)) from exc
    payload = parsed.model_dump(mode="json")
    public, credentials = split_settings(payload.get("settings") or {})
    sealed = OutboundSecretCodec(runtime.cipher).seal_import_credentials(
        parsed.kind, credentials)
    payload["settings"] = public
    payload["secret_state"] = {
        key: value not in (None, "") for key, value in sorted(credentials.items())
    }
    payload["sealed_credentials"] = sealed
    return {**payload, "supported_schemes": SUPPORTED_SCHEMES}


class WireGuardProfileBody(BaseModel):
    content: str = Field(min_length=1, max_length=128 * 1024)


@zagros_admin_router.post("/utils/parse-wireguard-profile")
async def parse_wireguard_profile_endpoint(
    body: WireGuardProfileBody, runtime=Depends(get_runtime),
):
    """Import a standard WireGuard client ``.conf`` into outbound settings."""
    from app.cores.outbounds.wireguard_profile import (
        WireGuardProfileError,
        parse_wireguard_profile,
    )

    try:
        settings = parse_wireguard_profile(body.content)
    except WireGuardProfileError as exc:
        raise HTTPException(422, str(exc)) from exc
    public, credentials = split_settings(settings)
    return {
        "kind": OutboundKind.WIREGUARD.value,
        "settings": public,
        "secret_state": {
            key: value not in (None, "") for key, value in sorted(credentials.items())
        },
        "sealed_credentials": OutboundSecretCodec(
            runtime.cipher).seal_import_credentials(
                OutboundKind.WIREGUARD, credentials),
        "name_hint": f"wireguard-{settings['server_port']}",
    }


def _render_ovpn(name: str, settings: dict[str, Any]) -> str:
    """Synthesize a client .ovpn profile from stored settings (or pass
    through an uploaded one verbatim)."""
    inline = str(settings.get("ovpn_content") or "").strip()
    if inline:
        return inline if inline.endswith("\n") else inline + "\n"
    server = settings.get("server")
    port = int(settings.get("server_port") or 1194)
    if not server:
        raise ValueError(f"outbound '{name}': no server configured")
    proto = str(settings.get("proto") or "udp")
    lines = [
        "client", "dev tun", f"proto {proto}",
        f"remote {server} {port}",
        "resolv-retry infinite", "nobind", "persist-key", "persist-tun",
        "remote-cert-tls server", "verb 3",
    ]
    if settings.get("cipher"):
        lines.append(f"cipher {settings['cipher']}")
    if settings.get("auth"):
        lines.append(f"auth {settings['auth']}")
    if settings.get("username"):
        lines.append("auth-user-pass")
    for key, tag in (("ca_pem", "ca"), ("cert_pem", "cert"), ("key_pem", "key")):
        pem = str(settings.get(key) or "").strip()
        if pem:
            lines += [f"<{tag}>", pem, f"</{tag}>"]
    lines.append("")
    return "\n".join(lines)


@zagros_admin_router.get("/outbounds/export")
async def outbounds_export(name: str, runtime=Depends(get_runtime)):
    """Re-export an OpenVPN outbound as a ready .ovpn client profile."""
    from fastapi.responses import PlainTextResponse

    outbounds = {o.name: o for o in await _load_outbounds(runtime)}
    outbound = outbounds.get(name)
    if outbound is None:
        raise HTTPException(404, f"outbound '{name}' not found")
    if outbound.kind is not OutboundKind.OPENVPN:
        raise HTTPException(422, "only openvpn outbounds export a .ovpn profile")
    if any(outbound.settings.get(key) for key in ("ovpn_content", "key_pem")):
        raise HTTPException(
            409,
            "credential-bearing OpenVPN profile export is disabled: API responses "
            "never return stored private-key/profile material; use the original "
            "secure credential source",
        )
    try:
        content = _render_ovpn(name, outbound.settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return PlainTextResponse(
        content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'})


class OutboundDeployBody(BaseModel):
    outbounds: list[OutboundWrite] = Field(default_factory=list)
    core_ids: list[str] | None = None


@zagros_admin_router.post("/outbounds/deploy")
async def outbounds_deploy(body: OutboundDeployBody, runtime=Depends(get_runtime)):
    previous = await _load_outbounds(runtime)
    candidates = await _merge_outbound_writes(runtime, body.outbounds)
    names = [outbound.name for outbound in candidates]
    if len(names) != len(set(names)):
        raise HTTPException(422, "duplicate outbound names are not allowed")
    _validate_outbound_capabilities(candidates, runtime)
    try:
        # Deploy-before-persist: a bad profile/interface/table cannot replace
        # the last known-good desired state. The manager receives a temporary
        # candidate registry; SQL changes only after every runtime converges.
        _sync_manager(runtime.outbound_manager, candidates)
        report = await runtime.outbound_manager.deploy(core_ids=body.core_ids)
        await runtime.kv.set_value(
            _OUTBOUNDS_KEY,
            OutboundSecretCodec(runtime.cipher).encode(candidates),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _sync_manager(runtime.outbound_manager, previous)
        try:
            await runtime.outbound_manager.deploy(core_ids=body.core_ids)
        except Exception as rollback_exc:  # noqa: BLE001
            raise HTTPException(
                500,
                f"outbound deployment failed ({exc}); rollback also failed: {rollback_exc}",
            ) from exc
        raise _err(exc) from exc
    result = report.model_dump(mode="json")
    result["saved"] = True
    policy_router = getattr(runtime, "policy_router", None)
    result["policy_domains"] = (policy_router.domain_views() if policy_router else [])
    return result


# --------------------------------------------------------------------- #
# sessions / client sessions / devices
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/sessions")
async def sessions_list(user_id: int | None = None, limit: int = 200,
                        runtime=Depends(get_runtime)):
    limit = max(1, min(limit, 1000))
    records = await runtime.sessions_store.history(user_id=user_id, limit=limit)
    return {"sessions": [r.model_dump(mode="json") for r in records]}


@zagros_admin_router.get("/client-sessions")
async def client_sessions(limit: int = 200, runtime=Depends(get_runtime)):
    from sqlalchemy import desc, select

    from app.persistence.models import RefreshTokenModel, UserModel

    limit = max(1, min(limit, 1000))

    def _sync():
        with runtime.session_factory() as s:
            stmt = (select(RefreshTokenModel, UserModel.username)
                    .join(UserModel, UserModel.id == RefreshTokenModel.user_id)
                    .order_by(desc(RefreshTokenModel.created_at)).limit(limit))
            return s.execute(stmt).all()

    rows = await asyncio.to_thread(_sync)
    return {"sessions": [{
        "token_hash": row.RefreshTokenModel.token_hash,
        "user_id": row.RefreshTokenModel.user_id,
        "username": row.username,
        "created_at": row.RefreshTokenModel.created_at,
        "expires_at": row.RefreshTokenModel.expires_at,
        "revoked": row.RefreshTokenModel.revoked,
        "rotated_to": row.RefreshTokenModel.rotated_to,
        "user_agent": row.RefreshTokenModel.user_agent,
    } for row in rows]}


@zagros_admin_router.delete("/client-sessions/{token_hash}")
async def client_session_revoke(token_hash: str, runtime=Depends(get_runtime)):
    record = await runtime.refresh_tokens.get(token_hash)
    if record is None:
        raise HTTPException(404, "session not found")
    await runtime.refresh_tokens.revoke(token_hash)
    return {"ok": True, "revoked": token_hash}


@zagros_admin_router.post("/client-sessions/user/{user_id}/revoke")
async def client_sessions_revoke_user(user_id: int, runtime=Depends(get_runtime)):
    if runtime.users.get_user(user_id) is None:
        raise HTTPException(404, "user not found")
    await runtime.refresh_tokens.revoke_all_for_user(user_id)
    return {"ok": True, "user_id": user_id}


@zagros_admin_router.get("/devices")
async def devices_list(limit: int = 500, runtime=Depends(get_runtime)):
    from sqlalchemy import desc, select

    from app.persistence.models import DeviceModel, UserModel

    limit = max(1, min(limit, 2000))

    def _sync():
        with runtime.session_factory() as s:
            stmt = (select(DeviceModel, UserModel.username)
                    .join(UserModel, UserModel.id == DeviceModel.user_id)
                    .order_by(desc(DeviceModel.last_seen)).limit(limit))
            return s.execute(stmt).all()

    rows = await asyncio.to_thread(_sync)
    return {"devices": [{
        "device_id": row.DeviceModel.device_id,
        "user_id": row.DeviceModel.user_id,
        "username": row.username,
        "name": row.DeviceModel.name,
        "platform": row.DeviceModel.platform,
        "app_version": row.DeviceModel.app_version,
        "last_ip": row.DeviceModel.last_ip,
        "first_seen": row.DeviceModel.first_seen,
        "last_seen": row.DeviceModel.last_seen,
        "current_core": row.DeviceModel.current_core,
        "cores": row.DeviceModel.cores_json,
    } for row in rows]}


@zagros_admin_router.delete("/devices/{device_id}")
async def devices_remove(device_id: str, runtime=Depends(get_runtime)):
    from sqlalchemy import delete

    from app.persistence.models import DeviceModel

    def _sync() -> int:
        with runtime.session_factory() as s:
            result = s.execute(
                delete(DeviceModel).where(DeviceModel.device_id == device_id))
            s.commit()
            return int(result.rowcount or 0)

    removed = await asyncio.to_thread(_sync)
    if removed == 0:
        raise HTTPException(404, "device not found")
    return {"ok": True, "removed": device_id}


# --------------------------------------------------------------------- #
# certificates
# --------------------------------------------------------------------- #

def _data_dir(runtime) -> str:
    url = runtime.database_url
    if url.startswith("sqlite:///"):
        from pathlib import Path

        return str(Path(url[10:]).parent)
    return "/var/lib/zagros"


@zagros_admin_router.get("/certificates")
async def certificates_list(runtime=Depends(get_runtime)):
    from app.platform import acme

    return {"certificates": [c.model_dump(mode="json")
                             for c in certificates.scan(_data_dir(runtime),
                                                        managed_only=True)],
            "acme": acme.acme_available()}


class AcmeIssueBody(BaseModel):
    domain: str
    email: str | None = None
    provider: str | None = None  # certbot | acme.sh | lego (auto = first found)
    force: bool = False


@zagros_admin_router.get("/certificates/acme")
async def certificates_acme_status(runtime=Depends(get_runtime)):
    """ACME reality: which clients exist on this host + every ACME-managed
    entry with expiry/renewal facts (alpha.7.5 item 9)."""
    from app.platform import acme

    return acme.acme_status(_data_dir(runtime))


@zagros_admin_router.post("/certificates/acme/issue")
async def certificates_acme_issue(body: AcmeIssueBody, runtime=Depends(get_runtime)):
    """REAL issuance via the host ACME client (HTTP-01 standalone). A failed
    run returns the client's own error tail — never a fake success."""
    from app.platform import acme

    try:
        return await asyncio.to_thread(
            acme.issue, _data_dir(runtime), body.domain,
            email=body.email, provider_id=body.provider, force=body.force)
    except acme.ACMEError as exc:
        raise HTTPException(422, str(exc)) from exc


class AcmeRenewBody(BaseModel):
    force: bool = False


@zagros_admin_router.post("/certificates/acme/{domain}/renew")
async def certificates_acme_renew(domain: str, body: AcmeRenewBody | None = None,
                                  runtime=Depends(get_runtime)):
    from app.platform import acme

    try:
        return await asyncio.to_thread(
            acme.renew, _data_dir(runtime), domain,
            force=bool(body and body.force))
    except acme.ACMEError as exc:
        raise HTTPException(422, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc


@zagros_admin_router.delete("/certificates/acme/{domain}")
async def certificates_acme_remove(domain: str, runtime=Depends(get_runtime)):
    """Delete an ACME entry — managed-store removal authoritative, provider
    cleanup best-effort and reported."""
    from app.platform import acme

    try:
        return await asyncio.to_thread(acme.remove_acme, _data_dir(runtime), domain)
    except acme.ACMEError as exc:
        raise HTTPException(422, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc


class CertImportBody(BaseModel):
    name: str
    cert_pem: str = Field(min_length=1)
    key_pem: str = Field(min_length=1)
    overwrite: bool = False


@zagros_admin_router.post("/certificates/import")
async def certificates_import(body: CertImportBody, runtime=Depends(get_runtime)):
    try:
        info = certificates.import_cert(
            _data_dir(runtime), body.name, body.cert_pem, body.key_pem,
            overwrite=body.overwrite)
    except FileExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ok": True, "certificate": info.model_dump(mode="json")}


class CertSelfSignedBody(BaseModel):
    name: str
    common_name: str = Field(min_length=1)
    days: int = Field(default=3650, ge=1, le=3650)
    san_dns: list[str] = Field(default_factory=list)
    overwrite: bool = False


@zagros_admin_router.post("/certificates/self-signed")
async def certificates_self_signed(body: CertSelfSignedBody, runtime=Depends(get_runtime)):
    try:
        info = certificates.self_signed(
            _data_dir(runtime), body.name, body.common_name,
            days=body.days, san_dns=body.san_dns, overwrite=body.overwrite)
    except FileExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ok": True, "certificate": info.model_dump(mode="json")}


@zagros_admin_router.delete("/certificates/{ident:path}")
async def certificates_remove(ident: str, runtime=Depends(get_runtime)):
    """Delete by stable identifier: the inventory `id` (data-dir-relative
    path — the ONLY handle that reaches core-materialized certs, item 18)
    or a plain managed name for the legacy caller contract."""
    ident = ident.strip().lstrip("/")
    # ACME-managed material must go through the ACME endpoint, which also
    # performs provider-side cleanup and reports it — a bare store delete
    # would orphan the provider account copy and leave a sidecar pointing
    # at files that no longer exist (alpha.7.5 item 9).
    managed_name = ident[len("certs/"):] if ident.startswith("certs/") else ident
    if "/" not in managed_name and managed_name:
        from app.platform import acme
        if acme.has_sidecar(_data_dir(runtime), managed_name):
            raise HTTPException(
                409, f"'{managed_name}' is ACME-managed — delete it via the "
                     f"ACME endpoint (DELETE /api/zagros/certificates/acme/"
                     f"{managed_name}) so provider cleanup runs and is reported")
    try:
        certificates.remove(_data_dir(runtime), ident)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ok": True, "removed": ident}


# --------------------------------------------------------------------- #
# native Zagros multi-core nodes (separate from legacy Xray-only nodes)
# --------------------------------------------------------------------- #

class NativeNodePendingBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=256)
    api_port: int = Field(default=62050, ge=1, le=65535)
    expires_in_seconds: int = Field(default=900, ge=60, le=3600)
    usage_coefficient: float = Field(default=1.0, gt=0)


class NativeNodeCallbackBody(BaseModel):
    pending_id: int = Field(ge=1)
    registration_token: SecretStr
    bootstrap_token: SecretStr
    certificate_fingerprint: str = Field(min_length=64, max_length=128)
    agent_version: str | None = Field(default=None, max_length=64)


class NativeNodeRegisterBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=256)
    port: int = Field(default=62050, ge=1, le=65535)
    registration_token: SecretStr
    certificate_fingerprint: str = Field(min_length=64, max_length=128)
    usage_coefficient: float = Field(default=1.0, gt=0)


class NativeNodeLifecycleBody(BaseModel):
    action: str
    settings: dict[str, Any] = Field(default_factory=dict)
    purge: bool = False
    force: bool = False


class UserNodeAssignmentBody(BaseModel):
    node_id: int | None = Field(default=None, ge=1)


def _native_node_view(row) -> dict[str, Any]:
    settings = dict(row.settings_json or {})
    settings.pop("certificate_pem", None)
    return {
        "id": row.id, "name": row.name, "address": row.address,
        "port": row.port, "status": row.status,
        "usage_coefficient": row.usage_coefficient,
        "agent_type": row.agent_type,
        "agent_identity": row.agent_identity,
        "certificate_fingerprint": row.certificate_fingerprint,
        "last_seen": row.last_seen,
        "agent_version": settings.get("agent_version"),
        "health": settings.get("health"),
        "cores": settings.get("cores"),
    }


def _native_node_client(runtime, row):
    import base64

    from app.nodes.client import ZagrosNodeClient

    if row.agent_type != "zagros_native" or not row.agent_identity \
            or not row.agent_credentials_enc:
        raise ValueError("node is not a registered native Zagros agent")
    credentials = runtime.cipher.decrypt_json(
        row.agent_credentials_enc, aad=f"node-agent:{row.agent_identity}")
    key = base64.b64decode(credentials["signing_key"])
    cert = str((row.settings_json or {}).get("certificate_pem") or "")
    if len(key) != 32 or not cert:
        raise ValueError("node credentials are incomplete")
    return ZagrosNodeClient(
        row.address, row.port, row.agent_identity, key, cert)


def _native_node_row(runtime, node_id: int):
    from app.persistence.models import NodeModel

    with runtime.session_factory() as session:
        row = session.get(NodeModel, node_id)
        if row is None or row.agent_type != "zagros_native":
            return None
        session.expunge(row)
        return row


@zagros_admin_router.get("/nodes")
async def native_nodes_list(runtime=Depends(get_runtime)):
    from sqlalchemy import select
    from app.persistence.models import NodeModel

    def load():
        with runtime.session_factory() as session:
            rows = session.execute(select(NodeModel).where(
                NodeModel.agent_type == "zagros_native")).scalars().all()
            return [_native_node_view(row) for row in rows]
    return {"nodes": await asyncio.to_thread(load)}


@zagros_admin_router.post("/nodes/pending")
async def native_node_pending(body: NativeNodePendingBody, request: Request,
                              runtime=Depends(get_runtime)):
    """Reserve a Node and return its one-time installer command.

    The bearer credential is returned exactly once and only its digest is
    committed. It is intentionally absent from the Node row and settings.
    """
    import hashlib
    from datetime import timedelta

    from sqlalchemy import select
    from app.persistence.models import NodeModel, PendingNodeRegistrationModel

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=body.expires_in_seconds)

    def persist():
        with runtime.session_factory() as session:
            if session.scalar(select(NodeModel.id).where(NodeModel.name == body.name)):
                raise ValueError(f"node '{body.name}' already exists")
            row = NodeModel(
                name=body.name, address=body.address, port=body.api_port,
                status="pending", usage_coefficient=body.usage_coefficient,
                agent_type="zagros_native", settings_json={},
            )
            session.add(row)
            session.flush()
            pending = PendingNodeRegistrationModel(
                node_id=row.id, token_hash=digest, status="pending",
                created_at=now, expires_at=expires,
            )
            session.add(pending)
            session.commit()
            session.refresh(pending)
            return row.id, pending.id

    try:
        node_id, pending_id = await asyncio.to_thread(persist)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

    master_url = str(request.base_url).rstrip("/")
    args = [
        "install", "--name", body.name, "--address", body.address,
        "--port", str(body.api_port), "--master-url", master_url,
        "--pending-id", str(pending_id), "--registration-token", token,
    ]
    command = (
        "curl -fsSL "
        "https://raw.githubusercontent.com/ZagrosGM/zagros-node/main/install.sh "
        "| sudo bash -s -- " + " ".join(shlex.quote(value) for value in args)
    )
    return {
        "node_id": node_id, "pending_id": pending_id,
        "expires_at": expires, "installer_command": command,
    }


@zagros_admin_router.delete("/nodes/{node_id}/pending")
async def native_node_pending_revoke(node_id: int, runtime=Depends(get_runtime)):
    from sqlalchemy import select
    from app.persistence.models import PendingNodeRegistrationModel

    def revoke():
        with runtime.session_factory() as session:
            row = session.scalar(select(PendingNodeRegistrationModel).where(
                PendingNodeRegistrationModel.node_id == node_id))
            if row is None:
                return False
            if row.status == "consumed":
                raise ValueError("registration was already consumed")
            row.status = "revoked"
            row.revoked_at = datetime.now(timezone.utc)
            session.commit()
            return True
    try:
        found = await asyncio.to_thread(revoke)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if not found:
        raise HTTPException(404, "pending registration not found")
    return {"ok": True, "status": "revoked"}


@zagros_router.post("/api/zagros/node-registration/callback")
async def native_node_registration_callback(body: NativeNodeCallbackBody,
                                            runtime=Depends(get_runtime)):
    """Token-authenticated callback used by the unattended installer."""
    import base64
    import hashlib
    import hmac

    from sqlalchemy import select
    from app.nodes.client import NodeClientError, ZagrosNodeClient, fetch_pinned_certificate
    from app.persistence.models import NodeModel, PendingNodeRegistrationModel

    supplied_hash = hashlib.sha256(
        body.registration_token.get_secret_value().encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)

    def reserve():
        with runtime.session_factory() as session:
            pending = session.get(PendingNodeRegistrationModel, body.pending_id)
            if pending is None or not hmac.compare_digest(pending.token_hash, supplied_hash):
                return None, "invalid registration credential"
            if pending.status != "pending" or pending.consumed_at or pending.revoked_at:
                return None, "registration credential is not active"
            if pending.expires_at <= now:
                pending.status = "expired"
                session.commit()
                return None, "registration credential has expired"
            pending.status = "registering"
            node = session.get(NodeModel, pending.node_id)
            session.commit()
            session.expunge(node)
            return node, None

    node, error = await asyncio.to_thread(reserve)
    if error:
        raise HTTPException(401, error)
    try:
        certificate_pem, fingerprint = await asyncio.to_thread(
            fetch_pinned_certificate, node.address, node.port,
            body.certificate_fingerprint)
        client = ZagrosNodeClient(node.address, node.port, None, None, certificate_pem)
        panel_id = "panel-" + hashlib.sha256(runtime.cipher._key).hexdigest()[:24]
        registration = await asyncio.to_thread(
            client.register, panel_id, body.bootstrap_token.get_secret_value())
        node_identity = str(registration["node_id"])
        signing_key = base64.b64decode(registration["signing_key"])
        if len(signing_key) != 32:
            raise NodeClientError("agent returned an invalid signing key")
        encrypted = runtime.cipher.encrypt_json(
            {"signing_key": base64.b64encode(signing_key).decode("ascii")},
            aad=f"node-agent:{node_identity}")
    except Exception as exc:
        def release():
            with runtime.session_factory() as session:
                pending = session.get(PendingNodeRegistrationModel, body.pending_id)
                if pending and pending.status == "registering":
                    pending.status = "pending" if pending.expires_at > datetime.now(timezone.utc) else "expired"
                    session.commit()
        await asyncio.to_thread(release)
        raise HTTPException(422, f"node registration failed: {str(exc)[:300]}") from exc

    def complete():
        with runtime.session_factory() as session:
            pending = session.get(PendingNodeRegistrationModel, body.pending_id)
            current = session.get(NodeModel, pending.node_id) if pending else None
            if pending is None or current is None or pending.status != "registering":
                raise ValueError("registration reservation was lost")
            duplicate = session.scalar(select(NodeModel.id).where(
                NodeModel.agent_identity == node_identity,
                NodeModel.id != current.id))
            if duplicate:
                raise ValueError("this node identity is already registered")
            current.status = "connected"
            current.agent_identity = node_identity
            current.certificate_fingerprint = fingerprint
            current.agent_credentials_enc = encrypted
            current.last_seen = datetime.now(timezone.utc)
            current.settings_json = {
                "certificate_pem": certificate_pem,
                "agent_version": body.agent_version,
            }
            pending.status = "consumed"
            pending.consumed_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(current)
            return _native_node_view(current)
    try:
        return await asyncio.to_thread(complete)
    except Exception as exc:
        try:
            registered = ZagrosNodeClient(node.address, node.port, node_identity,
                                          signing_key, certificate_pem)
            await asyncio.to_thread(registered.revoke)
        except Exception:  # noqa: BLE001
            pass
        raise HTTPException(500, "registration persistence failed; remote authority revoked") from exc


@zagros_admin_router.post("/nodes/register")
async def native_node_register(body: NativeNodeRegisterBody,
                               runtime=Depends(get_runtime)):
    import base64
    import hashlib
    from datetime import datetime, timezone

    from sqlalchemy import select
    from app.nodes.client import (
        NodeClientError, ZagrosNodeClient, fetch_pinned_certificate)
    from app.persistence.models import NodeModel

    def duplicate_name() -> bool:
        with runtime.session_factory() as session:
            return session.scalar(select(NodeModel.id).where(
                NodeModel.name == body.name)) is not None
    if await asyncio.to_thread(duplicate_name):
        raise HTTPException(409, f"node '{body.name}' already exists")

    try:
        certificate_pem, fingerprint = await asyncio.to_thread(
            fetch_pinned_certificate, body.address, body.port,
            body.certificate_fingerprint)
        client = ZagrosNodeClient(
            body.address, body.port, None, None, certificate_pem)
        panel_id = "panel-" + hashlib.sha256(runtime.cipher._key).hexdigest()[:24]
        registration = await asyncio.to_thread(
            client.register, panel_id, body.registration_token.get_secret_value())
        node_identity = str(registration["node_id"])
        signing_key = base64.b64decode(registration["signing_key"])
        if len(signing_key) != 32:
            raise NodeClientError("agent returned an invalid signing key")
    except (NodeClientError, KeyError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc

    encrypted = runtime.cipher.encrypt_json(
        {"signing_key": base64.b64encode(signing_key).decode("ascii")},
        aad=f"node-agent:{node_identity}")

    def persist():
        with runtime.session_factory() as session:
            if session.scalar(select(NodeModel).where(NodeModel.name == body.name)):
                raise ValueError(f"node '{body.name}' already exists")
            if session.scalar(select(NodeModel).where(
                    NodeModel.agent_identity == node_identity)):
                raise ValueError("this node identity is already registered")
            row = NodeModel(
                name=body.name, address=body.address, port=body.port,
                status="connected", usage_coefficient=body.usage_coefficient,
                agent_type="zagros_native", agent_identity=node_identity,
                certificate_fingerprint=fingerprint,
                agent_credentials_enc=encrypted,
                settings_json={"certificate_pem": certificate_pem},
                last_seen=datetime.now(timezone.utc),
            )
            session.add(row); session.commit(); session.refresh(row)
            return _native_node_view(row)
    try:
        return await asyncio.to_thread(persist)
    except Exception as exc:
        # Registration was consumed but persistence failed (duplicate race,
        # database outage, constraint failure). Revoke the newly issued key so
        # no orphan panel authority remains. If revocation itself fails, never
        # claim the operation rolled back cleanly.
        revoked = False
        try:
            registered = ZagrosNodeClient(
                body.address, body.port, node_identity, signing_key,
                certificate_pem)
            await asyncio.to_thread(registered.revoke)
            revoked = True
        except Exception:  # noqa: BLE001
            pass
        if isinstance(exc, ValueError):
            raise HTTPException(409, str(exc)) from exc
        detail = ("node registration persistence failed; remote authority revoked"
                  if revoked else
                  "node registration persistence failed and remote revocation could not be confirmed; isolate the node")
        raise HTTPException(500, detail) from exc


@zagros_admin_router.post("/nodes/{node_id}/heartbeat")
async def native_node_heartbeat(node_id: int, runtime=Depends(get_runtime)):
    from datetime import datetime, timezone
    from app.persistence.models import NodeModel

    row = await asyncio.to_thread(_native_node_row, runtime, node_id)
    if row is None:
        raise HTTPException(404, "native node not found")
    try:
        client = _native_node_client(runtime, row)
        heartbeat, health, cores = await asyncio.gather(
            asyncio.to_thread(client.heartbeat),
            asyncio.to_thread(client.health),
            asyncio.to_thread(client.cores),
        )
    except Exception as exc:
        def failed():
            with runtime.session_factory() as session:
                current = session.get(NodeModel, node_id)
                if current:
                    current.status = "error"
                    current.settings_json = {
                        **(current.settings_json or {}),
                        "last_error": f"{type(exc).__name__}: {str(exc)[:300]}",
                    }
                    session.commit()
        await asyncio.to_thread(failed)
        raise HTTPException(502, str(exc)) from exc

    def persist():
        with runtime.session_factory() as session:
            current = session.get(NodeModel, node_id)
            current.status = "connected"
            current.last_seen = datetime.now(timezone.utc)
            current.settings_json = {
                **(current.settings_json or {}),
                "health": health, "cores": cores,
            }
            session.commit(); session.refresh(current)
            return _native_node_view(current)
    view = await asyncio.to_thread(persist)
    view["heartbeat"] = heartbeat
    return view


@zagros_admin_router.post("/nodes/{node_id}/cores/{core_id}/lifecycle")
async def native_node_core_lifecycle(node_id: int, core_id: str,
                                     body: NativeNodeLifecycleBody,
                                     runtime=Depends(get_runtime)):
    allowed = {"install", "uninstall", "start", "stop", "restart"}
    if body.action not in allowed:
        raise HTTPException(422, f"action must be one of {sorted(allowed)}")
    row = await asyncio.to_thread(_native_node_row, runtime, node_id)
    if row is None:
        raise HTTPException(404, "native node not found")
    try:
        return await asyncio.to_thread(
            _native_node_client(runtime, row).lifecycle,
            core_id, body.action, settings=body.settings,
            purge=body.purge, force=body.force)
    except Exception as exc:
        raise HTTPException(502, str(exc)) from exc


@zagros_admin_router.get("/nodes/{node_id}/cores/{core_id}/logs")
async def native_node_core_logs(node_id: int, core_id: str, tail: int = 200,
                                runtime=Depends(get_runtime)):
    row = await asyncio.to_thread(_native_node_row, runtime, node_id)
    if row is None:
        raise HTTPException(404, "native node not found")
    try:
        return await asyncio.to_thread(
            _native_node_client(runtime, row).core_logs,
            core_id, max(1, min(tail, 2000)))
    except Exception as exc:
        raise HTTPException(502, str(exc)) from exc


class NativeNodeInboundBody(BaseModel):
    document: dict[str, Any]


@zagros_admin_router.put("/nodes/{node_id}/cores/{core_id}/inbounds")
async def native_node_core_inbounds(node_id: int, core_id: str,
                                    body: NativeNodeInboundBody,
                                    runtime=Depends(get_runtime)):
    row = await asyncio.to_thread(_native_node_row, runtime, node_id)
    if row is None:
        raise HTTPException(404, "native node not found")
    try:
        return await asyncio.to_thread(
            _native_node_client(runtime, row).apply_inbounds,
            core_id, body.document)
    except Exception as exc:
        raise HTTPException(502, str(exc)) from exc


@zagros_admin_router.delete("/nodes/{node_id}")
async def native_node_delete(node_id: int, force: bool = False,
                             runtime=Depends(get_runtime)):
    from app.persistence.models import NodeModel

    row = await asyncio.to_thread(_native_node_row, runtime, node_id)
    if row is None:
        raise HTTPException(404, "native node not found")
    remote_revoked = False
    # A pending row has no remote authority yet; deleting it cascades and
    # revokes its hashed enrollment credential without touching Node data.
    if row.agent_identity:
        try:
            await asyncio.to_thread(_native_node_client(runtime, row).revoke)
            remote_revoked = True
        except Exception as exc:
            if not force:
                raise HTTPException(
                    502, f"node key revocation failed; use force only after isolating the node: {exc}") from exc
    def remove():
        with runtime.session_factory() as session:
            current = session.get(NodeModel, node_id)
            if current:
                session.delete(current); session.commit()
    await asyncio.to_thread(remove)
    return {"deleted": node_id, "remote_revoked": remote_revoked}


async def _account_target_write(runtime, node_row, user, account: dict,
                                *, create: bool) -> dict:
    """Write account to Master or one registered Node and return final settings."""
    from app.cores.types import UserAccount

    settings = dict(account.get("settings") or {})
    if node_row is not None:
        result = await asyncio.to_thread(
            _native_node_client(runtime, node_row).provision_account,
            account["core_id"], account["account_id"], user_id=user.id,
            username=user.username, protocol=account["protocol"],
            enabled=account["enabled"], settings=settings, create=create)
        return dict(result.get("settings") or settings)
    driver = runtime.core_manager.get(account["core_id"])
    model = UserAccount(
        user_id=user.id, username=user.username,
        account_id=account["account_id"], protocol=account["protocol"],
        enabled=account["enabled"], settings=settings)
    if create:
        await driver.create_account(model)
    else:
        await driver.update_account(model)
    return dict(model.settings)


async def _account_target_delete(runtime, node_row, account: dict) -> None:
    if node_row is not None:
        await asyncio.to_thread(
            _native_node_client(runtime, node_row).delete_account,
            account["core_id"], account["account_id"])
    else:
        await runtime.core_manager.get(account["core_id"]).delete_account(
            account["account_id"])


@zagros_admin_router.get("/users/{username}/node")
async def user_node_assignment(username: str, runtime=Depends(get_runtime)):
    user = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    if user is None:
        raise HTTPException(404, "user not found")
    node = (await asyncio.to_thread(_native_node_row, runtime, user.node_id)
            if user.node_id is not None else None)
    return {"username": username, "node_id": user.node_id,
            "target": "node" if node else "master",
            "node": _native_node_view(node) if node else None}


@zagros_admin_router.put("/users/{username}/node")
async def user_node_assign(username: str, body: UserNodeAssignmentBody,
                           runtime=Depends(get_runtime)):
    """Move every account with compensating rollback, then commit assignment."""
    user = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    if user is None:
        raise HTTPException(404, "user not found")
    if user.node_id == body.node_id:
        return {"username": username, "node_id": body.node_id,
                "migrated_accounts": 0}
    old_node = (await asyncio.to_thread(_native_node_row, runtime, user.node_id)
                if user.node_id is not None else None)
    new_node = (await asyncio.to_thread(_native_node_row, runtime, body.node_id)
                if body.node_id is not None else None)
    if body.node_id is not None and (new_node is None or new_node.status != "connected"):
        raise HTTPException(409, "target Node is not connected")
    accounts = await asyncio.to_thread(runtime.users.accounts_of, user.id)
    moved: list[tuple[dict, dict]] = []
    try:
        for account in accounts:
            original = dict(account.get("settings") or {})
            generated = await _account_target_write(
                runtime, new_node, user, account, create=True)
            try:
                await _account_target_delete(runtime, old_node, account)
            except Exception:
                rollback_account = {**account, "settings": generated}
                try:
                    await _account_target_delete(runtime, new_node, rollback_account)
                except Exception:  # noqa: BLE001 — preserve original exception
                    pass
                raise
            await asyncio.to_thread(
                runtime.users.upsert_core_account,
                user_id=user.id, core_id=account["core_id"],
                account_id=account["account_id"], protocol=account["protocol"],
                enabled=account["enabled"], settings=generated,
                node_id=body.node_id)
            moved.append((account, original))
        await asyncio.to_thread(runtime.users.set_node, user.id, body.node_id)
    except Exception as exc:
        # Compensate already completed account moves in reverse order.
        for account, original in reversed(moved):
            current = {**account, "settings": original}
            try:
                restored = await _account_target_write(
                    runtime, old_node, user, current, create=True)
                await _account_target_delete(runtime, new_node, current)
                await asyncio.to_thread(
                    runtime.users.upsert_core_account,
                    user_id=user.id, core_id=account["core_id"],
                    account_id=account["account_id"], protocol=account["protocol"],
                    enabled=account["enabled"], settings=restored,
                    node_id=user.node_id)
            except Exception as rollback_exc:  # noqa: BLE001
                logging.getLogger("zagros.node_assignment").critical(
                    "account migration rollback failed for %s/%s: %s",
                    account["core_id"], account["account_id"], rollback_exc)
        raise HTTPException(409, f"Node assignment migration failed: {exc}") from exc
    return {"username": username, "node_id": body.node_id,
            "target": "node" if body.node_id is not None else "master",
            "migrated_accounts": len(accounts)}


# --------------------------------------------------------------------- #
# users: multi-core online states (item 14)
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/users/online")
async def users_online_states(runtime=Depends(get_runtime)):
    """Per-user MULTI-CORE online states for the dashboard presence dot.

    * ``online`` — the freshest device-limit collect saw ≥1 session/presence
      for the user on ANY core (or the legacy xray flow touched online_at
      within the window);
    * ``offline`` — no session anywhere AND ≥1 online-capable core actually
      answered its read and NO probe failed;
    * ``unknown`` — ≥1 core failed its read in the last pass, OR NO
      online-capable core answered at all. A core without an online API
      must never fabricate 'offline': absence of evidence is not evidence
      of absence (alpha.7.5 item 15).
    """
    window = 90.0
    try:
        snapshot = (await runtime.kv.get_value("online.last_collect")) or {}
    except Exception:  # noqa: BLE001
        snapshot = {}
    online_ids = set(snapshot.get("online_user_ids") or [])
    failed = list(snapshot.get("failed_cores") or [])
    # snapshots predating the diagnostic field carry no count: treat a
    # missing count as "nothing answered" (honest, never a fake offline)
    probed = snapshot.get("probed_cores")
    probed = int(probed) if probed is not None else 0

    def _fresh_usernames() -> set[str]:
        now = datetime.now(timezone.utc)
        out: set[str] = set()
        try:
            from app.db import GetDB
            from app.db.models import User as LegacyUser

            with GetDB() as db:
                rows = db.query(LegacyUser.username, LegacyUser.online_at).all()
        except Exception:  # noqa: BLE001 — legacy store optional
            return out
        for username, online_at in rows:
            if not online_at:
                continue
            seen = online_at.replace(tzinfo=timezone.utc) \
                if online_at.tzinfo is None else online_at
            if (now - seen).total_seconds() <= window:
                out.add(username)
        return out

    def _pid_username_map() -> dict[int, str]:
        return {row.id: row.username for row in runtime.users.list_users(limit=100000)}

    fresh = await asyncio.to_thread(_fresh_usernames)
    try:
        pid_map = await asyncio.to_thread(_pid_username_map)
    except Exception:  # noqa: BLE001
        pid_map = {}
    states: dict[str, str] = {}
    for pid, username in pid_map.items():
        if pid in online_ids or username in fresh:
            states[username] = "online"
        elif failed or probed == 0:
            # failed read → state unknowable; no answering online API on
            # this deployment → equally unknowable (item 15)
            states[username] = "unknown"
        else:
            states[username] = "offline"
    return {"states": states, "collect_ts": snapshot.get("ts"),
            "failed_cores": failed, "probed_cores": probed,
            "window_seconds": int(window)}


# --------------------------------------------------------------------- #
# panel network settings — validated DB desired state + host-agent apply
# --------------------------------------------------------------------- #

def _panel_network_runtime_settings(runtime):
    """Actual process/.env network state, independent of staged DB desired state."""
    import config
    from app.platform.network_settings import PanelNetworkSettings

    scheme = "https" if config.TLS_MODE == "on" else "http"
    certificate_id = None
    configured_cert = str(getattr(config, "UVICORN_SSL_CERTFILE", "") or "")
    if scheme == "https" and configured_cert:
        try:
            wanted = Path(configured_cert).resolve()
            found = next((item for item in certificates.scan(
                _data_dir(runtime), managed_only=True)
                if Path(item.path).resolve() == wanted), None)
            certificate_id = found.id if found else None
        except OSError:
            certificate_id = None
    values = {
        "domain": config.DOMAIN or None,
        "port": int(config.UVICORN_PORT),
        "scheme": scheme,
        "bind_address": config.UVICORN_HOST,
        "trusted_proxies": [],
        "tls_certificate_id": certificate_id,
    }
    if scheme == "https" and not certificate_id:
        # Read-only representation of a historical/external TLS path. A future
        # Apply refuses it as a rollback baseline until the cert is imported.
        return PanelNetworkSettings.model_construct(**values)
    return PanelNetworkSettings.model_validate(values)


async def _panel_network_settings(runtime):
    from app.platform.network_settings import PanelNetworkSettings

    raw = await runtime.kv.get_value(_PANEL_NETWORK_KEY)
    if raw:
        return PanelNetworkSettings.model_validate(raw)
    return _panel_network_runtime_settings(runtime)


def _validate_network_certificate(runtime, settings) -> None:
    ident = (settings.tls_certificate_id or "").strip()
    if not ident:
        return
    inventory = certificates.scan(_data_dir(runtime), managed_only=True)
    found = next((item for item in inventory
                  if item.id == ident or item.name == ident), None)
    if found is None:
        raise ValueError(f"TLS certificate '{ident}' does not exist")
    if found.expired or not found.has_key:
        raise ValueError(f"TLS certificate '{ident}' is expired or has no private key")
    hostname = settings.domain
    if hostname and not certificates.certificate_covers(found.path, hostname):
        raise ValueError(
            f"TLS certificate '{ident}' does not cover panel hostname '{hostname}'")


async def _validate_panel_port_ownership(runtime, settings) -> list[dict[str, Any]]:
    import config
    from app.platform.network_settings import detect_port_conflicts

    conflicts = await detect_port_conflicts(
        runtime, settings, current_panel_port=int(config.UVICORN_PORT))
    if conflicts:
        raise HTTPException(409, conflicts[0].message())
    return [item.model_dump(mode="json") for item in conflicts]


async def _reconcile_panel_network_transaction(runtime) -> dict[str, Any] | None:
    """Commit/rollback DB desired state from the root agent's final result."""
    from app.platform.network_settings import HostNetworkRequest

    pending = await runtime.kv.get_value(_PANEL_NETWORK_PENDING_KEY)
    if not isinstance(pending, dict) or not pending.get("operation_id"):
        return None
    result = HostNetworkRequest().status(str(pending["operation_id"]))
    status = result.get("status")
    if status == "success":
        # Candidate was staged before the recreate so the new process sees a
        # coherent source of truth. Success finalizes it as rollback baseline.
        await runtime.kv.set_value(
            _PANEL_NETWORK_APPLIED_KEY, dict(pending.get("candidate") or {}))
        await runtime.kv.set_value(_PANEL_NETWORK_PENDING_KEY, None)
    elif status == "failed":
        await runtime.kv.set_value(
            _PANEL_NETWORK_KEY, dict(pending.get("previous") or {}))
        await runtime.kv.set_value(_PANEL_NETWORK_PENDING_KEY, None)
    return result


@zagros_admin_router.get("/settings/panel-network")
async def panel_network_get(runtime=Depends(get_runtime)):
    await _reconcile_panel_network_transaction(runtime)
    return (await _panel_network_settings(runtime)).model_dump(mode="json")


@zagros_admin_router.post("/settings/panel-network/test")
async def panel_network_test(body: dict[str, Any], runtime=Depends(get_runtime)):
    from app.platform.network_settings import PanelNetworkSettings

    try:
        settings = PanelNetworkSettings.model_validate(body)
        _validate_network_certificate(runtime, settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    await _validate_panel_port_ownership(runtime, settings)
    return {
        "ok": True,
        "public_url": settings.public_url(),
        "bind": f"{settings.bind_address}:{settings.port}",
        "tls": settings.scheme == "https",
        "certificate": settings.tls_certificate_id,
        "trusted_proxy_count": len(settings.trusted_proxies),
        "apply_mode": "host-agent-atomic-recreate",
    }


@zagros_admin_router.put("/settings/panel-network")
async def panel_network_save(body: dict[str, Any], runtime=Depends(get_runtime)):
    from app.platform.network_settings import PanelNetworkSettings

    await _reconcile_panel_network_transaction(runtime)
    if await runtime.kv.get_value(_PANEL_NETWORK_PENDING_KEY):
        raise HTTPException(409, "a panel network Apply transaction is still pending")
    try:
        settings = PanelNetworkSettings.model_validate(body)
        _validate_network_certificate(runtime, settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    await runtime.kv.set_value(_PANEL_NETWORK_KEY, settings.model_dump(mode="json"))
    return {"ok": True, "settings": settings.model_dump(mode="json")}


async def _panel_network_apply_locked(body: dict[str, Any], runtime):
    from app.platform.network_settings import HostNetworkRequest, PanelNetworkSettings

    await _reconcile_panel_network_transaction(runtime)
    if await runtime.kv.get_value(_PANEL_NETWORK_PENDING_KEY):
        raise HTTPException(409, "a panel network Apply transaction is still pending")
    try:
        settings = PanelNetworkSettings.model_validate(body)
        _validate_network_certificate(runtime, settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    await _validate_panel_port_ownership(runtime, settings)
    requester = HostNetworkRequest()
    if not requester.agent_ready():
        raise HTTPException(
            503,
            "Zagros host network agent is not installed; Apply cannot mutate desired state")
    applied = await runtime.kv.get_value(_PANEL_NETWORK_APPLIED_KEY)
    previous_model = (PanelNetworkSettings.model_validate(applied)
                      if applied else _panel_network_runtime_settings(runtime))
    if previous_model.scheme == "https" and not previous_model.tls_certificate_id:
        raise HTTPException(
            409,
            "current HTTPS certificate is not in the managed certificate store; "
            "import/select it before Apply so rollback is possible")
    previous = previous_model.model_dump(mode="json")
    candidate = settings.model_dump(mode="json")
    # Stage the DB transaction before publishing the atomic host request: a
    # watcher can never recreate the panel into a candidate the new process
    # cannot read. Request failure restores synchronously; host failure is
    # reconciled from its signed-by-filesystem result on status/settings read.
    operation = secrets.token_hex(16)
    await runtime.kv.set_value(_PANEL_NETWORK_PENDING_KEY, {
        "operation_id": operation, "previous": previous,
        "candidate": candidate,
    })
    await runtime.kv.set_value(_PANEL_NETWORK_KEY, candidate)
    try:
        accepted = requester.request(settings, operation_id=operation)
    except RuntimeError as exc:
        await runtime.kv.set_value(_PANEL_NETWORK_KEY, previous)
        await runtime.kv.set_value(_PANEL_NETWORK_PENDING_KEY, None)
        raise HTTPException(503, str(exc)) from exc
    return accepted


@zagros_admin_router.post("/settings/panel-network/apply")
async def panel_network_apply(body: dict[str, Any], runtime=Depends(get_runtime)):
    lock = getattr(runtime, "_panel_network_apply_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        runtime._panel_network_apply_lock = lock
    async with lock:
        return await _panel_network_apply_locked(body, runtime)


@zagros_admin_router.get("/settings/panel-network/apply-status")
async def panel_network_apply_status(operation_id: str | None = None,
                                     runtime=Depends(get_runtime)):
    from app.platform.network_settings import HostNetworkRequest

    reconciled = await _reconcile_panel_network_transaction(runtime)
    if reconciled is not None and (
            not operation_id or reconciled.get("operation_id") == operation_id):
        return reconciled
    return HostNetworkRequest().status(operation_id)


# --------------------------------------------------------------------- #
# panel info
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/panel/info")
async def panel_info(runtime=Depends(get_runtime)):
    import config
    from app import __version__

    return {
        "version": __version__,
        "app_name": config.ZAGROS_APP_NAME,
        "domain": config.DOMAIN,
        "panel_base_url": config.PANEL_BASE_URL,
        "app_base_url": config.APP_BASE_URL,
        "client_auth_mode": config.ZAGROS_CLIENT_AUTH_MODE,
        "subscription_path": config.SUBSCRIPTION_PATH,
        "tls_mode": config.TLS_MODE,
        "uptime_seconds": round(time.monotonic() - _STARTED_MONO, 1),
        "database_driver": (runtime.database_url.split(":", 1)[0]
                            if ":" in runtime.database_url else "unknown"),
    }


# --------------------------------------------------------------------- #
# host settings (alpha.7.2, item 13) — Marzban-parity, panel-native
# --------------------------------------------------------------------- #
#
# ONE feature, TWO storage backends, honest by construction:
#   * xray       → the legacy ``hosts`` table. The xray driver's delivery
#                  path already expands links per legacy host entry
#                  (Marzban byte-parity); these endpoints manage exactly
#                  that table and refresh ``xray.hosts`` after writes.
#   * every other core → the P3 ``core_hosts`` table consumed by the
#                  cross-core Host Settings engine at the delivery layer.
# Priority (item 13): an entry's position inside its tag's list IS its
# priority — persisted (core_hosts.sort / row order) and honored by both
# expansion paths.

class HostEntryBody(BaseModel):
    """One host variant — the full Marzban-parity field set."""

    remark: str = ""
    address: str = ""
    port: int | None = None
    sni: str | None = None
    host: str | None = None
    path: str | None = None
    security: str | None = None           # inbound_default / none / tls
    alpn: str | None = None
    fingerprint: str | None = None
    allowinsecure: bool | None = None
    is_disabled: bool = False
    mux_enable: bool = False
    fragment_setting: str | None = None
    noise_setting: str | None = None
    random_user_agent: bool = False
    use_sni_as_host: bool = False

    model_config = {"extra": "allow"}     # unrecognized attrs round-trip


class HostsPutBody(BaseModel):
    hosts: dict[str, list[HostEntryBody]]


_HOST_SECURITIES = {"inbound_default", "none", "tls"}


def _normalize_security(value: str | None) -> str:
    """Return the explicit non-null state required by legacy ProxyHost.

    Older dashboard builds sent ``null`` for ``inbound_default`` and empty TLS
    hints.  HostEntryBody accepts that compatibility input, but the Xray model
    is backed by non-null enums; normalize at the API boundary so old and new
    clients persist one canonical wire shape.
    """
    if value is None or not value.strip():
        return "inbound_default"
    value = value.strip().lower()
    if value not in _HOST_SECURITIES:
        raise HTTPException(422, f"invalid security '{value}' — "
                            f"one of {sorted(_HOST_SECURITIES)} (or empty)")
    return value


def _validate_entry(e: HostEntryBody, *, for_xray: bool) -> None:
    if e.port is not None and not (1 <= e.port <= 65535):
        raise HTTPException(422, f"invalid port {e.port}")
    e.security = _normalize_security(e.security)
    # ALPN and fingerprint are enum-backed empty strings on Xray.  Never pass
    # a nullable compatibility value into ProxyHost validation.
    e.alpn = e.alpn or ""
    e.fingerprint = e.fingerprint or ""
    if for_xray:
        # the legacy columns are single-value enums — validate membership
        from app.models.proxy import ProxyHostALPN, ProxyHostFingerprint

        if e.alpn:
            try:
                ProxyHostALPN(e.alpn)
            except ValueError:
                raise HTTPException(422, f"invalid alpn '{e.alpn}'") from None
        if e.fingerprint:
            try:
                ProxyHostFingerprint(e.fingerprint)
            except ValueError:
                raise HTTPException(422, f"invalid fingerprint '{e.fingerprint}'") from None


def _entry_wire(e) -> dict[str, Any]:
    """HostEntry | HostEntryBody | legacy ProxyHost → one wire shape."""
    get = (lambda k, d=None: getattr(e, k, d))
    out = {
        "remark": get("remark", "") or "",
        "address": get("address", "") or "",
        "port": get("port"),
        "sni": get("sni"),
        "host": get("host") if get("host") is not None else get("host_header"),
        "path": get("path"),
        "security": get("security") or "inbound_default",
        "alpn": get("alpn") or "",
        "fingerprint": get("fingerprint") or "",
        "allowinsecure": get("allowinsecure"),
        "is_disabled": bool(get("is_disabled", False)),
        "mux_enable": bool(get("mux_enable", False)),
        "fragment_setting": get("fragment_setting"),
        "noise_setting": get("noise_setting"),
        "random_user_agent": bool(get("random_user_agent", False)),
        "use_sni_as_host": bool(get("use_sni_as_host", False)),
    }
    extras = getattr(e, "extras", None) or getattr(e, "model_extra", None) or {}
    out.update(extras)
    return out


async def _known_catalog(runtime) -> dict[str, Any]:
    from app.platform.inbounds import catalog as _catalog

    return {g.core_id: g for g in await _catalog(runtime)}


@zagros_admin_router.get("/cores/{core_id}/hosts/schema")
async def host_settings_schema(core_id: str, runtime=Depends(get_runtime)):
    """Item 16 — per-inbound FIELD MATRIX for the editor: which HostEntry
    fields this (core, protocol) pair can actually apply. The dashboard
    renders only those inputs instead of an xray-shaped one-size-fits-all
    (a WireGuard row no longer offers ALPN/fragment/fingerprint)."""
    from app.portal.hostengine import host_field_matrix

    groups = await _known_catalog(runtime)
    group = groups.get(core_id)
    if group is None:
        raise HTTPException(404, f"unknown core '{core_id}'")
    engine = None
    try:
        engine = runtime.core_manager.get(core_id).metadata.name
    except Exception:  # noqa: BLE001
        pass
    return {"core_id": core_id, "engine": engine, "inbounds": [
        {"tag": i.tag, "protocol": i.protocol,
         "fields": host_field_matrix(i.protocol, engine=engine)}
        for i in group.inbounds
    ]}


@zagros_admin_router.get("/cores/{core_id}/hosts")
async def host_settings_get(core_id: str, runtime=Depends(get_runtime)):
    """``{inbound_tag: [entries in priority order]}`` for one core."""
    if core_id == "xray":
        return _xray_hosts_get()
    groups = await _known_catalog(runtime)
    if core_id not in groups:
        raise HTTPException(404, f"unknown core '{core_id}'")
    grouped = await runtime.core_hosts.list_grouped(core_id)
    return {tag: [_entry_wire(e) for e in entries]
            for tag, entries in grouped.items()}


@zagros_admin_router.put("/cores/{core_id}/hosts")
async def host_settings_put(body: HostsPutBody, core_id: str,
                            runtime=Depends(get_runtime)):
    """Bulk-partial replace: only the listed tags are touched; an empty list
    clears a tag; every tag keeps its rows otherwise. List order is the
    priority (item 13)."""
    if core_id == "xray":
        return _xray_hosts_put(body)
    groups = await _known_catalog(runtime)
    if core_id not in groups:
        raise HTTPException(404, f"unknown core '{core_id}'")
    known_tags = {i.tag for i in groups[core_id].inbounds}
    for tag, entries in body.hosts.items():
        if tag not in known_tags:
            raise HTTPException(404, f"unknown inbound tag '{tag}' on core "
                                f"'{core_id}'")
        for e in entries:
            _validate_entry(e, for_xray=False)
    from app.portal.hostengine import HostEntry

    await runtime.core_hosts.replace_tags(core_id, {
        tag: [HostEntry(**{k: v for k, v in e.model_dump().items()
                           if k in HostEntry.__dataclass_fields__} | {"extras": e.model_extra or {}})
              for e in entries]
        for tag, entries in body.hosts.items()
    })
    grouped = await runtime.core_hosts.list_grouped(core_id)
    return {tag: [_entry_wire(e) for e in entries]
            for tag, entries in grouped.items()}


# ---- built-in xray: legacy hosts table, managed independently --------- #

def _xray_stack():
    try:
        from app import xray as _xray_mod  # noqa: PLC0415 — lazy by design
        from app.db import GetDB, crud     # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            503, f"the legacy xray stack is unavailable on this install: "
            f"{exc.__class__.__name__}") from exc
    return _xray_mod, GetDB, crud


def _xray_host_wire(row) -> dict[str, Any]:
    def _enum(v):
        return getattr(v, "value", v)
    return {
        "remark": row.remark or "",
        "address": row.address or "",
        "port": row.port,
        "sni": row.sni,
        "host": row.host,
        "path": row.path,
        "security": _enum(row.security) or "inbound_default",
        "alpn": _enum(row.alpn) or "",
        "fingerprint": _enum(row.fingerprint) or "",
        "allowinsecure": row.allowinsecure,
        "is_disabled": bool(row.is_disabled),
        "mux_enable": bool(row.mux_enable),
        "fragment_setting": row.fragment_setting,
        "noise_setting": row.noise_setting,
        "random_user_agent": bool(row.random_user_agent),
        "use_sni_as_host": bool(row.use_sni_as_host),
    }


def _xray_hosts_get() -> dict[str, list[dict[str, Any]]]:
    _xray_mod, GetDB, crud = _xray_stack()
    tags = [inb.get("tag")
            for items in _xray_mod.config.inbounds_by_protocol.values()
            for inb in items if isinstance(inb, dict) and inb.get("tag")]
    out: dict[str, list[dict[str, Any]]] = {}
    old_default = "🚀 Marz ({USERNAME}) [{PROTOCOL} - {TRANSPORT}]"
    new_default = "🛸 Zagros ({USERNAME}) [{PROTOCOL} - {TRANSPORT}]"
    with GetDB() as db:
        migrated = False
        for tag in dict.fromkeys(tags):
            rows = crud.get_hosts(db, tag)
            for row in rows:
                # Upgrade only the byte-exact former product default. Any
                # customized remark, including one mentioning Marz, is owned
                # by the admin and remains untouched.
                if row.remark == old_default and row.address == "{SERVER_IP}":
                    row.remark = new_default
                    migrated = True
            out[tag] = [_xray_host_wire(h) for h in rows]
        if migrated:
            db.commit()
    return out


def _xray_hosts_put(body: HostsPutBody) -> dict[str, list[dict[str, Any]]]:
    _xray_mod, GetDB, crud = _xray_stack()
    known_tags = {inb.get("tag")
                  for items in _xray_mod.config.inbounds_by_protocol.values()
                  for inb in items if isinstance(inb, dict)}
    for tag, entries in body.hosts.items():
        if tag not in known_tags:
            raise HTTPException(404, f"unknown xray inbound tag '{tag}'")
        for e in entries:
            _validate_entry(e, for_xray=True)
    from app.models.proxy import ProxyHost as ProxyHostModify

    with GetDB() as db:
        for tag, entries in body.hosts.items():
            models = []
            for e in entries:
                data = {k: v for k, v in e.model_dump().items() if k != "extras"}
                # legacy model carries enum instances, not raw strings
                try:
                    models.append(ProxyHostModify(**data))
                except Exception as exc:  # noqa: BLE001 — real validator error
                    raise HTTPException(422, str(exc)) from exc
            crud.update_hosts(db, tag, models)
    try:
        _xray_mod.hosts.update()          # delivery cache refresh
    except Exception:  # noqa: BLE001 — rows are persisted; cache refreshes on reload
        pass
    return _xray_hosts_get()
