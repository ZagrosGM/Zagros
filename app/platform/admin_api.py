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
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from app.cores.exceptions import CoreNotFoundError
from app.cores.outbounds.manager import OutboundManager
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.model import RoutingRule
from app.platform import certificates
from app.platform.routers import get_runtime, zagros_admin_router

_STARTED_MONO = time.monotonic()

_RULES_KEY = "admin.routing.rules.v1"
_OUTBOUNDS_KEY = "admin.outbounds.v1"


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
        "studio_inbounds_path": meta.studio_inbounds_path,
        "config_schema": meta.config_schema,
        "state": state_value or "installed",
        "enabled": bool(enabled),
        "builtin": core_id in BUILTIN_CORE_IDS,
        "settings": _mask_settings(driver.settings),
        "binary_path": binary_path,
        "health": None,
        "core_version": None,
        "message": None,
        "pid": None,
        "uptime_seconds": None,
        "metrics": None,
    }
    if status is not None:
        view.update({
            "health": status.health.value if isinstance(status.health, HealthStatus) else str(status.health),
            "core_version": status.core_version,
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


async def _manager_call(runtime, core_id: str, method: str, *args, **kwargs):
    manager = runtime.core_manager
    if core_id not in manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    fn = getattr(manager, method)
    try:
        return await fn(core_id, *args, **kwargs)
    except Exception as exc:
        raise _err(exc) from exc


@zagros_admin_router.post("/cores/{core_id}/install")
async def cores_install(core_id: str, body: CoreInstallBody, runtime=Depends(get_runtime)):
    from app.cores.registry import available_drivers

    if core_id not in available_drivers():
        raise HTTPException(404, f"unknown core '{core_id}' — see /cores/registry")
    try:
        state = await runtime.core_manager.install_core(
            core_id, body.settings, enabled=body.enabled)
    except Exception as exc:
        raise _err(exc) from exc
    return {"ok": True, "core": core_id, "state": state.value, "enabled": body.enabled}


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
    if not raw:
        return []
    return [Outbound.model_validate(item) for item in raw]


def _sync_manager(manager: OutboundManager, stored: list[Outbound]) -> None:
    """Reconcile the in-memory registry with the persisted set (idempotent)."""
    for existing in list(manager.list()):
        manager.unregister(existing.name)
    for outbound in stored:
        manager.register(outbound)


async def _save_outbounds(runtime, outbounds: list[Outbound]) -> list[Outbound]:
    names = [o.name for o in outbounds]
    if len(names) != len(set(names)):
        raise HTTPException(422, "duplicate outbound names are not allowed")
    await runtime.kv.set_value(
        _OUTBOUNDS_KEY, [o.model_dump(mode="json") for o in outbounds])
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


@zagros_admin_router.get("/routing/rules")
async def routing_list(runtime=Depends(get_runtime)):
    rules = await _load_rules(runtime)
    return {"rules": [r.model_dump(mode="json") for r in rules]}


class RoutingSetBody(BaseModel):
    rules: list[RoutingRule] = Field(default_factory=list)


@zagros_admin_router.put("/routing/rules")
async def routing_save(body: RoutingSetBody, runtime=Depends(get_runtime)):
    try:
        normalized = await _save_rules(runtime, body.rules)
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
        report = await runtime.routing_engine.preview(
            normalized, core_ids=body.core_ids, outbounds=outbounds)
    except Exception as exc:
        raise _err(exc) from exc
    return report.model_dump(mode="json")


@zagros_admin_router.post("/routing/deploy")
async def routing_deploy(body: RoutingBody, runtime=Depends(get_runtime)):
    try:
        normalized = await _save_rules(runtime, body.rules)
        outbounds = await _load_outbounds(runtime)
        _sync_manager(runtime.outbound_manager, outbounds)
        report = await runtime.routing_engine.deploy(
            normalized, core_ids=body.core_ids, outbounds=outbounds)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise _err(exc) from exc
    result = report.model_dump(mode="json")
    result["saved"] = True
    return result


# --------------------------------------------------------------------- #
# outbounds — persistent registry + live connectivity test
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/outbounds")
async def outbounds_list(runtime=Depends(get_runtime)):
    outbounds = await _load_outbounds(runtime)
    return {"outbounds": [o.model_dump(mode="json") for o in outbounds]}


class OutboundsSetBody(BaseModel):
    outbounds: list[Outbound] = Field(default_factory=list)


@zagros_admin_router.put("/outbounds")
async def outbounds_save(body: OutboundsSetBody, runtime=Depends(get_runtime)):
    try:
        saved = await _save_outbounds(runtime, body.outbounds)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ok": True, "count": len(saved)}


async def _test_outbound(runtime, outbound: Outbound) -> dict[str, Any]:
    """REAL reachability: TCP dial to server:port with latency for upstream
    kinds; registry/state checks for CORE chains; direct/sinks pass trivially."""
    if outbound.kind is OutboundKind.CORE:
        core_id = str(outbound.settings.get("core_id", ""))
        manager = runtime.core_manager
        if core_id not in manager.list_cores():
            return {"ok": False, "error": f"target core '{core_id}' is not installed",
                    "latency_ms": None}
        states = await runtime.core_state.load()
        state = states.get(core_id, {}).get("state", "installed")
        running = state == "running"
        return {"ok": running, "latency_ms": None,
                "detail": f"target core state: {state}"}
    if outbound.kind in (OutboundKind.DIRECT, OutboundKind.BLOCK,
                         OutboundKind.BLACKHOLE, OutboundKind.DNS):
        return {"ok": True, "latency_ms": None,
                "detail": f"'{outbound.kind.value}' needs no remote endpoint"}
    server = outbound.settings.get("server")
    port = outbound.settings.get("server_port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "latency_ms": None,
                "error": f"invalid server_port: {port!r}"}
    started = time.monotonic()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=6)
    except Exception as exc:  # noqa: BLE001 - dial failure IS the answer
        return {"ok": False, "latency_ms": None, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        latency = round((time.monotonic() - started) * 1000, 1)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001, S110 - close is best-effort cleanup
        pass
    return {"ok": True, "latency_ms": latency, "detail": f"tcp {server}:{port} reachable"}


@zagros_admin_router.post("/outbounds/test")
async def outbounds_test(body: Outbound, runtime=Depends(get_runtime)):
    return await _test_outbound(runtime, body)


# --------------------------------------------------------------------- #
# outbounds schema + share-url import + ovpn export (alpha.7)
# --------------------------------------------------------------------- #

@zagros_admin_router.get("/outbounds/schema")
async def outbounds_schema(runtime=Depends(get_runtime)):
    """Per-kind field schemas — the SPA builds its forms from THIS, never
    from a hardcoded template (transports + security matrices included)."""
    from app.cores.outbounds.profile_schema import outbound_schemas

    return {"schemas": outbound_schemas()}


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
    return {**parsed.model_dump(mode="json"), "supported_schemes": SUPPORTED_SCHEMES}


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
    try:
        content = _render_ovpn(name, outbound.settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return PlainTextResponse(
        content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'})


class OutboundDeployBody(BaseModel):
    outbounds: list[Outbound] = Field(default_factory=list)
    core_ids: list[str] | None = None


@zagros_admin_router.post("/outbounds/deploy")
async def outbounds_deploy(body: OutboundDeployBody, runtime=Depends(get_runtime)):
    try:
        await _save_outbounds(runtime, body.outbounds)  # registers into the manager
        report = await runtime.outbound_manager.deploy(core_ids=body.core_ids)
    except HTTPException:
        raise
    except Exception as exc:
        raise _err(exc) from exc
    result = report.model_dump(mode="json")
    result["saved"] = True
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


def _normalize_security(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None  # inbound default
    value = value.strip().lower()
    if value not in _HOST_SECURITIES:
        raise HTTPException(422, f"invalid security '{value}' — "
                            f"one of {sorted(_HOST_SECURITIES)} (or empty)")
    return value


def _validate_entry(e: HostEntryBody, *, for_xray: bool) -> None:
    if e.port is not None and not (1 <= e.port <= 65535):
        raise HTTPException(422, f"invalid port {e.port}")
    e.security = _normalize_security(e.security)
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
        "security": get("security"),
        "alpn": get("alpn"),
        "fingerprint": get("fingerprint"),
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
    with GetDB() as db:
        for tag in dict.fromkeys(tags):
            out[tag] = [_xray_host_wire(h) for h in crud.get_hosts(db, tag)]
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
