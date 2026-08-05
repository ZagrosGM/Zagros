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
from typing import Any

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from app.cores.outbounds.manager import OutboundManager, UnsupportedOutbound
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
    if state_value is None and status is not None:
        state_value = status.state.value if isinstance(status.state, CoreState) else str(status.state)
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


@zagros_admin_router.get("/cores/{core_id}")
async def cores_detail(core_id: str, runtime=Depends(get_runtime)):
    try:
        status = (await asyncio.wait_for(
            runtime.core_manager.get(core_id).status(), timeout=10))
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
    except Exception as exc:  # noqa: BLE001 - surface driver's real message
        raise _err(exc) from exc


@zagros_admin_router.post("/cores/{core_id}/install")
async def cores_install(core_id: str, body: CoreInstallBody, runtime=Depends(get_runtime)):
    from app.cores.registry import available_drivers

    if core_id not in available_drivers():
        raise HTTPException(404, f"unknown core '{core_id}' — see /cores/registry")
    try:
        state = await runtime.core_manager.install_core(
            core_id, body.settings, enabled=body.enabled)
    except Exception as exc:  # noqa: BLE001
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
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
    return {"ok": True, "core": core_id, "purged": body.purge}


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


@zagros_admin_router.get("/cores/{core_id}/logs")
async def cores_logs(core_id: str, lines: int = 200, runtime=Depends(get_runtime)):
    manager = runtime.core_manager
    if core_id not in manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    lines = max(10, min(lines, 2000))
    try:
        entries = await manager.get_logs(core_id, tail=lines)
    except Exception as exc:  # noqa: BLE001
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
    keep = {o.name: o for o in stored}
    for name in manager.list():
        if name.name not in keep:
            manager.unregister(name.name)
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
    except Exception as exc:  # noqa: BLE001 (CoreError on duplicates)
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
    except Exception as exc:  # noqa: BLE001
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
    except Exception as exc:  # noqa: BLE001
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
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=6)
    except Exception as exc:  # noqa: BLE001 - dial failure IS the answer
        return {"ok": False, "latency_ms": None, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        latency = round((time.monotonic() - started) * 1000, 1)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True, "latency_ms": latency, "detail": f"tcp {server}:{port} reachable"}


@zagros_admin_router.post("/outbounds/test")
async def outbounds_test(body: Outbound, runtime=Depends(get_runtime)):
    return await _test_outbound(runtime, body)


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
    except Exception as exc:  # noqa: BLE001
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
    return {"certificates": [c.model_dump(mode="json")
                             for c in certificates.scan(_data_dir(runtime))],
            "acme": {"available": False,
                     "status": "roadmap — Let's Encrypt / ACME automation is not implemented yet"}}


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


@zagros_admin_router.delete("/certificates/{name}")
async def certificates_remove(name: str, runtime=Depends(get_runtime)):
    try:
        certificates.remove(_data_dir(runtime), name)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ok": True, "removed": name}


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
