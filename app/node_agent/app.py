"""HTTPS control plane for the native Zagros multi-core node agent."""
from __future__ import annotations

import asyncio
import base64
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import psutil
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.cores.manager import CoreManager
from app.cores.registry import available_drivers, discover_builtin
from app.node_agent.security import (
    NodeIdentityStore,
    NodeSecurityError,
    ReplayGuard,
    verify_signature,
)
from app.node_agent.state import NodeCoreStateStore

NODE_ROOT = os.environ.get("ZAGROS_NODE_DATA", "/var/lib/zagros-node")
REGISTRATION_HASH = os.environ.get("ZAGROS_NODE_REGISTRATION_HASH", "")

identity = NodeIdentityStore(NODE_ROOT, REGISTRATION_HASH)
replays = ReplayGuard(NODE_ROOT)
discover_builtin()
def _node_driver_settings(_core_id: str, settings: dict[str, Any]) -> dict[str, Any]:
    # Explicit composition context; unlike a process-global environment flag,
    # this cannot make panel-owned driver instances select node backends.
    return {**settings, "_runtime_mode": "node"}


core_manager = CoreManager(
    NodeCoreStateStore(NODE_ROOT), builtin_core_ids=frozenset(),
    settings_transform=_node_driver_settings)
NODE_CORE_ALLOWLIST = frozenset({
    "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether"})


def _authorize_core(core_id: str, settings: dict[str, Any] | None = None) -> None:
    """Constrain signed authority to known adapters and schema-owned settings."""
    if core_id not in NODE_CORE_ALLOWLIST:
        raise HTTPException(403, f"core '{core_id}' is not in the node allowlist")
    if not settings:
        return
    from app.cores.registry import get_driver_class

    metadata = get_driver_class(core_id).metadata
    allowed = set((metadata.config_schema.get("properties") or {}).keys())
    allowed.update(metadata.default_settings)
    allowed.add("release_version")
    unknown = sorted(set(settings) - allowed)
    if unknown:
        raise HTTPException(422, f"settings are not allowlisted for {core_id}: {unknown}")
    root = Path("/var/lib/zagros").resolve()
    for key, value in settings.items():
        lowered = key.lower()
        if not isinstance(value, str) or not any(
                marker in lowered for marker in ("path", "root", "dir")):
            continue
        path = Path(value)
        if path.is_absolute() and root != path.resolve() and root not in path.resolve().parents:
            raise HTTPException(
                422, f"setting '{key}' must remain under /var/lib/zagros")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await core_manager.boot()
    await core_manager.start_enabled()
    yield
    await core_manager.stop_all()


app = FastAPI(title="Zagros Node Agent", version="1", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


class RegisterBody(BaseModel):
    panel_id: str = Field(min_length=8, max_length=128,
                          pattern=r"^[A-Za-z0-9._-]+$")
    registration_token: str = Field(min_length=16, max_length=512)


class CoreActionBody(BaseModel):
    action: Literal["install", "uninstall", "start", "stop", "restart"]
    settings: dict[str, Any] = Field(default_factory=dict)
    purge: bool = False
    force: bool = False


class InboundDocument(BaseModel):
    document: dict[str, Any]


@app.post("/v1/register")
async def register(body: RegisterBody, request: Request):
    # Production runner always configures TLS. An explicit test-only switch is
    # required to exercise this route over TestClient's in-memory HTTP.
    if request.url.scheme != "https" and os.environ.get(
            "ZAGROS_NODE_ALLOW_INSECURE_TEST") != "1":
        raise HTTPException(400, "node registration requires HTTPS")
    try:
        key = identity.register(body.registration_token, body.panel_id)
    except NodeSecurityError as exc:
        raise HTTPException(401, str(exc)) from exc
    return {
        "node_id": identity.node_id,
        # Returned once, over the certificate-pinned TLS registration channel.
        # It is a signing key, not the bootstrap token (which is burned).
        "signing_key": base64.b64encode(key).decode("ascii"),
        "agent": "zagros-node",
        "api_version": 1,
    }


async def signed_request(
    request: Request,
    x_zagros_node: str = Header(alias="X-Zagros-Node"),
    x_zagros_timestamp: str = Header(alias="X-Zagros-Timestamp"),
    x_zagros_nonce: str = Header(alias="X-Zagros-Nonce"),
    x_zagros_signature: str = Header(alias="X-Zagros-Signature"),
) -> str:
    key = identity.signing_key()
    if key is None or x_zagros_node != identity.node_id:
        raise HTTPException(401, "node is not registered for this signer")
    try:
        timestamp = int(x_zagros_timestamp)
        body = await request.body()
        verify_signature(
            key, x_zagros_signature, request.method, request.url.path,
            x_zagros_timestamp, x_zagros_nonce, body)
        replays.accept(x_zagros_nonce, timestamp)
    except (ValueError, NodeSecurityError) as exc:
        raise HTTPException(401, str(exc)) from exc
    return x_zagros_node


@app.get("/v1/heartbeat")
async def heartbeat(_node=Depends(signed_request)):
    return {"node_id": identity.node_id, "ts": int(time.time()),
            "agent": "zagros-node", "api_version": 1}


@app.post("/v1/revoke")
async def revoke(_node=Depends(signed_request)):
    identity.revoke()
    return {"revoked": True}


@app.get("/v1/health")
async def health(_node=Depends(signed_request)):
    disk = psutil.disk_usage(NODE_ROOT)
    memory = psutil.virtual_memory()
    return {
        "node_id": identity.node_id,
        "healthy": True,
        "resources": {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_total": memory.total,
            "memory_used": memory.used,
            "disk_total": disk.total,
            "disk_used": disk.used,
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
        },
    }


@app.get("/v1/cores")
async def cores(_node=Depends(signed_request)):
    statuses = await core_manager.status_all()
    by_id = {status.core_id: status.model_dump(mode="json") for status in statuses}
    return {
        "installed": by_id,
        "available": sorted(NODE_CORE_ALLOWLIST.intersection(available_drivers())),
    }


@app.get("/v1/cores/{core_id}")
async def core_status(core_id: str, _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    status = await core_manager.status(core_id)
    return status.model_dump(mode="json")


@app.get("/v1/cores/{core_id}/version")
async def core_version(core_id: str, _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    return (await core_manager.get(core_id).version()).model_dump(mode="json")


@app.get("/v1/cores/{core_id}/logs")
async def core_logs(core_id: str, tail: int = 200,
                    _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    lines = await asyncio.wait_for(
        core_manager.get_logs(core_id, tail=max(1, min(tail, 2000))), timeout=30)
    return {"core_id": core_id, "lines": lines}


@app.post("/v1/cores/{core_id}/lifecycle")
async def core_lifecycle(core_id: str, body: CoreActionBody,
                         _node=Depends(signed_request)):
    _authorize_core(core_id, body.settings)
    action = body.action
    timeout = 900 if action in ("install", "uninstall") else 90

    async def execute():
        if action == "install":
            await core_manager.install_core(core_id, settings=body.settings)
        elif action == "uninstall":
            await core_manager.uninstall_core(
                core_id, purge=body.purge, force=body.force)
        elif action == "start":
            await core_manager.start_core(core_id)
        elif action == "stop":
            await core_manager.stop_core(core_id)
        elif action == "restart":
            await core_manager.restart_core(core_id)

    try:
        await asyncio.wait_for(execute(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        identity.audit("core.timeout", {"core_id": core_id, "action": action})
        raise HTTPException(504, f"core {action} timed out") from exc
    except Exception as exc:
        identity.audit("core.failed", {
            "core_id": core_id, "action": action,
            "error_type": type(exc).__name__,
        })
        raise HTTPException(409, str(exc)) from exc
    identity.audit("core.lifecycle", {"core_id": core_id, "action": action})
    if action == "uninstall":
        return {"core_id": core_id, "state": "uninstalled"}
    return (await core_manager.status(core_id)).model_dump(mode="json")


@app.put("/v1/cores/{core_id}/inbounds")
async def core_inbounds(core_id: str, body: InboundDocument,
                        _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    try:
        await asyncio.wait_for(
            core_manager.apply_studio_document(core_id, body.document), timeout=90)
    except asyncio.TimeoutError as exc:
        raise HTTPException(504, "inbound apply timed out") from exc
    except Exception as exc:
        identity.audit("inbounds.failed", {
            "core_id": core_id, "error_type": type(exc).__name__})
        raise HTTPException(409, str(exc)) from exc
    identity.audit("inbounds.apply", {
        "core_id": core_id,
        "inbound_count": len(body.document.get("inbounds") or []),
    })
    return {"ok": True, "core_id": core_id,
            "inbound_count": len(body.document.get("inbounds") or [])}
