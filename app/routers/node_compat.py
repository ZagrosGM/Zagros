"""Marzban node API compatibility for MirzaBot and existing shops.

Zagros replaced Marzban's Xray-only node transport with the certificate-pinned
multi-core agent under ``/api/zagros/nodes``.  User-management compatibility
remained intact, but integrations such as MirzaBot also call the historical
``/api/nodes`` family.  These thin aliases expose native Zagros nodes in the
old read/write shape without reintroducing the retired transport.
"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.dependencies import validate_dates
from app.models.admin import Admin
from app.nodes.client import NodeClientError
from app.nodes.models import NodeUpdate
from app.nodes.service import (
    delete_node,
    get_node,
    list_nodes,
    reconnect,
    update_node,
)


async def get_runtime(request: Request):
    """Reuse Zagros' lazy runtime recovery without importing its router while
    the legacy router package itself is still being assembled."""
    from app.platform.routers import get_runtime as platform_get_runtime

    return await platform_get_runtime(request)


router = APIRouter(
    tags=["Marzban compatibility"],
    prefix="/api",
    responses={401: {"description": "Unauthorized"},
               403: {"description": "Sudo administrator required"}},
)


class CompatNodeModify(BaseModel):
    """Fields MirzaBot can modify through the historical endpoint."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    address: str | None = Field(default=None, min_length=1, max_length=256)
    port: int | None = Field(default=None, ge=1, le=65535)
    api_port: int | None = Field(default=None, ge=1, le=65535)
    usage_coefficient: float | None = Field(default=None, gt=0)
    add_as_new_host: bool | None = None
    # Present in Marzban's model but not writable in the native pairing state
    # machine. Accepting it in the schema gives a precise 422 instead of an
    # unexplained extra-field drop.
    status: str | None = None


def _node_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(404, "node not found")
    if isinstance(exc, PermissionError):
        return HTTPException(409, str(exc))
    if isinstance(exc, NodeClientError):
        return HTTPException(502, str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(422, str(exc))
    raise exc


def _xray_version(node: Any) -> str | None:
    installed = getattr(getattr(node, "cores", None), "installed", None) or {}
    xray = installed.get("xray") or {}
    for key in ("version", "core_version", "installed_version"):
        if xray.get(key):
            return str(xray[key])
    return None


def _node_wire(node: Any) -> dict[str, Any]:
    """Native NodeView -> fields consumed by Marzban.php in MirzaBot."""
    return {
        "id": int(node.id),
        "name": node.name,
        "address": node.address,
        "port": int(node.port),
        "api_port": int(node.api_port),
        "usage_coefficient": float(node.usage_coefficient),
        "status": node.status,
        "message": node.last_error,
        "xray_version": _xray_version(node),
        # Additive Zagros fields are harmless to Marzban clients and useful to
        # integrations that want to distinguish the native agent.
        "agent_type": node.agent_type,
        "agent_version": node.agent_version,
        "last_seen": node.last_seen,
    }


@router.get("/nodes")
async def compat_nodes(
    _admin: Admin = Depends(Admin.check_sudo_admin),
    runtime=Depends(get_runtime),
):
    """Historical direct array response (not Zagros' ``{"nodes": [...]}``)."""
    return [_node_wire(node) for node in await list_nodes(runtime)]


@router.get("/node/{node_id}")
async def compat_node(
    node_id: int,
    _admin: Admin = Depends(Admin.check_sudo_admin),
    runtime=Depends(get_runtime),
):
    node = await get_node(runtime, node_id)
    if node is None:
        raise HTTPException(404, "node not found")
    return _node_wire(node)


@router.put("/node/{node_id}")
async def compat_node_update(
    node_id: int,
    body: CompatNodeModify,
    _admin: Admin = Depends(Admin.check_sudo_admin),
    runtime=Depends(get_runtime),
):
    if body.status is not None:
        raise HTTPException(
            422,
            "native Zagros node status is controlled by pairing/health and cannot be set directly",
        )
    dump = getattr(body, "model_dump", None)
    values = (dump(exclude={"status"}, exclude_none=True)
              if dump is not None
              else body.dict(exclude={"status"}, exclude_none=True))
    update = NodeUpdate(**values)
    try:
        node = await update_node(runtime, node_id, update)
    except Exception as exc:  # noqa: BLE001 - translated to stable HTTP errors
        raise _node_error(exc) from exc
    return _node_wire(node)


@router.post("/node/{node_id}/reconnect")
async def compat_node_reconnect(
    node_id: int,
    _admin: Admin = Depends(Admin.check_sudo_admin),
    runtime=Depends(get_runtime),
):
    try:
        node = await reconnect(runtime, node_id)
    except Exception as exc:  # noqa: BLE001
        raise _node_error(exc) from exc
    return {"detail": "Node reconnected", "node": _node_wire(node)}


@router.delete("/node/{node_id}")
async def compat_node_delete(
    node_id: int,
    force: bool = False,
    _admin: Admin = Depends(Admin.check_sudo_admin),
    runtime=Depends(get_runtime),
):
    try:
        await delete_node(runtime, node_id, force=force)
    except Exception as exc:  # noqa: BLE001
        raise _node_error(exc) from exc
    return {}


def _usage_rows(runtime, start, end) -> list[dict[str, Any]]:
    from app.persistence.models import NodeModel, UsageRecordModel

    with runtime.session_factory() as session:
        nodes = session.execute(
            select(NodeModel.id, NodeModel.name).order_by(NodeModel.id)
        ).all()
        totals = {
            int(node_id): (int(uplink or 0), int(downlink or 0))
            for node_id, uplink, downlink in session.execute(
                select(
                    UsageRecordModel.node_id,
                    func.coalesce(func.sum(UsageRecordModel.uplink_bytes), 0),
                    func.coalesce(func.sum(UsageRecordModel.downlink_bytes), 0),
                )
                .where(
                    UsageRecordModel.node_id.isnot(None),
                    UsageRecordModel.recorded_at >= start,
                    UsageRecordModel.recorded_at <= end,
                )
                .group_by(UsageRecordModel.node_id)
            ).all()
        }
    return [
        {
            "node_id": int(node_id),
            "node_name": name,
            "uplink": totals.get(int(node_id), (0, 0))[0],
            "downlink": totals.get(int(node_id), (0, 0))[1],
        }
        for node_id, name in nodes
    ]


@router.get("/nodes/usage")
async def compat_nodes_usage(
    start: str = "",
    end: str = "",
    _admin: Admin = Depends(Admin.check_sudo_admin),
    runtime=Depends(get_runtime),
):
    """Historical aggregate shape backed by Zagros' unified usage journal."""
    start_at, end_at = validate_dates(start, end)
    return {"usages": await asyncio.to_thread(
        _usage_rows, runtime, start_at, end_at)}
