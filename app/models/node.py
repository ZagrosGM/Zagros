"""Legacy node *accounting* types — deliberately the only survivor of the
removed Xray-only node transport.

The Marzban-era node feature (rpyc transport, ``app/xray/node.py``,
``/api/node*``, node CRUD) is gone: a Zagros node is now the standalone
multi-core agent, implemented in ``app/nodes/`` and paired over
certificate-pinned HTTPS.

What remains here is the historical usage schema. ``nodes``, ``node_usages``
and ``node_user_usages`` hold traffic records operators already collected,
and the reporting endpoints (``crud.get_users_usage`` / ``get_nodes_usage``)
read them. Dropping the tables would destroy accounting history for a
feature that is simply no longer offered, so they stay — read-only in
practice, with the enum and the response model they need.

Nothing in this module can create, connect or command a node any more.
"""
from enum import Enum

from pydantic import BaseModel


class NodeStatus(str, Enum):
    """Historical status values persisted in ``nodes.status``."""

    connected = "connected"
    connecting = "connecting"
    error = "error"
    disabled = "disabled"


class NodeUsageResponse(BaseModel):
    node_id: int | None = None
    node_name: str
    uplink: int
    downlink: int
