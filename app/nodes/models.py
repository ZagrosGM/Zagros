"""API schemas for Zagros native nodes.

A node moves through exactly three pairing states:

``pending`` → the panel has issued a one-time token and produced an
installer command, but the node has not proven itself yet.
``connected`` → the certificate is pinned and a signing key is sealed;
signed commands work.
``error`` → the last signed call or heartbeat failed; the last error is
kept so the dashboard can show *why* instead of just "red".
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, SecretStr

DEFAULT_NODE_PORT = 62050      # HTTPS control plane
DEFAULT_NODE_API_PORT = 62051  # read-only bootstrap/info

NODE_ACTIONS = ("install", "uninstall", "start", "stop", "restart", "update")


class NodeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=256)
    port: int = Field(default=DEFAULT_NODE_PORT, ge=1, le=65535)
    api_port: int = Field(default=DEFAULT_NODE_API_PORT, ge=1, le=65535)
    usage_coefficient: float = Field(default=1.0, gt=0)
    # Add the node's address as a Host on every inbound it will serve, so
    # client configs can be issued against the node IP (see sync_node).
    add_as_new_host: bool = True

    model_config = {"json_schema_extra": {"example": {
        "name": "DE node", "address": "203.0.113.10",
        "port": 62050, "api_port": 62051, "add_as_new_host": True}}}


class NodeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    address: str | None = Field(default=None, min_length=1, max_length=256)
    port: int | None = Field(default=None, ge=1, le=65535)
    api_port: int | None = Field(default=None, ge=1, le=65535)
    usage_coefficient: float | None = Field(default=None, gt=0)
    add_as_new_host: bool | None = None

    model_config = {"json_schema_extra": {"example": {
        "name": "DE node", "usage_coefficient": 1.5}}}


class InstallerCommand(BaseModel):
    """The one-shot command an operator pastes into the node server."""

    command: str
    panel_id: str
    # Returned exactly once, at creation time. The panel stores only its
    # SHA-256 and can never show it again.
    registration_token: str | None = None
    notes: list[str] = Field(default_factory=list)


class Discovery(BaseModel):
    """What the node publishes about itself on its info port."""

    reachable: bool
    node_id: str | None = None
    name: str | None = None
    agent_version: str | None = None
    certificate_sha256: str | None = None
    certificate_not_after: str | None = None
    registered: bool | None = None
    pending_token: bool | None = None
    control_plane_port: int | None = None
    already_paired: bool = False
    error: str | None = None


class PairBody(BaseModel):
    """Confirm the fingerprint and complete pairing.

    ``certificate_fingerprint`` is mandatory and must equal what the node
    serves: this is the trust-on-first-use step, the node equivalent of
    checking an SSH host key.
    """

    certificate_fingerprint: str = Field(min_length=40, max_length=128)
    registration_token: SecretStr | None = None
    node_id: str | None = None
    address: str | None = None


class LifecycleBody(BaseModel):
    action: str
    settings: dict[str, Any] = Field(default_factory=dict)
    purge: bool = False
    force: bool = False
    # Pin the release to install/update to ('' = whatever the node defaults to).
    version: str | None = None


class NodeCores(BaseModel):
    """A node's core inventory: installed state + installable catalog."""

    installed: dict[str, dict[str, Any]] = Field(default_factory=dict)
    available: list[str] = Field(default_factory=list)
    preview: dict[str, dict[str, Any]] = Field(default_factory=dict)
    stale: bool = False
    error: str | None = None


class NodeView(BaseModel):
    id: int
    name: str
    address: str
    port: int
    api_port: int
    status: str
    usage_coefficient: float
    add_as_new_host: bool
    agent_type: str
    agent_identity: str | None = None
    certificate_fingerprint: str | None = None
    agent_version: str | None = None
    last_seen: str | None = None
    last_error: str | None = None
    pending: bool = False
    health: dict[str, Any] | None = None
    cores: NodeCores | None = None


class NodeList(BaseModel):
    nodes: list[NodeView]


class SyncResult(BaseModel):
    node_id: int
    pushed: list[dict[str, Any]] = Field(default_factory=list)
    skipped: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
