"""Panel-side service layer for native Zagros nodes.

Every node operation lives here rather than in the router: pairing has a
state machine (pending → connected → error) with an **irreversible** step in
the middle (the node burns its one-time token), so the ordering, the
rollback rules and the "never leave an orphan authority behind" guarantees
need to be testable in one place.

Two invariants this module protects:

1. **A fingerprint is never trusted implicitly.** Pairing requires the
   operator's pin and verifies it against the certificate the node actually
   serves on the control plane — the node equivalent of checking an SSH host
   key before typing "yes".
2. **No orphan panel authority.** If registration succeeds on the node but
   persistence fails, the freshly issued signing key is revoked remotely
   before the error is reported.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import hashlib
import json
import os
import secrets
import threading
import time
from typing import Any

from sqlalchemy import select

from app import logger

from app.nodes.client import (
    NodeClientError,
    ZagrosNodeClient,
    fetch_node_info,
    fetch_pinned_certificate,
)
from app.nodes.models import (
    NODE_ACTIONS,
    Discovery,
    InstallerCommand,
    NodeCores,
    NodeCreate,
    NodeUpdate,
    NodeView,
    SyncResult,
)

# Where the generated installer script is fetched from. It lives in
# zagros-scripts next to the panel's own installer, so a node is installed
# from one repository — the agent repository builds the image and nothing
# else. Overridable so forks and air-gapped setups can serve their own copy.
SCRIPTS_REPO_RAW = os.environ.get(
    "ZAGROS_SCRIPTS_REPO_RAW",
    "https://raw.githubusercontent.com/ZagrosGM/zagros-scripts")
NODE_INSTALLER_SCRIPT = "install-node.sh"
# How long a "does that tag exist?" answer is trusted: tag lookups are cheap
# but they are still a network call on the path of every installer command.
_REF_LOOKUP_TTL = 3600.0
_ref_cache: tuple[str, float] | None = None


def _scripts_ref_exists(ref: str, timeout: float = 4.0) -> bool:
    """Does ``install-node.sh`` exist in zagros-scripts at this ref?"""
    import requests

    url = f"{SCRIPTS_REPO_RAW}/{ref}/{NODE_INSTALLER_SCRIPT}"
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
    except Exception:  # noqa: BLE001 - offline is an answer, not an error
        return False
    return response.status_code == 200


def installer_scripts_ref() -> str:
    """The zagros-scripts ref a new node should install from.

    A released panel wants the installer that shipped with it — that is what
    makes a node installed a year from now reproducible. But a development
    build carries a version nobody has tagged yet, and a 404 on the node is a
    far worse outcome than tracking the branch. So: the matching tag when it
    exists, ``main`` when it does not.
    """
    override = (os.environ.get("ZAGROS_SCRIPTS_REF") or "").strip()
    if override:
        return override
    global _ref_cache
    now = time.monotonic()
    if _ref_cache and now - _ref_cache[1] < _REF_LOOKUP_TTL:
        return _ref_cache[0]
    ref = "main"
    try:
        from app import __version__

        tag = f"v{__version__}"
        if _scripts_ref_exists(tag):
            ref = tag
    except Exception:  # noqa: BLE001 - never fail an installer for this
        ref = "main"
    _ref_cache = (ref, now)
    return ref
PANEL_ID_PREFIX = "panel-"
# Cores whose accounts live INSIDE their config document instead of the
# platform account table (see app/platform/provisioning.py).
LEGACY_CORE_ID = "xray"


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _settings(row) -> dict[str, Any]:
    return dict(row.settings_json or {})


def _normalize_fingerprint(value: str) -> str:
    return "".join(char for char in (value or "").lower() if char in "0123456789abcdef")


def panel_id(runtime) -> str:
    """Stable, non-secret identifier this panel presents when registering."""
    return PANEL_ID_PREFIX + hashlib.sha256(runtime.cipher._key).hexdigest()[:24]


# --------------------------------------------------------------------------- #
# persistence helpers
# --------------------------------------------------------------------------- #
def _get_row(runtime, node_id: int):
    from app.persistence.models import NodeModel

    with runtime.session_factory() as session:
        row = session.get(NodeModel, node_id)
        if row is None:
            return None
        session.expunge(row)
        return row


def _persist(runtime, mutate):
    """Open a session, run ``mutate(session)``, commit and return its result.

    Each mutation is responsible for its own ``refresh``/``expunge``: rows are
    handed back detached so callers can read them after the session is closed.
    """
    def _run():
        with runtime.session_factory() as session:
            result = mutate(session)
            session.commit()
            return result
    return _run


def _view(row) -> NodeView:
    settings = _settings(row)
    return NodeView(
        id=row.id,
        name=row.name,
        address=row.address,
        port=row.port,
        api_port=getattr(row, "api_port", 62051) or 62051,
        status=row.status,
        usage_coefficient=row.usage_coefficient,
        add_as_new_host=bool(getattr(row, "add_as_new_host", False)),
        agent_type=row.agent_type,
        agent_identity=row.agent_identity,
        certificate_fingerprint=row.certificate_fingerprint,
        agent_version=getattr(row, "agent_version", None),
        last_seen=row.last_seen.isoformat() if row.last_seen else None,
        last_error=getattr(row, "last_error", None),
        pending=row.status != "connected",
        health=settings.get("health"),
        cores=NodeCores(**settings["cores"]) if settings.get("cores") else None,
    )


def _seal_token(runtime, node_identity: str, token: str) -> str:
    return runtime.cipher.encrypt_json(
        {"registration_token": token}, aad=f"node-token:{node_identity}")


def _row_token(runtime, row) -> str | None:
    """The node's one-time registration token, however it came to be sealed.

    The token is sealed under the node's identity at the time — a bare
    ``pending:<name>`` while the node is unpaired, the agent's id afterwards.
    Re-installing the agent changes that id underneath us, so a single guess
    is not enough: an operator who rotates the token of a node whose agent was
    reinstalled would otherwise be told (wrongly) that no token exists.
    """
    blob = getattr(row, "registration_token_enc", "") or ""
    if not blob:
        return None
    for identity in (getattr(row, "agent_identity", "") or "",
                     f"pending:{getattr(row, 'name', '') or ''}"):
        if not identity:
            continue
        token = _unseal_token(runtime, identity, blob)
        if token:
            return token
    return None


def _unseal_token(runtime, node_identity: str, blob: str) -> str | None:
    if not blob:
        return None
    try:
        value = runtime.cipher.decrypt_json(blob, aad=f"node-token:{node_identity}")
    except Exception:  # noqa: BLE001 — a lost key must not mask the real error
        return None
    return str(value.get("registration_token") or "") or None


# --------------------------------------------------------------------------- #
# client construction
# --------------------------------------------------------------------------- #
def _client(runtime, row) -> ZagrosNodeClient:
    import base64 as _b64

    if row.agent_type != "zagros_native" or not row.agent_identity \
            or not row.agent_credentials_enc:
        raise NodeClientError("node is not paired yet")
    credentials = runtime.cipher.decrypt_json(
        row.agent_credentials_enc, aad=f"node-agent:{row.agent_identity}")
    key = _b64.b64decode(credentials["signing_key"])
    cert = str((row.settings_json or {}).get("certificate_pem") or "")
    if len(key) != 32 or not cert:
        raise NodeClientError("node credentials are incomplete")
    return ZagrosNodeClient(row.address, row.port, row.agent_identity, key, cert,
                            api_port=getattr(row, "api_port", None))


# --------------------------------------------------------------------------- #
# listing
# --------------------------------------------------------------------------- #
async def list_nodes(runtime) -> list[NodeView]:
    from app.persistence.models import NodeModel

    def load():
        with runtime.session_factory() as session:
            rows = session.execute(select(NodeModel)).scalars().all()
            views = [_view(row) for row in rows]
            for row in rows:
                session.expunge(row)
            return views
    return await asyncio.to_thread(load)


async def get_node(runtime, node_id: int) -> NodeView | None:
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    return None if row is None else _view(row)


# --------------------------------------------------------------------------- #
# create + installer command
# --------------------------------------------------------------------------- #
def _installer_command(row, token: str | None, *, rotated: bool = False,
                       ref: str | None = None) -> InstallerCommand:
    command = (
        f"curl -fsSL {SCRIPTS_REPO_RAW}/{ref or installer_scripts_ref()}/"
        f"{NODE_INSTALLER_SCRIPT} | bash -s --"
        f" --panel-id {row.panel_id}"
        f" --token {token or '<TOKEN>'}"
        f" --name {row.name}"
        f" --address {row.address}"
        f" --port {row.port}"
        f" --api-port {getattr(row, 'api_port', 62051)}"
    )
    notes = [
        "Run it as root on the node server.",
        "The token is single-use and is not shown again — regenerate it if lost.",
        "The installer prints the TLS fingerprint; confirm it here to finish pairing.",
    ]
    if rotated:
        notes.insert(0, "A previous token was invalidated by this command.")
    return InstallerCommand(command=command, panel_id=row.panel_id,
                            registration_token=token, notes=notes)


async def create_node(runtime, body: NodeCreate) -> tuple[NodeView, InstallerCommand]:
    from app.persistence.models import NodeModel

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    def mutate(session):
        if session.scalar(select(NodeModel).where(NodeModel.name == body.name)):
            raise ValueError(f"node '{body.name}' already exists")
        row = NodeModel(
            name=body.name, address=body.address, port=body.port,
            api_port=body.api_port, status="pending",
            usage_coefficient=body.usage_coefficient,
            add_as_new_host=body.add_as_new_host,
            agent_type="zagros_native",
            panel_id=panel_id(runtime),
            registration_token_hash=token_hash,
            registration_token_enc=_seal_token(runtime, f"pending:{body.name}", token),
            created_at=_now(),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        session.expunge(row)
        return row

    row = await asyncio.to_thread(_persist(runtime, mutate))
    return _view(row), _installer_command(row, token,
                                          ref=installer_scripts_ref())


async def installer_command(runtime, node_id: int, *,
                            rotate: bool = False) -> InstallerCommand:
    """Show (or reissue) the installer command for a node."""
    from app.persistence.models import NodeModel

    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    if not rotate:
        ref = await asyncio.to_thread(installer_scripts_ref)
        return _installer_command(row, _row_token(runtime, row), ref=ref)

    if row.status == "connected":
        raise PermissionError(
            "this node is paired — rotating the token would orphan the pairing; "
            "delete and re-add the node instead")

    token = secrets.token_urlsafe(32)

    def mutate(session):
        current = session.get(NodeModel, node_id)
        if current is None:
            raise KeyError(node_id)
        current.registration_token_hash = hashlib.sha256(token.encode()).hexdigest()
        current.registration_token_enc = _seal_token(
            runtime, current.agent_identity or f"pending:{current.name}", token)
        current.status = "pending"
        session.commit()
        session.refresh(current)
        session.expunge(current)
        return current

    row = await asyncio.to_thread(_persist(runtime, mutate))
    ref = await asyncio.to_thread(installer_scripts_ref)
    return _installer_command(row, token, rotated=True, ref=ref)


# --------------------------------------------------------------------------- #
# discovery + pairing
# --------------------------------------------------------------------------- #
async def discover(runtime, node_id: int) -> Discovery:
    """Ask the node's info port who it is (read-only, unauthenticated)."""
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    try:
        info = await asyncio.to_thread(
            fetch_node_info, row.address, getattr(row, "api_port", 62051))
    except NodeClientError as exc:
        return Discovery(reachable=False, error=str(exc))

    fingerprint = _normalize_fingerprint(str(info.get("certificate_sha256") or ""))
    return Discovery(
        reachable=True,
        node_id=info.get("node_id"),
        name=info.get("name"),
        agent_version=info.get("agent_version"),
        certificate_sha256=fingerprint,
        certificate_not_after=info.get("certificate_not_after"),
        registered=bool(info.get("registered")),
        pending_token=bool(info.get("pending_token")),
        control_plane_port=info.get("control_plane_port"),
        already_paired=bool(
            row.agent_identity and info.get("node_id") == row.agent_identity),
    )


async def pair(runtime, node_id: int, *, certificate_fingerprint: str,
               registration_token: str | None = None,
               node_id_hint: str | None = None) -> NodeView:
    """Pin the node's certificate and exchange the signing key.

    The fingerprint is verified against the certificate the node *actually*
    serves on the control plane (not merely against what the info port
    claims), then the one-time token is exchanged once.
    """
    from app.persistence.models import NodeModel

    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)

    fingerprint = _normalize_fingerprint(certificate_fingerprint)
    if len(fingerprint) != 64:
        raise ValueError("certificate fingerprint must be a 64-character hex SHA-256")

    token = registration_token or _row_token(runtime, row)
    if not token:
        raise ValueError(
            "no registration token is available — regenerate the installer "
            "command or paste the token manually")

    try:
        certificate_pem, pinned = await asyncio.to_thread(
            fetch_pinned_certificate, row.address, row.port, fingerprint)
        client = ZagrosNodeClient(
            row.address, row.port, None, None, certificate_pem)
        registration = await asyncio.to_thread(
            client.register, row.panel_id or panel_id(runtime), token)
    except NodeClientError as exc:
        await _mark_error(runtime, node_id, str(exc))
        raise

    identity = str(registration["node_id"])
    if node_id_hint and identity != node_id_hint:
        # The operator pinned a certificate belonging to a different node.
        # Nothing was persisted, but the token is now burned on that node —
        # say so plainly instead of silently half-pairing.
        raise ValueError(
            f"the node answered with id '{identity}', not the expected "
            f"'{node_id_hint}' — it must be re-armed with a new token")

    signing_key = base64.b64decode(registration["signing_key"])
    if len(signing_key) != 32:
        raise NodeClientError("agent returned an invalid signing key")

    sealed = runtime.cipher.encrypt_json(
        {"signing_key": base64.b64encode(signing_key).decode("ascii")},
        aad=f"node-agent:{identity}")

    def mutate(session):
        current = session.get(NodeModel, node_id)
        if current is None:
            raise KeyError(node_id)
        clash = session.scalar(select(NodeModel).where(
            NodeModel.agent_identity == identity, NodeModel.id != node_id))
        if clash is not None:
            raise ValueError(
                f"node identity {identity[:12]}… is already registered as "
                f"'{clash.name}'")
        current.agent_identity = identity
        current.agent_credentials_enc = sealed
        current.certificate_fingerprint = pinned
        current.agent_version = str(registration.get("agent_version") or "")
        current.status = "connected"
        current.last_seen = _now()
        current.last_error = None
        # The token is single-use: destroy every copy the panel holds.
        current.registration_token_hash = ""
        current.registration_token_enc = ""
        settings = dict(current.settings_json or {})
        settings["certificate_pem"] = certificate_pem
        current.settings_json = settings
        session.commit()
        session.refresh(current)
        session.expunge(current)
        return current

    try:
        row = await asyncio.to_thread(_persist(runtime, mutate))
    except Exception as exc:
        # Registration was consumed remotely but could not be stored here.
        # Revoke the key we just received so no orphan authority remains.
        try:
            await asyncio.to_thread(
                ZagrosNodeClient(row.address, row.port, identity, signing_key,
                                 certificate_pem).revoke)
        except Exception:  # noqa: BLE001 — best effort, never mask the cause
            pass
        raise exc
    return _view(row)


async def _mark_error(runtime, node_id: int, message: str) -> None:
    from app.persistence.models import NodeModel

    def mutate(session):
        current = session.get(NodeModel, node_id)
        if current is not None:
            current.status = "error" if current.status == "connected" else current.status
            current.last_error = str(message)[:500]
            session.commit()
    await asyncio.to_thread(_persist(runtime, mutate))


# --------------------------------------------------------------------------- #
# health / cores / lifecycle
# --------------------------------------------------------------------------- #
async def heartbeat(runtime, node_id: int) -> NodeView:
    """Verify the signing key end-to-end and refresh health + inventory."""
    from app.persistence.models import NodeModel

    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    client = _client(runtime, row)
    try:
        beat, health, cores = await asyncio.gather(
            asyncio.to_thread(client.heartbeat),
            asyncio.to_thread(client.health),
            asyncio.to_thread(client.cores),
        )
    except NodeClientError as exc:
        await _mark_error(runtime, node_id, str(exc))
        raise

    def mutate(session):
        current = session.get(NodeModel, node_id)
        if current is None:
            raise KeyError(node_id)
        current.status = "connected"
        current.last_seen = _now()
        current.last_error = None
        current.agent_version = str(beat.get("agent_version") or current.agent_version or "")
        settings = dict(current.settings_json or {})
        settings["health"] = health
        settings["cores"] = cores
        current.settings_json = settings
        session.commit()
        session.refresh(current)
        session.expunge(current)
        return current

    row = await asyncio.to_thread(_persist(runtime, mutate))
    return _view(row)


async def node_cores(runtime, node_id: int, *,
                     allow_stale: bool = True) -> NodeCores:
    """Live inventory (installed + catalog), falling back to the last known."""
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    try:
        inventory = await asyncio.to_thread(_client(runtime, row).cores)
        inventory.setdefault("preview", {})
        return NodeCores(**inventory, stale=False)
    except NodeClientError as exc:
        cached = _settings(row).get("cores")
        if allow_stale and cached:
            return NodeCores(**cached, stale=True, error=str(exc))
        raise


async def core_settings(runtime, node_id: int, core_id: str) -> dict:
    """A core's effective settings on the node (secrets already masked)."""
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    return await asyncio.to_thread(_client(runtime, row).core_settings, core_id)


async def update_core_settings(runtime, node_id: int, core_id: str,
                               settings: dict) -> dict:
    """Patch a core's settings on the node.

    The node re-validates every value against the driver's own schema and
    refuses paths outside the core root, so the panel cannot be used to
    smuggle a setting the driver would not accept locally.
    """
    if not isinstance(settings, dict) or not settings:
        raise ValueError("no settings supplied")
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    return await asyncio.to_thread(
        _client(runtime, row).apply_settings, core_id, settings)


async def core_lifecycle(runtime, node_id: int, core_id: str, *, action: str,
                         settings: dict | None = None, purge: bool = False,
                         force: bool = False, version: str | None = None) -> dict:
    if action not in NODE_ACTIONS:
        raise ValueError(f"action must be one of {list(NODE_ACTIONS)}")
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    if version and action not in ("install", "update"):
        raise ValueError(
            "a version can only be pinned when installing or updating; "
            f"'{action}' does not install anything")
    # The agent pins a release through the driver's own settings, so a version
    # is just one more setting — no protocol change, and cores that do not
    # understand it simply keep their own default.
    effective = dict(settings or {})
    if version:
        effective["release_version"] = str(version)
    result = await asyncio.to_thread(
        _client(runtime, row).lifecycle, core_id, action, settings=effective,
        purge=purge, force=force)
    # A freshly installed core owns no listeners yet: it cannot start, and it
    # serves nothing, until this panel's configuration reaches it. Converge it
    # here so "install" means "installed and serving", not "installed, now go
    # find the sync button".
    if action in ("install", "update"):
        try:
            result["convergence"] = await converge_node(
                runtime, node_id, core_ids=[core_id])
        except Exception as exc:  # noqa: BLE001 — the action itself succeeded
            result["convergence"] = {"errors": [str(exc)]}
    # Refresh the cached inventory so the UI reflects the change immediately.
    try:
        await heartbeat(runtime, node_id)
    except Exception:  # noqa: BLE001 — the action itself already succeeded
        pass
    return result


async def core_versions(runtime, node_id: int, core_id: str,
                        limit: int = 10) -> dict:
    """Upstream release tags a core on this node can be pinned to.

    The node's drivers are a vendored copy of the panel's, so the panel knows
    the release feed of every core the node can install — including ones the
    master itself does not run. The list is advisory: applying it is a normal
    install/update with a version pin.
    """
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    try:
        from app.cores.releases import NoReleaseFeed, recent_releases

        payload = await recent_releases(core_id, limit=limit)
    except KeyError:
        raise KeyError(f"core '{core_id}' is not known to this panel") from None
    except NoReleaseFeed as exc:
        raise ValueError(str(exc)) from None
    except Exception as exc:  # noqa: BLE001 - upstream is a network call
        raise ConnectionError(f"could not read the release list: {exc}") from exc
    return {"node_id": node_id, **payload}


async def core_logs(runtime, node_id: int, core_id: str, tail: int = 200) -> dict:
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    return await asyncio.to_thread(
        _client(runtime, row).core_logs, core_id, max(1, min(tail, 2000)))


# --------------------------------------------------------------------------- #
# configuration sync (so clients can connect through the node's address)
# --------------------------------------------------------------------------- #
async def _master_document(runtime, core_id: str) -> dict | None:
    """The master's authoritative config document for one core.

    Cores whose configuration still lives in their own file (xray reads the
    mounted ``XRAY_JSON``) expose it through ``export_config_document()``.
    Reading it directly — instead of through ``studio.get_document`` — keeps
    the sync read-only: it must not seed the Studio store as a side effect of
    a sync, because that would silently change what the Studio page edits.
    """
    if core_id == LEGACY_CORE_ID:
        return _xray_document_with_accounts()
    document = await runtime.studio_store.get_document(core_id)
    if (document or {}).get("inbounds"):
        return document
    try:
        driver = runtime.core_manager.get(core_id)
    except Exception:  # noqa: BLE001 — driver missing = nothing to push
        return document or None
    export = getattr(driver, "export_config_document", None)
    if not callable(export):
        return document or None
    try:
        seeded = export()
    except Exception:  # noqa: BLE001 — a broken core must not abort the sync
        return document or None
    return seeded if isinstance(seeded, dict) else (document or None)


def _xray_document_with_accounts() -> dict | None:
    """The master's xray config **including its database users**.

    xray is the one core whose accounts live inside its configuration file
    (as inbound ``clients``), not in the platform account table — it is still
    governed by the legacy proxy stack. Pushing the bare config would give
    the node correct inbounds with an empty client list, which is exactly the
    failure "the master connects, the node does not": the node would simply
    not recognise the user's credential.

    ``include_db_users()`` is a copy, so the running master config is never
    mutated here.
    """
    try:
        from app import xray as _xray

        config = _xray.config.include_db_users()
        document = json.loads(config.to_json())
    except Exception:  # noqa: BLE001 — legacy stack unavailable: report honestly
        return None
    return document if isinstance(document, dict) else None


def _core_accounts(runtime, core_id: str) -> list[dict] | None:
    """Every live account the master holds for one core (credentials included).

    Secrets are decrypted here — the panel is the only side that owns the
    master key — and travel to the node inside the signed TLS channel.
    """
    try:
        rows = runtime.users.accounts_of_core(core_id)
    except Exception:  # noqa: BLE001 — a core may have no account table yet
        return None  # unknown, NOT empty: never revoke accounts on a read error
    accounts: list[dict] = []
    for row in rows:
        accounts.append({
            "user_id": int(row["user_id"]),
            "username": str(row.get("username") or row["account_id"]),
            "account_id": str(row["account_id"]),
            "protocol": str(row.get("protocol") or ""),
            "enabled": bool(row.get("enabled", True)),
            "settings": dict(row.get("settings") or {}),
        })
    return accounts


async def _push_identity(runtime, client, core_id: str,
                         result: "SyncResult") -> list[str] | None:
    """Hand the master's server identity to a node (best-effort).

    Returns the applied material names, or ``None`` when there was nothing
    to federate. A failure is recorded on ``result`` and never aborts the
    rest of the sync: an outdated identity is a client-trust problem, while
    a cancelled sync would leave the node serving stale inbounds.
    """
    exporter = getattr(runtime.core_manager.get(core_id), "export_identity", None)
    if not callable(exporter):
        return None
    try:
        material = await asyncio.to_thread(exporter)
    except Exception as exc:  # noqa: BLE001 — per-core isolation
        result.errors.append(f"{core_id}: identity could not be read: {exc}")
        return None
    if not material:
        return None
    try:
        response = await asyncio.to_thread(client.apply_identity, core_id, material)
    except NodeClientError as exc:
        result.errors.append(f"{core_id} identity: {exc}")
        return None
    applied = response.get("applied") or []
    return list(applied)


def _clients(inbound: dict) -> int:
    """How many accounts one xray inbound carries (they live in the document)."""
    settings = inbound.get("settings") or {}
    return len(settings.get("clients") or inbound.get("clients") or [])


def _accounts_digest(payload: object) -> str:
    """Fingerprint of one core's accounts, so a push can be skipped."""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _account_payload(runtime, core_id: str):
    """This core's accounts as the panel has them right now.

    ``None`` means *unknown*, not empty — a read failure must never be
    mistaken for "there are no users", which would revoke everyone on the
    node.
    """
    if core_id == LEGACY_CORE_ID:
        return _xray_document_with_accounts()
    return _core_accounts(runtime, core_id)


async def _push_core_accounts(runtime, client, core_id: str, *,
                              payload, apply: bool) -> tuple[int | None, str | None]:
    """Move one core's accounts onto a node. Returns ``(count, error)``.

    xray carries its users inside the configuration document; every other
    core keeps them in the platform account table and reconciles them
    explicitly. ``apply=False`` counts without sending (used by a full sync,
    which has already applied the document itself).
    """
    if core_id == LEGACY_CORE_ID:
        if not payload or not (payload.get("inbounds") or []):
            return None, None
        if apply:
            await asyncio.to_thread(client.apply_inbounds, core_id, payload)
        return (sum(_clients(inbound) for inbound in (payload.get("inbounds") or [])
                    if isinstance(inbound, dict)), None)
    if payload is None:
        return None, ("accounts could not be read from the panel database "
                      "— left untouched on the node")
    if apply:
        synced = await asyncio.to_thread(client.apply_accounts, core_id, payload)
        return synced.get("count", len(payload)), None
    return len(payload), None


def _accounts_digest_map(row) -> dict[str, str]:
    settings = dict(getattr(row, "settings_json", None) or {})
    stored = settings.get("accounts_digest") or {}
    return dict(stored) if isinstance(stored, dict) else {}


def _store_accounts_digests(runtime, node_id: int, digests: dict[str, str]) -> None:
    """Remember what a node already has, so the next pass can skip it."""
    if not digests:
        return
    from app.persistence.models import NodeModel

    def mutate(session):
        current = session.get(NodeModel, node_id)
        if current is None:
            return
        settings = dict(current.settings_json or {})
        merged = dict(settings.get("accounts_digest") or {})
        merged.update(digests)
        settings["accounts_digest"] = merged
        current.settings_json = settings
        session.commit()

    try:
        _persist(runtime, mutate)()
    except Exception as exc:  # noqa: BLE001 — bookkeeping must never fail a push
        logger.debug("node accounts: cannot record digests: %s", exc)


async def push_node_accounts(runtime, node_id: int, *,
                             core_ids: list[str] | None = None,
                             force: bool = False) -> dict:
    """Re-send ONLY the accounts to one node.

    The other half of a sync (server identity, inbound layout, hosts) does not
    change when a user is added, edited or removed — the accounts do. Keeping
    this separate means "a new user can connect through the node" does not
    wait for, or pay for, a full convergence pass.
    """
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    client = _client(runtime, row)
    inventory = await asyncio.to_thread(client.cores)
    installed = dict(inventory.get("installed") or {})
    master_cores = set(runtime.core_manager.list_cores())

    result: dict[str, Any] = {"node_id": node_id, "pushed": [], "skipped": [],
                              "errors": []}
    wanted = sorted(installed if core_ids is None
                    else [c for c in installed if c in set(core_ids or ())])
    known = _accounts_digest_map(row)
    digests: dict[str, str] = {}

    for core_id in wanted:
        if core_id not in master_cores:
            result["skipped"].append({"core_id": core_id,
                                      "reason": "core is not installed on the master"})
            continue
        payload = _account_payload(runtime, core_id)
        if payload is None:
            result["errors"].append(
                f"{core_id}: accounts could not be read from the panel "
                "database — left untouched on the node")
            continue
        digest = _accounts_digest(payload)
        if not force and known.get(core_id) == digest:
            result["skipped"].append({"core_id": core_id,
                                      "reason": "accounts unchanged"})
            digests[core_id] = digest
            continue
        try:
            count, error = await _push_core_accounts(
                runtime, client, core_id, payload=payload, apply=True)
        except NodeClientError as exc:
            result["errors"].append(f"{core_id}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001 — one core never blocks another
            result["errors"].append(f"{core_id}: {exc}")
            continue
        if error:
            result["errors"].append(f"{core_id}: {error}")
            continue
        digests[core_id] = digest
        result["pushed"].append({"core_id": core_id, "accounts": count})

    _store_accounts_digests(runtime, node_id, digests)
    return result


def schedule_accounts_fanout(runtime, *, core_ids: list[str] | None = None) -> None:
    """Push accounts to the nodes in the background — never block a request.

    Called right after a user was created, edited or removed so "the config
    they just downloaded" works immediately; the periodic sweep remains the
    safety net for every path that does not call this.
    """
    def _run() -> None:
        try:
            asyncio.run(fanout_accounts(runtime, core_ids=core_ids, force=True))
        except Exception as exc:  # noqa: BLE001 — a fan-out must never raise
            logger.debug("node accounts fan-out failed: %s", exc)

    threading.Thread(target=_run, name="node-accounts-fanout", daemon=True).start()


async def fanout_accounts(runtime, *, core_ids: list[str] | None = None,
                          force: bool = False) -> dict:
    """Send the current account set to every paired node.

    Every path that can change a user — creation, edit, deletion, expiry, a
    device limit cutting someone off — ends here, so no call site has to
    remember to tell a node about it.
    """
    pushed: list[dict] = []
    errors: list[str] = []
    for row in paired_nodes(runtime):
        try:
            outcome = await push_node_accounts(
                runtime, int(row.id), core_ids=core_ids, force=force)
        except Exception as exc:  # noqa: BLE001 — one node never blocks another
            errors.append(f"node {row.id}: {exc}")
            continue
        if outcome.get("pushed"):
            pushed.append({"node_id": int(row.id),
                           "pushed": outcome["pushed"]})
        errors.extend(str(item) for item in outcome.get("errors") or [])
    return {"pushed": pushed, "errors": errors}


async def sync_node(runtime, node_id: int, *,
                    core_ids: list[str] | None = None) -> SyncResult:
    """Push this panel's desired inbound state to every core on the node.

    ``core_ids`` narrows the pass to a subset (used right after one core was
    installed, so the node converges without waiting for a manual sync).

    Two halves, because "a client can connect via the node" needs both:

    1. **identity** — the master's server identity (CA, server keypair,
       IPsec PSK) is handed to the node, so a profile keeps authenticating
       the server when its address is switched to the node;
    2. **config** — each core's Config Studio document is applied on the
       node, so the node serves the same inbounds as the master;
    3. **accounts** — the users themselves (xray carries them inside the
       document; every other core needs them reconciled explicitly);
    4. **hosts** — the node's address is registered as a Host on those
       inbounds, so subscriptions can be issued against the node IP.
    """
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    client = _client(runtime, row)
    inventory = await asyncio.to_thread(client.cores)
    installed = dict(inventory.get("installed") or {})
    master_cores = set(runtime.core_manager.list_cores())

    result = SyncResult(node_id=node_id)
    _pending_digests: dict[str, str] = {}
    wanted = sorted(installed if core_ids is None
                    else [c for c in installed if c in set(core_ids or ())])
    for core_id in wanted:
        if core_id not in master_cores:
            result.skipped.append({"core_id": core_id,
                                   "reason": "core is not installed on the master"})
            continue
        try:
            document = await _master_document(runtime, core_id)
        except Exception as exc:  # noqa: BLE001 — per-core isolation
            result.errors.append(f"{core_id}: cannot read its configuration: {exc}")
            continue
        if not document or not (document.get("inbounds") or []):
            result.skipped.append({"core_id": core_id,
                                   "reason": "no inbounds configured on the master"})
            continue
        # Identity first: the node must own the master's server material
        # BEFORE it applies listeners, or it would serve a locally generated
        # CA / keypair that no existing profile trusts.
        identity_applied = await _push_identity(runtime, client, core_id, result)

        try:
            applied = await asyncio.to_thread(client.apply_inbounds, core_id, document)
        except NodeClientError as exc:
            result.errors.append(f"{core_id}: {exc}")
            continue
        pushed: dict[str, Any] = {
            "core_id": core_id,
            "inbound_count": applied.get("inbound_count", 0),
        }
        if identity_applied is not None:
            pushed["identity"] = identity_applied
        # Accounts: the other half of "a config that points at the node
        # actually connects". xray carries its users inside the document that
        # was just applied; every other core keeps them in the platform
        # account table and needs them reconciled explicitly.
        # xray's users travel inside the document that was just applied; every
        # other core keeps them in the account table and reconciles them here.
        payload = (document if core_id == LEGACY_CORE_ID
                   else await asyncio.to_thread(_core_accounts, runtime, core_id))
        count, account_error = await _push_core_accounts(
            runtime, client, core_id, payload=payload,
            apply=(core_id != LEGACY_CORE_ID))
        if account_error:
            result.errors.append(f"{core_id} accounts: {account_error}")
        else:
            if count is not None:
                pushed["accounts"] = count
            if payload is not None:
                _pending_digests[core_id] = _accounts_digest(payload)
        result.pushed.append(pushed)

    if row.add_as_new_host:
        try:
            result.hosts = await _add_node_hosts(runtime, row, wanted)
        except Exception as exc:  # noqa: BLE001 — config push already succeeded
            result.errors.append(f"hosts: {exc}")

    if _pending_digests:
        _store_accounts_digests(runtime, node_id, _pending_digests)

    def mutate(session):
        from app.persistence.models import NodeModel

        current = session.get(NodeModel, node_id)
        if current is not None:
            settings = dict(current.settings_json or {})
            settings["last_sync"] = _now().isoformat()
            current.settings_json = settings
            session.commit()
    await asyncio.to_thread(_persist(runtime, mutate))
    return result


async def _add_node_hosts(runtime, row, core_ids: list[str]) -> list[str]:
    """Register the node's address as a Host on every inbound it will serve."""
    added: list[str] = []
    remark = f"{row.name} ({{USERNAME}}) [{{PROTOCOL}} - {{TRANSPORT}}]"

    if "xray" in core_ids:
        # xray keeps its hosts in the legacy table consumed by delivery.
        from app import xray as _xray
        from app.db import GetDB, crud
        from app.models.proxy import ProxyHost

        with GetDB() as db:
            for tag in _xray.config.inbounds_by_tag:
                existing = crud.get_hosts(db, tag)
                if any(host.address == row.address for host in existing):
                    continue
                crud.add_host(db, tag, ProxyHost(remark=remark, address=row.address))
                added.append(f"xray:{tag}")
        try:
            _xray.hosts.update()
        except Exception:  # noqa: BLE001 — rows are persisted; cache refreshes later
            pass

    for core_id in core_ids:
        if core_id == "xray":
            continue
        try:
            document = (await _master_document(runtime, core_id)) or {}
        except Exception:  # noqa: BLE001
            continue
        tags = [inbound.get("tag") for inbound in (document.get("inbounds") or [])
                if inbound.get("tag")]
        if not tags:
            continue
        from app.portal.hostengine import HostEntry

        grouped = await runtime.core_hosts.list_grouped(core_id)
        touched: dict[str, list] = {}
        for tag in tags:
            entries = list(grouped.get(tag) or [])
            if any(entry.address == row.address for entry in entries):
                continue
            entries.append(HostEntry(remark=f"{row.name}", address=row.address))
            touched[tag] = entries
            added.append(f"{core_id}:{tag}")
        if touched:
            await runtime.core_hosts.replace_tags(core_id, touched)
    return added


# --------------------------------------------------------------------------- #
# modify / delete
# --------------------------------------------------------------------------- #
async def update_node(runtime, node_id: int, body: NodeUpdate) -> NodeView:
    from app.persistence.models import NodeModel

    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)

    def mutate(session):
        current = session.get(NodeModel, node_id)
        if current is None:
            raise KeyError(node_id)
        for field in ("name", "address", "port", "api_port",
                      "usage_coefficient", "add_as_new_host"):
            value = getattr(body, field, None)
            if value is not None:
                setattr(current, field, value)
        # Changing how we reach the node invalidates the pinned certificate
        # and the sealed key: the node must be paired again.
        if body.address is not None and body.address != row.address:
            current.status = "pending"
            current.agent_identity = None
            current.agent_credentials_enc = None
            current.certificate_fingerprint = None
        session.commit()
        session.refresh(current)
        session.expunge(current)
        return current

    row = await asyncio.to_thread(_persist(runtime, mutate))
    return _view(row)


async def delete_node(runtime, node_id: int, *, force: bool = False) -> dict:
    """Revoke the panel's authority on the node, then forget it."""
    from app.persistence.models import NodeModel

    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)

    revoked = False
    if row.agent_identity and row.agent_credentials_enc:
        try:
            await asyncio.to_thread(_client(runtime, row).revoke)
            revoked = True
        except NodeClientError as exc:
            if not force:
                raise PermissionError(
                    f"revoking the node's key failed ({exc}); pass force=true only "
                    "after isolating the node") from exc

    def mutate(session):
        current = session.get(NodeModel, node_id)
        if current is not None:
            session.delete(current)
            session.commit()
    await asyncio.to_thread(_persist(runtime, mutate))
    return {"deleted": node_id, "remote_revoked": revoked}


# --------------------------------------------------------------------------- #
# bandwidth limits — push enforcement to the host that carries the traffic
# --------------------------------------------------------------------------- #
# Shaping is host-local: tc filters and nft marks only change what happens on
# the machine forwarding the packets. The panel therefore cannot enforce a
# limit for a user connected through a node; it hands the node the same
# decision its own limiter would have made.

def bandwidth_limits_payload(runtime) -> dict[str, dict]:
    """{user_id: {username, upload_mbps, download_mbps, accounts}}.

    Mirrors what :meth:`BandwidthLimiter._desired` builds locally, minus the
    per-core identities — those are host-specific (a node's ssh uid or dhcp
    lease differs from the master's), so each node resolves its own.
    """
    from sqlalchemy import select

    from app.persistence.models import UserModel

    def read(session):
        rows = session.execute(select(UserModel)).scalars().all()
        owners = runtime.users.account_owners()
        by_user: dict[int, dict[str, list[str]]] = {}
        for (core_id, account_id), user_id in owners.items():
            by_user.setdefault(int(user_id), {}).setdefault(
                str(core_id), []).append(str(account_id))
        payload: dict[str, dict] = {}
        for row in rows:
            user_id = int(row.id)
            payload[str(user_id)] = {
                "username": str(row.username),
                "upload_mbps": max(0, int(row.upload_limit_mbps or 0)),
                "download_mbps": max(0, int(row.download_limit_mbps or 0)),
                "accounts": by_user.get(user_id, {}),
            }
        return payload

    try:
        return _persist(runtime, read)()
    except Exception as exc:  # noqa: BLE001 — shaping push is best-effort
        logger.warning("bandwidth limits could not be read for nodes: %s", exc)
        return {}


async def push_bandwidth_limits(runtime) -> dict[str, Any]:
    """Send the current limits to every paired node. Returns a per-node report."""
    payload = await asyncio.to_thread(bandwidth_limits_payload, runtime)
    if not payload:
        return {"pushed": [], "errors": []}
    loop = asyncio.get_running_loop()
    pushed: list[dict[str, Any]] = []
    errors: list[str] = []

    def _one(row):
        return _client(runtime, row).push_bandwidth_limits(payload)

    for row in paired_nodes(runtime):
        try:
            result = await loop.run_in_executor(None, _one, row)
        except Exception as exc:  # noqa: BLE001 — one node never blocks others
            errors.append(f"node {row.id}: {exc}")
            continue
        pushed.append({"node_id": int(row.id),
                       "limited_users": (result or {}).get("limited_users"),
                       "ok": bool((result or {}).get("ok", True))})
    return {"pushed": pushed, "errors": errors}


# --------------------------------------------------------------------------- #
# telemetry fan-out — what a node knows and the panel cannot see locally
# --------------------------------------------------------------------------- #
# Quota, presence and shaping are all computed from the panel's OWN cores, so
# a user connected through a node looked offline, consumed nothing and was
# never limited. These helpers ask every paired node for the same readings its
# local drivers give it, and never let one unreachable node distort the rest.

def paired_nodes(runtime) -> list[Any]:
    """Rows of every node that finished pairing (cheap, no I/O)."""
    from app.persistence.models import NodeModel

    def read(session):
        return (session.query(NodeModel)
                .filter(NodeModel.agent_type == "zagros_native",
                        NodeModel.agent_credentials_enc.isnot(None))
                .all())

    try:
        rows = _persist(runtime, read)()
    except Exception:  # noqa: BLE001 — telemetry must never break accounting
        logger.debug("node telemetry: cannot enumerate nodes")
        return []
    return list(rows or [])


async def collect_node_devices(runtime) -> tuple[list[dict], list[str]]:
    """(sessions, failed_node_names) from every paired node."""
    loop = asyncio.get_running_loop()
    sessions: list[dict] = []
    failed: list[str] = []

    def _one(row):
        client = _client(runtime, row)
        response = client.runtime_devices()
        rows = list(response.get("devices") or [])
        for item in rows:
            if isinstance(item, dict):
                item["node_id"] = int(row.id)
        return rows

    for row in paired_nodes(runtime):
        try:
            found = await loop.run_in_executor(None, _one, row)
        except Exception as exc:  # noqa: BLE001 — one node never blocks others
            logger.debug("node %s device collect failed: %s", row.id, exc)
            failed.append(getattr(row, "name", str(row.id)))
            continue
        sessions.extend(found)
    return sessions, failed


async def collect_node_usage(runtime) -> list[Any]:
    """UsageRecord-shaped deltas from every paired node."""
    from app.cores.types import UsageRecord

    loop = asyncio.get_running_loop()
    records: list[Any] = []

    def _one(row):
        client = _client(runtime, row)
        return list(client.runtime_usage().get("usage") or [])

    for row in paired_nodes(runtime):
        try:
            raw = await loop.run_in_executor(None, _one, row)
        except Exception as exc:  # noqa: BLE001 — one node never blocks others
            logger.debug("node %s usage collect failed: %s", row.id, exc)
            continue
        node_id = int(row.id)
        coefficient = float(getattr(row, "usage_coefficient", 1.0) or 1.0)
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                up = int(item.get("uplink_bytes") or 0)
                down = int(item.get("downlink_bytes") or 0)
            except (TypeError, ValueError):
                continue
            if not (up or down):
                continue
            if coefficient != 1.0:
                up = int(up * coefficient)
                down = int(down * coefficient)
            records.append(UsageRecord(
                core_id=str(item.get("core_id") or ""),
                account_id=str(item.get("account_id") or ""),
                node_id=node_id,
                uplink_bytes=up,
                downlink_bytes=down,
            ))
    return records


async def sync_bandwidth_limits(runtime) -> dict[str, Any]:
    """Push limits to nodes, recording failures on the node row."""
    try:
        result = await push_bandwidth_limits(runtime)
    except Exception as exc:  # noqa: BLE001 — never break the caller
        return {"pushed": [], "errors": [str(exc)]}
    for message in result.get("errors") or []:
        logger.warning("node bandwidth push: %s", message)
    return result


# --------------------------------------------------------------------------- #
# convergence — a node must end up configured AND running, not merely paired   #
# --------------------------------------------------------------------------- #
# Pairing only proves identity. A freshly installed core still has no listeners
# and no accounts, and it refuses to start until it does — which used to mean
# an operator had to find the "sync config" button before the node served
# anything. These helpers make the panel finish the job it started.

_RUNNING_STATES = frozenset({"running", "starting"})


def native_nodes(runtime) -> list[Any]:
    """Every Zagros-native node row, paired or not."""
    from app.persistence.models import NodeModel

    def read(session):
        return (session.query(NodeModel)
                .filter(NodeModel.agent_type == "zagros_native")
                .all())

    try:
        rows = _persist(runtime, read)()
    except Exception:  # noqa: BLE001 — never break a boot over bookkeeping
        logger.debug("node convergence: cannot enumerate nodes")
        return []
    return list(rows or [])


async def start_node_cores(runtime, node_id: int, *,
                           core_ids: list[str] | None = None) -> dict[str, Any]:
    """Start every installed core that should be serving traffic.

    A core the master does not run is left alone: the node is an extension of
    this panel, not an independent server with its own opinion.
    """
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)
    client = _client(runtime, row)
    inventory = await asyncio.to_thread(client.cores)
    installed = dict(inventory.get("installed") or {})
    master = set(runtime.core_manager.list_cores())

    started: list[str] = []
    errors: list[str] = []
    skipped: list[str] = []
    for core_id in sorted(installed):
        if core_ids is not None and core_id not in set(core_ids):
            continue
        if core_id not in master:
            skipped.append(f"{core_id}: not installed on the master")
            continue
        state = str((installed.get(core_id) or {}).get("state") or "").lower()
        if state in _RUNNING_STATES:
            continue
        try:
            await asyncio.to_thread(client.lifecycle, core_id, "start")
        except Exception as exc:  # noqa: BLE001 — one core never blocks the rest
            errors.append(f"{core_id}: {exc}")
            continue
        started.append(core_id)

    report = {"started": started, "errors": errors, "skipped": skipped}
    try:
        await heartbeat(runtime, node_id)
    except Exception:  # noqa: BLE001 — the state was changed either way
        pass
    return report


async def converge_node(runtime, node_id: int, *,
                        core_ids: list[str] | None = None) -> dict[str, Any]:
    """Push the configuration, then start what the node has to serve.

    Order matters: a node core refuses to start before it owns its listeners
    (identity, inbounds, accounts), so the sync always runs first.
    """
    report: dict[str, Any] = {"synced": None, "started": [], "errors": []}
    try:
        sync = await sync_node(runtime, node_id, core_ids=core_ids)
    except Exception as exc:  # noqa: BLE001 — report, never raise into pairing
        report["errors"].append(f"sync: {exc}")
        return report
    report["synced"] = sync.model_dump(mode="json")
    report["errors"].extend(str(e) for e in (sync.errors or []))
    if core_ids is None or any(
            item.get("core_id") in set(core_ids)
            for item in (sync.pushed or []) if isinstance(item, dict)):
        try:
            started = await start_node_cores(runtime, node_id, core_ids=core_ids)
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(f"start: {exc}")
        else:
            report["started"] = started.get("started") or []
            report["errors"].extend(started.get("errors") or [])
            report.setdefault("skipped", started.get("skipped") or [])
    return report


async def reconnect(runtime, node_id: int) -> NodeView:
    """Bring one node back online — pairing it first when that is what is missing.

    Adding a node only records intent: the agent is installed afterwards, by
    hand, on a machine this panel cannot see. Nothing then moved the row out of
    ``pending``. This is the single entry point that closes that gap, for the
    button, the scheduler and the boot sequence alike:

    1. a paired node only needs a heartbeat (cheapest proof of life);
    2. an unpaired one is discovered on its info port and paired with the
       one-time token the installer carried — the token is single-use and the
       fingerprint is verified against the certificate the control plane
       actually serves, so this is not trust-on-first-use over a new channel;
    3. anything that just came up is converged (configuration + start).
    """
    row = await asyncio.to_thread(_get_row, runtime, node_id)
    if row is None:
        raise KeyError(node_id)

    paired = bool(row.agent_identity and row.agent_credentials_enc)
    heartbeat_error = ""
    if paired:
        try:
            return await heartbeat(runtime, node_id)
        except Exception as exc:  # noqa: BLE001 — fall through to re-pairing
            heartbeat_error = str(exc)
            logger.info("node %s heartbeat failed (%s); checking whether it can "
                        "be paired again", node_id, exc)

    # A node that is not reachable keeps its credentials: a container restart
    # is not a reason to throw a working pairing away and demand the installer
    # be run again.
    info = await discover(runtime, node_id)
    if not info.reachable:
        message = info.error or "node is not reachable"
        await _mark_error(runtime, node_id, message)
        raise NodeClientError(message)
    if not info.pending_token:
        if paired:
            # The agent answers, but with no token to offer and no memory of
            # us — the usual cause is a reinstall. Say so, because "re-run the
            # installer" is only half the story: the token has to be rotated
            # first, the old one is spent.
            message = ("this node no longer recognises the stored pairing \u2014 the "
                       "agent looks freshly installed; rotate the installer token "
                       "and run the new command on the node")
        else:
            message = ("the node is not waiting for a registration token \u2014 "
                       "run the installer command on the node")
        await _mark_error(runtime, node_id, message)
        raise NodeClientError(message)
    if not info.certificate_sha256:
        await _mark_error(runtime, node_id, "the node published no certificate")
        raise NodeClientError("the node published no certificate")

    view = await pair(runtime, node_id,
                      certificate_fingerprint=info.certificate_sha256,
                      node_id_hint=info.node_id)
    try:
        await converge_node(runtime, node_id)
    except Exception as exc:  # noqa: BLE001 — pairing already succeeded
        logger.warning("node %s paired but could not be converged: %s",
                       node_id, exc)
    return view


async def reconnect_all(runtime) -> dict[str, Any]:
    """Reconnect every native node. Used at boot and by the scheduler."""
    report: dict[str, Any] = {"checked": 0, "connected": [], "paired": [],
                              "failed": {}}
    for row in native_nodes(runtime):
        report["checked"] += 1
        was_connected = row.status == "connected"
        try:
            view = await reconnect(runtime, int(row.id))
        except Exception as exc:  # noqa: BLE001 — one node never blocks the rest
            report["failed"][str(row.name)] = str(exc)[:300]
            continue
        bucket = "connected" if was_connected else "paired"
        report[bucket].append({"node_id": int(row.id), "name": view.name,
                               "status": view.status})
    return report
