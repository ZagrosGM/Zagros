"""Zagros HTTP routers — thin adapters over the tested service layer.

Mount under the FastAPI app (the lazy ``app`` builder includes this router
when the platform runtime is available):

    Client API:  /client/v1/...        (official Zagros app)
    Portal:      /zagros/sub/{token}   (driver-agnostic subscription page;
                 the path segment is customizable via portal settings —
                 /zagros/{subscription_path}/{token} — with /zagros/sub/...
                 kept as the canonical alias so existing links never die)
    Admin API:   /api/zagros/...       (dashboard, studio, settings, migration)
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
import base64 as _base64

from app.clientapi.errors import ClientApiError
from app.clientapi.models import AppCredentials, AuthTokens, ConnectOffer
from app.clientapi.tokens import TokenError
from app.cores.exceptions import CoreError
from app.portal.models import PortalSettings
from app.portal.render import render_page_html
from app.studio.jsonpatch import PatchOperation
from app.studio.service import (
    InboundSpec,
    StudioConflictError,
    StudioError,
    StudioNotFoundError,
)

logger = logging.getLogger(__name__)

zagros_router = APIRouter(tags=["Zagros"])


# ---------------------------------------------------------------------- #
# auth plumbing: admin endpoints ride the legacy OAuth2/JWT stack and are
# restricted to sudo admins. If the legacy stack is not importable (bare
# test shims), the dependency FAILS CLOSED — never open-by-default.
# ---------------------------------------------------------------------- #
def _resolve_sudo_deps():
    """Resolve the sudo dependency WITHOUT depending on import order.

    ``app.models.admin`` and ``app.db`` import each other, so the model is
    only importable once the DB package has been initialised — importing it
    first raises a circular ImportError. That exception used to be swallowed
    here, which silently bound EVERY admin endpoint to a 503 dependency:
    the whole admin API went dead with no log line, purely because some
    other module happened to be imported first (a test file's order is
    enough). Importing the DB package first always breaks the cycle.
    """
    try:
        import app.db  # noqa: F401  — must precede the model import
    except Exception as exc:  # noqa: BLE001 — surfaced by the caller
        logger.warning("admin auth stack: app.db failed to import (%s: %s)",
                       type(exc).__name__, exc)
    from app.models.admin import Admin

    return [Depends(Admin.check_sudo_admin)]


try:
    _SUDO_DEPS = _resolve_sudo_deps()
except Exception as exc:  # pragma: no cover - import-time safety net
    # Failing CLOSED is the right direction; failing SILENTLY is not: the
    # reason has to be in the log, or the next incident starts blind.
    logger.warning("admin authentication stack unavailable — admin endpoints "
                   "will fail closed with 503 (%s: %s)", type(exc).__name__, exc)

    async def _no_admin_stack() -> None:
        raise HTTPException(503, "admin authentication stack unavailable")

    _SUDO_DEPS = [Depends(_no_admin_stack)]

zagros_admin_router = APIRouter(
    prefix="/api/zagros", tags=["Zagros Admin"], dependencies=_SUDO_DEPS)


# ---------------------------------------------------------------------- #
# plumbing
# ---------------------------------------------------------------------- #

def get_runtime(request: Request):
    runtime = getattr(request.app.state, "zagros", None)
    if runtime is not None:
        return runtime

    # The runtime is built at boot, which can land before a managed
    # MySQL/MariaDB container accepts connections. Rather than staying
    # disabled until someone restarts the panel, retry once per request so
    # the platform layer heals as soon as the database is reachable.
    builder = getattr(request.app.state, "zagros_builder", None)
    if builder is not None:
        runtime, exc = builder()
        if runtime is not None:
            request.app.state.zagros = runtime
            logging.getLogger("uvicorn.error").info(
                "Zagros platform runtime recovered")
            return runtime
        raise HTTPException(
            503, f"Zagros platform runtime is not initialized: {exc}")

    raise HTTPException(503, "Zagros platform runtime is not initialized")


def _client_error(exc: Exception) -> HTTPException:
    code = getattr(exc, "status_code", 400)
    return HTTPException(code, {"error": getattr(exc, "error_code", "error"),
                                "message": str(exc)})


def _bearer(authorization: str | None, runtime) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        return runtime.client_api.verify_access(authorization[7:])
    except ClientApiError as exc:
        raise _client_error(exc) from exc


# ---------------------------------------------------------------------- #
# Client API (/client/v1)
# ---------------------------------------------------------------------- #

class LoginBody(BaseModel):
    username: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str


class ConfigBody(BaseModel):
    connect_token: str
    client_public_key: str  # base64url X25519 ephemeral public key


@zagros_router.post("/client/v1/auth/login", response_model=AuthTokens)
async def client_login(body: LoginBody, runtime=Depends(get_runtime)):
    try:
        return await runtime.client_api.authenticate(body.username, body.password)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


@zagros_router.post("/client/v1/auth/refresh", response_model=AuthTokens)
async def client_refresh(body: RefreshBody, runtime=Depends(get_runtime)):
    try:
        return await runtime.client_api.refresh(body.refresh_token)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


@zagros_router.post("/client/v1/auth/logout")
async def client_logout(body: RefreshBody, runtime=Depends(get_runtime)):
    await runtime.client_api.logout(body.refresh_token)
    return {"ok": True}


@zagros_router.get("/client/v1/profile")
async def client_profile(authorization: str | None = Header(default=None),
                         runtime=Depends(get_runtime)):
    user_id = _bearer(authorization, runtime)
    return await runtime.client_api.get_profile(user_id)


@zagros_router.post("/client/v1/connect/{core_id}", response_model=ConnectOffer)
async def client_connect(core_id: str,
                         authorization: str | None = Header(default=None),
                         runtime=Depends(get_runtime)):
    user_id = _bearer(authorization, runtime)
    try:
        return await runtime.client_api.request_connect(user_id, core_id)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


@zagros_router.post("/client/v1/config")
async def client_config(body: ConfigBody, request: Request,
                        runtime=Depends(get_runtime)):
    try:
        settings = await runtime.portal_settings.get_portal_settings()
        context = runtime.portal._delivery_context(  # noqa: SLF001
            settings, request.url.hostname)
        envelope = await runtime.client_api.deliver_config(
            body.connect_token, body.client_public_key, context
        )
    except ClientApiError as exc:
        raise _client_error(exc) from exc
    return envelope


# ---------------------------------------------------------------------- #
# Public transition readiness (cross-origin image probe, no credentials)
# ---------------------------------------------------------------------- #

@zagros_router.get("/api/zagros/network-transition/{operation_id}.svg",
                   include_in_schema=False)
async def panel_network_transition_probe(operation_id: str):
    """Return an image only after host apply and new-origin health succeeded.

    A page loaded from the old origin cannot read the new origin's authenticated
    API because of same-origin policy. Image loading is intentionally
    credential-free and still enforces browser DNS/TLS verification; non-success
    states return a non-image 503 so ``img.onerror`` keeps polling.
    """
    import re

    from app.platform.network_settings import HostNetworkRequest

    if not re.fullmatch(r"[0-9a-f]{32,128}", operation_id):
        return PlainTextResponse("not ready", status_code=503)
    result = HostNetworkRequest().status(operation_id)
    if result.get("status") != "success":
        return PlainTextResponse("not ready", status_code=503,
                                 headers={"Cache-Control": "no-store"})
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'>"
           "<rect width='1' height='1' fill='#16a34a'/></svg>")
    return Response(svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------------- #
# Subscription portal (/zagros/sub/{token})
# ---------------------------------------------------------------------- #

async def _legacy_sub_user_id(token: str) -> int | None:
    """Validate a LEGACY username token (pre-
    `create_subscription_token`) under the legacy rules (issued before the
    user's created_at is invalid; `sub_revoked_at` revokes). Returns the
    platform user id, or None when the token is not a valid legacy token.

    This is the migration bridge: the legacy /sub/ endpoint is GONE, but
    already-issued URLs (telegram bot messages, admin notes) must keep
    working — they land on the one multi-core portal now."""
    import asyncio as _asyncio

    from app.utils.jwt import get_subscription_payload

    sub = get_subscription_payload(token)
    if not sub:
        return None

    def _resolve() -> int | None:
        from app.db import crud
        from app.db.base import SessionLocal

        db = SessionLocal()
        try:
            dbuser = crud.get_user(db, sub["username"])
            if not dbuser or dbuser.created_at > sub["created_at"]:
                return None
            if dbuser.sub_revoked_at and dbuser.sub_revoked_at > sub["created_at"]:
                return None
            return int(dbuser.id)
        finally:
            db.close()

    return await _asyncio.to_thread(_resolve)


async def _verify_and_serve(token, request, runtime,
                            accept_language, user_agent):
    user_id: int | None = None
    try:
        payload = runtime.tokens.verify(token, expected_type="sub")
    except TokenError:
        payload = None
    if payload is not None:
        candidate = int(payload["sub"])
        # rotation invalidates older portal URLs immediately (fail-closed)
        current_jti = await runtime.kv.get_value(f"portal.sub_jti.{candidate}")
        if current_jti is not None and payload.get("jti") == current_jti:
            user_id = candidate
    if user_id is None:
        # legacy username token (issued pre-) — same portal, one
        # multi-core subscription surface, legacy revocation rules honored
        user_id = await _legacy_sub_user_id(token)
    if user_id is None:
        raise HTTPException(404, "subscription not found")
    return await _serve_subscription(runtime, user_id, request,
                                     accept_language, user_agent)


@zagros_router.get("/sub/{token}", response_class=HTMLResponse)
async def subscription_portal_canonical(token: str, request: Request,
                                        runtime=Depends(get_runtime),
                                        accept_language: str | None = Header(default=None),
                                        user_agent: str | None = Header(default=None)):
    """Canonical multi-core subscription URL — /sub/<token> (item
    12). One user → one link → every core."""
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


@zagros_router.get("/zagros/sub/{token}", response_class=HTMLResponse)
async def subscription_portal(token: str, request: Request,
                              runtime=Depends(get_runtime),
                              accept_language: str | None = Header(default=None),
                              user_agent: str | None = Header(default=None)):
    """Legacy alias of the canonical /sub/<token> — already-issued links
    keep working forever (no redirect, identical payload)."""
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


@zagros_router.get("/{sub_path}/{token}", response_class=HTMLResponse)
async def subscription_portal_configured_path(
    sub_path: str, token: str, request: Request,
    runtime=Depends(get_runtime),
    accept_language: str | None = Header(default=None),
    user_agent: str | None = Header(default=None),
):
    """Canonical configurable root path, e.g. /clients/<token>."""
    settings = await runtime.portal_settings.get_portal_settings()
    if sub_path != settings.subscription_path:
        raise HTTPException(404, "subscription not found")
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


@zagros_router.get("/zagros/{sub_path}/{token}", response_class=HTMLResponse)
async def subscription_portal_custom_path(sub_path: str, token: str,
                                          request: Request,
                                          runtime=Depends(get_runtime),
                                          accept_language: str | None = Header(default=None),
                                          user_agent: str | None = Header(default=None)):
    """Settings-driven subscription URL segment. Fail closed: any segment
    other than the currently-configured one is indistinguishable from a bad
    token (404), never a redirect that would leak the configured path."""
    settings = await runtime.portal_settings.get_portal_settings()
    if sub_path != settings.subscription_path:
        raise HTTPException(404, "subscription not found")
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


def _legacy_user_snapshot(username: str):
    """(used_traffic, data_limit, expire) from the legacy users row — the
    single master counters (quota is singular by design), for the
    `subscription-userinfo` response header the legacy endpoint sent."""
    from app.db import crud
    from app.db.base import SessionLocal

    db = SessionLocal()
    try:
        dbuser = crud.get_user(db, username)
        if dbuser is None:
            return None
        return (int(dbuser.used_traffic or 0),
                int(dbuser.data_limit or 0),
                int(dbuser.expire or 0))
    finally:
        db.close()


def _track_subscription_fetch(username: str, user_agent: str) -> None:
    """Keep `sub_updated_at` / `sub_last_user_agent` alive — the legacy
    endpoint bumped them on every GET; the admin Users page shows them."""
    from app.db import crud
    from app.db.base import SessionLocal

    db = SessionLocal()
    try:
        dbuser = crud.get_user(db, username)
        if dbuser is not None:
            crud.update_user_sub(db, dbuser, user_agent or "")
    finally:
        db.close()


async def _serve_subscription(runtime, user_id: int, request: Request,
                              accept_language: str | None,
                              user_agent: str | None):
    # Content negotiation: subscription CLIENTS (v2rayNG, Streisand, sing-box,
    # Nekoray...) fetch the link list (base64 body, Marzban convention);
    # BROWSERS get the rich multi-core portal page.
    import asyncio as _asyncio

    accept = request.headers.get("accept", "")
    ua = (user_agent or "").lower()
    # explicit ?format= always wins (browser may fetch clash/sing-box configs)
    explicit_fmt = (request.query_params.get("format") or "").lower().strip()
    is_browser = (not explicit_fmt) and "text/html" in accept and any(
        k in ua for k in ("mozilla", "chrome", "safari", "firefox", "edge"))
    lang = None
    if accept_language:
        lang = accept_language.split(",")[0].strip()[:5]

    # legacy-continuity bookkeeping: the removed /sub/
    # endpoint tracked every fetch and sent real quota headers — the portal
    # is THE subscription surface now, so it owns the same duties.
    username: str | None = None
    userinfo_header = ""
    try:
        row = await _asyncio.to_thread(runtime.users.get_user, user_id)
        username = row.username if row is not None else None
    except Exception:  # noqa: BLE001 — bookkeeping must never kill delivery
        username = None
    if username:
        try:
            await _asyncio.to_thread(
                _track_subscription_fetch, username, user_agent or "")
        except Exception:  # noqa: BLE001 — never break a fetch on tracking
            pass
        try:
            snapshot = await _asyncio.to_thread(_legacy_user_snapshot, username)
            if snapshot is not None:
                used, total, expire = snapshot
                userinfo_header = (
                    f"upload=0; download={used}; total={total}; expire={expire}")
        except Exception:  # noqa: BLE001
            userinfo_header = ""

    if is_browser:
        page = await runtime.portal.build_page(
            user_id, lang=lang, public_host=request.url.hostname)
        if page is None:
            raise HTTPException(404, "subscription not found")
        # an operator may have picked an uploaded page
        # template. A missing/broken one serves the built-in page, so a
        # subscriber is never the one who pays for an operator's typo.
        template_name: str | None = None
        templates_dir: str | None = None
        try:
            settings = await runtime.portal_settings.get_portal_settings()
            template_name = getattr(settings, "subscription_template", None) or None
            if template_name:
                from app.portal.templates_store import data_dir_for

                templates_dir = data_dir_for(runtime)
        except Exception:  # noqa: BLE001 — settings read must not break delivery
            template_name, templates_dir = None, None
        return HTMLResponse(render_page_html(page, template_name,
                                             templates_dir=templates_dir))

    bundle = await runtime.portal.build_links(
        user_id, public_host=request.url.hostname)
    if bundle is None:
        raise HTTPException(404, "subscription not found")
    links, notes = bundle

    # Client-specific formats (spec §8): ONE merged multi-core link set,
    # rendered for whatever is fetching. ``?format=`` overrides UA sniffing.
    from app.platform.sub_formats import dedupe_links, to_clash_meta, to_sing_box

    fmt = explicit_fmt or _format_for_ua(ua)
    if fmt in ("clash", "clash-meta", "meta", "stash", "yaml"):
        body, _fmt_notes = to_clash_meta(links, notes)
        return PlainTextResponse(
            body, media_type="text/yaml; charset=utf-8",
            headers={
                "profile-update-interval": "6",
                "subscription-userinfo": userinfo_header,
                "content-disposition": "attachment; filename=\"zagros.yaml\"",
            },
        )
    if fmt in ("sing-box", "singbox", "json"):
        body, _fmt_notes = to_sing_box(links, notes)
        return PlainTextResponse(
            body, media_type="application/json; charset=utf-8",
            headers={
                "profile-update-interval": "6",
                "subscription-userinfo": userinfo_header,
                "content-disposition": "attachment; filename=\"zagros.json\"",
            },
        )

    links = dedupe_links(links)
    body_lines = [f"# {n}" for n in notes] + links
    encoded = _base64.b64encode("\n".join(body_lines).encode()).decode()
    return PlainTextResponse(
        encoded,
        headers={
            "subscription-userinfo": userinfo_header,
            "profile-update-interval": "6",
            "content-disposition": "attachment; filename=\"zagros-subscription\"",
        },
    )


def _format_for_ua(ua: str) -> str:
    """User-Agent → subscription format (Marzban-style sniffing, multi-core)."""
    if any(k in ua for k in ("clash", "mihomo", "flclash", "stash")):
        return "clash-meta"
    if any(k in ua for k in ("sing-box", "singbox", "sfa", "sfi", "sfm")):
        return "sing-box"
    return ""


@zagros_admin_router.post("/users/{user_id}/subscription-token")
async def issue_subscription_token(user_id: int, runtime=Depends(get_runtime)):
    """Issue (rotate) the user's portal URL token; older links die at once."""
    token, _ = runtime.tokens.issue(user_id, ttl_seconds=10 * 365 * 24 * 3600,
                                    token_type="sub")
    payload = runtime.tokens.verify(token, expected_type="sub")
    await runtime.kv.set_value(f"portal.sub_jti.{user_id}", payload["jti"])
    settings = (await runtime.portal_settings.get_portal_settings()).normalize()
    # New links honor the configured canonical root path. /sub/<token> and
    # /zagros/sub/<token> remain permanent aliases for every older token.
    path = settings.canonical_path(token)
    prefix = (settings.public_base_url() or "").rstrip("/")
    return {"token": token, "path": path,
            "url": f"{prefix}{path}" if prefix else None}


@zagros_admin_router.post("/users/by-username/{username}/subscription-token")
async def issue_subscription_token_by_username(username: str, runtime=Depends(get_runtime)):
    """Same as by-id, for the dashboard which identifies users by username."""
    import asyncio as _asyncio

    row = await _asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, f"user '{username}' not found")
    return await issue_subscription_token(row.id, runtime)


@zagros_admin_router.get("/users/by-username/{username}/subscription-url")
async def canonical_subscription_url_by_username(
    username: str, runtime=Depends(get_runtime),
):
    """Build a copy/QR URL from the SQL portal settings source of truth.

    Legacy user serializers still expose their historical config.py-derived
    field for API compatibility. The dashboard must not absolutize that field
    against ``window.location.origin`` because doing so silently discards the
    dedicated subscription domain/port.
    """
    import asyncio as _asyncio

    from app.utils.jwt import create_subscription_token

    row = await _asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, f"user '{username}' not found")
    settings = (await runtime.portal_settings.get_portal_settings()).normalize()
    token = create_subscription_token(username)
    path = settings.canonical_path(token)
    base = (settings.public_base_url() or "").rstrip("/")
    return {"path": path, "url": f"{base}{path}" if base else None,
            "listener_mode": settings.listener_mode}


# ---------------------------------------------------------------------- #
# Admin: dashboard / studio / settings / migration
# ---------------------------------------------------------------------- #

@zagros_admin_router.get("/dashboard/snapshot")
async def dashboard_snapshot(runtime=Depends(get_runtime)):
    snapshot = await runtime.dashboard.snapshot()
    return snapshot


@zagros_admin_router.get("/studio/{core_id}/raw")
async def studio_raw(core_id: str, runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    return {"core_id": core_id, "json": await runtime.studio.raw_text(core_id, driver)}


@zagros_admin_router.get("/cores/{core_id}/wizard-schema")
async def core_wizard_schema(core_id: str, runtime=Depends(get_runtime)):
    """Dynamic inbound-wizard blueprint for this engine and live runtime.

    SoftEther availability is refined from the installed binary's read-only
    ``vpncmd Help`` inventory.  The endpoint therefore cannot claim PPTP (or
    any other server transport) merely because a static UI label exists.
    """
    import asyncio as _asyncio

    from app.studio.wizard import blueprint_for

    try:
        blueprint = blueprint_for(core_id)
    except KeyError:
        raise HTTPException(404, f"no inbound-wizard blueprint for core '{core_id}'") from None
    if blueprint["core_id"] == "softether":
        from app.cores.drivers.softether.capabilities import (
            apply_softether_wizard_capabilities,
        )

        blueprint = await _asyncio.to_thread(
            apply_softether_wizard_capabilities, blueprint, runtime)
    return blueprint


@zagros_admin_router.get("/cores/{core_id}/suggest-port")
async def core_suggest_port(core_id: str, runtime=Depends(get_runtime)):
    """ — a fresh RANDOM five-digit listen-port suggestion
    for the wizard: never a famous default, never one the host or a managed
    core already binds (best-effort collision avoidance)."""
    _driver_or_404(runtime, core_id)
    from app.studio.ports import host_listening_ports, studio_used_ports, suggest_port

    excluded = await studio_used_ports(runtime)
    excluded |= host_listening_ports()
    return {"port": suggest_port(excluded)}


class StudioPatchBody(BaseModel):
    operations: list[PatchOperation]


@zagros_admin_router.post("/studio/{core_id}/preview")
async def studio_preview(core_id: str, body: StudioPatchBody,
                         runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    return await runtime.studio.preview(driver, body.operations)


async def _materialize_studio(runtime, core_id: str, driver, doc) -> str | None:
    """Push the CANDIDATE studio document INTO the core (every driver
    implements apply_studio_document) — BEFORE it is
    persisted (: stage → materialize → persist, so a core
    that refuses the document fails the request WITHOUT moving the stored
    document to a state the engine rejected; the field-reported split where
    the API answered an opaque 5xx while the inbound HAD been persisted is
    gone for good).

    A driver that refuses the document (CoreError — cardinality violation,
    untranslatable wizard field, failed restart) speaks to the OPERATOR, so
    it maps to 422 with the driver's own message instead of leaking out as
    an opaque 500 (the field-reported TUIC/OpenVPN/… wizard crash)."""
    hook = getattr(driver, "apply_studio_document", None)
    if hook is None or doc is None:
        return ("document saved; this engine applies it on next start "
                "(no live studio→core bridge for this driver)")
    try:
        # CoreManager owns the lifecycle lock and persists any settings the
        # service driver derives from this document (port, PSK, endpoint,
        # listener set). Direct driver calls here raced start/restart and lost
        # settings on panel reboot.
        await runtime.core_manager.apply_studio_document(core_id, doc)
    except CoreError as exc:
        raise HTTPException(422, f"{core_id}: {exc}") from exc
    return None


async def _cascade_grants(runtime, core_id: str) -> None:
    """Item 6: an applied document may have REMOVED inbounds — cascade the
    change into materialized grants (prune dangling tags / revoke empty
    accounts) so a later User Edit can never die on a ghost tag. Runs AFTER
    the document persisted (the catalog reads the store)."""
    try:
        from app.platform.provisioning import (
            reconcile_accounts_after_inbound_change,
        )

        report = await reconcile_accounts_after_inbound_change(runtime, core_id)
        if any(report.get(k) for k in ("pruned", "revoked")):
            logger.info("studio apply on %s — grant cascade: %s", core_id, report)
    except Exception as exc:  # noqa: BLE001 — never mask a successful apply
        logger.warning("post-apply grant cascade failed on %s: %s", core_id, exc)


def _studio_error(exc: StudioError) -> HTTPException:
    """Map staged-mutation identity errors to honest HTTP statuses
: ghost tag → 404, identity clash → 409, anything
    else is a client-correctable 422 — an opaque 500 is NEVER right for
    lifecycle conflicts."""
    if isinstance(exc, StudioNotFoundError):
        return HTTPException(404, str(exc))
    if isinstance(exc, StudioConflictError):
        return HTTPException(409, str(exc))
    return HTTPException(422, str(exc))


async def _commit_staged(runtime, core_id: str, driver, result) -> dict:
    """DEPRECATED compatibility shim — the transaction (stage → materialize
    → persist under the core lock) now lives INSIDE the service
    (``wizard_create/update/delete``). Kept for one release for tests that
    emulate the routed flow; new callers use the service transactions."""
    if not result.changed:
        return {**result.model_dump(), "materialized": None,
                "notice": result.detail or "already in the requested state"}
    warning = await _materialize_studio(runtime, core_id, driver, result.document)
    await runtime.studio.persist(driver, result.document or {})
    await _cascade_grants(runtime, core_id)
    return {**result.model_dump(), "materialized": warning is None, "notice": warning}


def _materialize_hook(runtime, core_id: str, driver):
    """The callback the service transactions invoke INSIDE the lock — maps
    engine refusals to 422 before anything persists."""
    async def _run(doc):
        return await _materialize_studio(runtime, core_id, driver, doc)

    return _run


async def _respond_committed(runtime, core_id: str, result, *, warning=None) -> dict:
    """Tail of a committed studio transaction: grant cascade + response
    shaping (idempotent replays skip the cascade — nothing changed)."""
    if not result.changed:
        return {**result.model_dump(), "materialized": None,
                "notice": result.detail or "already in the requested state"}
    await _cascade_grants(runtime, core_id)
    if core_id != "xray" and result.document is not None:
        from app.portal.hostengine import reconcile_default_hosts

        inbounds = result.document.get("inbounds") or []
        tags = [str(item.get("tag")) for item in inbounds
                if isinstance(item, dict) and item.get("tag")]
        await reconcile_default_hosts(runtime.core_hosts, core_id, tags)
    return {**result.model_dump(),
            "materialized": warning is None,
            "notice": warning}


@zagros_admin_router.post("/studio/{core_id}/apply")
async def studio_apply(core_id: str, body: StudioPatchBody,
                       runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    result = await runtime.studio.apply_operations(
        driver, body.operations, _materialize_hook(runtime, core_id, driver))
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    return await _respond_committed(runtime, core_id, result)


def _certs_data_dir(runtime) -> str:
    """The panel data dir for the managed certificate store — same contract
    as admin_api._data_dir (kept local: admin_api depends on THIS module,
    so importing it back would cycle)."""
    url = str(getattr(runtime, "database_url", "") or "")
    if url.startswith("sqlite:///"):
        from pathlib import Path

        return str(Path(url[10:]).parent)
    return "/var/lib/zagros"


def _resolve_certificate_ref(runtime, spec: InboundSpec) -> None:
    """Item 10: ``certificate_ref`` (a managed certificate NAME from the
    Certificates store) in a wizard spec is resolved server-side into the
    inline PEM pair drivers already understand — with REAL validation
    (parse + key-matches-cert + expiry surfaced), never trust by name.
    Mutates the spec in place; ref always wins over pasted content."""
    ref = spec.settings.pop("certificate_ref", None)
    if not ref:
        return
    from pathlib import Path

    data_dir = _certs_data_dir(runtime)
    base = Path(data_dir) / "certs" / str(ref)
    cert_path, key_path = base / "fullchain.pem", base / "key.pem"
    if not base.is_dir() or not cert_path.exists() or not key_path.exists():
        raise HTTPException(
            404, f"managed certificate '{ref}' not found under {data_dir}/certs/")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert_pem = cert_path.read_bytes()
    key_pem = key_path.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
    except ValueError as exc:
        raise HTTPException(422, f"certificate '{ref}' is not a valid PEM pair: {exc}") from exc
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise HTTPException(422, f"certificate '{ref}' and its private key do NOT match")
    spec.settings["certificate"] = cert_pem.decode()
    spec.settings["certificate_key"] = key_pem.decode()


@zagros_admin_router.post("/studio/{core_id}/wizard/inbound")
async def studio_wizard_inbound(core_id: str, spec: InboundSpec,
                                runtime=Depends(get_runtime)):
    """Create — atomic + idempotent: staged under the
    per-core lock, materialized BEFORE persisted; an identical replay is a
    success without a duplicate; a conflicting tag is a 409."""
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_create(
            driver, spec, _materialize_hook(runtime, core_id, driver))
    except StudioError as exc:
        raise _studio_error(exc) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    return await _respond_committed(runtime, core_id, result)


@zagros_admin_router.put("/studio/{core_id}/wizard/inbound/{tag}")
async def studio_wizard_update_inbound(core_id: str, tag: str, spec: InboundSpec,
                                       runtime=Depends(get_runtime)):
    """Item 11 — Edit an existing inbound through the same wizard flow
    (staged → materialized → persisted, atomically)."""
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_update(
            driver, tag, spec, _materialize_hook(runtime, core_id, driver))
    except StudioError as exc:
        raise _studio_error(exc) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    return await _respond_committed(runtime, core_id, result)


@zagros_admin_router.delete("/studio/{core_id}/wizard/inbound/{tag}")
async def studio_wizard_delete_inbound(core_id: str, tag: str,
                                       runtime=Depends(get_runtime)):
    """Delete ONE inbound by its stable identity — the tag (item
    5; replaces the index-based frontend patch that could remove the WRONG
    listener off a stale snapshot). Ghost tag → 404; duplicate tags (broken
    document) → 409; success removes exactly one entry, cascades grants."""
    driver = _driver_or_404(runtime, core_id)
    try:
        result = await runtime.studio.wizard_delete(
            driver, tag, _materialize_hook(runtime, core_id, driver))
    except StudioError as exc:
        raise _studio_error(exc) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    if not result.changed:
        return {"ok": True, "deleted": None, "materialized": None,
                "notice": result.detail or "already absent"}
    notice = await _delete_cascade_notice(runtime, core_id)
    if core_id != "xray" and result.document is not None:
        from app.portal.hostengine import reconcile_default_hosts

        tags = [str(item.get("tag")) for item in (result.document.get("inbounds") or [])
                if isinstance(item, dict) and item.get("tag")]
        await reconcile_default_hosts(runtime.core_hosts, core_id, tags)
    elif core_id == "xray":
        # Grant cascade ran first; now the legacy inbound/host row can be
        # removed cleanly. ProxyHost has delete-orphan cascade from inbound.
        import asyncio as _asyncio

        def _remove_legacy_host() -> None:
            from app.db import GetDB
            from app.db.models import ProxyInbound

            with GetDB() as db:
                row = db.query(ProxyInbound).filter(ProxyInbound.tag == tag).first()
                if row is not None:
                    db.delete(row)
                    db.commit()

        await _asyncio.to_thread(_remove_legacy_host)
    return {"ok": True, "deleted": tag,
            "materialized": result.document is not None,
            "notice": notice}


async def _delete_cascade_notice(runtime, core_id: str) -> str | None:
    """Delete tail: grants bound to the removed inbound are pruned/revoked
    (item 6). Failures surface in logs only — the delete itself succeeded."""
    await _cascade_grants(runtime, core_id)
    return None


@zagros_admin_router.post("/studio/{core_id}/wizard/preview")
async def studio_wizard_preview(core_id: str, spec: InboundSpec,
                                runtime=Depends(get_runtime)):
    """Item 6 Preview gate: validate the wizard spec (patch + schema + diff)
    WITHOUT persisting or materializing — the stepper's review step calls
    this so an invalid inbound is rejected BEFORE any document mutation."""
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_preview_inbound(driver, spec)
    except StudioError as exc:
        raise HTTPException(422, str(exc)) from exc
    return result


def _driver_or_404(runtime, core_id: str):
    try:
        return runtime.core_manager.get(core_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(404, f"core '{core_id}' is not installed") from exc


@zagros_admin_router.get("/settings/portal", response_model=PortalSettings)
async def get_portal_settings(runtime=Depends(get_runtime)):
    return await runtime.portal_settings.get_portal_settings()


def _validate_portal_certificate(runtime, settings: PortalSettings) -> None:
    ident = (settings.tls_certificate_id or "").strip()
    if not ident:
        return
    from app.platform import certificates

    data_dir = (str(Path(runtime.database_url[10:]).parent)
                if runtime.database_url.startswith("sqlite:///")
                else "/var/lib/zagros")
    found = next((item for item in certificates.scan(data_dir, managed_only=True)
                  if item.id == ident or item.name == ident), None)
    if found is None:
        raise ValueError(f"TLS certificate '{ident}' does not exist")
    if found.expired or not found.has_key:
        raise ValueError(f"TLS certificate '{ident}' is expired or has no private key")
    hostname = settings.public_base_url()
    if hostname:
        from urllib.parse import urlsplit
        hostname = urlsplit(hostname).hostname
    if hostname and not certificates.certificate_covers(found.path, hostname):
        raise ValueError(
            f"TLS certificate '{ident}' does not cover subscription hostname '{hostname}'")


@zagros_admin_router.put("/settings/portal", response_model=PortalSettings)
async def put_portal_settings(settings: PortalSettings, request: Request,
                              runtime=Depends(get_runtime)):
    previous = await runtime.portal_settings.get_portal_settings()
    try:
        settings = settings.normalize()
        _validate_portal_certificate(runtime, settings)
        # Listener first, persistence second: an unbindable domain/port/TLS
        # configuration can never replace last-known-good desired state.
        await runtime.subscription_listener.apply(settings, runtime, request.app)
        try:
            return await runtime.portal_settings.save_portal_settings(settings)
        except Exception:
            await runtime.subscription_listener.apply(previous, runtime, request.app)
            raise
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@zagros_admin_router.post("/settings/portal/test")
async def portal_settings_test(settings: PortalSettings,
                               runtime=Depends(get_runtime)):
    """Validate and show every URL family without mutating persistence."""
    try:
        settings = settings.normalize()
        _validate_portal_certificate(runtime, settings)
        if settings.listener_mode == "dedicated":
            await runtime.subscription_listener._preflight(runtime, settings)  # noqa: SLF001
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    base = settings.public_base_url() or "https://panel.example.com"
    path = settings.canonical_path()
    subscription = base.rstrip("/") + path
    qr_base = (settings.qr_base_url or base).rstrip("/")
    warnings: list[str] = []
    if settings.public_scheme == "https" and not settings.tls_certificate_id:
        warnings.append("HTTPS selected without a panel-managed certificate; an external reverse proxy must terminate TLS")
    return {
        "ok": True,
        "base_url": base,
        "subscription": subscription,
        "portal": subscription,
        "clash": subscription + "?format=clash-meta",
        "sing_box": subscription + "?format=sing-box",
        "qr_base_url": qr_base,
        "openvpn_host": qr_base,
        "wireguard_host": qr_base,
        "force_https": settings.force_https,
        "listener_mode": settings.listener_mode,
        "listener": runtime.subscription_listener.public_status(),
        "warnings": warnings,
    }


@zagros_admin_router.post("/users/{user_id}/app-credentials",
                    response_model=AppCredentials)
async def issue_app_credentials(user_id: int, runtime=Depends(get_runtime)):
    try:
        return await runtime.client_api.issue_app_credentials(user_id)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


class MigrationBody(BaseModel):
    legacy_path: str = Field(description="Filesystem path to the Marzban sqlite DB")
    dry_run: bool = True


@zagros_admin_router.post("/migrate/legacy")
async def migrate_legacy(body: MigrationBody, runtime=Depends(get_runtime)):
    import asyncio

    from app.persistence.legacy_reader import read_legacy_sqlite
    from app.persistence.migration import LegacyImportService

    path = Path(body.legacy_path)
    if not path.is_file():
        raise HTTPException(404, f"legacy database not found: {body.legacy_path}")
    service = LegacyImportService(runtime.session_factory, runtime.users,
                                  runtime.cipher)
    snapshot = await asyncio.to_thread(read_legacy_sqlite, path)
    report = await asyncio.to_thread(service.migrate, snapshot, dry_run=body.dry_run)
    return report.as_dict()
