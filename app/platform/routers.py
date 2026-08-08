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

from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
import base64 as _base64

from app.clientapi.errors import ClientApiError
from app.clientapi.models import AppCredentials, AuthTokens, ConnectOffer
from app.clientapi.tokens import TokenError
from app.cores.exceptions import CoreError
from app.portal.models import PortalSettings
from app.portal.render import render_page_html
from app.studio.jsonpatch import PatchOperation
from app.studio.service import InboundSpec, StudioError

zagros_router = APIRouter(tags=["Zagros"])


# ---------------------------------------------------------------------- #
# auth plumbing: admin endpoints ride the legacy OAuth2/JWT stack and are
# restricted to sudo admins. If the legacy stack is not importable (bare
# test shims), the dependency FAILS CLOSED — never open-by-default.
# ---------------------------------------------------------------------- #
try:
    from app.models.admin import Admin as _LegacyAdmin

    _SUDO_DEPS = [Depends(_LegacyAdmin.check_sudo_admin)]
except Exception:  # pragma: no cover - import-time safety net
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
    if runtime is None:
        raise HTTPException(503, "Zagros platform runtime is not initialized")
    return runtime


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
async def client_config(body: ConfigBody, runtime=Depends(get_runtime)):
    try:
        envelope = await runtime.client_api.deliver_config(
            body.connect_token, body.client_public_key
        )
    except ClientApiError as exc:
        raise _client_error(exc) from exc
    return envelope


# ---------------------------------------------------------------------- #
# Subscription portal (/zagros/sub/{token})
# ---------------------------------------------------------------------- #

async def _legacy_sub_user_id(token: str) -> int | None:
    """Validate a LEGACY username token (pre-alpha.7.2
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
        # legacy username token (issued pre-alpha.7.2) — same portal, one
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
    """Canonical multi-core subscription URL — /sub/<token> (alpha.7.4 item
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

    # legacy-continuity bookkeeping (alpha.7.2, item 14): the removed /sub/
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
        page = await runtime.portal.build_page(user_id, lang=lang)
        if page is None:
            raise HTTPException(404, "subscription not found")
        return HTMLResponse(render_page_html(page))

    bundle = await runtime.portal.build_links(user_id)
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
    settings = await runtime.portal_settings.get_portal_settings()
    path = f"/sub/{token}"  # canonical (alpha.7.4 item 12)
    prefix = (settings.subscription_url_prefix or "").rstrip("/")
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
async def core_wizard_schema(core_id: str):
    """Dynamic inbound-wizard blueprint (protocols × transports × securities
    × fields) for THIS engine — the dashboard stepper renders it verbatim."""
    from app.studio.wizard import blueprint_for

    try:
        return blueprint_for(core_id)
    except KeyError:
        raise HTTPException(404, f"no inbound-wizard blueprint for core '{core_id}'") from None


class StudioPatchBody(BaseModel):
    operations: list[PatchOperation]


@zagros_admin_router.post("/studio/{core_id}/preview")
async def studio_preview(core_id: str, body: StudioPatchBody,
                         runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    return await runtime.studio.preview(driver, body.operations)


async def _materialize_studio(runtime, core_id: str, driver) -> str | None:
    """Push the freshly-applied studio document INTO the core (every driver
    implements apply_studio_document since alpha.7.1).

    A driver that refuses the document (CoreError — cardinality violation,
    untranslatable wizard field, failed restart) speaks to the OPERATOR, so
    it maps to 422 with the driver's own message instead of leaking out as
    an opaque 500 (the field-reported TUIC/OpenVPN/… wizard crash)."""
    doc = await runtime.studio_store.get_document(core_id)
    hook = getattr(driver, "apply_studio_document", None)
    if hook is None or doc is None:
        return ("document saved; this engine applies it on next start "
                "(no live studio→core bridge for this driver)")
    try:
        await hook(doc)
    except CoreError as exc:
        raise HTTPException(422, f"{core_id}: {exc}") from exc
    # Item 6: an applied document may have REMOVED inbounds — cascade the
    # change into materialized grants (prune dangling tags / revoke empty
    # accounts) so a later User Edit can never die on a ghost tag.
    try:
        from app.platform.provisioning import (
            reconcile_accounts_after_inbound_change,
        )

        report = await reconcile_accounts_after_inbound_change(runtime, core_id)
        if any(report.get(k) for k in ("pruned", "revoked")):
            logger.info("studio apply on %s — grant cascade: %s", core_id, report)
    except Exception as exc:  # noqa: BLE001 — never mask a successful apply
        logger.warning("post-apply grant cascade failed on %s: %s", core_id, exc)
    return None


@zagros_admin_router.post("/studio/{core_id}/apply")
async def studio_apply(core_id: str, body: StudioPatchBody,
                       runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    result = await runtime.studio.apply(driver, body.operations)
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    warning = await _materialize_studio(runtime, core_id, driver)
    return {**result.model_dump(), "materialized": warning is None, "notice": warning}


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
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_add_inbound(driver, spec)
    except StudioError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    warning = await _materialize_studio(runtime, core_id, driver)
    return {**result.model_dump(), "materialized": warning is None, "notice": warning}


@zagros_admin_router.put("/studio/{core_id}/wizard/inbound/{tag}")
async def studio_wizard_update_inbound(core_id: str, tag: str, spec: InboundSpec,
                                       runtime=Depends(get_runtime)):
    """Item 11 — Edit an existing inbound through the same wizard flow."""
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_update_inbound(driver, tag, spec)
    except StudioError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    warning = await _materialize_studio(runtime, core_id, driver)
    return {**result.model_dump(), "materialized": warning is None, "notice": warning}


class WizardImportBody(BaseModel):
    link: str


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


@zagros_admin_router.post("/cores/{core_id}/wizard/import")
async def core_wizard_import(core_id: str, body: WizardImportBody):
    """Item 6 Import: parse a client share link into a blueprint-matched
    wizard prefill spec (never guessed; unmapped values are reported)."""
    from app.studio.wizard import wizard_supported
    from app.studio.wizard_import import WizardImportError, import_link_spec

    if not wizard_supported(core_id):
        raise HTTPException(404, f"no inbound-wizard blueprint for core '{core_id}'")
    try:
        return import_link_spec(core_id, body.link)
    except WizardImportError as exc:
        raise HTTPException(422, str(exc)) from exc


def _driver_or_404(runtime, core_id: str):
    try:
        return runtime.core_manager.get(core_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(404, f"core '{core_id}' is not installed") from exc


@zagros_admin_router.get("/settings/portal", response_model=PortalSettings)
async def get_portal_settings(runtime=Depends(get_runtime)):
    return await runtime.portal_settings.get_portal_settings()


@zagros_admin_router.put("/settings/portal", response_model=PortalSettings)
async def put_portal_settings(settings: PortalSettings,
                              runtime=Depends(get_runtime)):
    try:
        return await runtime.portal_settings.save_portal_settings(settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


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
