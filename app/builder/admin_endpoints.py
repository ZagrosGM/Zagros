"""Admin build-system endpoints (registered on the sudo admin router).

Importing this module registers the routes as a side effect — see
``app/__init__.py``. Tests mount ``zagros_admin_router`` the same way.
"""
from __future__ import annotations

import asyncio

from fastapi import Depends, HTTPException, Request
from fastapi.responses import FileResponse

from app.builder.errors import BuildError
from app.builder.models import (
    ArtifactPublic,
    BuildCreateBody,
    BuildListResult,
    BuildPublic,
    CancelResult,
    CredentialCreateBody,
    ExternalHostProbeBody,
    ExternalHostProbeResult,
    ResolvedSourceResult,
    CredentialPublic,
    CredentialRotateBody,
    LogReadResult,
    RegisterTokenBody,
    RegisterTokenResult,
    WorkerCreateBody,
    WorkerPublic,
)
from app.platform.routers import (
    _owner_admin_id_or_current, get_runtime, zagros_admin_router,
)


def _build_error(exc: BuildError) -> HTTPException:
    return HTTPException(
        exc.status_code,
        {"error": exc.error_code, "message": str(exc)},
    )


# ---------------------------------------------------------------------- #
# builds
# ---------------------------------------------------------------------- #

@zagros_admin_router.post("/applications/{application_id}/builds",
                          response_model=BuildPublic, status_code=201)
async def create_build(application_id: str, body: BuildCreateBody,
                       request: Request,
                       runtime=Depends(get_runtime)):
    owner_admin_id = await _owner_admin_id_or_current(
        request, runtime, body.owner_admin_id)
    try:
        return await asyncio.to_thread(
            runtime.build_service.create_build,
            owner_admin_id=owner_admin_id,
            application_public_id=application_id, version=body.version,
            source_repo=body.source_repo,
            source_revision=body.source_revision,
            sdk_source_repo=body.sdk_source_repo,
            sdk_source_revision=body.sdk_source_revision,
            build_config=body.build_config,
            targets=[target.model_dump() for target in body.targets],
            credential_ids=body.credential_ids)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.post("/builds/resolve-source",
                          response_model=ResolvedSourceResult)
async def resolve_default_source(runtime=Depends(get_runtime)):
    """Wizard Simple mode: HEAD of the allowlisted app + SDK repos."""
    try:
        return await asyncio.to_thread(
            runtime.build_service.resolve_default_source)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.post("/builds/external-host-probe",
                          response_model=ExternalHostProbeResult)
async def probe_external_host(body: ExternalHostProbeBody,
                              runtime=Depends(get_runtime)):
    """Wizard: test an external build host before queueing on it.

    The supplied credentials are used for this probe only and are never
    persisted; storing them is an explicit separate wizard step.
    """
    try:
        return await asyncio.to_thread(
            runtime.build_service.probe_external_host,
            host=body.host, port=body.port, username=body.username,
            password=body.password, private_key=body.private_key)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/builds", response_model=BuildListResult)
async def list_builds(status: str | None = None,
                      application_id: str | None = None,
                      owner_admin_id: int | None = None,
                      limit: int = 50, offset: int = 0,
                      runtime=Depends(get_runtime)):
    try:
        items, total = await asyncio.to_thread(
            runtime.build_service.list_builds, limit=limit, offset=offset,
            status=status, application_public_id=application_id,
            owner_admin_id=owner_admin_id)
        return {"items": items, "total": total}
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/builds/{build_id}", response_model=BuildPublic)
async def get_build(build_id: str, runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.get_build, build_id)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.post("/builds/{build_id}/cancel",
                         response_model=CancelResult)
async def cancel_build(build_id: str, runtime=Depends(get_runtime)):
    try:
        result = await asyncio.to_thread(
            runtime.build_service.cancel_build, build_id)
        queue_cancel = result.pop("queue_cancel", [])
        return {"build": result, "queue_cancel": queue_cancel}
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/builds/{build_id}/logs",
                        response_model=LogReadResult)
async def read_build_logs(build_id: str, platform: str, arch: str,
                          cursor: str = "0", limit: int = 200,
                          runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.read_logs, build_id, platform=platform,
            arch=arch, cursor=cursor, limit=limit)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/builds/{build_id}/artifacts",
                        response_model=list[ArtifactPublic])
async def list_build_artifacts(build_id: str,
                               runtime=Depends(get_runtime)):
    try:
        build = await asyncio.to_thread(
            runtime.build_service.get_build, build_id)
        return build["artifacts"]
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get(
    "/builds/{build_id}/artifacts/{platform}/{arch}/{filename}")
async def download_build_artifact(build_id: str, platform: str, arch: str,
                                  filename: str,
                                  runtime=Depends(get_runtime)):
    try:
        path, artifact = await asyncio.to_thread(
            runtime.build_service.download_artifact, build_id,
            platform=platform, arch=arch, filename=filename)
        return FileResponse(
            path, filename=artifact["filename"],
            media_type="application/octet-stream")
    except BuildError as exc:
        raise _build_error(exc) from exc


# ---------------------------------------------------------------------- #
# workers
# ---------------------------------------------------------------------- #

@zagros_admin_router.post("/builder/workers", response_model=WorkerPublic)
async def create_worker(body: WorkerCreateBody,
                        runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.create_worker,
            worker_id=body.worker_id, display_name=body.display_name,
            platform_labels=body.platform_labels)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/builder/workers",
                        response_model=list[WorkerPublic])
async def list_workers(runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(runtime.build_service.list_workers)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/builder/workers/{worker_id}",
                        response_model=WorkerPublic)
async def get_worker(worker_id: str, runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.get_worker, worker_id)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.post("/builder/workers/{worker_id}/register-token",
                         response_model=RegisterTokenResult)
async def issue_worker_register_token(
        worker_id: str, body: RegisterTokenBody,
        runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.issue_register_token, worker_id,
            ttl_seconds=body.ttl_seconds)
    except BuildError as exc:
        raise _build_error(exc) from exc


# ---------------------------------------------------------------------- #
# build credentials (metadata only — material never leaves this API)
# ---------------------------------------------------------------------- #

@zagros_admin_router.post("/build-credentials",
                         response_model=CredentialPublic)
async def store_build_credential(body: CredentialCreateBody,
                                 runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.store_credential, scope=body.scope,
            owner_ref=body.owner_ref, kind=body.kind, label=body.label,
            material=body.material)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/build-credentials",
                        response_model=list[CredentialPublic])
async def list_build_credentials(scope: str | None = None,
                                 owner_ref: str | None = None,
                                 include_revoked: bool = False,
                                 runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.list_credentials, scope=scope,
            owner_ref=owner_ref, include_revoked=include_revoked)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.get("/build-credentials/{credential_id}",
                        response_model=CredentialPublic)
async def get_build_credential(credential_id: str,
                               runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.get_credential, credential_id)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.post("/build-credentials/{credential_id}/rotate",
                         response_model=CredentialPublic)
async def rotate_build_credential(credential_id: str,
                                  body: CredentialRotateBody,
                                  runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.rotate_credential, credential_id,
            body.material)
    except BuildError as exc:
        raise _build_error(exc) from exc


@zagros_admin_router.post("/build-credentials/{credential_id}/revoke",
                         response_model=CredentialPublic)
async def revoke_build_credential(credential_id: str,
                                  runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.revoke_credential, credential_id)
    except BuildError as exc:
        raise _build_error(exc) from exc
