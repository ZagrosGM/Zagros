"""Worker-facing build API (job-token / worker-token authenticated).

Mounted WITHOUT the sudo admin dependency — every endpoint authenticates
via tokens instead. The only secret-bearing response in the whole panel
is the job document (decrypted build credentials for the authenticated
worker); it must only ever travel over TLS.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import (
    APIRouter, Depends, File, Form, Header, HTTPException, Query,
    UploadFile,
)
from fastapi.responses import FileResponse

from app.builder.errors import (
    BuildError,
    BuildValidationFailed,
    WorkerAuthFailed,
)
from app.builder.models import (
    ArtifactPublic,
    BuildPublic,
    ClaimBody,
    HeartbeatResult,
    JobFetchResult,
    JobPublic,
    WorkerEnrolledResult,
    WorkerRegisterBody,
    StatusReportBody,
)
from app.platform.routers import get_runtime

builder_worker_router = APIRouter(
    prefix="/api/zagros/builder", tags=["Builder"])


def _build_error(exc: BuildError) -> HTTPException:
    return HTTPException(
        exc.status_code,
        {"error": exc.error_code, "message": str(exc)},
    )


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise WorkerAuthFailed("missing or malformed Authorization header")
    token = authorization[len("Bearer "):].strip()
    if not token:
        raise WorkerAuthFailed("missing or malformed Authorization header")
    return token


@builder_worker_router.post("/workers/register",
                           response_model=WorkerEnrolledResult)
async def register_worker(body: WorkerRegisterBody,
                          runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.register_worker, body.worker_id,
            body.register_token)
    except BuildError as exc:
        raise _build_error(exc) from exc


@builder_worker_router.post("/workers/heartbeat",
                           response_model=HeartbeatResult)
async def worker_heartbeat(
        x_zagros_worker_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        runtime=Depends(get_runtime)):
    try:
        if not x_zagros_worker_id:
            raise WorkerAuthFailed("missing X-Zagros-Worker-Id header")
        return await asyncio.to_thread(
            runtime.build_service.heartbeat, x_zagros_worker_id,
            _bearer(authorization))
    except BuildError as exc:
        raise _build_error(exc) from exc


@builder_worker_router.post(
    "/jobs/{build_id}/{platform}/{arch}/claim", response_model=JobPublic)
async def claim_job(build_id: str, platform: str, arch: str,
                    body: ClaimBody,
                    artifact: str = Query(default="apk"),
                    authorization: str | None = Header(default=None),
                    runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.claim_job,
            build_public_id=build_id, platform=platform, arch=arch,
            artifact=artifact, token=_bearer(authorization),
            worker_id=body.worker_id,
            worker_token=body.worker_token)
    except BuildError as exc:
        raise _build_error(exc) from exc


@builder_worker_router.get("/jobs/{build_id}/{platform}/{arch}",
                          response_model=JobFetchResult)
async def fetch_job(build_id: str, platform: str, arch: str,
                    artifact: str = Query(default="apk"),
                    authorization: str | None = Header(default=None),
                    runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.build_service.fetch_job, build_public_id=build_id,
            platform=platform, arch=arch, artifact=artifact,
            token=_bearer(authorization))
    except BuildError as exc:
        raise _build_error(exc) from exc


@builder_worker_router.get("/jobs/{build_id}/{platform}/{arch}/icon")
async def fetch_job_icon(build_id: str, platform: str, arch: str,
                         artifact: str = Query(default="apk"),
                         authorization: str | None = Header(default=None),
                         runtime=Depends(get_runtime)):
    """Serve the application's rendered launcher pack (job-token authed).

    404 when the application has no icon; a worker that was advertised a
    pack (job ``icon.present``) but gets a 404 here fails the job loudly
    instead of shipping a silently unbranded build.
    """
    from app.applicationapi.icons import pack_file_path
    from app.portal.templates_store import data_dir_for

    try:
        ref = await asyncio.to_thread(
            runtime.build_service.fetch_job_icon,
            build_public_id=build_id, platform=platform, arch=arch,
            artifact=artifact, token=_bearer(authorization))
    except BuildError as exc:
        raise _build_error(exc) from exc
    path = pack_file_path(data_dir_for(runtime), ref["public_id"])
    if not path.is_file():
        raise HTTPException(404, "launcher icon pack file is missing")
    return FileResponse(path, media_type="application/zip",
                        filename=f"{build_id}-icon-pack.zip")


@builder_worker_router.post("/jobs/{build_id}/{platform}/{arch}/status",
                           response_model=BuildPublic)
async def report_job_status(build_id: str, platform: str, arch: str,
                            body: StatusReportBody,
                            artifact: str = Query(default="apk"),
                            authorization: str | None = Header(default=None),
                            runtime=Depends(get_runtime)):
    try:
        final_log = (body.final_log.encode("utf-8", "replace")
                     if body.final_log is not None else None)
        return await asyncio.to_thread(
            runtime.build_service.report_status,
            build_public_id=build_id, platform=platform, arch=arch,
            artifact=artifact,
            token=_bearer(authorization), status=body.status,
            failure_code=body.failure_code,
            failure_message=body.failure_message, final_log=final_log)
    except BuildError as exc:
        raise _build_error(exc) from exc


@builder_worker_router.post("/jobs/{build_id}/{platform}/{arch}/artifacts",
                           response_model=ArtifactPublic)
async def upload_job_artifact(
        build_id: str, platform: str, arch: str,
        artifact: str = Query(default="apk"),
        file: UploadFile = File(...),
        sha256: str = Form(...),
        size_bytes: int = Form(...),
        toolchain: str | None = Form(default=None),
        authorization: str | None = Header(default=None),
        runtime=Depends(get_runtime)):
    try:
        manifest = json.loads(toolchain) if toolchain else None
        if manifest is not None and not isinstance(manifest, dict):
            raise BuildValidationFailed("toolchain must be a JSON object")
        filename = file.filename or ""
        # UploadFile.file is a SpooledTemporaryFile — the service streams
        # it in chunks so multi-hundred-MB artifacts never hit RAM twice.
        return await asyncio.to_thread(
            runtime.build_service.upload_artifact,
            build_public_id=build_id, platform=platform, arch=arch,
            artifact=artifact, token=_bearer(authorization),
            filename=filename,
            stream=file.file, sha256=sha256, size_bytes=int(size_bytes),
            toolchain=manifest)
    except BuildError as exc:
        raise _build_error(exc) from exc
